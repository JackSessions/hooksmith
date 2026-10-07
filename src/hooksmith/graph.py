"""The pipeline as a LangGraph state machine.

    triage -> next_finding -> decompile -> plan -> generate -> validate --ok--> execute -> classify -> record -+
                   ^              |                    ^           |                |                   ^     |
                   |              |                    +--retry----+ (once, with    +--not attached----+     |
                   |              +--unresolved--------------------- validator feedback)                     |
                   +------------------------------------------------- next_finding <--------------------------+
                                                                            |
                                                                      (no findings left)
                                                                            v
                                                                          report -> END

`triage` runs once before any finding touches a device: merges exact duplicates (same type + same class.method)
so they don't cost device time twice, and orders the rest by severity. `report` runs once after every finding has
a verdict: writes a grounded bug_report markdown file for each PROVEN finding, straight from the evidence already
on disk -- no new claims, nothing the signal library didn't already decide.

Every path through the loop ends in `record` with exactly one of the four verdicts. A finding can leave the graph
through UNVALIDATED at several points, and each of them stores the reason. Nothing is dropped silently.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, TypedDict

from langgraph.graph import END, StateGraph

from . import signals
from .decompile import Resolved, Unresolved, resolve
from .executors.base import Executor, RunSpec
from .exercise import plan_steps, validate_plan
from .manifest import Manifest
from .models import ExecutionResult, Finding, HookAttempt, Outcome, Verdict
from .providers import GenRequest, Provider, overload_for, trim_source
from .store import Store
from .validator import validate_hook

Event = Callable[..., None]


@dataclass
class Ctx:
    findings: list[Finding]
    sources: Path
    store: Store
    provider: Provider
    executor: Executor
    package: str
    manifest: Manifest = field(default_factory=Manifest)
    timeout_s: int = 45
    max_attempts: int = 2
    max_runtime_repairs: int = 1  # extra regenerations driven by real on-device errors
    agent_plan: bool = False
    bug_reports: bool = True  # write bugs/<id>.md for PROVEN findings once the run finishes
    record: bool = False  # screen-record the device per finding, for demo proof (adb-based executors only)
    on_event: Event = lambda *a, **k: None  # noqa: E731
    duplicate_of: dict[str, str] = field(default_factory=dict)  # set by the triage node
    all_findings: dict[str, Finding] = field(default_factory=dict)  # set by the triage node


class State(TypedDict, total=False):
    idx: int
    finding: Finding | None
    resolved: Resolved | None
    overload: list[str] | None
    steps: list[str] | None
    attempts: list[HookAttempt]
    execution: ExecutionResult | None
    outcome: Outcome | None
    t0: float
    done: int
    runtime_error: str | None
    repairs: int


def build_graph(ctx: Ctx):
    store, ev = ctx.store, ctx.on_event
    decided = store.decided()

    # ---- nodes ---------------------------------------------------------------------------
    def triage_node(s: State) -> State:
        """Runs once, before any finding touches a device: merge duplicates, order by severity."""
        from .triage import triage as run_triage

        ctx.all_findings = {f.id: f for f in ctx.findings}
        result = run_triage(ctx.findings)
        ctx.duplicate_of = result.duplicate_of
        ctx.findings = result.ordered
        if result.duplicate_of:
            ev(
                "note",
                None,
                text=f"triage: {len(result.duplicate_of)} duplicate finding(s) merged into {len(result.ordered)} "
                f"to run (same type + same target reported more than once)",
            )
        return {}

    def next_finding(s: State) -> State:
        i = s.get("idx", 0)
        while i < len(ctx.findings) and ctx.findings[i].id in decided:
            i += 1  # resumed run: skip what already has a verdict
        if i >= len(ctx.findings):
            return {"finding": None, "idx": i}
        f = ctx.findings[i]
        store.add_finding(f)
        ev("start", f, index=i + 1, total=len(ctx.findings))
        return {
            "idx": i + 1,
            "finding": f,
            "resolved": None,
            "overload": None,
            "steps": None,
            "attempts": [],
            "execution": None,
            "outcome": None,
            "runtime_error": None,
            "repairs": 0,
            "t0": time.time(),
        }

    def after_next(s: State) -> str:
        return "decompile" if s.get("finding") else END

    def decompile(s: State) -> State:
        f = s["finding"]
        ev("stage", f, stage="decompile")
        r = resolve(f, ctx.sources)
        if isinstance(r, Unresolved):
            return {"outcome": Outcome(verdict=Verdict.UNVALIDATED, reason=r.reason)}
        store.save_source(f.id, r.java_class.source)
        if r.class_name != f.class_name:  # jadx's folder path (e.g. a "defpackage" placeholder) wasn't the real name
            ev("note", f, text=f"runtime class is {r.class_name!r}, not {f.class_name!r} (resolved from source)")
        f.class_name, f.method = r.class_name, r.method_name
        store.add_finding(f)
        return {"resolved": r, "overload": overload_for(r.java_class, r.method)}

    def after_decompile(s: State) -> str:
        return "record" if s.get("outcome") else "plan"

    def plan(s: State) -> State:
        f = s["finding"]
        ev("stage", f, stage="plan")
        steps = plan_steps(ctx.package, ctx.manifest, f)
        planner = getattr(ctx.provider, "plan", None)
        if ctx.agent_plan and planner:
            try:
                proposed = planner(f, ctx.manifest, steps)
                steps = validate_plan(proposed) if proposed else steps
            except Exception as exc:  # noqa: BLE001 - planning is best-effort; fall back to the heuristic plan
                ev("note", f, text=f"agent planner failed ({exc}); using heuristic plan")
        return {"steps": steps}

    def generate(s: State) -> State:
        f, r = s["finding"], s["resolved"]
        attempts = list(s["attempts"])
        ev("stage", f, stage="generate" if not attempts else "regenerate")
        last = attempts[-1] if attempts else None
        errors = last.validation.errors if last and last.validation else None
        if s.get("runtime_error"):  # the hook passed static checks but failed on the device: tell the model what Frida said
            errors = [f"on-device error from Frida: {s['runtime_error']}"]
            ev("note", f, text=f"repairing hook from runtime error: {s['runtime_error'][:120]}")
        req = GenRequest(
            finding_type=f.type,
            class_name=f.class_name or "",
            method=r.method_name,
            title=f.title,
            source=trim_source(r.java_class, r.method),
            overload=s.get("overload"),
            errors=errors,
            previous=last.js if last else None,
        )
        try:
            g = ctx.provider.generate(req)
            attempts.append(HookAttempt(n=len(attempts) + 1, js=g.js, raw=g.raw, model=g.model))
            return {"attempts": attempts, "runtime_error": None}
        except Exception as exc:  # noqa: BLE001
            return {
                "attempts": attempts,
                "outcome": Outcome(verdict=Verdict.UNVALIDATED, reason=f"hook generation failed: {exc}"),
            }

    def after_generate(s: State) -> str:
        return "record" if s.get("outcome") else "validate"

    def validate(s: State) -> State:
        f, r = s["finding"], s["resolved"]
        ev("stage", f, stage="validate")
        attempts = list(s["attempts"])
        a = attempts[-1]
        a.validation = validate_hook(a.js, f.class_name or "", r.method_name, r.java_class, f.param_types)
        store.save_attempt(f.id, a)
        ev("validation", f, attempt=a.n, ok=a.validation.ok, errors=a.validation.errors)
        if a.validation.ok:
            return {"attempts": attempts}
        if len(attempts) >= ctx.max_attempts:
            why = "; ".join(a.validation.errors)[:400]
            return {
                "attempts": attempts,
                "outcome": Outcome(
                    verdict=Verdict.UNVALIDATED,
                    reason=f"hook failed static validation {len(attempts)} times (hallucinated or malformed): {why}",
                ),
            }
        return {"attempts": attempts}

    def after_validate(s: State) -> str:
        if s.get("outcome"):
            return "record"
        return "execute" if s["attempts"][-1].validation.ok else "generate"

    def execute(s: State) -> State:
        f = s["finding"]
        ev("stage", f, stage="execute")
        hook = s["attempts"][-1].js
        store.save_executed_hook(f.id, hook)
        spec = RunSpec(
            finding=f,
            hook_js=hook,
            package=ctx.package,
            manifest=ctx.manifest,
            timeout_s=ctx.timeout_s,
            steps=s.get("steps"),
            record=ctx.record,
        )
        res = ctx.executor.run(spec)
        if res.screen:  # move it into the evidence store BEFORE saving execution.json, so the recorded path is stable
            dest = store.save_screen_recording(f.id, Path(res.screen))
            res.screen = dest.name
            ev("note", f, text=f"screen recording saved: {dest.name} ({dest.stat().st_size // 1024} KB)")
        store.save_execution(f.id, res)
        repairs = s.get("repairs", 0)
        no_call = not any(e["event"] == "call" for e in signals.parse_events(res.log))
        broken = bool(res.load_error) or (res.attached and bool(res.error) and no_call)
        if broken and repairs < ctx.max_runtime_repairs:
            (store.finding_dir(f.id) / f"runtime.attempt{len(s['attempts'])}.log").write_text(
                "\n".join(res.log) + f"\n[error] {res.error}\n"
            )
            return {"execution": res, "runtime_error": res.error or res.load_error, "repairs": repairs + 1}
        if not res.attached:
            return {
                "execution": res,
                "outcome": Outcome(
                    verdict=Verdict.UNVALIDATED, reason=f"hook could not be attached: {res.error or 'unknown error'}"
                ),
            }
        return {"execution": res}

    def after_execute(s: State) -> str:
        if s.get("outcome"):
            return "record"
        return "generate" if s.get("runtime_error") else "classify"

    def classify(s: State) -> State:
        f, r, res = s["finding"], s["resolved"], s["execution"]
        ev("stage", f, stage="classify")
        o = signals.classify(f, res.log, r.java_class.source, sources_root=ctx.sources)
        if res.error and o.verdict == Verdict.UNREACHABLE:
            o.reason += f" (hook error: {res.error})"
        return {"outcome": o}

    def record(s: State) -> State:
        f, o = s["finding"], s["outcome"]
        store.save_verdict(f.id, o)
        decided.add(f.id)
        ev("verdict", f, outcome=o, seconds=round(time.time() - s["t0"], 1))
        copied = [dup_id for dup_id, canon_id in ctx.duplicate_of.items() if canon_id == f.id]
        for dup_id in copied:
            dup = ctx.all_findings.get(dup_id)
            if dup is None:
                continue
            store.add_finding(dup)
            store.save_verdict(dup_id, Outcome(verdict=o.verdict, reason=f"(duplicate of {f.id}) {o.reason}", signal=o.signal))
        if copied:
            ev("note", f, text=f"same verdict copied to {len(copied)} duplicate finding(s): {', '.join(copied)}")
        return {"done": s.get("done", 0) + 1}

    def report_node(s: State) -> State:
        """Runs once, after every finding has a verdict: write bug_reports for whatever is PROVEN."""
        if not ctx.bug_reports:
            return {}
        from .bugreport import write_bug_reports

        rows = store.rows()
        written = write_bug_reports(store.root, rows)
        if written:
            ev("note", None, text=f"wrote {len(written)} bug report(s) to {store.root / 'bugs'}/")
        return {}

    # ---- wiring --------------------------------------------------------------------------
    g = StateGraph(State)
    for name, fn in [
        ("triage", triage_node),
        ("next_finding", next_finding),
        ("decompile", decompile),
        ("plan", plan),
        ("generate", generate),
        ("validate", validate),
        ("execute", execute),
        ("classify", classify),
        ("record", record),
        ("report", report_node),
    ]:
        g.add_node(name, fn)
    g.set_entry_point("triage")
    g.add_edge("triage", "next_finding")
    g.add_conditional_edges("next_finding", after_next, {"decompile": "decompile", END: "report"})
    g.add_edge("report", END)
    g.add_conditional_edges("decompile", after_decompile, {"record": "record", "plan": "plan"})
    g.add_edge("plan", "generate")
    g.add_conditional_edges("generate", after_generate, {"record": "record", "validate": "validate"})
    g.add_conditional_edges("validate", after_validate, {"record": "record", "execute": "execute", "generate": "generate"})
    g.add_conditional_edges("execute", after_execute, {"record": "record", "classify": "classify", "generate": "generate"})
    g.add_edge("classify", "record")
    g.add_edge("record", "next_finding")
    return g.compile()


def run_pipeline(ctx: Ctx) -> dict[str, Any]:
    app = build_graph(ctx)
    limit = 50 + len(ctx.findings) * 14  # each finding visits ~6-9 nodes; retries add a few more
    return app.invoke({"idx": 0}, config={"recursion_limit": limit})
