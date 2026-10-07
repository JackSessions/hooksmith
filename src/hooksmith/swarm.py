"""Swarm triage: a real LangGraph fan-out/fan-in subgraph that classifies a raw MobSF report in parallel,
*before* a single finding reaches the main per-finding pipeline.

    load (MobSF JSON -> one raw item per rule+file)
         │
         ▼ (Send: one parallel branch per raw item)
    classify_one  classify_one  classify_one  ...   <- the "swarm": runs concurrently, one per finding
         │             │             │
         └──────────── merge ────────┘
                         │
                         ▼
          testable findings (triage-ordered)  +  skipped (type HookSmith can't runtime-test)

Each `classify_one` worker is pure and deterministic (reuses `ingest.classify_type`; no device, no network, no
LLM) and does two things the straight-line `ingest -> triage` path does not:
  1. Flags whether the finding's class looks like the app's own code or a bundled third-party SDK -- real apps
     ship dozens of vendor libraries (analytics, fraud detection, MFA, crash reporting, ...) that get reported by
     the same scanner rules as the app's own bugs. This never drops a finding; it annotates it, so a human (or
     --fail-on policy) can prioritize or exclude vendor noise without losing the finding entirely.
  2. Separates findings into `testable` (one of the 5 types the signal library can prove or refute) and `skipped`
     (everything else: HookSmith does not invent a verdict for a finding type it has no signal for).
The existing `triage` node in the main graph still runs afterwards and still does its job (duplicate merging);
this module's job is classification and vendor-flagging, upstream of that.
"""

from __future__ import annotations

import operator
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, TypedDict

from langgraph.graph import END, StateGraph
from langgraph.types import Send

from .ingest import classify_type, from_mobsf
from .models import Finding, FindingType
from .triage import SEVERITY_RANK, triage

# Common third-party SDK package roots. Not exhaustive -- it does not need to be, since it only ever *annotates*,
# never drops. Extended from real-world findings (a 49-finding scan of a commercial Ionic/Capacitor app) alongside
# scan.py's own noise list, which covers the Android/Kotlin/Google framework side of the same problem.
VENDOR_PACKAGES = re.compile(
    r"^(?:"
    r"kotlin|kotlinx|androidx?|android\.support|com\.google\.(?:android\.gms|android\.material|firebase|android\.datatransport)|"
    r"com\.facebook|com\.squareup|okhttp3|okio|retrofit2|io\.reactivex|rx|org\.jetbrains|org\.junit|org\.mockito|org\.apache|"
    r"com\.bumptech\.glide|coil|com\.airbnb|"
    r"com\.biocatch|com\.cyberfend|com\.pingidentity|io\.ably|io\.intercom|ch\.qos\.logback|com\.getcapacitor|"
    r"com\.ionicframework|com\.google\.android\.datatransport"
    r")\."
)


def is_vendor_package(class_name: str) -> bool:
    return bool(VENDOR_PACKAGES.match(class_name or ""))


def is_own_code(class_name: str, package: str | None) -> bool:
    """A loose heuristic, not proof: true when the class sits under the app's own declared package, or under a
    generalised root of it (e.g. app package "com.realshape.app" also covers a sibling "com.realshape.feature").
    Known to miss R8-obfuscated own code moved outside the declared package entirely (a merged/repackaged class
    like "A2.i" instead of "com.realshape.app.Crypto") -- the same class of problem decompile.real_class_name()
    solves once source is available, which this heuristic runs before decompiling, so it cannot see.
    """
    if not package or not class_name:
        return False
    if class_name == package or class_name.startswith(package + "."):
        return True
    root = package.rsplit(".", 1)[0] if "." in package else package
    if root.count(".") >= 1:  # at least two segments (e.g. "com.realshape"); a bare "com" would match everything
        return class_name.startswith(root + ".")
    return False


def priority_score(finding: Finding, vendor_likely: bool) -> int:
    """Lower sorts first, same convention as triage.SEVERITY_RANK. Vendor code is real but lower priority: it is
    usually out of the app developer's direct control and more likely to be a known, accepted risk in the SDK.
    """
    base = SEVERITY_RANK.get((finding.severity or "info").lower(), 4)
    return base + (1 if vendor_likely else 0)


@dataclass
class SwarmResult:
    findings: list[Finding]  # testable, vendor-annotated, triage-ordered
    skipped: list[dict]  # [{"class": ..., "title": ..., "reason": ...}] -- types with no signal in v1
    vendor_count: int
    own_code_count: int


class ClassifyState(TypedDict):
    item: dict
    package: str | None


class SwarmState(TypedDict, total=False):
    raw: list[dict]
    package: str | None
    classified: Annotated[list[dict], operator.add]  # each parallel branch appends; this is the fan-in reducer
    result: SwarmResult


def _raw_items(report: dict) -> list[dict]:
    """One dict per (rule, file) pair -- the same granularity as ingest.from_mobsf, kept as plain dicts so the
    swarm can annotate them before a single Finding object (and its generated id) is created.
    """
    out = []
    for f in from_mobsf(report):
        out.append(
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "description": f.description,
                "class_name": f.class_name,
                "file_path": f.file_path,
                "lines": f.lines,
                "raw": f.raw,
            }
        )
    return out


def _fan_out(state: SwarmState) -> list[Send]:
    return [Send("classify_one", {"item": item, "package": state.get("package")}) for item in state["raw"]]


def _classify_one(state: ClassifyState) -> dict:
    item = state["item"]
    rule = (item.get("raw") or {}).get("rule", "")
    ftype = classify_type(rule, item.get("title", ""), item.get("description", ""))
    cls = item.get("class_name") or ""
    annotated = {
        **item,
        "type": ftype.value,
        "vendor_likely": is_vendor_package(cls),
        "own_code_likely": is_own_code(cls, state.get("package")),
    }
    return {"classified": [annotated]}


def _merge(state: SwarmState) -> dict:
    testable: list[Finding] = []
    skipped: list[dict] = []
    vendor_count = own_count = 0
    for c in state["classified"]:
        if c["vendor_likely"]:
            vendor_count += 1
        if c["own_code_likely"]:
            own_count += 1
        try:
            ftype = FindingType(c["type"])
        except ValueError:
            ftype = FindingType.UNKNOWN
        if ftype == FindingType.UNKNOWN:
            skipped.append(
                {
                    "id": c["id"],
                    "title": c["title"],
                    "class": c.get("class_name"),
                    "reason": "no HookSmith signal for this finding type yet",
                }
            )
            continue
        testable.append(
            Finding(
                id=c["id"],
                title=c["title"],
                type=ftype,
                severity=c.get("severity", "info"),
                description=c.get("description", ""),
                class_name=c.get("class_name"),
                file_path=c.get("file_path"),
                lines=c.get("lines") or [],
                source="mobsf",
                raw={**(c.get("raw") or {}), "vendor_likely": c["vendor_likely"], "own_code_likely": c["own_code_likely"]},
            )
        )
    ordered = triage(sorted(testable, key=lambda f: priority_score(f, f.raw.get("vendor_likely", False)))).ordered
    return {"result": SwarmResult(findings=ordered, skipped=skipped, vendor_count=vendor_count, own_code_count=own_count)}


def build_swarm_graph():
    g = StateGraph(SwarmState)
    g.add_node("classify_one", _classify_one)
    g.add_node("merge", _merge)
    g.set_conditional_entry_point(_fan_out, {"classify_one": "classify_one"})
    g.add_edge("classify_one", "merge")
    g.add_edge("merge", END)
    return g.compile()


def run_swarm_triage(report_path: Path, package: str | None = None) -> SwarmResult:
    """The public entry point: a raw MobSF report in, a testable-and-prioritised Finding list out."""
    import json

    report = json.loads(Path(report_path).read_text())
    raw = _raw_items(report)
    if not raw:
        return SwarmResult(findings=[], skipped=[], vendor_count=0, own_code_count=0)
    app = build_swarm_graph()
    out = app.invoke({"raw": raw, "package": package}, config={"recursion_limit": len(raw) + 20})
    return out["result"]


__all__ = ["SwarmResult", "run_swarm_triage", "build_swarm_graph", "is_vendor_package", "is_own_code", "priority_score"]
