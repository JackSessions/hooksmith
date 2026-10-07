"""Glue: turn CLI options into a Ctx, run the graph, write the report. Everything testable lives below the CLI."""

from __future__ import annotations

import json
import platform
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .decompile import DecompileError, run_jadx, sha256_file
from .executors import Executor
from .executors.adb import package_from_apk
from .graph import Ctx, run_pipeline
from .ingest import is_mobsf_shaped, load_findings
from .manifest import Manifest, parse_manifest
from .models import Finding
from .prompts import prompt_hash
from .providers import Provider
from .report import write_reports
from .store import Store
from .swarm import run_swarm_triage


@dataclass
class RunOptions:
    report: Path
    out_dir: Path
    provider: Provider
    executor: Executor
    apk: Path | None = None
    sources: Path | None = None  # pre-decompiled jadx output (skips jadx)
    jadx: str | None = None
    package: str | None = None
    timeout_s: int = 45
    limit: int | None = None
    only_types: list[str] | None = None
    resume: Path | None = None
    agent_plan: bool = False
    bug_reports: bool = True  # write bugs/<id>.md for PROVEN findings once the run finishes
    record: bool = False  # screen-record the device per finding, for demo proof (adb-based executors only)
    swarm_triage: bool = True  # raw MobSF reports: classify + vendor-flag + prioritise in parallel before the pipeline
    on_event: object = lambda *a, **k: None  # noqa: E731
    extra_meta: dict = field(default_factory=dict)


@dataclass
class RunResult:
    run_dir: Path
    rows: list[dict]
    report_md: Path
    report_json: Path
    meta: dict


def new_run_dir(out_dir: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    d = out_dir / f"run-{stamp}"
    n = 1
    while d.exists():
        n += 1
        d = out_dir / f"run-{stamp}-{n}"
    return d


def select(findings: list[Finding], opts: RunOptions) -> list[Finding]:
    if opts.only_types:
        findings = [f for f in findings if f.type.value in opts.only_types]
    return findings[: opts.limit] if opts.limit else findings


def run_assessment(opts: RunOptions) -> RunResult:
    run_dir = opts.resume or new_run_dir(opts.out_dir)
    store = Store(run_dir)
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")

    # -- decompile (once per run) --------------------------------------------------------------
    sources = opts.sources
    if sources is None:
        if not opts.apk:
            raise ValueError("pass --apk (to decompile with jadx) or --sources (already-decompiled tree)")
        sources = run_dir / "decompiled"
        if not (sources / "sources").is_dir():
            opts.on_event("note", None, text=f"decompiling {opts.apk.name} with jadx ...")
            run_jadx(opts.apk, sources, opts.jadx)
    java_root = sources / "sources" if (sources / "sources").is_dir() else sources

    # -- app facts ----------------------------------------------------------------------------
    manifest_path = next(
        iter([p for p in (sources / "resources" / "AndroidManifest.xml", sources / "AndroidManifest.xml") if p.exists()]), None
    )
    manifest = parse_manifest(manifest_path) if manifest_path else Manifest()
    package = opts.package or manifest.package or (package_from_apk(str(opts.apk)) if opts.apk else None) or "unknown.package"

    # -- findings (now that the app's own package is known, for the swarm's own-code/vendor split) --------------
    raw_report = json.loads(opts.report.read_text())
    if opts.swarm_triage and is_mobsf_shaped(raw_report):
        swarm_result = run_swarm_triage(opts.report, package if package != "unknown.package" else None)
        opts.on_event(
            "note",
            None,
            text=f"swarm triage: {len(swarm_result.findings)} testable ({swarm_result.own_code_count} own-code, "
            f"{swarm_result.vendor_count} vendor-likely), {len(swarm_result.skipped)} skipped (no signal for that type yet)",
        )
        findings = select(swarm_result.findings, opts)
    else:
        findings = select(load_findings(opts.report), opts)
    if not findings:
        raise ValueError("no findings left after filtering")

    # -- device -------------------------------------------------------------------------------
    device = opts.executor.prepare()
    if opts.apk and opts.executor.name not in ("none", "replay"):
        opts.on_event("note", None, text=f"installing {opts.apk.name} on the device ...")
        opts.executor.install(str(opts.apk))

    meta = {
        "run_id": run_dir.name,
        "started": started,
        "tool": f"hooksmith {__version__}",
        "python": platform.python_version(),
        "package": package,
        "apk": {"name": opts.apk.name, "sha256": sha256_file(opts.apk)} if opts.apk else {},
        "provider": opts.provider.name,
        "model": getattr(opts.provider, "model", None) or opts.provider.name,
        "temperature": opts.provider.temperature,
        "prompt_hash": prompt_hash(),
        "device": device,
        "timeout_s": opts.timeout_s,
        "findings": len(findings),
        **opts.extra_meta,
    }
    store.write_run(meta)

    ctx = Ctx(
        findings=findings,
        sources=java_root,
        store=store,
        provider=opts.provider,
        executor=opts.executor,
        package=package,
        manifest=manifest,
        timeout_s=opts.timeout_s,
        agent_plan=opts.agent_plan,
        bug_reports=opts.bug_reports,
        record=opts.record,
        on_event=opts.on_event,  # type: ignore[arg-type]
    )
    t0 = time.time()
    run_pipeline(ctx)
    meta["finished"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    meta["seconds"] = round(time.time() - t0, 1)
    store.write_run(meta)
    rows = store.rows()
    md, js = write_reports(run_dir, rows, meta)
    store.close()
    return RunResult(run_dir=run_dir, rows=rows, report_md=md, report_json=js, meta=meta)


__all__ = ["RunOptions", "RunResult", "run_assessment", "DecompileError"]
