"""hooksmith CLI. Click for commands, Rich for output."""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import click
import pyfiglet
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from . import __version__
from .models import VERDICT_HELP, Outcome, Verdict

console = Console()
STYLE = {"PROVEN": "bold green", "REFUTED": "bold yellow", "UNREACHABLE": "bold cyan", "UNVALIDATED": "bold red"}


def banner(subtitle: str = "") -> None:
    """Shown once at the start of the commands people actually watch run. Skipped for piped/non-interactive output."""
    if not console.is_terminal:
        return
    art = pyfiglet.figlet_format("HookSmith", font="slant").rstrip("\n")
    console.print(f"[bold cyan]{art}[/]")
    console.print(f"[dim]Prove or Delete{'  --  ' + subtitle if subtitle else ''}[/]\n")


def _verdict_table(rows: list[dict]) -> Table:
    t = Table(title="Prove or Delete", header_style="bold", show_lines=False)
    for col, kw in (("#", {"justify": "right"}), ("finding", {}), ("target", {}), ("verdict", {}), ("why", {"overflow": "fold"})):
        t.add_column(col, **kw)
    for i, r in enumerate(rows, 1):
        v = r["verdict"] or "UNVALIDATED"
        t.add_row(
            str(i),
            (r["title"] or "")[:44],
            f"{(r['class_name'] or '?').split('.')[-1]}.{r['method'] or '?'}",
            f"[{STYLE[v]}]{v}[/]",
            (r["reason"] or "")[:110],
        )
    return t


def _summary(rows: list[dict]) -> str:
    n = {v.value: 0 for v in Verdict}
    for r in rows:
        n[r["verdict"] or "UNVALIDATED"] += 1
    return "  ".join(f"[{STYLE[k]}]{k} {c}[/]" for k, c in n.items())


def _next_steps(rows: list[dict], run_dir: Path) -> str:
    """What to actually do with a finished run, keyed to the verdict mix that's actually in it."""
    n = {v.value: 0 for v in Verdict}
    for r in rows:
        n[r["verdict"] or "UNVALIDATED"] += 1
    lines: list[str] = []
    if n["PROVEN"]:
        lines.append(
            f"[bold green]{n['PROVEN']} PROVEN[/] -> read {run_dir / 'bugs'}/ (one report per finding: evidence, "
            f"hook, exact repro steps, remediation). Review before filing; nothing in them was written by a model."
        )
    if n["REFUTED"]:
        lines.append(f"[yellow]{n['REFUTED']} REFUTED[/] -> false positives, with proof. Safe to close in your scanner's report.")
    if n["UNREACHABLE"]:
        lines.append(
            f"[cyan]{n['UNREACHABLE']} UNREACHABLE[/] -> the hook never fired. Try a longer --timeout, "
            f"--agent-plan to let the model propose a route, or exercise the app by hand and re-run with "
            f"--resume {run_dir} (only the undecided findings will re-run)."
        )
    if n["UNVALIDATED"]:
        lines.append(
            f"[red]{n['UNVALIDATED']} UNVALIDATED[/] -> read findings/<id>/verdict.json for the reason "
            f"(obfuscation, native code, hallucination past the validator). Some will need a broader scanner or manual review."
        )
    lines.append(
        f"[dim]full report: {run_dir / 'report.md'}   evidence: {run_dir / 'findings'}/   rerun a report: hooksmith bugreport {run_dir}[/]"
    )
    return "\n".join(lines)


class Live:
    """Drives a progress bar across findings, printing stage/verdict lines above it, so a talk audience can watch
    both the headline number (N/Total, elapsed) and the detail (what's happening right now) at the same time.
    """

    def __init__(self, quiet: bool = False):
        self.quiet = quiet
        self.progress: Progress | None = None
        self.task = None

    def __enter__(self) -> "Live":
        if not self.quiet:
            self.progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                console=console,
            )
            self.progress.start()
            self.task = self.progress.add_task("findings", total=None)
        return self

    def __exit__(self, *exc) -> None:
        if self.progress:
            self.progress.stop()

    def _print(self, msg: str) -> None:
        (self.progress.console if self.progress else console).print(msg)

    def __call__(self, kind: str, finding, **k) -> None:
        if self.quiet:
            return
        if kind == "note":
            self._print(f"[dim]{k['text']}[/]")
        elif kind == "start":
            if self.progress and self.task is not None:
                self.progress.update(self.task, total=k["total"], description=finding.title[:50])
            self._print(f"\n[bold]({k['index']}/{k['total']})[/] {finding.title[:60]}  [dim]{finding.id}[/]")
        elif kind == "stage":
            self._print(f"   [dim]- {k['stage']}[/]")
        elif kind == "validation" and not k["ok"]:
            self._print(f"   [yellow]validator rejected attempt {k['attempt']}:[/] {'; '.join(k['errors'])[:160]}")
        elif kind == "verdict":
            o: Outcome = k["outcome"]
            self._print(f"   [{STYLE[o.verdict.value]}]{o.verdict.value}[/]  {o.reason[:140]}  [dim]({k['seconds']}s)[/]")
            if self.progress and self.task is not None:
                self.progress.advance(self.task)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="hooksmith")
def main() -> None:
    """HookSmith: Prove or Delete. Every static finding exits with one of four verdicts."""


# ---- run ------------------------------------------------------------------------------------


@main.command()
@click.option(
    "--report",
    "report_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="MobSF JSON (or native findings JSON).",
)
@click.option("--apk", type=click.Path(exists=True, dir_okay=False, path_type=Path), help="APK to decompile and install.")
@click.option(
    "--sources",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Already-decompiled jadx output (skips jadx).",
)
@click.option("--jadx", help="Path to the jadx executable.")
@click.option("--package", help="Package name (default: read from the manifest).")
@click.option("--out", "out_dir", default="runs", show_default=True, type=click.Path(path_type=Path))
@click.option(
    "--executor",
    "executor_kind",
    default="avd",
    show_default=True,
    type=click.Choice(["avd", "corellium", "adb", "replay", "none"]),
    help="Where hooks run. `none` = static only.",
)
@click.option(
    "--provider", "provider_kind", default="worker", show_default=True, type=click.Choice(["worker", "openai", "template"])
)
@click.option("--worker-url", envvar="HOOKSMITH_WORKER_URL")
@click.option("--worker-token", envvar="HOOKSMITH_WORKER_TOKEN")
@click.option("--llm-url", envvar="HOOKSMITH_LLM_URL", help="OpenAI-compatible base URL (provider=openai).")
@click.option("--llm-model", envvar="HOOKSMITH_LLM_MODEL")
@click.option("--llm-key", envvar="HOOKSMITH_LLM_KEY")
@click.option("--avd", "avd_name", default="hooksmith", show_default=True)
@click.option("--window", is_flag=True, help="Show the emulator window (default headless).")
@click.option("--serial", help="adb serial (executor=adb).")
@click.option("--corellium-endpoint", envvar="CORELLIUM_ENDPOINT")
@click.option("--corellium-token", envvar="CORELLIUM_API_TOKEN")
@click.option("--corellium-project", envvar="CORELLIUM_PROJECT")
@click.option("--corellium-instance", envvar="CORELLIUM_INSTANCE")
@click.option("--corellium-adb", help="host:port for adb on the Corellium instance (default serviceIp:5001).")
@click.option(
    "--replay-from", type=click.Path(exists=True, file_okay=False, path_type=Path), help="Run dir or log dir to replay."
)
@click.option("--timeout", "timeout_s", default=45, show_default=True, help="Seconds to wait for a hook to fire.")
@click.option(
    "--type",
    "only_types",
    multiple=True,
    type=click.Choice(["hardcoded_key", "cleartext_http", "insecure_random"]),
    help="Only these finding types.",
)
@click.option("--limit", type=int, help="Only the first N findings.")
@click.option(
    "--resume",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Resume an earlier run dir: findings that already have a verdict are skipped.",
)
@click.option("--agent-plan", is_flag=True, help="Let the LLM propose the exercise plan (allowlisted actions only).")
@click.option(
    "--record",
    is_flag=True,
    help="Screen-record the device per finding (findings/<id>/screen.mp4): visual proof for a demo. adb-based executors only (avd/corellium/adb).",
)
@click.option(
    "--no-bug-reports", "bug_reports", flag_value=False, default=True, help="Skip writing bugs/<id>.md for PROVEN findings."
)
@click.option(
    "--no-swarm-triage",
    "swarm_triage",
    flag_value=False,
    default=True,
    help="For a raw MobSF --report: skip the parallel classify/vendor-flag/prioritise pass and use every finding as-is.",
)
@click.option(
    "--expect",
    "expect_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="JSON of expected verdicts; exit 1 on any difference (regression test for your app).",
)
@click.option(
    "--fail-on",
    "fail_on",
    multiple=True,
    metavar="VERDICT[:SEVERITY]",
    help="Exit 1 if any finding has this verdict (at least this severity), e.g. PROVEN:high.",
)
@click.option("--max-unvalidated", type=int, help="Exit 1 if more than N findings are UNVALIDATED.")
@click.option("-q", "--quiet", is_flag=True)
def run(
    report_path,
    apk,
    sources,
    jadx,
    package,
    out_dir,
    executor_kind,
    provider_kind,
    worker_url,
    worker_token,
    llm_url,
    llm_model,
    llm_key,
    avd_name,
    window,
    serial,
    corellium_endpoint,
    corellium_token,
    corellium_project,
    corellium_instance,
    corellium_adb,
    replay_from,
    timeout_s,
    only_types,
    limit,
    resume,
    agent_plan,
    record,
    bug_reports,
    swarm_triage,
    expect_path,
    fail_on,
    max_unvalidated,
    quiet,
) -> None:
    """Run the full pipeline: ingest, decompile, generate, validate, execute, classify, report."""
    if not quiet:
        banner(f"{executor_kind} / {provider_kind}")
    from .executors import make_executor
    from .providers import make_provider
    from .runner import RunOptions

    try:
        provider = make_provider(
            provider_kind, worker_url=worker_url, worker_token=worker_token, llm_url=llm_url, llm_model=llm_model, llm_key=llm_key
        )
        executor = make_executor(
            executor_kind,
            avd=avd_name,
            window=window,
            serial=serial,
            corellium_endpoint=corellium_endpoint,
            corellium_token=corellium_token,
            corellium_project=corellium_project,
            corellium_instance=corellium_instance,
            corellium_adb=corellium_adb,
            replay_from=replay_from,
        )
    except Exception as exc:  # noqa: BLE001
        raise click.ClickException(str(exc)) from exc

    opts = RunOptions(
        report=report_path,
        out_dir=out_dir,
        provider=provider,
        executor=executor,
        apk=apk,
        sources=sources,
        jadx=jadx,
        package=package,
        timeout_s=timeout_s,
        limit=limit,
        only_types=list(only_types) or None,
        resume=resume,
        agent_plan=agent_plan,
        record=record,
        bug_reports=bug_reports,
        swarm_triage=swarm_triage,
    )
    _execute(opts, executor, expect_path=expect_path, fail_on=fail_on, max_unvalidated=max_unvalidated, quiet=quiet)


def _execute(opts, executor, expect_path=None, fail_on=(), max_unvalidated=None, quiet=False) -> None:
    from .harness import evaluate, load_expect, parse_fail_on
    from .runner import run_assessment

    try:  # validate policy flags before spending device time
        expect = load_expect(expect_path) if expect_path else None
        rules = parse_fail_on(list(fail_on))
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc

    try:
        with Live(quiet) as live, executor:
            opts.on_event = live
            result = run_assessment(opts)
    except Exception as exc:  # noqa: BLE001
        if os.environ.get("HOOKSMITH_DEBUG"):
            raise
        raise click.ClickException(f"{type(exc).__name__}: {exc}") from exc
    console.print()
    console.print(_verdict_table(result.rows))
    console.print(Panel.fit(_summary(result.rows), title=f"{len(result.rows)} findings, {len(result.rows)} verdicts"))
    console.print(Panel(_next_steps(result.rows, result.run_dir), title="what happens now", border_style="dim"))
    if expect or rules or max_unvalidated is not None:
        failures = evaluate(result.rows, expect, rules, max_unvalidated)
        if failures:
            console.print(Panel("\n".join(f"- {f}" for f in failures), title="[red]harness: FAILED[/]", border_style="red"))
            raise SystemExit(1)
        console.print("[green]harness: passed[/]")


@main.command()
@click.option(
    "--apk",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="The APK to scan. You must be authorised to test it.",
)
@click.option(
    "--sources",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Already-decompiled jadx output (skips jadx).",
)
@click.option("--jadx", help="Path to the jadx executable.")
@click.option("--out", "out_path", default="findings.json", show_default=True, type=click.Path(dir_okay=False, path_type=Path))
@click.option(
    "--include-test-classes", is_flag=True, help="Also scan common library/test packages (off by default: mostly noise)."
)
def scan(apk: Path, sources: Path | None, jadx: str | None, out_path: Path, include_test_classes: bool) -> None:
    """Built-in static pass: propose findings from just an APK, no external scanner report needed.

    Narrow and high-precision on purpose -- it only looks for the patterns HookSmith's signal library can prove
    or refute at runtime (hardcoded keys, insecure RNG, cleartext HTTP, trust-all TLS, allow-all hostnames).
    Prefer --report with a real MobSF/Semgrep report when you have one; it will usually find more.
    """
    banner("scan")
    from .decompile import run_jadx
    from .scan import scan_sources, to_native_report

    src = sources
    if src is None:
        with console.status(f"decompiling {apk.name} with jadx ...", spinner="dots"):
            src = run_jadx(apk, apk.with_suffix("").parent / f"{apk.stem}-decompiled", jadx)
    findings = scan_sources(src, include_test_classes)
    out_path.write_text(json.dumps(to_native_report(findings), indent=2))
    if not findings:
        console.print(
            "[yellow]no candidate findings matched[/] (try --include-test-classes, or point --report at a real scanner's output)"
        )
        return
    t = Table(title=f"{len(findings)} candidate finding(s)", header_style="bold")
    for col in ("id", "type", "severity", "target"):
        t.add_column(col)
    for f in findings:
        t.add_row(f.id, f.type.value, f.severity, f"{f.class_name}.{f.method}")
    console.print(t)
    console.print(f"wrote {out_path}  -  next: hooksmith run --report {out_path} --apk {apk} --executor avd")


@main.command()
@click.option(
    "--apk",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="The APK to test. You must be authorised to test it.",
)
@click.option("--jadx", help="Path to the jadx executable.")
@click.option(
    "--executor", "executor_kind", default="avd", show_default=True, type=click.Choice(["avd", "corellium", "adb", "none"])
)
@click.option(
    "--provider", "provider_kind", default="template", show_default=True, type=click.Choice(["worker", "openai", "template"])
)
@click.option("--worker-url", envvar="HOOKSMITH_WORKER_URL")
@click.option("--worker-token", envvar="HOOKSMITH_WORKER_TOKEN")
@click.option("--llm-url", envvar="HOOKSMITH_LLM_URL")
@click.option("--llm-model", envvar="HOOKSMITH_LLM_MODEL")
@click.option("--llm-key", envvar="HOOKSMITH_LLM_KEY")
@click.option("--avd", "avd_name", default="hooksmith", show_default=True)
@click.option("--serial", help="adb serial (executor=adb).")
@click.option("--out", "out_dir", default="runs", show_default=True, type=click.Path(path_type=Path))
@click.option("--timeout", "timeout_s", default=45, show_default=True)
@click.option(
    "--record",
    is_flag=True,
    help="Screen-record the device per finding (findings/<id>/screen.mp4): visual proof for a demo. adb-based executors only.",
)
@click.option("-q", "--quiet", is_flag=True)
def test(
    apk,
    jadx,
    executor_kind,
    provider_kind,
    worker_url,
    worker_token,
    llm_url,
    llm_model,
    llm_key,
    avd_name,
    serial,
    out_dir,
    timeout_s,
    record,
    quiet,
) -> None:
    """One command, one APK: self-scan then run. The quickest way to try HookSmith on an app you own."""
    if not quiet:
        banner(f"scan + run on {executor_kind}")
    from .decompile import run_jadx
    from .executors import make_executor
    from .providers import make_provider
    from .runner import RunOptions
    from .scan import scan_sources, to_native_report

    with console.status(f"decompiling {apk.name} with jadx ...", spinner="dots"):
        src = run_jadx(apk, apk.with_suffix("").parent / f"{apk.stem}-decompiled", jadx)
    findings = scan_sources(src)
    if not findings:
        raise click.ClickException(
            "the built-in scanner found no candidate findings in this APK; try `hooksmith run` with a real scanner's --report instead"
        )
    report_path = src.parent / "findings.json"
    report_path.write_text(json.dumps(to_native_report(findings), indent=2))
    console.print(f"[dim]{len(findings)} candidate finding(s) found; validating on {executor_kind} ...[/]")
    try:
        provider = make_provider(
            provider_kind, worker_url=worker_url, worker_token=worker_token, llm_url=llm_url, llm_model=llm_model, llm_key=llm_key
        )
        executor = make_executor(executor_kind, avd=avd_name, serial=serial)
    except Exception as exc:  # noqa: BLE001
        raise click.ClickException(str(exc)) from exc
    opts = RunOptions(
        report=report_path,
        out_dir=out_dir,
        provider=provider,
        executor=executor,
        apk=apk,
        sources=src,
        jadx=jadx,
        timeout_s=timeout_s,
        record=record,
    )
    _execute(opts, executor, quiet=quiet)


# ---- demo -----------------------------------------------------------------------------------


@main.command()
@click.option("--out", "out_dir", default="runs", show_default=True, type=click.Path(path_type=Path))
@click.option("-q", "--quiet", is_flag=True)
def demo(out_dir: Path, quiet: bool) -> None:
    """Replay a bundled sample app end to end: all four verdicts, no device, no network, no LLM."""
    if not quiet:
        banner("demo")
    from .demo import DemoProvider, demo_dir
    from .executors.replay import ReplayExecutor
    from .runner import RunOptions

    d = demo_dir()
    ex = ReplayExecutor(d / "logs")
    opts = RunOptions(
        report=d / "mobsf_report.json",
        out_dir=out_dir,
        provider=DemoProvider(),
        executor=ex,
        sources=d / "sources",
        package="com.demo.vault",
    )
    _execute(opts, ex, quiet=quiet)


# ---- inspection -----------------------------------------------------------------------------


@main.command()
@click.argument("run_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--format", "fmt", type=click.Choice(["md", "json", "table"]), default="table")
def report(run_dir: Path, fmt: str) -> None:
    """Show the report for a finished run."""
    from .report import build_markdown
    from .store import Store

    store = Store(run_dir)
    rows = store.rows()
    meta = json.loads((run_dir / "run.json").read_text()) if (run_dir / "run.json").exists() else {}
    if fmt == "md":
        click.echo(build_markdown(rows, meta))
    elif fmt == "json":
        click.echo(json.dumps({"meta": meta, "findings": rows}, indent=2, default=str))
    else:
        console.print(_verdict_table(rows))
        console.print(_summary(rows))


@main.command()
@click.argument("run_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.argument("finding")
def evidence(run_dir: Path, finding: str) -> None:
    """Open the evidence bundle for one finding (id, or a unique fragment of it)."""
    from .store import _safe

    base = run_dir / "findings"
    dirs = [d for d in base.iterdir() if d.is_dir() and finding.lower() in d.name.lower()]
    if len(dirs) != 1:
        raise click.ClickException(f"{len(dirs)} matches for {finding!r}: {', '.join(d.name for d in dirs) or 'none'}")
    d = dirs[0]
    console.rule(d.name)
    v = d / "verdict.json"
    if v.exists():
        o = json.loads(v.read_text())
        console.print(f"[{STYLE[o['verdict']]}]{o['verdict']}[/]  {o['reason']}")
    for name in ("hook.js", "runtime.log", "validation.json"):
        p = d / name
        if p.exists():
            console.rule(name)
            click.echo(p.read_text().rstrip())
    _ = _safe


@main.command()
@click.argument("run_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--verdicts",
    default="PROVEN",
    show_default=True,
    help="Comma-separated verdicts to write reports for, e.g. PROVEN,REFUTED for a full audit trail.",
)
def bugreport(run_dir: Path, verdicts: str) -> None:
    """(Re)write bugs/<id>.md for a finished run. Grounded entirely in evidence already on disk: no model, no new claims."""
    from .bugreport import write_bug_reports
    from .store import Store

    wanted = tuple(v.strip().upper() for v in verdicts.split(",") if v.strip())
    rows = Store(run_dir).rows()
    written = write_bug_reports(run_dir, rows, verdicts=wanted)
    if not written:
        console.print(f"[yellow]no findings with verdict in {wanted} had evidence to report on[/]")
        return
    for p in written:
        console.print(f"  {p}")
    console.print(f"[green]{len(written)} report(s)[/] written to {run_dir / 'bugs'}/")


@main.command()
def explain() -> None:
    """The four verdicts, and nothing else."""
    for v in Verdict:
        console.print(f"[{STYLE[v.value]}]{v.value:<12}[/] {VERDICT_HELP[v]}")
    console.print("\nNo fifth bucket. No 'probably fine'.")


# ---- doctor ---------------------------------------------------------------------------------


@main.command()
def doctor() -> None:
    """Check what is installed and what is missing."""
    import subprocess

    from .decompile import find_jadx
    from .executors.avd import sdk_root, sdk_tools

    t = Table(show_header=False, box=None)
    ok = lambda b: "[green]ok[/]" if b else "[red]missing[/]"  # noqa: E731
    t.add_row("python", sys.version.split()[0], ok(sys.version_info >= (3, 11)))
    node = shutil.which("node")
    t.add_row("node (syntax check)", node or "-", ok(node))
    jadx = find_jadx()
    t.add_row("jadx", jadx or "-", ok(jadx))
    try:
        import frida

        t.add_row("frida (python)", frida.__version__, ok(True))
    except ImportError:
        t.add_row("frida (python)", "install with: uv sync --extra device", ok(False))
    tools = sdk_tools()
    t.add_row("adb", tools["adb"] or "-", ok(tools["adb"]))
    t.add_row("android emulator", tools["emulator"] or f"- (sdk root {sdk_root()})", ok(tools["emulator"]))
    t.add_row("/dev/kvm", "present" if Path("/dev/kvm").exists() else "-", ok(Path("/dev/kvm").exists()))
    t.add_row("HOOKSMITH_WORKER_URL", os.environ.get("HOOKSMITH_WORKER_URL", "-"), ok(os.environ.get("HOOKSMITH_WORKER_URL")))
    t.add_row(
        "CORELLIUM_API_TOKEN", "set" if os.environ.get("CORELLIUM_API_TOKEN") else "-", ok(os.environ.get("CORELLIUM_API_TOKEN"))
    )
    console.print(t)
    console.print("[dim]Only python is required for `hooksmith demo` and `--executor none`.[/]")
    _ = subprocess


# ---- avd ------------------------------------------------------------------------------------


@main.group()
def avd() -> None:
    """Manage the local Android Virtual Device used by --executor avd."""


@avd.command("setup")
@click.option("--api", default=33, show_default=True)
@click.option("--name", default="hooksmith", show_default=True)
def avd_setup(api: int, name: str) -> None:
    """Install cmdline-tools, emulator and a Google APIs x86_64 image, then create the AVD (large download)."""
    from .executors.avd import setup_sdk

    setup_sdk(api, name, log=lambda m: console.print(f"[dim]{m}[/]"))
    console.print("[green]AVD ready.[/] Try: hooksmith run --executor avd ...")


@main.command()
@click.option(
    "--provider", "provider_kind", default="template", show_default=True, type=click.Choice(["worker", "openai", "template"])
)
@click.option("--worker-url", envvar="HOOKSMITH_WORKER_URL")
@click.option("--worker-token", envvar="HOOKSMITH_WORKER_TOKEN")
@click.option("--llm-url", envvar="HOOKSMITH_LLM_URL")
@click.option("--llm-model", envvar="HOOKSMITH_LLM_MODEL")
@click.option("--llm-key", envvar="HOOKSMITH_LLM_KEY")
@click.option(
    "--mastg",
    "mastg_path",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Existing MASTG checkout (default: shallow-clone into the cache).",
)
@click.option("--repeats", default=1, show_default=True, help="Runs per case (models vary between runs).")
@click.option("--out", "out_path", type=click.Path(dir_okay=False, path_type=Path), help="Write the Markdown report here.")
def bench(provider_kind, worker_url, worker_token, llm_url, llm_model, llm_key, mastg_path, repeats, out_path) -> None:
    """Measure how often a provider's hooks pass the static validator on OWASP MASTG demo apps (no device needed)."""
    from . import bench as b
    from .executors.adb import CACHE
    from .providers import make_provider

    try:
        provider = make_provider(
            provider_kind, worker_url=worker_url, worker_token=worker_token, llm_url=llm_url, llm_model=llm_model, llm_key=llm_key
        )
        root = b.ensure_mastg(mastg_path, CACHE)
    except Exception as exc:  # noqa: BLE001
        raise click.ClickException(str(exc)) from exc
    cases, skipped = b.load_cases(root)
    if not cases:
        raise click.ClickException("no runnable MASTG cases found")
    console.print(f"[dim]{len(cases)} MASTG cases, {repeats} run(s) each, provider={provider.name}[/]")
    results = b.run_bench(cases, provider, repeats)
    model = str(getattr(provider, "model", provider.name))
    md = b.to_markdown(provider.name, model, results, skipped, root)
    s = b.summarize(results)
    console.print(
        f"first pass [bold]{s['first_pass']}/{s['runs']}[/]  after one repair [bold]{s['after_retry']}/{s['runs']}[/]  avg {s['avg_seconds']}s"
    )
    if out_path:
        out_path.write_text(md)
        console.print(f"report: {out_path}")
    else:
        click.echo(md)


@main.group()
def corellium() -> None:
    """Corellium helpers."""


@corellium.command("list")
@click.option("--endpoint", envvar="CORELLIUM_ENDPOINT", default="https://app.corellium.com", show_default=True)
@click.option("--token", envvar="CORELLIUM_API_TOKEN", help="Prefer the env var: a --token flag lands in your shell history.")
def corellium_list(endpoint: str, token: str | None) -> None:
    """Read-only: log in and list projects and devices (id, state, type). Changes nothing."""
    from .executors.corellium import CorelliumClient, CorelliumError, describe, is_android

    if not token:
        raise click.ClickException("set CORELLIUM_API_TOKEN in your shell first")
    c = CorelliumClient(endpoint, token)
    try:
        c.login()
        projects = c.projects()
        console.print(f"[green]login ok[/]  {len(projects)} project(s)")
        for p in projects:
            console.print(f"project [bold]{p.get('name')}[/]  id={p.get('id')}")
            for i in c.req("GET", f"/projects/{p['id']}/instances").json():
                a = is_android(i)
                tag = "[green]android[/]" if a else "[red]NOT android[/]" if a is False else "[yellow]os unknown[/]"
                console.print(f"   {tag}  {describe(i)}")
    except CorelliumError as exc:
        raise click.ClickException(str(exc)) from exc


if __name__ == "__main__":
    main()
