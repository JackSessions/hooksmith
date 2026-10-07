"""Benchmark hook generation against OWASP MASTG demo apps.

MASTG (https://github.com/OWASP/mastg) is CC BY-SA 4.0. This module never copies its files into this repo: it clones
MASTG to a cache directory (or uses --mastg PATH) and reads the jadx-style `*_reversed.java` of each demo.

What is measured is the *generator*: for every case we ask the provider for a hook, run the static validator, and on a
failure give it one retry with the validator's errors, exactly as the pipeline does. No device is needed. A hook that
passes here still has to survive a real device; that is a separate measurement.
"""

from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from .javasrc import locate_method, parse_class
from .models import FindingType
from .providers import GenRequest, Provider, overload_for, trim_source
from .validator import validate_hook

MASTG_URL = "https://github.com/OWASP/mastg"

# MASTG demo id -> the HookSmith finding type it exercises. Demos whose type HookSmith cannot prove yet are listed
# with UNKNOWN so the coverage matrix is honest about the gap.
DEMO_TYPES: dict[str, FindingType] = {
    "MASTG-DEMO-0007": FindingType.INSECURE_RANDOM,
    "MASTG-DEMO-0008": FindingType.INSECURE_RANDOM,
    "MASTG-DEMO-0017": FindingType.HARDCODED_KEY,
    "MASTG-DEMO-0012": FindingType.UNKNOWN,  # insufficient key length
    "MASTG-DEMO-0022": FindingType.UNKNOWN,  # broken symmetric algorithms
    "MASTG-DEMO-0023": FindingType.UNKNOWN,  # broken encryption modes (ECB)
    "MASTG-DEMO-0048": FindingType.UNKNOWN,  # SSLSocket without hostname verification
    "MASTG-DEMO-0054": FindingType.UNKNOWN,  # TrustManager that does not validate
    "MASTG-DEMO-0055": FindingType.UNKNOWN,  # HostnameVerifier that allows any host
}


@dataclass
class BenchCase:
    demo_id: str
    category: str
    title: str
    ftype: FindingType
    class_name: str
    java: Path


@dataclass
class CaseResult:
    case: BenchCase
    first_pass: bool = False
    final_ok: bool = False
    attempts: int = 0
    seconds: float = 0.0
    failed_checks: list[str] = field(default_factory=list)
    error: str | None = None


def ensure_mastg(path: Path | None, cache: Path) -> Path:
    if path:
        if not path.exists():
            raise FileNotFoundError(path)
        return path
    dest = cache / "mastg"
    if not (dest / "demos" / "android").is_dir():
        cache.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--depth", "1", "-q", MASTG_URL, str(dest)], check=True, timeout=600)
    return dest


def _title(md: Path) -> str:
    m = re.search(r"^title:\s*(.+)$", md.read_text(errors="replace"), re.M)
    return m.group(1).strip().strip("\"'") if m else md.stem


def _class_name(java: str) -> str | None:
    pkg = re.search(r"^package\s+([\w.]+);", java, re.M)
    cls = re.search(r"^(?:public\s+)?(?:final\s+)?class\s+(\w+)", java, re.M)
    return f"{pkg.group(1)}.{cls.group(1)}" if pkg and cls else None


def load_cases(root: Path) -> tuple[list[BenchCase], list[tuple[str, str]]]:
    """(runnable cases, [(demo id, reason skipped)]) in a stable order."""
    cases: list[BenchCase] = []
    skipped: list[tuple[str, str]] = []
    for demo_id, ftype in sorted(DEMO_TYPES.items()):
        found = list((root / "demos" / "android").glob(f"MASVS-*/{demo_id}"))
        if not found:
            skipped.append((demo_id, "demo not found in this MASTG checkout"))
            continue
        d = found[0]
        java = d / "MastgTest_reversed.java"
        if ftype == FindingType.UNKNOWN:
            skipped.append((demo_id, "finding type not supported by HookSmith yet"))
            continue
        if not java.exists():
            skipped.append((demo_id, "no reversed Java in the demo"))
            continue
        cn = _class_name(java.read_text(errors="replace"))
        if not cn:
            skipped.append((demo_id, "could not read the class name"))
            continue
        cases.append(BenchCase(demo_id, d.parent.name.replace("MASVS-", ""), _title(d / f"{demo_id}.md"), ftype, cn, java))
    return cases, skipped


def run_case(case: BenchCase, provider: Provider, retries: int = 1) -> CaseResult:
    res = CaseResult(case=case)
    t0 = time.time()
    src = case.java.read_text(errors="replace")
    jc = parse_class(case.class_name, src)
    m = locate_method(jc, case.ftype.value) or next((x for x in jc.methods if x.name == "mastgTest"), None)
    if m is None:
        res.error = "no method to hook"
        return res
    errors: list[str] | None = None
    previous: str | None = None
    for attempt in range(1, retries + 2):
        req = GenRequest(
            finding_type=case.ftype,
            class_name=case.class_name,
            method=m.name,
            title=case.title,
            source=trim_source(jc, m),
            overload=overload_for(jc, m),
            errors=errors,
            previous=previous,
        )
        try:
            g = provider.generate(req)
        except Exception as exc:  # noqa: BLE001
            res.error = f"{type(exc).__name__}: {exc}"
            break
        v = validate_hook(g.js, case.class_name, m.name, jc, None)
        res.attempts = attempt
        if v.ok:
            res.final_ok, res.first_pass = True, attempt == 1
            res.failed_checks = []
            break
        res.failed_checks = [c.name for c in v.checks if c.gating and not c.passed]
        errors, previous = v.errors, g.js
    res.seconds = round(time.time() - t0, 2)
    return res


def run_bench(cases: list[BenchCase], provider: Provider, repeats: int = 1) -> list[CaseResult]:
    out: list[CaseResult] = []
    for case in cases:
        for _ in range(repeats):
            out.append(run_case(case, provider))
    return out


def summarize(results: list[CaseResult]) -> dict:
    n = len(results)
    ok = sum(r.final_ok for r in results)
    first = sum(r.first_pass for r in results)
    fails: dict[str, int] = {}
    for r in results:
        for c in r.failed_checks:
            fails[c] = fails.get(c, 0) + 1
    return {
        "runs": n,
        "first_pass": first,
        "after_retry": ok,
        "failed": n - ok,
        "first_pass_rate": round(first / n, 3) if n else 0.0,
        "final_rate": round(ok / n, 3) if n else 0.0,
        "avg_seconds": round(sum(r.seconds for r in results) / n, 2) if n else 0.0,
        "errors": sum(1 for r in results if r.error),
        "failed_checks": dict(sorted(fails.items(), key=lambda kv: -kv[1])),
    }


def to_markdown(provider_name: str, model: str, results: list[CaseResult], skipped: list[tuple[str, str]], root: Path) -> str:
    s = summarize(results)
    out = [
        "# HookSmith generation benchmark (OWASP MASTG demos)",
        "",
        f"- Provider: `{provider_name}`  model: `{model}`",
        f"- Cases run: {s['runs']}  | first-pass valid: **{s['first_pass']}/{s['runs']}** ({s['first_pass_rate']:.0%})"
        f"  | valid after one repair: **{s['after_retry']}/{s['runs']}** ({s['final_rate']:.0%})",
        f"- Average generation time per case: {s['avg_seconds']}s  | provider errors: {s['errors']}",
        "- *Static validation only. A hook that passes here still has to attach and fire on a device.*",
        "",
        "## Cases",
        "",
        "| Demo | Category | Type | First pass | After retry | Attempts | Failed checks |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in results:
        out.append(
            f"| {r.case.demo_id} | {r.case.category} | {r.case.ftype.value} | {'yes' if r.first_pass else 'no'} | "
            f"{'yes' if r.final_ok else 'no'} | {r.attempts} | {', '.join(r.failed_checks) or (r.error or '-')} |"
        )
    if s["failed_checks"]:
        out += ["", "## Most common validator failures", ""] + [f"- {k}: {v}" for k, v in s["failed_checks"].items()]
    out += ["", "## MASTG coverage (what HookSmith cannot test yet)", ""]
    out += [f"- {d}: {why}" for d, why in skipped] or ["- none"]
    out += ["", f"MASTG checkout: `{root}` (CC BY-SA 4.0, https://github.com/OWASP/mastg). Not redistributed here.", ""]
    return "\n".join(out)
