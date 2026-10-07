"""Markdown + JSON reports. One row per finding, one verdict each, and a pointer to the proof."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from . import mastg
from .models import VERDICT_HELP, FindingType, Verdict

ORDER = [Verdict.PROVEN, Verdict.REFUTED, Verdict.UNREACHABLE, Verdict.UNVALIDATED]
ICON = {"PROVEN": "[PROVEN]", "REFUTED": "[REFUTED]", "UNREACHABLE": "[UNREACHABLE]", "UNVALIDATED": "[UNVALIDATED]"}


def _esc(s: str) -> str:
    return (s or "").replace("|", "\\|").replace("\n", " ")


def build_markdown(rows: list[dict], meta: dict) -> str:
    counts = Counter((r["verdict"] or "UNVALIDATED") for r in rows)
    total = len(rows)
    out = ["# HookSmith report", ""]
    app = meta.get("apk", {})
    out += [
        f"- **APK:** `{app.get('name', '?')}`  sha256 `{str(app.get('sha256', '?'))[:16]}…`",
        f"- **Package:** `{meta.get('package', '?')}`",
        f"- **Run:** `{meta.get('run_id', '?')}`  started {meta.get('started', '?')}",
        f"- **Generator:** {meta.get('provider', '?')} / `{meta.get('model', '?')}` at temperature {meta.get('temperature', '?')}"
        f" (prompts `{meta.get('prompt_hash', '?')}`)",
        f"- **Device:** {json.dumps(meta.get('device', {}))}",
        "",
        "## Verdicts",
        "",
        "| Verdict | Count | Meaning |",
        "|---|---:|---|",
    ]
    for v in ORDER:
        out.append(f"| {v.value} | {counts.get(v.value, 0)} | {VERDICT_HELP[v]} |")
    out += ["", f"**{total} findings, {total} verdicts. No finding left without one.**", "", "## Findings", ""]
    out += ["| # | Finding | Target | Verdict | Why | Evidence |", "|---:|---|---|---|---|---|"]
    for i, r in enumerate(rows, 1):
        v = r["verdict"] or "UNVALIDATED"
        target = f"{r['class_name'] or '?'}.{r['method'] or '?'}"
        ev = f"`findings/{Path(r['evidence_dir']).name}/`" if r.get("evidence_dir") else "-"
        out.append(
            f"| {i} | {_esc(r['title'])[:80]} (`{r['type']}`, {r['severity']}) | `{_esc(target)}` | "
            f"**{v}** | {_esc(r['reason'] or '')[:220]} | {ev} |"
        )
    out += [
        "",
        "## How to verify a PROVEN finding yourself",
        "",
        "Each evidence folder holds `source.java` (what the hook was written from), `hook.js` (what ran), "
        "`runtime.log` (raw output) and `verdict.json` (what the signal library concluded). "
        "Re-run `hook.js` against the same APK with `frida -U -f <package> -l hook.js` to reproduce.",
        "",
        "## OWASP MASTG coverage",
        "",
        "Finding types this run was able to test, and the MASTG methodology each one implements:",
        "",
    ]
    seen_types = sorted({r["type"] for r in rows if r.get("type")})
    for t in seen_types:
        try:
            ftype = FindingType(t)
        except ValueError:
            continue
        refs = mastg.for_type(ftype)
        if refs:
            out.append(f"- `{t}`: " + ", ".join(f"[{r.id}]({r.url})" for r in refs))
    out.append("")
    return "\n".join(out)


def write_reports(store_root: Path, rows: list[dict], meta: dict) -> tuple[Path, Path]:
    md = store_root / "report.md"
    js = store_root / "report.json"
    md.write_text(build_markdown(rows, meta))
    js.write_text(json.dumps({"meta": meta, "findings": rows}, indent=2, default=str))
    return md, js
