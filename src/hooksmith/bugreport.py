"""Turn a finished run's evidence into bug reports a dev team can act on, one Markdown file per PROVEN finding.

Deliberately not an LLM pass: every sentence here is built from facts already written to the evidence store by the
signal library (the thing that decided the verdict) or pulled verbatim from the hook/log/source on disk. Nothing is
invented, embellished, or re-judged. If you want prose polish on top of this, that is a separate, clearly-labelled
step to add later -- it must never be allowed to change a verdict or a fact, only the wording around one.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import mastg
from .impact import build_impact
from .models import FindingType
from .store import _safe

REMEDIATION = {
    FindingType.HARDCODED_KEY: (
        "Do not embed cryptographic key material as a source constant. Generate or derive the key at runtime and "
        "store it in the Android Keystore (`KeyStore` with a `KeyGenParameterSpec`), which keeps it out of the "
        "APK and out of memory dumps where practical."
    ),
    FindingType.CLEARTEXT_HTTP: (
        "Use `https://` for this request. If cleartext is required for a specific legacy host, scope it narrowly "
        "in the Network Security Config (`cleartextTrafficPermitted` per-domain) instead of enabling it app-wide."
    ),
    FindingType.INSECURE_RANDOM: (
        "Replace `java.util.Random` / `Math.random()` with `java.security.SecureRandom` for anything security-"
        "relevant: tokens, keys, IVs, nonces, session identifiers."
    ),
    FindingType.TLS_TRUST_ALL: (
        "Do not implement a permissive `X509TrustManager`. Delegate to the platform's default trust manager "
        "(`TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())`), or use certificate "
        "pinning (`okhttp3.CertificatePinner` or Network Security Config `pin-set`) if a specific CA is required."
    ),
    FindingType.HOSTNAME_VERIFIER: (
        "Do not implement a `HostnameVerifier` that returns `true` unconditionally. Use the platform default "
        "(`HttpsURLConnection.getDefaultHostnameVerifier()`), or validate the hostname against the certificate's "
        "subject/SAN explicitly if a custom verifier is genuinely required."
    ),
}


def _read_json(p: Path) -> dict:
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def _read_text(p: Path, limit: int = 4000) -> str:
    try:
        t = p.read_text()
        return t if len(t) <= limit else t[:limit] + "\n... (truncated)"
    except OSError:
        return ""


def build_report(row: dict, evidence_dir: Path, run_meta: dict) -> str:
    fid, target = row["id"], f"{row.get('class_name') or '?'}.{row.get('method') or '?'}"
    ftype_str = row.get("type") or "unknown"
    reason = row.get("reason", "") or ""
    try:
        ftype = FindingType(ftype_str)
        remediation = REMEDIATION.get(
            ftype, "Review the finding's hook and runtime evidence and remediate per your own standards."
        )
    except ValueError:
        ftype = None
        remediation = "Review the finding's hook and runtime evidence and remediate per your own standards."

    verdict_doc = _read_json(evidence_dir / "verdict.json")
    signal = verdict_doc.get("signal") or {}
    impact = (
        build_impact(ftype, target, signal, reason)
        if ftype
        else ("No impact template for this finding type yet; assess from the evidence directly.")
    )
    mastg_section = mastg.markdown_links(ftype) if ftype else "(no MASTG cross-reference for this finding type)"

    execution = _read_json(evidence_dir / "execution.json")
    hook = _read_text(evidence_dir / "hook.js")
    log = _read_text(evidence_dir / "runtime.log", limit=2000)
    exercised = execution.get("exercised", [])
    device = run_meta.get("device", {})

    steps = [
        "1. Install the APK on the device recorded below (or an equivalent one).",
        "2. Attach Frida and load `hook.js` (included in this report's evidence folder) with:",
    ]
    steps.append(f"   `frida -U -f {run_meta.get('package', '<package>')} -l hook.js`")
    if exercised:
        steps.append("3. Exercise the app exactly as HookSmith did, in order:")
        steps += [f"   - `{s}`" for s in exercised]
    else:
        steps.append("3. Exercise the app so the target method runs.")
    steps.append(
        f"4. Observe the log output matches `runtime.log` (reproduced below). The signal that produced this verdict: {json.dumps(reason)[:300]}."
    )

    lines = [
        f"# {row.get('title') or fid}",
        "",
        f"- **Finding ID:** `{fid}`",
        f"- **Verdict:** **{row.get('verdict')}**",
        f"- **Severity:** {row.get('severity', 'info')}",
        f"- **Type:** `{ftype_str}`",
        f"- **Component:** `{target}`",
        f"- **APK:** `{run_meta.get('apk', {}).get('name', '?')}`  sha256 `{str(run_meta.get('apk', {}).get('sha256', '?'))[:16]}…`",
        f"- **Package:** `{run_meta.get('package', '?')}`",
        f"- **Device:** {device.get('model', '?')} / Android {device.get('android', '?')} ({device.get('abi', '?')}, Frida {device.get('frida', '?')})",
        f"- **Run:** `{run_meta.get('run_id', '?')}`  generator: {run_meta.get('provider', '?')} / `{run_meta.get('model', '?')}`",
        "",
        "## Impact",
        "",
        impact,
        "",
        "## OWASP MASTG",
        "",
        mastg_section,
        "",
        "## What the signal library observed",
        "",
        reason or "(no reason recorded)",
        "",
        "## Steps to reproduce",
        "",
        *steps,
        "",
        "## Evidence (runtime log, as observed)",
        "",
        "```",
        log or "(no log captured)",
        "```",
        "",
        "## The hook that produced this evidence",
        "",
        "```javascript",
        hook or "(hook not recorded)",
        "```",
        "",
        "## Suggested remediation",
        "",
        remediation,
        "",
        "---",
        f"*Generated by HookSmith from `{evidence_dir}`. The Impact section is a fixed, type-specific template filled "
        "in only with facts the signal library observed; everything else states only what that library concluded "
        "from the runtime log above. Nothing in this report was written or embellished by a model.*",
        "",
    ]
    return "\n".join(lines)


def write_bug_reports(run_root: Path, rows: list[dict], verdicts: tuple[str, ...] = ("PROVEN",)) -> list[Path]:
    run_meta = _read_json(run_root / "run.json")
    out_dir = run_root / "bugs"
    written: list[Path] = []
    for row in rows:
        if (row.get("verdict") or "") not in verdicts:
            continue
        evidence_dir = Path(row["evidence_dir"]) if row.get("evidence_dir") else None
        if not evidence_dir or not evidence_dir.is_dir():
            continue
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"{_safe(row['id'])}.md"
        path.write_text(build_report(row, evidence_dir, run_meta))
        written.append(path)
    return written
