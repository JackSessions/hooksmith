"""Load scanner output into Findings. v1: MobSF JSON, plus a tiny native format for anything else.

Native format (for other scanners, or for hand-written findings):

    {"findings": [{"id": "F1", "title": "...", "type": "hardcoded_key",
                   "class": "com.example.Vault", "method": "encrypt", "severity": "high"}]}
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .models import Finding, FindingType

# (rule-id or description fragment) -> type. First match wins.
_RULES: list[tuple[str, FindingType]] = [
    (r"hardcoded|hard-coded|hard coded|secret key|encryption key|api key", FindingType.HARDCODED_KEY),
    (r"insecure random|insecure_random|random number generator|java\.util\.random|predictable", FindingType.INSECURE_RANDOM),
    (
        r"trustmanager|trust all|trust-all|checkservertrusted|does not validate (?:the )?certificate|accept(?:s|ing)? all certificate",
        FindingType.TLS_TRUST_ALL,
    ),
    (r"hostnameverifier|hostname verif|allow_all_hostname|any hostname|allows any host", FindingType.HOSTNAME_VERIFIER),
    (
        r"cleartext|clear text|clear-text|http://|usescleartext|insecure (?:network|connection|communication)|android_http|unencrypted",
        FindingType.CLEARTEXT_HTTP,
    ),
]


def classify_type(*texts: str) -> FindingType:
    blob = " ".join(t for t in texts if t).lower()
    for pat, ftype in _RULES:
        if re.search(pat, blob):
            return ftype
    return FindingType.UNKNOWN


def path_to_class(path: str) -> str:
    p = path.replace("\\", "/")
    for prefix in ("sources/", "java_source/", "src/"):
        if p.startswith(prefix):
            p = p[len(prefix) :]
    if p.endswith(".java"):
        p = p[:-5]
    elif p.endswith(".kt"):
        p = p[:-3]
    return p.strip("/").replace("/", ".")


def _lines(v) -> list[int]:
    if isinstance(v, (list, tuple)):
        return [int(x) for x in v if str(x).isdigit()]
    return [int(x) for x in re.findall(r"\d+", str(v))]


def _mobsf_sections(report: dict) -> list[tuple[str, dict]]:
    out: list[tuple[str, dict]] = []
    for key in ("code_analysis", "android_api"):
        sec = report.get(key)
        if not isinstance(sec, dict):
            continue
        # MobSF 4.x nests rules under "findings"; older reports put them at the top level
        rules = sec.get("findings") if isinstance(sec.get("findings"), dict) else sec
        for rule_id, body in rules.items():
            if isinstance(body, dict) and ("files" in body or "metadata" in body):
                out.append((rule_id, body))
    return out


def from_mobsf(report: dict) -> list[Finding]:
    findings: list[Finding] = []
    for rule_id, body in _mobsf_sections(report):
        meta = body.get("metadata") or {}
        desc = str(meta.get("description", ""))
        sev = str(meta.get("severity", "info")).lower()
        ftype = classify_type(rule_id, desc, str(meta.get("cwe", "")))
        files = body.get("files") or {}
        if isinstance(files, list):  # [{"file_path": ..., "match_lines": [a, b]}]
            files = {f.get("file_path", ""): f.get("match_lines", []) for f in files if isinstance(f, dict)}
        for path, lines in files.items():
            cls = path_to_class(path)
            fid = f"{rule_id}:{cls}"
            findings.append(
                Finding(
                    id=fid,
                    title=desc or rule_id,
                    type=ftype,
                    severity=sev,
                    description=desc,
                    class_name=cls,
                    file_path=path,
                    lines=_lines(lines),
                    source="mobsf",
                    raw={"rule": rule_id, "metadata": meta},
                )
            )
    return findings


def from_native(report: dict) -> list[Finding]:
    out = []
    for i, f in enumerate(report["findings"], 1):
        ftype = f.get("type")
        try:
            ftype = FindingType(ftype) if ftype else classify_type(f.get("title", ""), f.get("description", ""))
        except ValueError:
            ftype = classify_type(str(ftype), f.get("title", ""))
        out.append(
            Finding(
                id=str(f.get("id") or f"F{i}"),
                title=f.get("title", f.get("id", f"finding {i}")),
                type=ftype,
                severity=str(f.get("severity", "info")).lower(),
                description=f.get("description", ""),
                class_name=f.get("class") or f.get("class_name"),
                method=f.get("method"),
                param_types=f.get("param_types"),
                file_path=f.get("file"),
                lines=_lines(f.get("lines", [])),
                source="native",
                raw=f,
            )
        )
    return out


def is_mobsf_shaped(report: dict) -> bool:
    """True for a raw MobSF-style report; false for HookSmith's own native {"findings": [...]} format."""
    return not (
        isinstance(report, dict)
        and isinstance(report.get("findings"), list)
        and not isinstance(report.get("code_analysis"), dict)
    )


def load_findings(path: Path) -> list[Finding]:
    report = json.loads(Path(path).read_text())
    if not is_mobsf_shaped(report):
        return from_native(report)
    found = from_mobsf(report)
    if not found:
        raise ValueError(
            f"{path}: no findings recognised. Expected a MobSF JSON report (code_analysis / android_api) "
            "or the native format {'findings': [...]}"
        )
    return found
