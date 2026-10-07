"""A tiny built-in static scanner, so HookSmith can run from nothing but an APK.

This is not trying to replace MobSF, Semgrep or a real SAST tool: it is a narrow, high-precision pass that looks
for exactly the patterns HookSmith's signal library knows how to prove or refute at runtime, so a bug hunter can
drop an APK with no external report and still get something to validate. If you already have a MobSF/Semgrep
report, prefer `--report`: it will usually be broader.

One finding per matching method (not per line), because a finding here always becomes one hook.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .javasrc import JavaClass, JavaMethod, class_to_path, parse_class
from .models import Finding, FindingType

# Common class name fragments that are almost always test/library code, not the app under test.
_NOISE_PACKAGES = re.compile(
    r"^(?:kotlin|kotlinx|androidx?|android\.support|com\.google\.android\.gms|com\.google\.android\.material|"
    r"com\.google\.firebase|com\.facebook|com\.squareup|okhttp3|okio|retrofit2|io\.reactivex|rx|org\.jetbrains|"
    r"org\.junit|org\.mockito|org\.apache|com\.bumptech\.glide|coil|com\.airbnb)\."
)


@dataclass
class ScanRule:
    ftype: FindingType
    severity: str
    title: str
    class_pattern: re.Pattern  # a class is a candidate only if the class BODY matches this
    method_pattern: re.Pattern  # which method within the class to flag


_RULES = [
    ScanRule(
        FindingType.HARDCODED_KEY,
        "high",
        "Possible hardcoded cryptographic key",
        re.compile(r"SecretKeySpec|IvParameterSpec"),
        re.compile(r"\bnew\s+SecretKeySpec\s*\(|\bCipher\.getInstance\b"),
    ),
    ScanRule(
        FindingType.INSECURE_RANDOM,
        "medium",
        "Possible insecure random number generation",
        re.compile(r"\bnew\s+Random\s*\(\s*\)|\bMath\.random\s*\("),
        re.compile(r"\bnew\s+Random\s*\(\s*\)|\bMath\.random\s*\(|\.nextInt\(|\.nextLong\(|\.nextBytes\(|\.nextDouble\("),
    ),
    ScanRule(
        FindingType.CLEARTEXT_HTTP,
        "high",
        "Possible cleartext HTTP traffic",
        re.compile(r"openConnection\s*\(|new\s+Request\.Builder\s*\("),
        re.compile(r"openConnection\s*\(|\.url\s*\(|new\s+Request\.Builder\s*\("),
    ),
    ScanRule(
        FindingType.TLS_TRUST_ALL,
        "critical",
        "TrustManager that may not validate certificate chains",
        re.compile(r"implements\s+(?:[\w.]+\.)?X509TrustManager"),
        re.compile(r"\bcheckServerTrusted\b"),
    ),
    ScanRule(
        FindingType.HOSTNAME_VERIFIER,
        "critical",
        "HostnameVerifier that may accept any hostname",
        re.compile(r"implements\s+(?:[\w.]+\.)?HostnameVerifier"),
        re.compile(r"\bverify\s*\(\s*String\b|\bboolean\s+verify\s*\("),
    ),
]


def _is_noise(class_name: str) -> bool:
    return bool(_NOISE_PACKAGES.match(class_name))


def _method_for(jc: JavaClass, rule: ScanRule) -> JavaMethod | None:
    best, best_n = None, 0
    for m in jc.methods:
        if m.is_abstract or m.name == "<clinit>":
            continue
        n = len(rule.method_pattern.findall(m.body))
        if n > best_n:
            best, best_n = m, n
    return best


def scan_sources(root: Path, include_test_classes: bool = False) -> list[Finding]:
    """Walk decompiled sources (jadx's `sources/` dir, or a tree already at that root) and propose findings."""
    base = root / "sources" if (root / "sources").is_dir() else root
    findings: list[Finding] = []
    seen: set[tuple[FindingType, str]] = set()
    for java_file in sorted(base.rglob("*.java")):
        rel = java_file.relative_to(base).as_posix()
        class_name = rel[:-5].replace("/", ".")
        if not include_test_classes and _is_noise(class_name):
            continue
        try:
            src = java_file.read_text(errors="replace")
        except OSError:
            continue
        if "$" in class_name:  # inner classes are read as part of their outer class
            continue
        for rule in _RULES:
            if not rule.class_pattern.search(src):
                continue
            jc = parse_class(class_name, src)
            m = _method_for(jc, rule)
            if m is None or m.is_native:
                continue
            key = (rule.ftype, f"{class_name}.{m.name}")
            if key in seen:
                continue
            seen.add(key)
            fid = f"SCAN-{len(findings) + 1:03d}"
            findings.append(
                Finding(
                    id=fid,
                    title=rule.title,
                    type=rule.ftype,
                    severity=rule.severity,
                    description=f"Pattern match in {class_to_path(class_name)}; confirm at runtime before reporting.",
                    class_name=class_name,
                    method=m.name,
                    file_path=rel,
                    source="hooksmith-scan",
                )
            )
    return findings


def to_native_report(findings: list[Finding]) -> dict:
    return {
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "type": f.type.value,
                "severity": f.severity,
                "description": f.description,
                "class": f.class_name,
                "method": f.method,
                "file": f.file_path,
                "source": f.source,
            }
            for f in findings
        ]
    }
