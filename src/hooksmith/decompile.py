"""jadx wrapper plus class/method resolution. Anything we cannot resolve is UNVALIDATED, with the reason."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .javasrc import JavaClass, JavaMethod, class_to_path, locate_method, obfuscation_score, parse_class, real_class_name
from .models import Finding


class DecompileError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def find_jadx(explicit: str | None = None) -> str | None:
    if explicit:
        return explicit if Path(explicit).exists() else shutil.which(explicit)
    for cand in (shutil.which("jadx"), str(Path.home() / ".cache/hooksmith/jadx/bin/jadx")):
        if cand and Path(cand).exists():
            return cand
    return None


def run_jadx(apk: Path, out: Path, jadx: str | None = None, timeout: int = 900) -> Path:
    """Decompile the whole APK once per run. Returns the directory holding sources/ and resources/."""
    exe = find_jadx(jadx)
    if not exe:
        raise DecompileError("jadx not found. Install it (https://github.com/skylot/jadx) or pass --jadx / --sources.")
    out.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        [exe, "-d", str(out), "--no-debug-info", "--show-bad-code", "--threads-count", "4", str(apk)],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    # jadx exits non-zero when *some* classes fail, which is normal. No sources dir means real failure.
    if not (out / "sources").is_dir():
        raise DecompileError(f"jadx produced no sources (exit {proc.returncode}): {proc.stderr.strip()[-400:]}")
    return out


@dataclass
class Resolved:
    java_class: JavaClass
    method: JavaMethod
    method_name: str
    class_name: str  # the real runtime name (Java.use() target); may differ from finding.class_name, see real_class_name
    obfuscation: float


@dataclass
class Unresolved:
    reason: str


def resolve(finding: Finding, sources: Path) -> Resolved | Unresolved:
    """Find the class and the method to hook for a finding."""
    if not finding.class_name:
        return Unresolved("finding does not name a class")
    path = sources / class_to_path(finding.class_name)
    if not path.is_file():
        alt = sources / "sources" / class_to_path(finding.class_name)
        path = alt if alt.is_file() else path
    if not path.is_file():
        return Unresolved(f"class {finding.class_name} not found in the decompiled tree ({class_to_path(finding.class_name)})")
    src = path.read_text(errors="replace")
    if "Could not decompile" in src or "Failed to decompile" in src:
        return Unresolved("jadx failed to decompile this class")
    runtime_name = real_class_name(src, finding.class_name)
    jc = parse_class(runtime_name, src)
    obf = obfuscation_score(runtime_name, src)

    method: JavaMethod | None
    explicit = bool(finding.method)
    if explicit:
        found = jc.find(finding.method, len(finding.param_types) if finding.param_types is not None else None)
        if not found:
            return Unresolved(f"method {finding.method} not found in {finding.class_name}")
        method = found[0]
    else:
        method = locate_method(jc, finding.type.value, finding.lines)
        if method is None:
            natives = [m.name for m in jc.methods if m.is_native]
            if natives:
                return Unresolved(
                    f"{finding.class_name} implements the sensitive logic in native JNI method(s) "
                    f"({', '.join(natives[:3])}); v1 cannot hook native code reliably"
                )
            return Unresolved(f"could not choose a method to hook in {finding.class_name} for a {finding.type.value} finding")
    if method.is_native:
        return Unresolved(f"{method.name} is a native JNI method; v1 cannot hook native code reliably")
    # The obfuscation gate exists to stop *guessing* which renamed method to hook. When the finding already names
    # the exact method (no locate_method ambiguity to worry about) AND that name resolved to exactly one
    # candidate, hooking it is mechanically unambiguous regardless of how terse the names look -- short/renamed
    # symbols are completely hookable, they just give the LLM less to work with semantically. Blocking this case
    # was a real false negative, found on OWASP MASTG's UnCrackable-Level1.apk (class "a", method "a").
    unambiguous = explicit and len(found) == 1
    if obf > 0.6 and not unambiguous:
        return Unresolved(f"class looks heavily obfuscated (score {obf:.2f}); renamed members make hooks unreliable")
    return Resolved(java_class=jc, method=method, method_name=method.name, class_name=runtime_name, obfuscation=obf)
