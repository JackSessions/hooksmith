"""Static validation of LLM-written Frida hooks, run *before* any device time is spent.

The six gating checks come straight from the talk. A hook that fails any of them is regenerated
once with the errors fed back. A seventh gating "policy" check keeps obviously dangerous APIs
out of generated code, and the advisory checks never block, they only land in the evidence.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import esprima

from .javasrc import JavaClass
from .models import CheckResult, ValidationResult

_USE_RE = re.compile(r"""Java\.use\(\s*(["'])([^"']+)\1\s*\)""")
# APIs a generated *observation* hook has no business touching.
FORBIDDEN = {
    r"\beval\s*\(": "eval()",
    r"\bnew\s+Function\s*\(": "new Function()",
    # not a bare `.exec(`: RegExp.exec is harmless and our own hostname helper uses it
    r"Runtime\.getRuntime|java\.lang\.Runtime\b": "process execution",
    r"ProcessBuilder": "ProcessBuilder",
    r"System\.exit|Process\.killProcess": "killing the app",
    r"java\.net\.(?:Socket|URL)\b.*\.(?:connect|openConnection)\(": "making network calls",
    r"Interceptor\.replace": "Interceptor.replace",
    r"Memory\.(?:write|protect|patch)": "memory writes",
    r"File(?:Output|Writer)": "writing files",
    r"\brequire\s*\(": "require()",
    r"\bimport\s*\(": "dynamic import",
}


def _js_syntax(js: str) -> tuple[bool, str]:
    """node --check is the authority (Frida runs modern JS); esprima is the fallback."""
    node = shutil.which("node")
    if node:
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as fh:
            fh.write(js)
            name = fh.name
        try:
            r = subprocess.run([node, "--check", name], capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                return True, "node --check ok"
            first = next((ln for ln in r.stderr.splitlines() if "Error" in ln), r.stderr.strip()[:200])
            return False, first
        finally:
            Path(name).unlink(missing_ok=True)
    try:
        esprima.parseScript(js, tolerant=False)
        return True, "esprima ok"
    except Exception as exc:  # noqa: BLE001
        return False, f"esprima: {exc}"


def _method_pattern(method: str) -> str:
    m = "$init" if method in ("<init>", "$init") else re.escape(method)
    m = m.replace(r"\$", r"\$")
    return m


def validate_hook(
    js: str,
    class_name: str,
    method: str,
    java_class: JavaClass | None = None,
    param_types: list[str] | None = None,
) -> ValidationResult:
    checks: list[CheckResult] = []

    def add(name: str, ok: bool, detail: str = "", gating: bool = True) -> None:
        checks.append(CheckResult(name=name, passed=ok, detail=detail if not ok else detail or "ok", gating=gating))

    stripped = js.strip()
    if not stripped:
        add("parses as JavaScript", False, "empty output")
        return ValidationResult(ok=False, checks=checks)

    ok, detail = _js_syntax(js)
    add("parses as JavaScript", ok, detail)

    add("contains Java.perform", bool(re.search(r"\bJava\.perform\s*\(", js)), "no Java.perform(...) wrapper")

    uses = [m.group(2) for m in _USE_RE.finditer(js)]
    add(
        "Java.use targets the correct class",
        class_name in uses,
        f"expected Java.use({class_name!r}); found {uses or 'no Java.use calls'}",
    )

    mp = _method_pattern(method)
    bracket = re.escape(method) if method not in ("<init>", "$init") else r"\$init"
    hooked = (
        re.search(rf"\.{mp}\s*(?:\.overload\([^)]*\)\s*)?\.implementation\s*=", js)
        or re.search(rf"\[\s*[\"']{bracket}[\"']\s*\]\s*(?:\.overload\([^)]*\)\s*)?\.implementation\s*=", js)
        # hook every overload: C.method.overloads.forEach(function (ov) { ov.implementation = ... })
        or (re.search(rf"\.{mp}\.overloads\b", js) and re.search(r"\.implementation\s*=", js))
    )
    add("hooks the requested method", bool(hooked), f"no `.{method}.implementation =` assignment found")

    add(
        "produces observable output",
        bool(re.search(r"\bconsole\.log\s*\(|\bsend\s*\(", js)),
        "no console.log() or send(): a silent hook proves nothing",
    )

    calls_orig = (
        re.search(rf"this\.{mp}\s*(?:\.(?:call|apply)\s*)?\(", js)
        or re.search(rf"this\s*\[\s*[\"']{bracket}[\"']\s*\]", js)
        or re.search(rf"\.{mp}\s*\.call\(\s*this", js)
        or (re.search(rf"\.{mp}\.overloads\b", js) and re.search(r"\.(?:apply|call)\s*\(\s*this", js))
    )
    add(
        "calls the original implementation",
        bool(calls_orig),
        f"no this.{method}(...) call: the hook would break app flow",
    )

    bad = [label for pat, label in FORBIDDEN.items() if re.search(pat, js)]
    add("avoids dangerous APIs", not bad, f"generated hook uses {', '.join(bad)}")

    # ---- advisory only -----------------------------------------------------------------------
    if java_class is not None:
        decl = java_class.find(method)
        if not decl:
            add("method exists in decompiled source", False, f"{method} not found in {class_name}", gating=False)
        elif param_types is not None:
            arities = {len(m.params) for m in decl}
            ov = re.search(r"\.overload\(([^)]*)\)", js)
            if ov is not None:
                n_args = len([a for a in ov.group(1).split(",") if a.strip()])
                add(
                    "overload arity matches source",
                    n_args in arities,
                    f"overload() has {n_args} types but source declares arities {sorted(arities)}",
                    gating=False,
                )
        if len(decl) > 1 and ".overload(" not in js:
            add(
                "overloads disambiguated",
                False,
                f"{method} has {len(decl)} overloads and the hook doesn't pick one",
                gating=False,
            )

    return ValidationResult(ok=all(c.passed for c in checks if c.gating), checks=checks)
