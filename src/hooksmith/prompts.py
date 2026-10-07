"""Prompt assembly. The text lives in prompts/*.txt so the Cloudflare Worker bundles the very same files."""

from __future__ import annotations

import hashlib
import re
from importlib import resources

from .models import FindingType

_DIR = resources.files("hooksmith") / "prompts"


def _read(name: str) -> str:
    return (_DIR / name).read_text(encoding="utf-8")


def fill(template: str, **values: str) -> str:
    return re.sub(r"\{\{(\w+)\}\}", lambda m: values.get(m.group(1), ""), template)


def prompt_hash() -> str:
    """Short hash of every prompt file, stored with each run so results are reproducible."""
    h = hashlib.sha256()
    for p in sorted(_DIR.iterdir(), key=lambda x: x.name):
        if p.name.endswith(".txt"):
            h.update(p.name.encode())
            h.update(p.read_text(encoding="utf-8").encode())
    return h.hexdigest()[:12]


def build_messages(
    *,
    finding_type: FindingType,
    class_name: str,
    method: str,
    title: str,
    source: str,
    overload: list[str] | None = None,
    errors: list[str] | None = None,
    previous: str | None = None,
) -> list[dict[str, str]]:
    guidance = _read(f"{finding_type.value}.txt") if finding_type != FindingType.UNKNOWN else ""
    overload_line = (
        f"Overload to hook: .overload({', '.join(repr(t) for t in overload)})"
        if overload is not None  # [] is a real answer: the zero-argument overload
        else "Overload: not specified. If the method has overloads, hook all of them via .overloads.forEach."
    )
    feedback = ""
    if errors:
        feedback = fill(_read("feedback.txt"), errors="\n".join(f"- {e}" for e in errors), previous=previous or "")
    user = fill(
        _read("user.txt"),
        class_name=class_name,
        method=method,
        overload_line=overload_line,
        title=title,
        type_guidance=guidance,
        source=source,
        feedback=feedback,
    )
    return [{"role": "system", "content": _read("system.txt")}, {"role": "user", "content": user}]


_FENCE = re.compile(r"```(?:javascript|js|typescript|ts)?\s*\n(.*?)```", re.S | re.I)


def extract_js(raw: str) -> str:
    """Models love markdown fences and chatter. Take the first code block if there is one."""
    m = _FENCE.search(raw)
    if m:
        return m.group(1).strip()
    text = raw.strip()
    # strip a dangling opening fence (truncated output)
    text = re.sub(r"^```\w*\s*\n", "", text)
    return text


def plan_messages(
    *, package: str, class_name: str, finding_type: str, deep_links: list[str], activities: list[str], default: list[str]
) -> list[dict[str, str]]:
    user = (
        f"Package: {package}\nTarget class: {class_name}\nFinding type: {finding_type}\n"
        f"Declared deep links: {deep_links or 'none'}\nExported activities: {activities or 'none'}\n"
        f"Default plan: {default}\nPropose a better plan as a JSON array."
    )
    return [{"role": "system", "content": _read("plan.txt")}, {"role": "user", "content": user}]


def parse_plan(raw: str) -> list[str]:
    import json

    m = re.search(r"\[.*\]", raw, re.S)
    if not m:
        return []
    try:
        data = json.loads(m.group(0))
    except json.JSONDecodeError:
        return []
    return [str(x) for x in data] if isinstance(data, list) else []
