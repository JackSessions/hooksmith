"""Planning how to exercise the app so a hook gets a chance to fire.

Steps are plain strings ("launch", "deeplink myapp://x", "activity .Foo", "monkey 80", "wait 2") so a plan can
be logged, stored with the evidence and replayed. `validate_plan` is the allowlist an LLM-proposed plan has to
pass: an agent may choose among these actions and nothing else.
"""

from __future__ import annotations

import re

from .manifest import Manifest
from .models import Finding, FindingType

ALLOWED = {"launch", "deeplink", "activity", "monkey", "wait", "explore"}
_SAFE_ARG = re.compile(r"^[\w\-\./:@%?=&#+,\$]*$")


def plan_steps(package: str, manifest: Manifest, finding: Finding, monkey_events: int = 80) -> list[str]:
    steps = ["launch", "wait 3"]
    for link in manifest.deep_links[:4]:
        steps += [f"deeplink {link}", "wait 1.5"]
    # activities whose name resembles the finding's class are the likeliest route to the hooked method
    hint = (finding.class_name or "").split(".")[-1].lower()
    ranked = sorted(manifest.exported_activities, key=lambda a: hint[:6] not in a.lower() if hint else 0)
    for act in ranked[:3]:
        steps += [f"activity {act}", "wait 1.5"]
    steps.append("explore 8")  # tap through visible, non-destructive controls (see ui.py)
    steps.append(f"monkey {monkey_events}")
    return steps


def validate_plan(steps: list[str], max_steps: int = 20) -> list[str]:
    """Drop anything outside the allowlist. Used on plans proposed by an LLM agent."""
    out = []
    for s in steps[:max_steps]:
        kind, _, arg = str(s).strip().partition(" ")
        if kind not in ALLOWED or not _SAFE_ARG.match(arg):
            continue
        if kind in ("monkey", "explore") and not arg.isdigit():
            continue
        if kind == "wait" and not re.fullmatch(r"\d+(\.\d+)?", arg or "2"):
            continue
        out.append(f"{kind} {arg}".strip())
    return out or ["launch", "wait 3", "monkey 60"]


def wants_network(finding: Finding) -> bool:
    return finding.type == FindingType.CLEARTEXT_HTTP
