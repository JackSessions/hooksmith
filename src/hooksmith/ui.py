"""Navigation-only UI exploration, so hooks get a chance to fire on screens a deep link cannot reach.

Safety rules, enforced here and not left to a model:
  * only taps controls that belong to the target package; if the app is left, press Back
  * never taps anything whose label looks destructive or costs money (DENY below)
  * never types text, never fills forms, never changes settings: it only taps what is already on screen
  * bounded: a fixed number of rounds, one tap each
Run it only against apps and devices you are authorised to test.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass

DENY = re.compile(
    r"delete|remove|erase|wipe|reset|format|factory|log\s?out|sign\s?out|uninstall|unlink|deactivate|close account|"
    r"purchase|buy|pay|checkout|subscribe|donate|order|call|dial|sms|send money|transfer|confirm payment",
    re.I,
)
_BOUNDS = re.compile(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]")


@dataclass(frozen=True)
class Target:
    key: str  # stable identity for "already visited"
    label: str
    x: int
    y: int


def parse_targets(xml_text: str, package: str, screen: tuple[int, int] = (10000, 10000)) -> list[Target]:
    """Tappable controls of `package` in a uiautomator dump, minus anything on the denylist."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    out: list[Target] = []
    for n in root.iter("node"):
        if n.get("package") != package or n.get("clickable") != "true" or n.get("enabled") != "true":
            continue
        label = " ".join(filter(None, [n.get("text"), n.get("content-desc"), n.get("resource-id")])).strip()
        if DENY.search(label):
            continue
        m = _BOUNDS.fullmatch(n.get("bounds", ""))
        if not m:
            continue
        x1, y1, x2, y2 = map(int, m.groups())
        if x2 <= x1 or y2 <= y1 or (x2 - x1) * (y2 - y1) < 400 or x2 > screen[0] or y2 > screen[1]:
            continue
        out.append(
            Target(
                key=f"{n.get('resource-id')}|{n.get('text')}|{n.get('content-desc')}|{x1},{y1}",
                label=label[:60],
                x=(x1 + x2) // 2,
                y=(y1 + y2) // 2,
            )
        )
    return out


def pick(targets: list[Target], visited: set[str]) -> Target | None:
    """Prefer unvisited controls that have a label; stable order so runs are reproducible."""
    fresh = [t for t in targets if t.key not in visited]
    fresh.sort(key=lambda t: (not t.label, t.y, t.x))
    return fresh[0] if fresh else None
