"""Read AndroidManifest.xml (as decoded by jadx) to plan how to exercise the app."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

ANDROID = "{http://schemas.android.com/apk/res/android}"


@dataclass
class Manifest:
    package: str | None = None
    launcher: str | None = None  # fully-qualified activity
    exported_activities: list[str] = field(default_factory=list)
    deep_links: list[str] = field(default_factory=list)  # scheme://host[/path]
    uses_cleartext: bool | None = None


def _qual(pkg: str | None, name: str) -> str:
    if name.startswith("."):
        return (pkg or "") + name
    return name if "." in name else f"{pkg}.{name}"


def parse_manifest(path: Path) -> Manifest:
    m = Manifest()
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return m
    m.package = root.get("package")
    app = root.find("application")
    if app is None:
        return m
    if app.get(f"{ANDROID}usesCleartextTraffic") is not None:
        m.uses_cleartext = app.get(f"{ANDROID}usesCleartextTraffic") == "true"
    for act in list(app.findall("activity")) + list(app.findall("activity-alias")):
        name = _qual(m.package, act.get(f"{ANDROID}name", ""))
        filters = act.findall("intent-filter")
        exported = act.get(f"{ANDROID}exported") == "true" or (act.get(f"{ANDROID}exported") is None and filters)
        for f in filters:
            actions = {a.get(f"{ANDROID}name") for a in f.findall("action")}
            cats = {c.get(f"{ANDROID}name") for c in f.findall("category")}
            if "android.intent.action.MAIN" in actions and "android.intent.category.LAUNCHER" in cats:
                m.launcher = m.launcher or name
            for d in f.findall("data"):
                scheme, host = d.get(f"{ANDROID}scheme"), d.get(f"{ANDROID}host")
                if scheme and scheme not in ("content", "file"):
                    link = f"{scheme}://{host or 'example.com'}{d.get(f'{ANDROID}pathPrefix') or d.get(f'{ANDROID}path') or ''}"
                    if link not in m.deep_links:
                        m.deep_links.append(link)
        if exported and name not in m.exported_activities and name != m.launcher:
            m.exported_activities.append(name)
    return m
