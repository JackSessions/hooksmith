"""Triage: the graph's first node, run once before any finding touches a device.

Two jobs, both deterministic and both cheap (no device, no LLM, no I/O beyond what's already in memory):
  1. Merge exact duplicates (same type + same class.method) that different scanner rules reported separately.
     Each one still gets its own verdict in the evidence store -- merging only picks which one the device actually
     runs a hook for, and copies that single verdict onto the others, so one finding doesn't cost device time twice.
  2. Order the rest by severity, so a run that gets interrupted or time-boxed (--limit) spends its device time on
     the findings most worth proving first.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Finding

SEVERITY_RANK = {"critical": 0, "high": 1, "warning": 2, "medium": 2, "low": 3, "info": 4}


def _key(f: Finding) -> tuple[str, str | None, str | None]:
    return (f.type.value, f.class_name, f.method)


@dataclass
class TriageResult:
    ordered: list[Finding]
    duplicate_of: dict[str, str]  # dropped finding id -> the id of the one that will actually run


def triage(findings: list[Finding]) -> TriageResult:
    """Stable: equal-severity findings keep their original relative order."""
    seen: dict[tuple, str] = {}
    kept: list[Finding] = []
    duplicate_of: dict[str, str] = {}
    for f in findings:
        k = _key(f)
        canon = seen.get(k)
        if canon is None:
            seen[k] = f.id
            kept.append(f)
        else:
            duplicate_of[f.id] = canon
    ordered = sorted(kept, key=lambda f: (SEVERITY_RANK.get((f.severity or "info").lower(), 4), findings.index(f)))
    return TriageResult(ordered=ordered, duplicate_of=duplicate_of)
