"""Test-harness policy: turn a finished run into pass/fail for CI.

    --expect expected.json     assert exact verdicts, e.g. {"VL-1": "PROVEN", "com.x.Api.fetch": "REFUTED"}
    --fail-on PROVEN:high      fail if any finding with this verdict is at least this severity
    --max-unvalidated N        fail if more than N findings could not be validated

Keys in the expectations file can be a finding id or `Class.method`.
"""

from __future__ import annotations

import json
from pathlib import Path

SEVERITY = {"info": 0, "low": 1, "warning": 2, "medium": 2, "high": 3, "critical": 4}


def load_expect(path: Path) -> dict[str, str]:
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict):
        raise ValueError("expectations file must be a JSON object of {finding: VERDICT}")
    out = {}
    for k, v in data.items():
        v = str(v).upper()
        if v not in {"PROVEN", "REFUTED", "UNREACHABLE", "UNVALIDATED"}:
            raise ValueError(f"{k}: {v!r} is not one of the four verdicts")
        out[k] = v
    return out


def _target(row: dict) -> str:
    return f"{row.get('class_name') or '?'}.{row.get('method') or '?'}"


def parse_fail_on(specs: list[str]) -> list[tuple[str, int]]:
    out = []
    for spec in specs:
        verdict, _, sev = spec.partition(":")
        verdict = verdict.upper()
        if verdict not in {"PROVEN", "REFUTED", "UNREACHABLE", "UNVALIDATED"}:
            raise ValueError(f"--fail-on {spec!r}: unknown verdict")
        if sev and sev.lower() not in SEVERITY:
            raise ValueError(f"--fail-on {spec!r}: unknown severity {sev!r}")
        out.append((verdict, SEVERITY[sev.lower()] if sev else 0))
    return out


def evaluate(
    rows: list[dict],
    expect: dict[str, str] | None = None,
    fail_on: list[tuple[str, int]] | None = None,
    max_unvalidated: int | None = None,
) -> list[str]:
    """Return human-readable failures; empty list means the run passes."""
    failures: list[str] = []
    by_key = {}
    for r in rows:
        by_key[r["id"]] = r
        by_key[_target(r)] = r
    for key, want in (expect or {}).items():
        r = by_key.get(key)
        if r is None:
            failures.append(f"expected {key} = {want}, but no such finding in this run")
        elif (r["verdict"] or "UNVALIDATED") != want:
            failures.append(f"{key}: expected {want}, got {r['verdict']} ({(r['reason'] or '')[:100]})")
    for verdict, min_sev in fail_on or []:
        for r in rows:
            if r["verdict"] == verdict and SEVERITY.get((r["severity"] or "info").lower(), 0) >= min_sev:
                failures.append(f"{r['id']} ({_target(r)}) is {verdict} at severity {r['severity']}")
    if max_unvalidated is not None:
        n = sum(1 for r in rows if r["verdict"] == "UNVALIDATED")
        if n > max_unvalidated:
            failures.append(f"{n} findings UNVALIDATED (allowed: {max_unvalidated})")
    return failures
