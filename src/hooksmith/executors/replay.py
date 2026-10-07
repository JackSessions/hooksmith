"""Replay and null executors.

`replay` plays back runtime logs recorded by an earlier run (or the bundled demo fixtures). It is how the talk's
pre-recorded Corellium leg works, and how CI exercises the whole pipeline without a device.
`none` attaches nothing: every finding that survives validation is reported UNVALIDATED ("no device").
"""

from __future__ import annotations

import json
from pathlib import Path

from ..models import ExecutionResult
from .base import Executor, RunSpec


class NullExecutor(Executor):
    name = "none"

    def prepare(self) -> dict:
        return {"executor": "none"}

    def run(self, spec: RunSpec) -> ExecutionResult:
        return ExecutionResult(attached=False, error="no device executor selected (static-only run)")


class ReplayExecutor(Executor):
    name = "replay"

    def __init__(self, source: Path):
        self.source = Path(source)

    def prepare(self) -> dict:
        return {"executor": "replay", "replay_from": str(self.source)}

    def _log_for(self, finding_id: str) -> list[str] | None:
        from ..store import _safe

        for base in (self.source / "findings", self.source):
            p = base / _safe(finding_id) / "runtime.log"
            if p.exists():
                return p.read_text().splitlines()
            j = base / f"{_safe(finding_id)}.json"
            if j.exists():
                return json.loads(j.read_text()).get("log", [])
        return None

    def run(self, spec: RunSpec) -> ExecutionResult:
        log = self._log_for(spec.finding.id)
        if log is None:
            return ExecutionResult(attached=False, error=f"no recorded log for {spec.finding.id}")
        return ExecutionResult(attached=True, log=log, exercised=["replayed"], device={"executor": "replay"})
