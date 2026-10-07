"""Evidence store: SQLite for queries, flat files for the proof. One folder per finding.

runs/<run_id>/
  run.json                      tool/model/device metadata for reproducibility
  evidence.db                   runs, findings, attempts, verdicts
  findings/<finding_id>/
    source.java                 the decompiled class the hook was written from
    hook.attempt1.js  ...       every generated hook, validated or not
    hook.js                     the hook that actually ran
    validation.json             the six(+) checks for each attempt
    runtime.log                 raw hook output
    verdict.json                verdict + reason + what the signal library saw
"""

from __future__ import annotations

import json
import re
import sqlite3
import time
from pathlib import Path

from .models import ExecutionResult, Finding, HookAttempt, Outcome

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY, title TEXT, type TEXT, severity TEXT, class_name TEXT, method TEXT, data TEXT);
CREATE TABLE IF NOT EXISTS attempts (
  finding_id TEXT, n INTEGER, ok INTEGER, errors TEXT, model TEXT, path TEXT, PRIMARY KEY (finding_id, n));
CREATE TABLE IF NOT EXISTS verdicts (
  finding_id TEXT PRIMARY KEY, verdict TEXT, reason TEXT, signal TEXT, evidence_dir TEXT, ts REAL);
"""


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:120] or "finding"


class Store:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "findings").mkdir(exist_ok=True)
        self.db = sqlite3.connect(self.root / "evidence.db")
        self.db.executescript(SCHEMA)

    # -- paths -----------------------------------------------------------------------------
    def finding_dir(self, finding_id: str) -> Path:
        d = self.root / "findings" / _safe(finding_id)
        d.mkdir(parents=True, exist_ok=True)
        return d

    # -- writes ----------------------------------------------------------------------------
    def write_run(self, meta: dict) -> None:
        (self.root / "run.json").write_text(json.dumps(meta, indent=2, default=str))

    def add_finding(self, f: Finding) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?)",
            (f.id, f.title, f.type.value, f.severity, f.class_name, f.method, f.model_dump_json()),
        )
        self.db.commit()

    def save_source(self, finding_id: str, source: str) -> None:
        (self.finding_dir(finding_id) / "source.java").write_text(source)

    def save_attempt(self, finding_id: str, a: HookAttempt) -> None:
        d = self.finding_dir(finding_id)
        path = d / f"hook.attempt{a.n}.js"
        path.write_text(a.js)
        if a.raw and a.raw != a.js:
            (d / f"llm.attempt{a.n}.txt").write_text(a.raw)
        errs = a.validation.errors if a.validation else []
        self.db.execute(
            "INSERT OR REPLACE INTO attempts VALUES (?,?,?,?,?,?)",
            (finding_id, a.n, int(bool(a.validation and a.validation.ok)), json.dumps(errs), a.model, str(path)),
        )
        self.db.commit()
        v = d / "validation.json"
        data = json.loads(v.read_text()) if v.exists() else {}
        data[f"attempt{a.n}"] = a.validation.model_dump() if a.validation else None
        v.write_text(json.dumps(data, indent=2))

    def save_executed_hook(self, finding_id: str, js: str) -> None:
        (self.finding_dir(finding_id) / "hook.js").write_text(js)

    def save_execution(self, finding_id: str, r: ExecutionResult) -> None:
        d = self.finding_dir(finding_id)
        (d / "runtime.log").write_text("\n".join(r.log) + ("\n" if r.log else ""))
        (d / "execution.json").write_text(json.dumps(r.model_dump(exclude={"log"}), indent=2, default=str))

    def save_screen_recording(self, finding_id: str, local_mp4: Path) -> Path:
        """Moves a (temp-file) screen recording into the evidence store, then cleans up its temp directory."""
        dest = self.finding_dir(finding_id) / "screen.mp4"
        tmp_dir = local_mp4.parent
        local_mp4.replace(dest)
        try:
            tmp_dir.rmdir()  # only succeeds if screen.mp4 was the only thing in there
        except OSError:
            pass
        return dest

    def save_verdict(self, finding_id: str, o: Outcome) -> None:
        d = self.finding_dir(finding_id)
        (d / "verdict.json").write_text(o.model_dump_json(indent=2))
        self.db.execute(
            "INSERT OR REPLACE INTO verdicts VALUES (?,?,?,?,?,?)",
            (finding_id, o.verdict.value, o.reason, json.dumps(o.signal, default=str), str(d), time.time()),
        )
        self.db.commit()

    # -- reads -----------------------------------------------------------------------------
    def decided(self) -> set[str]:
        return {r[0] for r in self.db.execute("SELECT finding_id FROM verdicts")}

    def rows(self) -> list[dict]:
        q = """SELECT f.id, f.title, f.type, f.severity, f.class_name, f.method,
                      v.verdict, v.reason, v.evidence_dir,
                      (SELECT COUNT(*) FROM attempts a WHERE a.finding_id=f.id) AS attempts
               FROM findings f LEFT JOIN verdicts v ON v.finding_id=f.id ORDER BY f.rowid"""
        cols = ["id", "title", "type", "severity", "class_name", "method", "verdict", "reason", "evidence_dir", "attempts"]
        return [dict(zip(cols, r)) for r in self.db.execute(q)]

    def close(self) -> None:
        self.db.close()
