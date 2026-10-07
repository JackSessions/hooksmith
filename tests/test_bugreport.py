import json

from hooksmith.bugreport import build_report, write_bug_reports

ROW = {
    "id": "F1",
    "title": "Hardcoded key",
    "type": "hardcoded_key",
    "severity": "high",
    "class_name": "com.x.C",
    "method": "enc",
    "verdict": "PROVEN",
    "reason": "observed key matches a static constant",
    "evidence_dir": None,
}
META = {
    "apk": {"name": "app.apk", "sha256": "abc123def456"},
    "package": "com.x",
    "run_id": "run-1",
    "provider": "worker",
    "model": "qwen",
    "device": {"model": "Pixel", "android": "13", "abi": "x86_64", "frida": "17.0"},
}


def make_evidence(tmp_path):
    d = tmp_path / "findings" / "F1"
    d.mkdir(parents=True)
    (d / "hook.js").write_text("Java.perform(function(){ console.log('HS|{}'); });")
    (d / "runtime.log").write_text('HS|{"event":"ready"}\nHS|{"event":"call"}')
    (d / "execution.json").write_text(json.dumps({"exercised": ["launch", "wait 3"]}))
    return d


def test_report_contains_evidence_hook_and_remediation(tmp_path):
    d = make_evidence(tmp_path)
    md = build_report(ROW, d, META)
    assert "**Verdict:** **PROVEN**" in md
    assert "com.x.C.enc" in md
    assert "Java.perform" in md  # the actual hook, not a description of it
    assert "HS|" in md  # the actual log
    assert "Android Keystore" in md  # type-specific remediation
    assert "launch" in md and "wait 3" in md  # the real exercise steps, not invented ones
    assert "written or embellished by a model" in md


def test_unknown_finding_type_gets_a_generic_remediation(tmp_path):
    d = make_evidence(tmp_path)
    row = dict(ROW, type="something_new")
    md = build_report(row, d, META)
    assert "Review the finding's hook" in md


def test_missing_evidence_files_do_not_crash(tmp_path):
    d = tmp_path / "findings" / "F1"
    d.mkdir(parents=True)  # no hook.js / runtime.log / execution.json at all
    md = build_report(ROW, d, META)
    assert "(hook not recorded)" in md and "(no log captured)" in md


def test_write_bug_reports_only_covers_requested_verdicts(tmp_path):
    d = make_evidence(tmp_path)
    (tmp_path / "run.json").write_text(json.dumps(META))
    rows = [
        dict(ROW, evidence_dir=str(d)),
        dict(ROW, id="F2", verdict="REFUTED", evidence_dir=str(d)),
        dict(ROW, id="F3", verdict="PROVEN", evidence_dir=str(tmp_path / "findings" / "missing")),  # no dir: skipped
    ]
    written = write_bug_reports(tmp_path, rows)
    assert [p.name for p in written] == ["F1.md"]
    assert (tmp_path / "bugs" / "F1.md").exists()


def test_write_bug_reports_can_include_other_verdicts(tmp_path):
    d = make_evidence(tmp_path)
    (tmp_path / "run.json").write_text(json.dumps(META))
    rows = [dict(ROW, id="F2", verdict="REFUTED", evidence_dir=str(d))]
    written = write_bug_reports(tmp_path, rows, verdicts=("PROVEN", "REFUTED"))
    assert len(written) == 1
