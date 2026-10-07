"""Golden test: the bundled demo must land every finding in the expected bucket, through the real LangGraph."""

from hooksmith.demo import DemoProvider
from hooksmith.executors.replay import NullExecutor, ReplayExecutor
from hooksmith.providers import TemplateProvider
from hooksmith.runner import RunOptions, run_assessment

EXPECTED = {
    "android_hardcoded:com.demo.vault.Crypto": "PROVEN",
    "android_hardcoded:com.demo.vault.SessionCrypto": "REFUTED",
    "android_hardcoded:com.demo.vault.PinStore": "UNVALIDATED",  # validator rejects the hook twice
    "android_insecure_random:com.demo.auth.TokenGen": "PROVEN",  # recovers on regeneration
    "android_insecure_random:com.demo.auth.Cosmetics": "REFUTED",
    "android_insecure_random:com.demo.auth.PromoRotator": "UNREACHABLE",
    "android_cleartext_http:com.demo.net.LegacyApi": "PROVEN",
    "android_cleartext_http:com.demo.net.ProfileClient": "REFUTED",
    "android_hardcoded_jni:com.demo.jni.NativeCrypto": "UNVALIDATED",  # native
    "android_hardcoded_jni:com.demo.ghost.Vanished": "UNVALIDATED",  # class missing
}


def opts(demo, tmp_path, provider, executor):
    return RunOptions(
        report=demo / "mobsf_report.json",
        out_dir=tmp_path,
        provider=provider,
        executor=executor,
        sources=demo / "sources",
        package="com.demo.vault",
    )


def test_demo_verdicts_and_evidence(demo, tmp_path):
    res = run_assessment(opts(demo, tmp_path, DemoProvider(), ReplayExecutor(demo / "logs")))
    got = {r["id"]: r["verdict"] for r in res.rows}
    assert got == EXPECTED
    assert all(r["verdict"] for r in res.rows), "every finding must exit with a verdict"
    # the evidence bundle exists and is reproducible
    d = res.run_dir / "findings" / "android_hardcoded_com.demo.vault.Crypto"
    for name in ("source.java", "hook.js", "runtime.log", "verdict.json", "validation.json"):
        assert (d / name).exists(), name
    md = res.report_md.read_text()
    assert "10 findings, 10 verdicts" in md and "PROVEN" in md
    # TokenGen needed a regeneration: two attempts stored
    t = res.run_dir / "findings" / "android_insecure_random_com.demo.auth.TokenGen"
    assert (t / "hook.attempt1.js").exists() and (t / "hook.attempt2.js").exists()


def test_static_only_run_marks_unvalidated_with_reason(demo, tmp_path):
    res = run_assessment(opts(demo, tmp_path, TemplateProvider(), NullExecutor()))
    assert all(r["verdict"] == "UNVALIDATED" for r in res.rows)
    assert any("no device" in (r["reason"] or "") for r in res.rows)


def test_resume_skips_decided(demo, tmp_path):
    first = run_assessment(opts(demo, tmp_path, DemoProvider(), ReplayExecutor(demo / "logs")))
    o = opts(demo, tmp_path, DemoProvider(), ReplayExecutor(demo / "logs"))
    o.resume = first.run_dir
    seen = []
    o.on_event = lambda kind, f, **k: seen.append(kind)
    run_assessment(o)
    assert "start" not in seen  # nothing left to do


def test_demo_run_writes_bug_reports_for_proven_findings(demo, tmp_path):
    res = run_assessment(opts(demo, tmp_path, DemoProvider(), ReplayExecutor(demo / "logs")))
    proven_ids = {r["id"] for r in res.rows if r["verdict"] == "PROVEN"}
    bugs_dir = res.run_dir / "bugs"
    from hooksmith.store import _safe

    written = {p.stem for p in bugs_dir.glob("*.md")}
    assert written == {_safe(i) for i in proven_ids} and len(proven_ids) == 3  # Crypto, TokenGen, LegacyApi
    md = (bugs_dir / f"{_safe(next(iter(proven_ids)))}.md").read_text()
    assert "**Verdict:** **PROVEN**" in md and "written or embellished by a model" in md


def test_bug_reports_can_be_disabled(demo, tmp_path):
    o = opts(demo, tmp_path, DemoProvider(), ReplayExecutor(demo / "logs"))
    o.bug_reports = False
    res = run_assessment(o)
    assert not (res.run_dir / "bugs").exists()


def test_triage_merges_a_real_duplicate_through_the_whole_pipeline(demo, tmp_path):
    """Feed the SAME finding twice under different scanner ids and confirm only one hook actually runs."""
    import json

    # native-format override: two ids, identical type+class+method
    native = tmp_path / "dup_findings.json"
    native.write_text(
        json.dumps(
            {
                "findings": [
                    # DUP-A's id matches a recorded replay log (demo/logs/); DUP-B does not need one, since
                    # triage must merge it away as a duplicate BEFORE it ever reaches the executor.
                    {
                        "id": "android_hardcoded:com.demo.vault.Crypto",
                        "title": "a",
                        "type": "hardcoded_key",
                        "class": "com.demo.vault.Crypto",
                        "method": "encrypt",
                    },
                    {"id": "DUP-B", "title": "b", "type": "hardcoded_key", "class": "com.demo.vault.Crypto", "method": "encrypt"},
                ]
            }
        )
    )
    o = RunOptions(
        report=native,
        out_dir=tmp_path,
        provider=DemoProvider(),
        executor=ReplayExecutor(demo / "logs"),
        sources=demo / "sources",
        package="com.demo.vault",
    )
    res = run_assessment(o)
    rows = {r["id"]: r for r in res.rows}
    canon_id = "android_hardcoded:com.demo.vault.Crypto"
    assert rows[canon_id]["verdict"] == "PROVEN"
    assert rows["DUP-B"]["verdict"] == "PROVEN" and f"duplicate of {canon_id}" in rows["DUP-B"]["reason"]
    assert len(res.rows) == 2  # confirms DUP-B never ran its own hook: still just the one evidence-producing run


def test_swarm_triage_runs_automatically_for_a_raw_mobsf_report_and_matches_direct_ingest(demo, tmp_path):
    """run_assessment, with swarm_triage left on its default True, must route a raw MobSF report through the
    swarm and land on the same verdicts as the plain ingest path (the demo report has no finding types the
    swarm would classify as unknown, so nothing should be filtered out either).
    """
    seen_notes = []
    o = opts(demo, tmp_path, DemoProvider(), ReplayExecutor(demo / "logs"))
    o.on_event = lambda kind, f, **k: seen_notes.append(k.get("text", "")) if kind == "note" else None
    res = run_assessment(o)
    got = {r["id"]: r["verdict"] for r in res.rows}
    assert got == EXPECTED
    assert any("swarm triage" in n for n in seen_notes), seen_notes


def test_swarm_triage_can_be_disabled(demo, tmp_path):
    seen_notes = []
    o = opts(demo, tmp_path, DemoProvider(), ReplayExecutor(demo / "logs"))
    o.swarm_triage = False
    o.on_event = lambda kind, f, **k: seen_notes.append(k.get("text", "")) if kind == "note" else None
    res = run_assessment(o)
    assert {r["id"]: r["verdict"] for r in res.rows} == EXPECTED
    assert not any("swarm triage" in n for n in seen_notes)
