import json

import pytest

from hooksmith.harness import evaluate, load_expect, parse_fail_on

ROWS = [
    {"id": "A", "class_name": "com.x.Api", "method": "fetch", "verdict": "PROVEN", "severity": "high", "reason": ""},
    {
        "id": "B",
        "class_name": "com.x.Rnd",
        "method": "pick",
        "verdict": "REFUTED",
        "severity": "medium",
        "reason": "not security",
    },
    {"id": "C", "class_name": "com.x.Dead", "method": "key", "verdict": "UNVALIDATED", "severity": "low", "reason": "native"},
]


def test_expect_by_id_and_by_target():
    assert evaluate(ROWS, {"A": "PROVEN", "com.x.Rnd.pick": "REFUTED"}) == []
    f = evaluate(ROWS, {"A": "REFUTED", "ZZ": "PROVEN"})
    assert len(f) == 2 and "expected REFUTED, got PROVEN" in f[0] and "no such finding" in f[1]


def test_fail_on_respects_severity():
    assert evaluate(ROWS, fail_on=parse_fail_on(["PROVEN:high"]))
    assert not evaluate(ROWS, fail_on=parse_fail_on(["PROVEN:critical"]))
    assert not evaluate(ROWS, fail_on=parse_fail_on(["UNREACHABLE"]))


def test_max_unvalidated():
    assert evaluate(ROWS, max_unvalidated=0) and not evaluate(ROWS, max_unvalidated=1)


def test_bad_inputs(tmp_path):
    p = tmp_path / "e.json"
    p.write_text(json.dumps({"A": "MAYBE"}))
    with pytest.raises(ValueError):
        load_expect(p)
    with pytest.raises(ValueError):
        parse_fail_on(["PROVEN:extreme"])


def test_cli_exit_codes(tmp_path):
    from click.testing import CliRunner

    from hooksmith.cli import main
    from hooksmith.demo import demo_dir

    d = demo_dir()
    exp = tmp_path / "exp.json"
    exp.write_text(json.dumps({"android_hardcoded:com.demo.vault.Crypto": "PROVEN"}))
    base = [
        "run",
        "--report",
        str(d / "mobsf_report.json"),
        "--sources",
        str(d / "sources"),
        "--package",
        "com.demo.vault",
        "--executor",
        "replay",
        "--replay-from",
        str(d / "logs"),
        "--provider",
        "template",
        "--out",
        str(tmp_path / "r"),
        "-q",
    ]
    ok = CliRunner().invoke(main, base + ["--expect", str(exp)])
    assert ok.exit_code == 0, ok.output
    bad = CliRunner().invoke(main, base + ["--fail-on", "PROVEN"])
    assert bad.exit_code == 1 and "harness: FAILED" in bad.output
