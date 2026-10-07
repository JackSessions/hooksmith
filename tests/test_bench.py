"""Benchmark accounting, tested on a synthetic MASTG-shaped tree (no MASTG content is copied into this repo)."""

from hooksmith import bench
from hooksmith.models import FindingType
from hooksmith.providers import GenResult, TemplateProvider

JAVA = """package org.example.app;

import java.util.Random;

public final class MastgTest {
    public final String mastgTest() {
        Random r = new Random();
        return Integer.toString(r.nextInt(10));
    }
}
"""


def fake_mastg(tmp_path):
    d = tmp_path / "demos" / "android" / "MASVS-CRYPTO" / "MASTG-DEMO-0007"
    d.mkdir(parents=True)
    (d / "MastgTest_reversed.java").write_text(JAVA)
    (d / "MASTG-DEMO-0007.md").write_text('---\ntitle: "Common Uses of Insecure Random APIs"\n---\n')
    return tmp_path


class BrokenThenGood(TemplateProvider):
    """First answer lacks Java.perform; the retry (which carries validator errors) is correct."""

    def __init__(self):
        self.calls = 0
        self.seen_errors = None

    def generate(self, req):
        self.calls += 1
        good = super().generate(req)
        if self.calls == 1:
            return GenResult(js=good.js.replace("Java.perform", "Java.run"), raw="", model="x")
        self.seen_errors = req.errors
        return good


class AlwaysBroken(TemplateProvider):
    def generate(self, req):
        return GenResult(js="console.log('hi')", raw="", model="x")


def test_cases_and_skips(tmp_path):
    root = fake_mastg(tmp_path)
    cases, skipped = bench.load_cases(root)
    assert [c.demo_id for c in cases] == ["MASTG-DEMO-0007"]
    c = cases[0]
    assert c.class_name == "org.example.app.MastgTest" and c.ftype == FindingType.INSECURE_RANDOM
    assert c.title == "Common Uses of Insecure Random APIs"
    reasons = dict(skipped)
    assert "not found" in reasons["MASTG-DEMO-0017"] and "not found" in reasons["MASTG-DEMO-0054"]


def test_template_is_the_ceiling(tmp_path):
    cases, _ = bench.load_cases(fake_mastg(tmp_path))
    r = bench.run_bench(cases, TemplateProvider())[0]
    assert r.first_pass and r.final_ok and r.attempts == 1


def test_retry_is_counted_and_gets_the_validator_errors(tmp_path):
    cases, _ = bench.load_cases(fake_mastg(tmp_path))
    prov = BrokenThenGood()
    r = bench.run_bench(cases, prov)[0]
    assert not r.first_pass and r.final_ok and r.attempts == 2
    assert prov.seen_errors and "contains Java.perform" in prov.seen_errors[0]


def test_failure_is_reported_with_the_failing_checks(tmp_path):
    cases, _ = bench.load_cases(fake_mastg(tmp_path))
    results = bench.run_bench(cases, AlwaysBroken(), repeats=2)
    s = bench.summarize(results)
    assert s["runs"] == 2 and s["failed"] == 2 and s["final_rate"] == 0.0
    assert "contains Java.perform" in s["failed_checks"]
    md = bench.to_markdown("fake", "m", results, [], tmp_path)
    assert "0/2" in md and "Not redistributed" in md


def test_provider_errors_do_not_crash_the_run(tmp_path):
    class Boom(TemplateProvider):
        def generate(self, req):
            raise RuntimeError("503 from the model")

    cases, _ = bench.load_cases(fake_mastg(tmp_path))
    r = bench.run_bench(cases, Boom())[0]
    assert not r.final_ok and "503" in r.error


def test_unsupported_types_are_reported_as_coverage_gaps_when_the_demo_exists(tmp_path):
    root = fake_mastg(tmp_path)
    d = root / "demos" / "android" / "MASVS-NETWORK" / "MASTG-DEMO-0054"
    d.mkdir(parents=True)
    (d / "MastgTest_reversed.java").write_text(JAVA)
    cases, skipped = bench.load_cases(root)
    assert "not supported" in dict(skipped)["MASTG-DEMO-0054"]
    assert all(c.demo_id != "MASTG-DEMO-0054" for c in cases)
