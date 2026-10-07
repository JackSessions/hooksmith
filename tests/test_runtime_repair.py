"""The hook-writer loop must feed real on-device errors back to the model, once, and then give up honestly."""

import json

from hooksmith.executors.base import Executor, RunSpec
from hooksmith.models import ExecutionResult
from hooksmith.providers import GenRequest, TemplateProvider
from hooksmith.runner import RunOptions, run_assessment

GOOD_LOG = ['HS|{"event":"ready"}', 'HS|{"event":"call"}', 'HS|{"event":"url","url":"http://api.example.com/x"}']


class RecordingProvider(TemplateProvider):
    def __init__(self):
        self.requests: list[GenRequest] = []

    def generate(self, req):
        self.requests.append(req)
        return super().generate(req)


class FlakyDevice(Executor):
    """Fails the first N hook loads like Frida would, then behaves."""

    name = "fake"

    def __init__(self, failures: int, error="Error: java.lang.ClassNotFoundException: Didn't find class"):
        self.failures, self.error, self.runs = failures, error, 0

    def run(self, spec: RunSpec) -> ExecutionResult:
        self.runs += 1
        if self.runs <= self.failures:
            return ExecutionResult(attached=False, error=self.error, load_error=self.error)
        return ExecutionResult(attached=True, log=GOOD_LOG)


def run(demo, tmp_path, device, provider):
    rep = tmp_path / "f.json"
    rep.write_text(
        json.dumps(
            {
                "findings": [
                    {"id": "N1", "title": "http", "type": "cleartext_http", "class": "com.demo.net.LegacyApi", "method": "upload"}
                ]
            }
        )
    )
    o = RunOptions(
        report=rep,
        out_dir=tmp_path / "runs",
        provider=provider,
        executor=device,
        sources=demo / "sources",
        package="com.demo.vault",
    )
    return run_assessment(o)


def test_runtime_error_triggers_one_repair_then_proves(demo, tmp_path):
    prov, dev = RecordingProvider(), FlakyDevice(failures=1)
    res = run(demo, tmp_path, dev, prov)
    assert res.rows[0]["verdict"] == "PROVEN"
    assert dev.runs == 2 and len(prov.requests) == 2
    # the second request carried the real Frida error and the previous hook
    assert "on-device error from Frida" in prov.requests[1].errors[0] and "ClassNotFoundException" in prov.requests[1].errors[0]
    assert prov.requests[1].previous
    d = res.run_dir / "findings" / "N1"
    assert (d / "runtime.attempt1.log").exists() and (d / "hook.attempt2.js").exists()


def test_repair_is_bounded_and_failure_is_honest(demo, tmp_path):
    prov, dev = RecordingProvider(), FlakyDevice(failures=5)
    res = run(demo, tmp_path, dev, prov)
    row = res.rows[0]
    assert row["verdict"] == "UNVALIDATED" and "ClassNotFoundException" in row["reason"]
    assert dev.runs == 2  # one original + exactly one repair, never a loop
