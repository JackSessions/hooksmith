"""The --record path, tested without a device: a fake executor stands in for the adb screen-recording leg."""

import json

from hooksmith.executors.base import Executor, RunSpec
from hooksmith.models import ExecutionResult
from hooksmith.providers import TemplateProvider
from hooksmith.runner import RunOptions, run_assessment
from hooksmith.store import Store


def test_store_save_screen_recording_moves_and_cleans_up(tmp_path):
    store = Store(tmp_path / "run")
    rec_dir = tmp_path / "temp-rec"
    rec_dir.mkdir()
    src = rec_dir / "screen.mp4"
    src.write_bytes(b"\x00\x01fake-mp4-bytes")

    dest = store.save_screen_recording("F1", src)

    assert dest == store.finding_dir("F1") / "screen.mp4"
    assert dest.read_bytes() == b"\x00\x01fake-mp4-bytes"
    assert not src.exists()
    assert not rec_dir.exists()  # the now-empty temp dir is cleaned up


def test_store_save_screen_recording_leaves_other_files_in_the_temp_dir(tmp_path):
    store = Store(tmp_path / "run")
    rec_dir = tmp_path / "temp-rec"
    rec_dir.mkdir()
    src = rec_dir / "screen.mp4"
    src.write_bytes(b"x")
    (rec_dir / "other.txt").write_text("not ours")

    store.save_screen_recording("F1", src)

    assert rec_dir.exists() and (rec_dir / "other.txt").exists()  # not deleted: wasn't actually empty


class RecordingAwareExecutor(Executor):
    """Stands in for AdbFridaExecutor: honours spec.record by setting res.screen, like a real pulled recording."""

    name = "fake"

    def __init__(self, rec_root):
        self.rec_root = rec_root
        self.calls: list[bool] = []

    def run(self, spec: RunSpec) -> ExecutionResult:
        self.calls.append(spec.record)
        res = ExecutionResult(
            attached=True, log=['HS|{"event":"ready"}', 'HS|{"event":"call"}', 'HS|{"event":"url","url":"http://a.example/x"}']
        )
        if spec.record:
            d = self.rec_root / f"rec-{spec.finding.id}"
            d.mkdir()
            p = d / "screen.mp4"
            p.write_bytes(b"fake-recording")
            res.screen = str(p)
        return res


def _opts(demo, tmp_path, executor, record):
    import json as _json

    report = tmp_path / "findings.json"
    report.write_text(
        _json.dumps(
            {
                "findings": [
                    {"id": "N1", "title": "http", "type": "cleartext_http", "class": "com.demo.net.LegacyApi", "method": "upload"}
                ]
            }
        )
    )
    return RunOptions(
        report=report,
        out_dir=tmp_path / "runs",
        provider=TemplateProvider(),
        executor=executor,
        sources=demo / "sources",
        package="com.demo.vault",
        record=record,
    )


def test_recording_is_pulled_into_evidence_when_requested(demo, tmp_path):
    ex = RecordingAwareExecutor(tmp_path / "device-side")
    (tmp_path / "device-side").mkdir()
    res = run_assessment(_opts(demo, tmp_path, ex, record=True))
    assert ex.calls == [True]
    d = res.run_dir / "findings" / "N1"
    assert (d / "screen.mp4").exists() and (d / "screen.mp4").read_bytes() == b"fake-recording"
    exec_json = json.loads((d / "execution.json").read_text())
    assert exec_json.get("screen") == "screen.mp4"  # the stable in-evidence name, not the now-deleted temp path


def test_recording_off_by_default_means_no_screen_mp4(demo, tmp_path):
    ex = RecordingAwareExecutor(tmp_path / "device-side")
    (tmp_path / "device-side").mkdir()
    res = run_assessment(_opts(demo, tmp_path, ex, record=False))
    assert ex.calls == [False]
    assert not (res.run_dir / "findings" / "N1" / "screen.mp4").exists()
