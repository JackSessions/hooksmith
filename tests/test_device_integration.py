"""Real emulator test. Opt in:  HOOKSMITH_DEVICE_TESTS=1 uv run pytest tests/test_device_integration.py

Needs: `hooksmith avd setup`, `uv sync --extra device`, jadx, and examples/vulnlab/vulnlab.apk (run build.sh).
"""

import os
from pathlib import Path

import pytest

from hooksmith.providers import TemplateProvider
from hooksmith.runner import RunOptions, run_assessment

LAB = Path(__file__).resolve().parents[1] / "examples" / "vulnlab"
pytestmark = pytest.mark.skipif(os.environ.get("HOOKSMITH_DEVICE_TESTS") != "1", reason="set HOOKSMITH_DEVICE_TESTS=1")


def test_vulnlab_on_a_real_avd(tmp_path):
    from hooksmith.executors.avd import AvdExecutor

    apk = LAB / "vulnlab.apk"
    assert apk.exists(), "run examples/vulnlab/build.sh first"
    opts = RunOptions(
        report=LAB / "findings.json", out_dir=tmp_path, provider=TemplateProvider(), executor=AvdExecutor(), apk=apk, timeout_s=40
    )
    with opts.executor:
        res = run_assessment(opts)
    got = {r["id"]: r["verdict"] for r in res.rows}
    assert got == {
        "VL-1": "PROVEN",
        "VL-2": "REFUTED",
        "VL-3": "UNREACHABLE",
        "VL-4": "PROVEN",
        "VL-5": "REFUTED",
        "VL-6": "PROVEN",
        "VL-7": "REFUTED",
    }
