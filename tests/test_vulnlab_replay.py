"""Hermetic replay of a REAL run: logs recorded from VulnLab on an x86_64 Android 13 emulator with Frida 17.22."""

from pathlib import Path

import pytest

from hooksmith.executors.replay import ReplayExecutor
from hooksmith.providers import TemplateProvider
from hooksmith.runner import RunOptions, run_assessment

LAB = Path(__file__).resolve().parents[1] / "examples" / "vulnlab"

EXPECTED = {
    "VL-1": "PROVEN",
    "VL-2": "REFUTED",
    "VL-3": "UNREACHABLE",
    "VL-4": "PROVEN",
    "VL-5": "REFUTED",
    "VL-6": "PROVEN",
    "VL-7": "REFUTED",
    "VL-8": "PROVEN",
    "VL-9": "REFUTED",
    "VL-10": "PROVEN",
    "VL-11": "REFUTED",
}


def test_recorded_device_run_reproduces(tmp_path):
    opts = RunOptions(
        report=LAB / "findings.json",
        out_dir=tmp_path,
        provider=TemplateProvider(),
        executor=ReplayExecutor(LAB / "recorded"),
        sources=LAB / "decompiled",
        package="com.hooksmith.vulnlab",
    )
    res = run_assessment(opts)
    assert {r["id"]: r["verdict"] for r in res.rows} == EXPECTED


def test_generated_hooks_match_what_ran_on_the_device():
    """The template hooks must be byte-identical to the ones that produced the recorded logs."""
    from hooksmith.decompile import resolve
    from hooksmith.ingest import load_findings
    from hooksmith.providers import GenRequest, overload_for, trim_source

    for f in load_findings(LAB / "findings.json"):
        r = resolve(f, LAB / "decompiled" / "sources")
        req = GenRequest(
            finding_type=f.type,
            class_name=f.class_name,
            method=r.method_name,
            title=f.title,
            source=trim_source(r.java_class, r.method),
            overload=overload_for(r.java_class, r.method),
        )
        ran = (LAB / "recorded" / "findings" / f.id / "hook.js").read_text()
        assert TemplateProvider().generate(req).js == ran, f.id


@pytest.mark.skipif(not (LAB / "recorded" / "run.json").exists(), reason="recorded evidence missing")
def test_recorded_run_metadata_is_present():
    import json

    meta = json.loads((LAB / "recorded" / "run.json").read_text())
    assert meta["device"]["abi"] == "x86_64" and meta["device"]["frida"].startswith("17.")
