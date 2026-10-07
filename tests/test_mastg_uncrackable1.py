"""Hermetic replay of a REAL run against OWASP MASTG's UnCrackable-Level1.apk, a well-known crackme shipped
directly in the MASTG repo (Crackmes/Android/Level_01/) -- the "live demo on a real MASTG app" promised in the
SINCON talk, not just the project's own VulnLab.

Regression test for the two fixes that made this PROVEN possible:
  1. javasrc.py: a method sharing its enclosing class's simple name (`class a { static byte[] a(...) {...} }`,
     real code in this APK) was being misparsed as a constructor and renamed to "<init>", so the hook targeted
     the wrong thing entirely.
  2. The obfuscation gate no longer blocks an explicitly-named, unambiguous method just because its (real, not
     R8-renamed -- this app is simply terse) name is short.
  3. signals.hardcoded_key falls back to searching the whole decompiled tree: the actual key constant lives in
     the CALLER (sg.vantagepoint.uncrackable1.a), not in the generic AES helper we hook
     (sg.vantagepoint.a.a) -- a very common real-world pattern.
"""

import json
from pathlib import Path

from hooksmith.executors.replay import ReplayExecutor
from hooksmith.providers import TemplateProvider
from hooksmith.runner import RunOptions, run_assessment

APP = Path(__file__).resolve().parents[1] / "examples" / "mastg-uncrackable1"
RECORDED = APP / "recorded"


def test_uncrackable1_hardcoded_key_is_proven(tmp_path):
    opts = RunOptions(
        report=RECORDED / "findings.json" if (RECORDED / "findings.json").exists() else APP / "findings.json",
        out_dir=tmp_path,
        provider=TemplateProvider(),
        executor=ReplayExecutor(RECORDED),
        sources=APP / "decompiled",
        package="owasp.mstg.uncrackable1",
    )
    res = run_assessment(opts)
    assert {r["id"]: r["verdict"] for r in res.rows} == {"SCAN-001": "PROVEN"}


def test_the_real_method_was_hooked_not_a_misparsed_constructor():
    hook = (RECORDED / "findings" / "SCAN-001" / "hook.js").read_text()
    assert 'Java.use("sg.vantagepoint.a.a")' in hook
    # the TARGET method must be hooked by its real name "a" (`C.a.overload(...)`), not folded into a constructor.
    # ($init does legitimately appear elsewhere in this hook, for the unrelated SecretKeySpec constructor watch.)
    assert "C.a.overload(" in hook


def test_the_observed_key_matches_the_apks_actual_hardcoded_string():
    log = (RECORDED / "findings" / "SCAN-001" / "runtime.log").read_text()
    assert "8d127684cbc37c17616d806cf50473cc" in log  # the real key, straight from the decompiled source


def test_the_key_constant_was_found_in_the_calling_class():
    verdict = json.loads((RECORDED / "findings" / "SCAN-001" / "verdict.json").read_text())
    assert verdict["signal"]["matched_constant"]["file"] == "sg/vantagepoint/uncrackable1/a.java"


def test_recorded_device_metadata():
    meta = json.loads((RECORDED / "run.json").read_text())
    assert meta["device"]["abi"] == "x86_64" and meta["device"]["frida"].startswith("17.")
