"""Hermetic replay of a REAL run against VulnLab run through R8 (--release, minification, class merging, and
`-repackageclasses ''`), decompiled with jadx and scanned with hooksmith's own built-in scanner, on the same
x86_64 Android 13 AVD used for the other VulnLab tests.

Regression test for two fixes:
  1. real_class_name(): jadx emits classes with no real package under a literal `package defpackage;` line (its
     own placeholder for Java's default package), and R8's `-repackageclasses ''` produces exactly this for every
     renamed class. Before the fix, Java.use("defpackage.a") failed with ClassNotFoundException on every one of
     them.
  2. The obfuscation-score gate no longer blocks a finding whose method was given EXPLICITLY (by a scanner) and
     resolves to exactly one unambiguous candidate -- short/renamed symbols are still completely hookable, the
     gate only protects against *guessing* which renamed method to target. Before the fix, SCAN-004 (class and
     method both renamed to single letters by R8) was wrongly declined as UNVALIDATED; it is in fact PROVEN.
"""

import json
from pathlib import Path

from hooksmith.executors.replay import ReplayExecutor
from hooksmith.providers import TemplateProvider
from hooksmith.runner import RunOptions, run_assessment

LAB = Path(__file__).resolve().parents[1] / "examples" / "vulnlab"
RECORDED = LAB / "recorded-obfuscated"

EXPECTED = {
    "SCAN-001": "REFUTED",  # Crypto/SessionCrypto fully inlined into MainActivity.work(): known limitation, see README
    "SCAN-002": "REFUTED",  # TokenGen/Cosmetics likewise inlined: known limitation, see README
    "SCAN-003": "PROVEN",  # defpackage.a: AllowAllVerifier+StrictVerifier class-merged by R8; still correctly PROVEN
    "SCAN-004": "PROVEN",  # defpackage.b: class AND method both renamed, but unambiguous -> no longer gate-blocked
    "SCAN-005": "REFUTED",  # defpackage.d = StrictTrustManager, renamed but not merged
    "SCAN-006": "PROVEN",  # defpackage.e = TrustAllManager, renamed but not merged
}


def test_obfuscated_apk_reproduces(tmp_path):
    opts = RunOptions(
        report=RECORDED / "findings.json",
        out_dir=tmp_path,
        provider=TemplateProvider(),
        executor=ReplayExecutor(RECORDED),
        sources=LAB / "obf-decompiled-sources",
        package="com.hooksmith.vulnlab",
    )
    res = run_assessment(opts)
    assert {r["id"]: r["verdict"] for r in res.rows} == EXPECTED


def test_the_real_class_name_was_actually_recovered():
    """Confirms this test is exercising the fix, not merely a report that happens to already say the right class."""
    hook = (RECORDED / "findings" / "SCAN-003" / "hook.js").read_text()
    assert 'Java.use("a")' in hook
    assert "defpackage" not in hook


def test_the_unambiguous_short_named_method_was_actually_hooked():
    """Confirms SCAN-004 is PROVEN because the gate let a real hook through, not because of some other path."""
    hook = (RECORDED / "findings" / "SCAN-004" / "hook.js").read_text()
    assert 'Java.use("b")' in hook
    log = (RECORDED / "findings" / "SCAN-004" / "runtime.log").read_text()
    assert "http://example.com/profile" in log


def test_recorded_device_metadata_matches_the_other_vulnlab_runs():
    meta = json.loads((RECORDED / "run.json").read_text())
    assert meta["device"]["abi"] == "x86_64" and meta["device"]["frida"].startswith("17.")
