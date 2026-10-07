"""The swarm triage layer: a real LangGraph Send-based fan-out/fan-in subgraph, tested end to end (not mocked)."""

import json

from hooksmith.models import FindingType
from hooksmith.swarm import build_swarm_graph, is_own_code, is_vendor_package, priority_score, run_swarm_triage

REPORT = {
    "code_analysis": {
        "findings": {
            "android_hardcoded": {
                "files": {"com/app/Crypto.java": "12", "io/ably/lib/Keys.java": "8"},
                "metadata": {"description": "hardcoded encryption key", "severity": "high", "cwe": "CWE-312"},
            },
            "android_cleartext_http": {
                "files": {"com/app/Api.java": "4"},
                "metadata": {"description": "App uses cleartext HTTP traffic", "severity": "high", "cwe": "CWE-319"},
            },
            "android_webview_debuggable": {
                "files": {"com/app/Debug.java": "3"},
                "metadata": {"description": "This app has WebView debugging enabled.", "severity": "warning", "cwe": "CWE-919"},
            },
        }
    }
}


def test_vendor_detection():
    assert is_vendor_package("com.google.firebase.Messaging")
    assert is_vendor_package("io.ably.lib.rest.Auth")
    assert not is_vendor_package("com.myapp.Crypto")
    assert not is_vendor_package("")


def test_own_code_detection():
    assert is_own_code("com.myapp.feature.Crypto", "com.myapp.feature")
    assert not is_own_code("com.other.Thing", "com.myapp.feature")
    assert not is_own_code("com.myapp.Crypto", None)  # no package hint: can't claim it either way


def test_priority_prefers_severity_then_penalises_vendor():
    from hooksmith.models import Finding

    high = Finding(id="a", title="t", type=FindingType.HARDCODED_KEY, severity="high")
    warn = Finding(id="b", title="t", type=FindingType.HARDCODED_KEY, severity="warning")
    assert priority_score(high, vendor_likely=False) < priority_score(warn, vendor_likely=False)
    assert priority_score(high, vendor_likely=True) > priority_score(high, vendor_likely=False)


def test_graph_builds_and_has_the_fan_out_shape():
    app = build_swarm_graph()
    nodes = set(app.get_graph().nodes)
    assert {"classify_one", "merge"} <= nodes


def test_run_swarm_triage_classifies_filters_and_annotates(tmp_path):
    p = tmp_path / "mobsf.json"
    p.write_text(json.dumps(REPORT))
    r = run_swarm_triage(p, package="com.app")

    by_class = {f.class_name: f for f in r.findings}
    assert set(by_class) == {"com.app.Crypto", "io.ably.lib.Keys", "com.app.Api"}
    assert by_class["com.app.Crypto"].type == FindingType.HARDCODED_KEY
    assert by_class["com.app.Crypto"].raw["own_code_likely"] is True
    assert by_class["com.app.Crypto"].raw["vendor_likely"] is False
    assert by_class["io.ably.lib.Keys"].raw["vendor_likely"] is True
    assert by_class["io.ably.lib.Keys"].raw["own_code_likely"] is False

    # the unknown-type finding (WebView debug flag) is filtered OUT of the testable set, not silently dropped
    assert len(r.findings) == 3
    assert len(r.skipped) == 1 and r.skipped[0]["class"] == "com.app.Debug"
    assert (
        r.vendor_count == 1 and r.own_code_count == 3
    )  # includes the skipped com.app.Debug: it IS own code, just not a testable type


def test_own_code_high_severity_sorts_ahead_of_vendor_warning(tmp_path):
    p = tmp_path / "mobsf.json"
    p.write_text(json.dumps(REPORT))
    r = run_swarm_triage(p, package="com.app")
    # equal severity (all "high" in this fixture): vendor-penalised priority must still place the vendor finding
    # last among equals, even though it was declared before com.app.Api in the raw MobSF report.
    classes_in_order = [f.class_name for f in r.findings]
    assert classes_in_order.index("com.app.Crypto") < classes_in_order.index("io.ably.lib.Keys")
    assert classes_in_order.index("com.app.Api") < classes_in_order.index("io.ably.lib.Keys")


def test_empty_report_does_not_crash(tmp_path):
    p = tmp_path / "empty.json"
    p.write_text(json.dumps({"code_analysis": {"findings": {}}}))
    r = run_swarm_triage(p, package="com.app")
    assert r.findings == [] and r.skipped == []


def test_no_package_hint_still_classifies(tmp_path):
    p = tmp_path / "mobsf.json"
    p.write_text(json.dumps(REPORT))
    r = run_swarm_triage(p, package=None)
    assert len(r.findings) == 3
    assert all(f.raw["own_code_likely"] is False for f in r.findings)  # can't claim own-code with no package hint


def test_own_code_two_segment_package_does_not_match_everything():
    # com.app's generalised root would be a bare "com", which must NOT match arbitrary other orgs' classes
    assert not is_own_code("com.otherorg.Thing", "com.app")
    assert is_own_code("com.app.feature.Thing", "com.app")  # exact subpackage still matches


def test_own_code_three_segment_package_generalises_one_level():
    assert is_own_code("com.realshape.other.Thing", "com.realshape.app")  # sibling subpackage: still "ours"
    assert not is_own_code("com.different.Thing", "com.realshape.app")
