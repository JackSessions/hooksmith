import json

from hooksmith.ingest import classify_type, from_mobsf, load_findings, path_to_class
from hooksmith.models import FindingType


def test_path_to_class():
    assert path_to_class("sources/com/a/B.java") == "com.a.B"
    assert path_to_class("com/a/B.kt") == "com.a.B"


def test_classify():
    assert classify_type("android_hardcoded", "") == FindingType.HARDCODED_KEY
    assert classify_type("x", "The App uses an insecure Random Number Generator.") == FindingType.INSECURE_RANDOM
    assert classify_type("x", "App uses cleartext HTTP traffic") == FindingType.CLEARTEXT_HTTP
    assert classify_type("x", "something else") == FindingType.UNKNOWN


def test_mobsf_nested_and_flat():
    body = {"files": {"com/a/B.java": "3,9"}, "metadata": {"description": "hardcoded key", "severity": "high"}}
    nested = {"code_analysis": {"findings": {"r1": body}}}
    flat = {"code_analysis": {"r1": body}}
    for rep in (nested, flat):
        fs = from_mobsf(rep)
        assert len(fs) == 1 and fs[0].class_name == "com.a.B" and fs[0].lines == [3, 9]
        assert fs[0].type == FindingType.HARDCODED_KEY


def test_native_format(tmp_path):
    p = tmp_path / "f.json"
    p.write_text(json.dumps({"findings": [{"id": "A", "title": "t", "type": "cleartext_http", "class": "a.B", "method": "go"}]}))
    f = load_findings(p)[0]
    assert (f.id, f.class_name, f.method, f.type) == ("A", "a.B", "go", FindingType.CLEARTEXT_HTTP)


def test_unrecognised_report(tmp_path):
    import pytest

    p = tmp_path / "x.json"
    p.write_text("{}")
    with pytest.raises(ValueError):
        load_findings(p)
