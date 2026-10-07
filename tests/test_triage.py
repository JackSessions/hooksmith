from hooksmith.models import Finding, FindingType
from hooksmith.triage import triage


def f(id_, t, cls, method, sev="info"):
    return Finding(id=id_, title=id_, type=t, class_name=cls, method=method, severity=sev)


def test_exact_duplicates_merged_keeping_the_first():
    findings = [
        f("A", FindingType.HARDCODED_KEY, "com.x.C", "enc", "high"),
        f("B", FindingType.HARDCODED_KEY, "com.x.C", "enc", "high"),  # same type+class+method: a duplicate
        f("C", FindingType.CLEARTEXT_HTTP, "com.x.C", "enc", "high"),  # different TYPE, same target: not a duplicate
    ]
    r = triage(findings)
    assert [x.id for x in r.ordered] == ["A", "C"]
    assert r.duplicate_of == {"B": "A"}


def test_ordered_by_severity_critical_first_info_last():
    findings = [
        f("low1", FindingType.INSECURE_RANDOM, "a.A", "m", "low"),
        f("crit1", FindingType.TLS_TRUST_ALL, "b.B", "m", "critical"),
        f("high1", FindingType.HARDCODED_KEY, "c.C", "m", "high"),
        f("info1", FindingType.CLEARTEXT_HTTP, "d.D", "m", "info"),
    ]
    r = triage(findings)
    assert [x.id for x in r.ordered] == ["crit1", "high1", "low1", "info1"]


def test_equal_severity_keeps_original_relative_order():
    findings = [f("x", FindingType.HARDCODED_KEY, "a.A", "m", "high"), f("y", FindingType.CLEARTEXT_HTTP, "b.B", "m", "high")]
    assert [x.id for x in triage(findings).ordered] == ["x", "y"]


def test_no_duplicates_is_a_no_op_beyond_ordering():
    findings = [f("1", FindingType.HARDCODED_KEY, "a.A", "m"), f("2", FindingType.CLEARTEXT_HTTP, "b.B", "m")]
    r = triage(findings)
    assert r.duplicate_of == {} and len(r.ordered) == 2


def test_unknown_severity_sorts_last_like_info():
    findings = [
        f("weird", FindingType.HARDCODED_KEY, "a.A", "m", "nonsense"),
        f("normal", FindingType.CLEARTEXT_HTTP, "b.B", "m", "high"),
    ]
    assert [x.id for x in triage(findings).ordered] == ["normal", "weird"]
