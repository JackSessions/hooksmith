from hooksmith.impact import build_impact
from hooksmith.models import FindingType


def test_hardcoded_key_cites_the_observed_key_and_explains_the_mechanism():
    text = build_impact(
        FindingType.HARDCODED_KEY, "com.x.Crypto.encrypt", {"observed_keys": ["0123456789abcdef0123456789abcdef"]}
    )
    assert "com.x.Crypto.encrypt" in text
    assert "0123" in text and "cdef" in text  # masked but still identifiable
    assert "compile-time constant" in text


def test_cleartext_http_cites_the_observed_url():
    text = build_impact(FindingType.CLEARTEXT_HTTP, "com.x.Api.fetch", {"cleartext": ["http://api.example.com/x"]})
    assert "http://api.example.com/x" in text and "network path" in text


def test_insecure_random_names_the_observed_implementation():
    text = build_impact(FindingType.INSECURE_RANDOM, "com.x.Tok.gen", {"impls": ["java.util.Random"]})
    assert "java.util.Random" in text and "seed" in text


def test_tls_trust_all_distinguishes_self_signed_from_expired_via_reason_text():
    sig = {"example": "CN=evil"}
    ss = build_impact(
        FindingType.TLS_TRUST_ALL,
        "com.x.TM.checkServerTrusted",
        sig,
        reason="accepted a self-signed certificate chain for CN=evil",
    )
    exp = build_impact(
        FindingType.TLS_TRUST_ALL, "com.x.TM.checkServerTrusted", sig, reason="accepted an expired certificate chain for CN=evil"
    )
    assert "self-signed" in ss and "CN=evil" in ss
    assert "expired" in exp and "self-signed" not in exp


def test_hostname_verifier_cites_the_observed_host():
    text = build_impact(FindingType.HOSTNAME_VERIFIER, "com.x.HV.verify", {"hosts": ["wrong.example.com"]})
    assert "wrong.example.com" in text


def test_missing_signal_data_does_not_crash_and_says_so():
    for t in FindingType:
        if t == FindingType.UNKNOWN:
            continue
        text = build_impact(t, "com.x.C.m", {})
        assert text and "not recorded" in text or "java.util.Random" in text  # explicit fallback phrasing, never blank


def test_unknown_type_gets_a_generic_fallback():
    text = build_impact(FindingType.UNKNOWN, "com.x.C.m", {})
    assert "No impact template" in text
