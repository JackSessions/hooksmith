import json

import pytest

from hooksmith.models import Finding, FindingType, Verdict
from hooksmith.providers import GenRequest, template_hook
from hooksmith.signals import classify
from hooksmith.validator import validate_hook


def ev(**kw):
    return "HS|" + json.dumps(kw)


def f(t):
    return Finding(id="x", title="t", type=t, class_name="com.x.C", method="m")


CALL = ev(event="call")
TLS = FindingType.TLS_TRUST_ALL
HOST = FindingType.HOSTNAME_VERIFIER


def chain(accepted, self_signed=False, expired=False, subject="CN=badssl"):
    return ev(event="tls_chain", accepted=accepted, self_signed=self_signed, expired=expired, subject=subject)


def test_trust_all_proven_on_accepted_invalid_chain():
    o = classify(f(TLS), [CALL, chain(True, self_signed=True)], "")
    assert o.verdict == Verdict.PROVEN and "self-signed" in o.reason
    assert classify(f(TLS), [CALL, chain(True, expired=True)], "").verdict == Verdict.PROVEN


def test_trust_all_refuted_when_a_chain_was_rejected():
    assert classify(f(TLS), [CALL, chain(False, expired=True)], "").verdict == Verdict.REFUTED


def test_trust_all_is_honest_when_only_valid_chains_are_seen():
    o = classify(f(TLS), [CALL, chain(True)], "")
    assert o.verdict == Verdict.UNVALIDATED and "invalid certificate" in o.reason


def test_trust_all_unreachable_and_unreadable():
    assert classify(f(TLS), [ev(event="ready")], "").verdict == Verdict.UNREACHABLE
    assert classify(f(TLS), [CALL], "").verdict == Verdict.UNVALIDATED


def host(result, matches, h="wrong.host.example.com"):
    return ev(event="hostname", host=h, result=result, cert_matches=matches)


def test_hostname_verifier_verdicts():
    assert classify(f(HOST), [CALL, host(True, False)], "").verdict == Verdict.PROVEN
    assert classify(f(HOST), [CALL, host(False, False)], "").verdict == Verdict.REFUTED
    o = classify(f(HOST), [CALL, host(True, True, "good.example.com")], "")
    assert o.verdict == Verdict.UNVALIDATED and "mismatch" in o.reason
    assert classify(f(HOST), [CALL, host(True, None)], "").verdict == Verdict.UNVALIDATED
    # one accepted mismatch outweighs correct behaviour elsewhere
    assert classify(f(HOST), [CALL, host(False, False), host(True, False, "b.example.com")], "").verdict == Verdict.PROVEN


@pytest.mark.parametrize(
    "t,method,ov",
    [
        (TLS, "checkServerTrusted", ["[Ljava.security.cert.X509Certificate;", "java.lang.String"]),
        (TLS, "checkServerTrusted", None),
        (HOST, "verify", ["java.lang.String", "javax.net.ssl.SSLSession"]),
        (HOST, "verify", None),
    ],
)
def test_templates_pass_the_validator(t, method, ov):
    js = template_hook(GenRequest(finding_type=t, class_name="com.x.C", method=method, title="", source="", overload=ov))
    v = validate_hook(js, "com.x.C", method)
    assert v.ok, v.errors


def test_trust_all_template_rethrows_the_original_exception():
    js = template_hook(
        GenRequest(finding_type=TLS, class_name="com.x.C", method="checkServerTrusted", title="", source="", overload=[])
    )
    assert "throw e;" in js  # swallowing it would silently turn a strict manager into a trust-all one


def test_ingest_classifies_tls_findings():
    from hooksmith.ingest import classify_type

    assert classify_type("x", "Use of a TrustManager that Does Not Validate Certificate Chains") == TLS
    assert classify_type("x", "The HostnameVerifier that Allows Any Hostname") == HOST
    assert classify_type("x", "App uses cleartext HTTP traffic") == FindingType.CLEARTEXT_HTTP
