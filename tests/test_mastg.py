from hooksmith.mastg import for_type, markdown_links
from hooksmith.models import FindingType


def test_every_hookable_type_has_at_least_one_reference():
    for t in (
        FindingType.HARDCODED_KEY,
        FindingType.CLEARTEXT_HTTP,
        FindingType.INSECURE_RANDOM,
        FindingType.TLS_TRUST_ALL,
        FindingType.HOSTNAME_VERIFIER,
    ):
        refs = for_type(t)
        assert refs, t


def test_test_urls_include_the_masvs_category_segment():
    r = for_type(FindingType.HARDCODED_KEY)[0]
    assert r.kind == "test"
    assert r.url == "https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0013/"


def test_demo_urls_double_the_id_segment():
    demo = next(r for r in for_type(FindingType.HARDCODED_KEY) if r.kind == "demo")
    assert demo.id == "MASTG-DEMO-0017"
    assert demo.url == "https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0017/MASTG-DEMO-0017/"


def test_unknown_type_has_no_references():
    assert for_type(FindingType.UNKNOWN) == []
    assert "no MASTG cross-reference" in markdown_links(FindingType.UNKNOWN)


def test_markdown_links_render_as_a_list():
    md = markdown_links(FindingType.TLS_TRUST_ALL)
    assert "MASTG-TEST-0020" in md and "MASTG-TEST-0021" in md and md.startswith("-")
