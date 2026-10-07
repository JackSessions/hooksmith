from hooksmith.models import Finding, FindingType, Verdict
from hooksmith.signals import classify


def f(t, method="m", cls="com.x.C"):
    return Finding(id="x", title="t", type=t, class_name=cls, method=method)


def ev(**kw):
    import json

    return "HS|" + json.dumps(kw)


SRC = 'class C { static final String K = "0123456789abcdef"; }'
KEY = b"0123456789abcdef".hex()


def test_unreachable_when_nothing_fires():
    o = classify(f(FindingType.HARDCODED_KEY), [ev(event="ready"), "noise"], SRC)
    assert o.verdict == Verdict.UNREACHABLE


def test_key_proven_refuted_unvalidated():
    call = ev(event="call")
    assert classify(f(FindingType.HARDCODED_KEY), [call, ev(event="key", hex=KEY)], SRC).verdict == Verdict.PROVEN
    assert (
        classify(
            f(FindingType.HARDCODED_KEY), [call, ev(event="key", hex=KEY), call, ev(event="key", hex="aa" * 16)], SRC
        ).verdict
        == Verdict.REFUTED
    )
    assert classify(f(FindingType.HARDCODED_KEY), [call, ev(event="key", hex="bb" * 16)], SRC).verdict == Verdict.UNVALIDATED
    assert classify(f(FindingType.HARDCODED_KEY), [call], SRC).verdict == Verdict.UNVALIDATED


def test_key_matches_base64_and_byte_array_constants():
    import base64

    raw = bytes(range(32))
    src = f'class C {{ static final String K = "{base64.b64encode(raw).decode()}"; }}'
    assert (
        classify(f(FindingType.HARDCODED_KEY), [ev(event="call"), ev(event="key", hex=raw.hex())], src).verdict == Verdict.PROVEN
    )
    src2 = "class C { byte[] K = new byte[]{" + ",".join(map(str, range(16))) + "}; }"
    assert (
        classify(f(FindingType.HARDCODED_KEY), [ev(event="call"), ev(event="key", hex=bytes(range(16)).hex())], src2).verdict
        == Verdict.PROVEN
    )


def test_http():
    call = ev(event="call")
    t = FindingType.CLEARTEXT_HTTP
    assert classify(f(t), [call, ev(event="url", url="http://api.example.com/x")], "").verdict == Verdict.PROVEN
    assert classify(f(t), [call, ev(event="url", url="https://api.example.com/x")], "").verdict == Verdict.REFUTED
    assert classify(f(t), [call, ev(event="url", url="http://localhost:8080/x")], "").verdict == Verdict.REFUTED
    assert classify(f(t), [call], "").verdict == Verdict.REFUTED


def test_random_context_uses_identifier_words_not_substrings():
    t = FindingType.INSECURE_RANDOM
    rnd = [ev(event="call"), ev(event="random", impl="java.util.Random")]
    assert classify(f(t, "newSessionToken"), rnd, "").verdict == Verdict.PROVEN
    assert classify(f(t, "generate_api_key"), rnd, "").verdict == Verdict.PROVEN
    # 'ping', 'monkey', 'design' contain 'pin'/'key'/'sign' as substrings: must NOT count
    assert classify(f(t, "pingServer", cls="com.x.Monkey"), rnd, "").verdict == Verdict.REFUTED
    # package names must not count
    assert classify(f(t, "color", cls="com.x.auth.Confetti"), rnd, "").verdict == Verdict.REFUTED
    secure = [ev(event="call"), ev(event="random", impl="java.security.SecureRandom")]
    assert classify(f(t, "newToken"), secure, "").verdict == Verdict.REFUTED


def test_garbage_lines_are_ignored():
    assert classify(f(FindingType.CLEARTEXT_HTTP), ["HS|{not json", "HS|[1]", "hello"], "").verdict == Verdict.UNREACHABLE


def test_argument_buffer_is_not_mistaken_for_a_key():
    # plaintext that happens to be 16 bytes must not be read as the key when SecretKeySpec reported the real one
    plain = ev(event="key", hex=("41" * 16), via="argument")
    real = ev(event="key", hex=KEY, algorithm="AES")
    o = classify(f(FindingType.HARDCODED_KEY), [ev(event="call"), plain, real], SRC)
    assert o.verdict == Verdict.PROVEN and o.signal["observed_keys"] == [KEY]
    # with no SecretKeySpec event, the argument is the only candidate and is still used
    o2 = classify(f(FindingType.HARDCODED_KEY), [ev(event="call"), ev(event="key", hex=KEY, via="argument")], SRC)
    assert o2.verdict == Verdict.PROVEN


def test_unreachable_reason_does_not_count_protocol_lines():
    o = classify(f(FindingType.HARDCODED_KEY), [ev(event="ready")], SRC)
    assert o.verdict == Verdict.UNREACHABLE and "unrelated" not in o.reason
    o = classify(f(FindingType.HARDCODED_KEY), [ev(event="ready"), "some app noise"], SRC)
    assert "1 unrelated" in o.reason


def test_hardcoded_key_falls_back_to_searching_other_decompiled_classes(tmp_path):
    """Real case, found on OWASP MASTG's UnCrackable-Level1.apk: a shared crypto helper takes the key as a
    parameter, and the actual key constant is declared in a DIFFERENT class that calls it.
    """
    sources = tmp_path / "sources"
    (sources / "sg" / "vantagepoint" / "a").mkdir(parents=True)
    (sources / "sg" / "vantagepoint" / "uncrackable1").mkdir(parents=True)
    hooked_src = "package sg.vantagepoint.a;\npublic class a {\n  public static byte[] a(byte[] k, byte[] d) { return d; }\n}\n"
    (sources / "sg" / "vantagepoint" / "a" / "a.java").write_text(hooked_src)
    caller_src = (
        "package sg.vantagepoint.uncrackable1;\npublic class a {\n"
        '  static final String KEY = "0123456789abcdef0123456789abcdef";\n'
        "}\n"
    )
    (sources / "sg" / "vantagepoint" / "uncrackable1" / "a.java").write_text(caller_src)

    finding = Finding(id="x", title="t", type=FindingType.HARDCODED_KEY, class_name="sg.vantagepoint.a.a", method="a")
    key_hex = bytes.fromhex("0123456789abcdef0123456789abcdef").hex()
    log = [ev(event="call"), ev(event="key", hex=key_hex)]

    without_root = classify(finding, log, hooked_src)
    assert without_root.verdict == Verdict.UNVALIDATED  # the narrow, single-class search alone still finds nothing

    with_root = classify(finding, log, hooked_src, sources_root=sources)
    assert with_root.verdict == Verdict.PROVEN
    assert with_root.signal["matched_constant"]["file"] == "sg/vantagepoint/uncrackable1/a.java"


def test_hardcoded_key_tree_search_does_not_rematch_the_hooked_class_itself(tmp_path):
    sources = tmp_path / "sources"
    sources.mkdir()
    hooked_src = 'public class C { static final String K = "aabbccddeeff00112233445566778899"; }'
    (sources / "C.java").write_text(hooked_src)
    finding = Finding(id="x", title="t", type=FindingType.HARDCODED_KEY, class_name="C", method="m")
    log = [ev(event="call"), ev(event="key", hex="ffeeddccbbaa99887766554433221100")]
    # the hooked class's own key doesn't match the observed one, and there's nothing else in the tree
    o = classify(finding, log, hooked_src, sources_root=sources)
    assert o.verdict == Verdict.UNVALIDATED


def test_hardcoded_key_prefers_the_narrow_match_without_needing_the_tree_search(tmp_path):
    sources = tmp_path / "sources"
    sources.mkdir()
    src = 'public class C { static final String K = "0123456789abcdef"; }'
    (sources / "C.java").write_text(src)
    finding = Finding(id="x", title="t", type=FindingType.HARDCODED_KEY, class_name="C", method="m")
    log = [ev(event="call"), ev(event="key", hex=KEY)]
    o = classify(finding, log, src, sources_root=sources)
    assert o.verdict == Verdict.PROVEN and o.signal["matched_constant"]["file"] == "(hooked class)"
