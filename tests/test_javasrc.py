from hooksmith import javasrc as j

SRC = """package a.b;
import javax.crypto.spec.SecretKeySpec;
import java.util.List;
public class V {
    private static final String KEY = "0123456789abcdef";
    private static final byte[] RAW = new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    public V() { }
    public byte[] enc(byte[] d, String s) throws Exception { if (d == null) { return null; } return d; }
    public native int nat(int x);
    public byte[] k() { return new SecretKeySpec(RAW, "AES").getEncoded(); }
    void over(int a) { }
    void over(String a, List<String> b) { }
}
"""


def test_methods_and_native():
    jc = j.parse_class("a.b.V", SRC)
    names = [m.name for m in jc.methods]
    assert "enc" in names and "<init>" in names
    assert jc.find("nat")[0].is_native
    assert len(jc.find("over")) == 2
    assert jc.find("enc")[0].params == ["byte[]", "String"]


def test_constants():
    keys = j.key_constants(SRC)
    assert ("string", b"0123456789abcdef") in keys
    assert any(o == "bytes" and v == bytes(range(1, 17)) for o, v in keys)


def test_overload_types():
    jc = j.parse_class("a.b.V", SRC)
    assert j.overload_types(jc.find("enc")[0], SRC) == ["[B", "java.lang.String"]
    assert j.overload_types(jc.find("over", 2)[0], SRC) == ["java.lang.String", "java.util.List"]


def test_locate_by_pattern_and_by_line():
    jc = j.parse_class("a.b.V", SRC)
    assert j.locate_method(jc, "hardcoded_key").name == "k"
    line = SRC[: jc.find("enc")[0].start].count("\n") + 1
    assert j.locate_method(jc, "hardcoded_key", [line]).name == "enc"


def test_obfuscation_score_normal_vs_renamed():
    normal = j.obfuscation_score("com.demo.auth.TokenGen", "class TokenGen { String newToken(){ int i=0; return null; } }")
    renamed = j.obfuscation_score("a.b.c", "class c { void a(){} int b(){return 1;} void c(){} }")
    assert normal < 0.3 < 0.6 < renamed


def test_real_class_name_default_package_strips_placeholder_folder():
    # exactly the R8 `-repackageclasses ''` + jadx "defpackage/a.java" case that broke Java.use() on a real device
    src = "public final class a implements javax.net.ssl.HostnameVerifier {\n    public final boolean verify(String s, javax.net.ssl.SSLSession e) { return true; }\n}\n"
    assert j.real_class_name(src, "defpackage.a") == "a"


def test_real_class_name_normal_package_is_unaffected():
    src = "package com.x.y;\npublic final class Foo {\n}\n"
    assert j.real_class_name(src, "com.x.y.Foo") == "com.x.y.Foo"


def test_real_class_name_trusts_source_over_a_wrong_path_guess():
    # the source is the ground truth; a mismatched file-path-derived name must not be trusted
    src = "package com.real.pkg;\npublic final class Real {\n}\n"
    assert j.real_class_name(src, "defpackage.whatever") == "com.real.pkg.Real"


def test_real_class_name_inner_class_keeps_the_given_simple_name():
    src = "package com.x;\npublic final class Outer {\n}\n"  # the inner class's own decl isn't at top level
    assert j.real_class_name(src, "com.x.Outer$Inner") == "com.x.Outer"  # best effort: outer's real name + pkg


def test_real_class_name_falls_back_when_no_declaration_found():
    assert j.real_class_name("garbage, not java", "defpackage.a") == "defpackage.a"


def test_method_sharing_the_class_name_is_not_mistaken_for_a_constructor():
    # Real bug, found on OWASP MASTG's UnCrackable-Level1.apk: a jadx-obfuscated class named "a" containing a
    # regular static method ALSO named "a" (valid Java: it has a return type, so it isn't a constructor).
    src = """package sg.vantagepoint.a;
public class a {
    public static byte[] a(byte[] bArr, byte[] bArr2) throws Exception {
        return bArr2;
    }
}
"""
    jc = j.parse_class("sg.vantagepoint.a.a", src)
    names = [m.name for m in jc.methods]
    assert "a" in names and "<init>" not in names
    assert jc.find("a")[0].params == ["byte[]", "byte[]"]


def test_a_genuine_constructor_sharing_the_class_name_is_still_detected():
    src = """package sg.vantagepoint.a;
public class a {
    public a(byte[] bArr) {
    }
}
"""
    jc = j.parse_class("sg.vantagepoint.a.a", src)
    names = [m.name for m in jc.methods]
    assert "<init>" in names and "a" not in names
    assert jc.find("<init>")[0].params == ["byte[]"]
