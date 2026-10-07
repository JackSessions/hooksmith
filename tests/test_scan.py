from hooksmith.models import FindingType
from hooksmith.scan import _is_noise, scan_sources, to_native_report

TRUST_ALL = """package com.x;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;
public class Evil implements X509TrustManager {
    public void checkClientTrusted(X509Certificate[] c, String a) {}
    public void checkServerTrusted(X509Certificate[] c, String a) {}
    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
}
"""

HOSTNAME = """package com.x;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
public class EvilHV implements HostnameVerifier {
    public boolean verify(String host, SSLSession s) { return true; }
}
"""

KEY = """package com.x;
import javax.crypto.spec.SecretKeySpec;
public class Crypto {
    private static final String K = "0123456789abcdef";
    public void enc(byte[] d) {
        SecretKeySpec s = new SecretKeySpec(K.getBytes(), "AES");
        Cipher c = Cipher.getInstance("AES");
    }
}
"""

RANDOM = """package com.x;
import java.util.Random;
public class TokenGen {
    public String go() { Random r = new Random(); return Integer.toString(r.nextInt(10)); }
}
"""

CLEAN = """package com.x;
public class Nothing {
    public int add(int a, int b) { return a + b; }
}
"""

NOISE = """package androidx.core.app;
import java.util.Random;
public class NotificationCompat {
    public int go() { return new Random().nextInt(10); }
}
"""


def write(tmp_path, rel, content):
    p = tmp_path / "sources" / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)


def test_finds_each_type_and_skips_clean_and_noise(tmp_path):
    write(tmp_path, "com/x/Evil.java", TRUST_ALL)
    write(tmp_path, "com/x/EvilHV.java", HOSTNAME)
    write(tmp_path, "com/x/Crypto.java", KEY)
    write(tmp_path, "com/x/TokenGen.java", RANDOM)
    write(tmp_path, "com/x/Nothing.java", CLEAN)
    write(tmp_path, "androidx/core/app/NotificationCompat.java", NOISE)
    found = {(f.type, f.class_name, f.method) for f in scan_sources(tmp_path)}
    assert found == {
        (FindingType.TLS_TRUST_ALL, "com.x.Evil", "checkServerTrusted"),
        (FindingType.HOSTNAME_VERIFIER, "com.x.EvilHV", "verify"),
        (FindingType.HARDCODED_KEY, "com.x.Crypto", "enc"),
        (FindingType.INSECURE_RANDOM, "com.x.TokenGen", "go"),
    }


def test_noise_packages_excluded_by_default_but_includable(tmp_path):
    write(tmp_path, "androidx/core/app/NotificationCompat.java", NOISE)
    assert scan_sources(tmp_path) == []
    found = scan_sources(tmp_path, include_test_classes=True)
    assert len(found) == 1 and found[0].class_name == "androidx.core.app.NotificationCompat"


def test_is_noise():
    assert _is_noise("androidx.core.app.Foo")
    assert _is_noise("kotlin.jvm.internal.Intrinsics")
    assert not _is_noise("com.hooksmith.vulnlab.Crypto")


def test_inner_classes_skipped_outer_classes_scanned(tmp_path):
    write(tmp_path, "com/x/Outer.java", KEY)
    write(tmp_path, "com/x/Outer$Inner.java", KEY)
    found = scan_sources(tmp_path)
    assert len(found) == 1 and found[0].class_name == "com.x.Outer"


def test_ids_are_stable_and_sequential(tmp_path):
    write(tmp_path, "com/x/A.java", KEY)
    write(tmp_path, "com/x/B.java", RANDOM)
    found = scan_sources(tmp_path)
    assert [f.id for f in found] == ["SCAN-001", "SCAN-002"]


def test_native_method_is_not_flagged(tmp_path):
    native_key = KEY.replace("public void enc(byte[] d) {", "public native void enc(byte[] d);").replace(
        'SecretKeySpec s = new SecretKeySpec(K.getBytes(), "AES");\n        Cipher c = Cipher.getInstance("AES");\n    }', ""
    )
    write(tmp_path, "com/x/Native.java", native_key)
    assert scan_sources(tmp_path) == []


def test_to_native_report_round_trips_through_ingest(tmp_path):
    from hooksmith.ingest import from_native

    write(tmp_path, "com/x/Crypto.java", KEY)
    findings = scan_sources(tmp_path)
    report = to_native_report(findings)
    assert report["findings"][0]["class"] == "com.x.Crypto"
    back = from_native(report)
    assert [f.id for f in back] == [f.id for f in findings]
    assert back[0].type == FindingType.HARDCODED_KEY


def test_sources_dir_or_bare_root_both_work(tmp_path):
    write(tmp_path, "com/x/Crypto.java", KEY)  # writes under tmp_path/sources/...
    assert len(scan_sources(tmp_path)) == 1
    bare = tmp_path / "bare"
    (bare / "com" / "x").mkdir(parents=True)
    (bare / "com" / "x" / "Crypto.java").write_text(KEY)
    assert len(scan_sources(bare)) == 1


def test_cli_scan_command_end_to_end(tmp_path):
    from click.testing import CliRunner

    from hooksmith.cli import main

    write(tmp_path, "com/x/Crypto.java", KEY)
    out = tmp_path / "findings.json"
    res = CliRunner().invoke(main, ["scan", "--apk", str(_dummy_apk(tmp_path)), "--sources", str(tmp_path), "--out", str(out)])
    assert res.exit_code == 0, res.output
    assert out.exists() and "com.x.Crypto" in out.read_text()
    assert "candidate finding" in res.output


def test_cli_scan_reports_nothing_found(tmp_path):
    from click.testing import CliRunner

    from hooksmith.cli import main

    write(tmp_path, "com/x/Nothing.java", CLEAN)
    res = CliRunner().invoke(
        main, ["scan", "--apk", str(_dummy_apk(tmp_path)), "--sources", str(tmp_path), "--out", str(tmp_path / "f.json")]
    )
    assert res.exit_code == 0 and "no candidate findings" in res.output


def _dummy_apk(tmp_path):
    p = tmp_path / "app.apk"
    p.write_bytes(b"PK\x03\x04")  # scan never opens the APK when --sources is given; it just needs to exist
    return p
