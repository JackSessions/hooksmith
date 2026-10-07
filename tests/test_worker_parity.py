"""The Worker (TypeScript) and the CLI (Python) must build byte-identical LLM prompts."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from hooksmith.models import FindingType
from hooksmith.prompts import build_messages, extract_js

WORKER = Path(__file__).resolve().parents[1] / "worker"
TSX = WORKER / "node_modules" / ".bin" / "tsx"

CASES = [
    dict(
        finding_type="hardcoded_key",
        class_name="com.x.Vault",
        method="encrypt",
        title="Hardcoded key",
        source='class A { String k = "x"; }',
        overload=["[B", "java.lang.String"],
        errors=None,
        previous=None,
    ),
    dict(
        finding_type="cleartext_http",
        class_name="com.x.Api",
        method="<init>",
        title="HTTP",
        source="line1\nline2 {{not_a_placeholder}}",
        overload=[],
        errors=None,
        previous=None,
    ),
    dict(
        finding_type="insecure_random",
        class_name="com.x.Tok$Inner",
        method="gen",
        title="Random",
        source="x",
        overload=None,
        errors=["contains Java.perform: no wrapper", "hooks the requested method: nope"],
        previous="old();",
    ),
    dict(
        finding_type="tls_trust_all",
        class_name="com.x.TM",
        method="checkServerTrusted",
        title="TLS",
        source="s",
        overload=["[Ljava.security.cert.X509Certificate;", "java.lang.String"],
        errors=None,
        previous=None,
    ),
    dict(
        finding_type="hostname_verifier",
        class_name="com.x.HV",
        method="verify",
        title="HV",
        source="s",
        overload=["java.lang.String", "javax.net.ssl.SSLSession"],
        errors=["x: y"],
        previous="p();",
    ),
    dict(finding_type="unknown", class_name="a.B", method="m", title="t", source="s", overload=None, errors=None, previous=None),
]


@pytest.mark.skipif(not TSX.exists() or not shutil.which("node"), reason="run `npm install` in worker/ first")
def test_prompts_identical():
    cases = [dict(c, raw="Sure\n```javascript\nvar a = 1;\n```\n") for c in CASES]
    out = subprocess.run(
        [str(TSX), "scripts/parity.ts"], cwd=WORKER, input=json.dumps(cases), capture_output=True, text=True, timeout=60
    )
    assert out.returncode == 0, out.stderr
    ts = json.loads(out.stdout)
    for c, t in zip(CASES, ts):
        py = build_messages(
            finding_type=FindingType(c["finding_type"]),
            class_name=c["class_name"],
            method=c["method"],
            title=c["title"],
            source=c["source"],
            overload=c["overload"],
            errors=c["errors"],
            previous=c["previous"],
        )
        assert t["messages"] == py, c["finding_type"]
        assert t["js"] == extract_js("Sure\n```javascript\nvar a = 1;\n```\n") == "var a = 1;"
