"""OWASP MASTG cross-references for each finding type.

Verified against an OWASP MASTG checkout, not guessed: each MASTG-TEST id below was grepped for the actual API
names this finding type's signal watches for (SecretKeySpec, TrustManager, HostnameVerifier, ...), and each
MASTG-DEMO id is a worked example HookSmith's own `bench` command runs against (see bench.py's DEMO_TYPES). The
URLs are the live mas.owasp.org pattern, checked by fetching one of each kind (not guessed): tests resolve at
`/tests/android/<category>/<id>/`; demos resolve at `/demos/android/<category>/<id>/<id>/` (the id doubled, matching
the repo's `demos/android/<category>/<id>/<id>.md` layout).

MASTG (https://github.com/OWASP/mastg) is CC BY-SA 4.0: these are references (id, title, URL), not copied text.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import FindingType

BASE = "https://mas.owasp.org/MASTG"


@dataclass(frozen=True)
class MastgRef:
    id: str
    title: str
    kind: str  # "test" (methodology) or "demo" (worked example)
    category: str  # e.g. "MASVS-CRYPTO"

    @property
    def url(self) -> str:
        if self.kind == "test":
            return f"{BASE}/tests/android/{self.category}/{self.id}/"
        return f"{BASE}/demos/android/{self.category}/{self.id}/{self.id}/"


REFERENCES: dict[FindingType, list[MastgRef]] = {
    FindingType.HARDCODED_KEY: [
        MastgRef("MASTG-TEST-0013", "Testing Symmetric Cryptography", "test", "MASVS-CRYPTO"),
        MastgRef("MASTG-TEST-0015", "Testing the Purposes of Keys", "test", "MASVS-CRYPTO"),
        MastgRef("MASTG-DEMO-0017", "Use of Hardcoded AES Key in SecretKeySpec", "demo", "MASVS-CRYPTO"),
    ],
    FindingType.INSECURE_RANDOM: [
        MastgRef("MASTG-TEST-0016", "Testing Random Number Generation", "test", "MASVS-CRYPTO"),
        MastgRef("MASTG-DEMO-0007", "Common Uses of Insecure Random APIs", "demo", "MASVS-CRYPTO"),
    ],
    FindingType.CLEARTEXT_HTTP: [
        MastgRef("MASTG-TEST-0019", "Testing Data Encryption on the Network", "test", "MASVS-NETWORK"),
        MastgRef("MASTG-DEMO-0048", "Cleartext Traffic Allowed via Network Security Config", "demo", "MASVS-NETWORK"),
    ],
    FindingType.TLS_TRUST_ALL: [
        MastgRef("MASTG-TEST-0020", "Testing the TLS Settings", "test", "MASVS-NETWORK"),
        MastgRef("MASTG-TEST-0021", "Testing Endpoint Identify Verification", "test", "MASVS-NETWORK"),
        MastgRef("MASTG-DEMO-0054", "TrustManager that Does Not Validate Certificate Chains", "demo", "MASVS-NETWORK"),
    ],
    FindingType.HOSTNAME_VERIFIER: [
        MastgRef("MASTG-TEST-0021", "Testing Endpoint Identify Verification", "test", "MASVS-NETWORK"),
        MastgRef("MASTG-DEMO-0055", "HostnameVerifier that Allows Any Hostname", "demo", "MASVS-NETWORK"),
    ],
}


def for_type(ftype: FindingType) -> list[MastgRef]:
    return REFERENCES.get(ftype, [])


def markdown_links(ftype: FindingType) -> str:
    refs = for_type(ftype)
    if not refs:
        return "(no MASTG cross-reference for this finding type)"
    return "\n".join(f"- [{r.id} -- {r.title}]({r.url}) ({r.kind})" for r in refs)
