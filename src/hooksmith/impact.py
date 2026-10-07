"""Impact statements: what a PROVEN finding actually means for someone attacking the app.

Deliberately not an LLM pass, same rule as bugreport.py: every sentence is a fixed, type-specific template filled
in only with facts already in the finding's `signal` dict (verdict.json) -- the same facts the signal library used
to decide PROVEN in the first place. No speculation about what the exposed data IS (we don't know, and say so);
only what an attacker is positioned to DO, which follows directly from the mechanism observed.
"""

from __future__ import annotations

from .models import FindingType


def _mask(hexstr: str, keep: int = 4) -> str:
    if not hexstr or len(hexstr) <= keep * 2:
        return hexstr
    return f"{hexstr[:keep]}…{hexstr[-keep:]} ({len(hexstr) // 2} bytes)"


def hardcoded_key_impact(target: str, signal: dict) -> str:
    keys = signal.get("observed_keys") or []
    shown = _mask(keys[0]) if keys else "(key bytes not recorded)"
    return (
        f"The key `{target}` uses is a compile-time constant, not something derived per-install, per-user or "
        f"per-session. Anyone who obtains the APK -- which is to say anyone who installs the app, since that is "
        f"how APKs are obtained -- can read the same key straight out of the decompiled source, with no device "
        f"exploit required. Observed key material: `{shown}`.\n\n"
        f"Practical effect: whatever this key protects (data at rest, a token, an API payload) is protected only "
        f"against someone who has not looked at the app. It cannot be revoked or rotated without shipping a new "
        f"build, and it is identical across every install, so compromising one install's key compromises all of them."
    )


def cleartext_http_impact(target: str, signal: dict) -> str:
    urls = signal.get("cleartext") or []
    shown = urls[0] if urls else "(URL not recorded)"
    return (
        f"`{target}` sent this request over plain HTTP: `{shown}`. Anyone with a position on the network path -- "
        f"a shared Wi-Fi network, a rogue access point, a compromised router, or DNS/ARP spoofing on a LAN -- can "
        f"read this request and its response in full, and can modify either one in transit, without the app or "
        f"the user having any way to detect it.\n\n"
        f"What exactly is exposed depends on what this endpoint carries, which this run did not inspect; the "
        f"request itself proves the transport gives an attacker that access regardless of payload."
    )


def insecure_random_impact(target: str, signal: dict) -> str:
    impls = signal.get("impls") or []
    shown = ", ".join(impls) if impls else "java.util.Random / Math.random"
    return (
        f"`{target}` produced its value using `{shown}` while handling something the finding flags as security-"
        f"relevant (a token, key, session id, or similar, based on the method/class name). `{shown.split(',')[0]}` "
        f"is a linear PRNG seeded from system time by default: an attacker who can bound the time window a value "
        f"was generated in (often narrow -- login timestamps, server logs, or the app's own activity are usually "
        f"enough) can enumerate or directly reconstruct the seed and reproduce every value it ever produced in "
        f"that window.\n\n"
        f"Practical effect: whatever this value authenticates or protects (a session, a reset token, a key) can "
        f"potentially be predicted or forged by an attacker who did not observe it directly."
    )


def tls_trust_all_impact(target: str, signal: dict, reason: str = "") -> str:
    example = signal.get("example") or "(certificate subject not recorded)"
    why = "self-signed" if "self-signed" in reason else "expired" if "expired" in reason else "invalid"
    return (
        f"`{target}` accepted a {why} certificate chain (`{example}`) that correct validation should have rejected. "
        f"TLS's entire protection against interception rests on certificate validation; once it accepts anything, "
        f"an attacker performing a machine-in-the-middle attack (rogue Wi-Fi, a compromised network device, DNS "
        f"hijacking) can present a certificate they generated themselves and the app will trust it exactly as it "
        f"trusts the real server.\n\n"
        f"Practical effect: every request and response on this connection -- credentials, tokens, session data, "
        f"whatever this channel carries -- should be considered fully exposed to interception and tampering, with "
        f"no cryptographic protection in practice despite the app appearing to use HTTPS."
    )


def hostname_verifier_impact(target: str, signal: dict) -> str:
    hosts = signal.get("hosts") or []
    shown = hosts[0] if hosts else "(host not recorded)"
    return (
        f"`{target}` returned `true` for `{shown}`, a host the presented certificate does not cover. Certificate "
        f"validation can be entirely correct and this still fails: an attacker only needs ANY certificate they "
        f"control the private key for, for example one issued for a domain they legitimately own, and this "
        f"verifier will accept it for a connection claiming to be `{shown}`.\n\n"
        f"Practical effect: this defeats TLS's protection against impersonation specifically, independent of "
        f"whatever certificate chain validation is doing correctly elsewhere. An attacker in a machine-in-the-"
        f"middle position can terminate the connection with their own valid-but-wrong-host certificate."
    )


_BUILDERS = {
    FindingType.HARDCODED_KEY: lambda t, s, r: hardcoded_key_impact(t, s),
    FindingType.CLEARTEXT_HTTP: lambda t, s, r: cleartext_http_impact(t, s),
    FindingType.INSECURE_RANDOM: lambda t, s, r: insecure_random_impact(t, s),
    FindingType.TLS_TRUST_ALL: tls_trust_all_impact,
    FindingType.HOSTNAME_VERIFIER: lambda t, s, r: hostname_verifier_impact(t, s),
}


def build_impact(ftype: FindingType, target: str, signal: dict, reason: str = "") -> str:
    fn = _BUILDERS.get(ftype)
    if fn is None:
        return "No impact template for this finding type yet; assess from the evidence directly."
    return fn(target, signal or {}, reason)
