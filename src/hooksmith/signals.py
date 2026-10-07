"""The signal library. The LLM writes the hook; *this* decides what the hook's output means.

Hooks report through one line protocol so signals never parse free text:

    HS|{"event": "ready"}                      hook installed (not evidence the method fired)
    HS|{"event": "call", ...}                  the target method ran
    HS|{"event": "key", "hex": "..."}          key material seen          (hardcoded_key)
    HS|{"event": "url", "url": "http://..."}   URL seen                   (cleartext_http)
    HS|{"event": "random", "impl": "..."}      RNG implementation seen    (insecure_random)
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from .javasrc import key_constants
from .models import Finding, FindingType, Outcome, Verdict

PREFIX = "HS|"
NON_FIRING = {"ready", "loaded", "hooked", "installed", "attached"}
LOOPBACK = {"localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"}
SECURITY_WORDS = {
    "token",
    "password",
    "passwd",
    "secret",
    "key",
    "iv",
    "nonce",
    "salt",
    "session",
    "otp",
    "auth",
    "crypt",
    "cipher",
    "sign",
    "signature",
    "csrf",
    "login",
    "credential",
    "pin",
    "hash",
    "seed",
    "uuid",
}


def parse_events(log: list[str]) -> list[dict]:
    events = []
    for line in log:
        i = line.find(PREFIX)
        if i == -1:
            continue
        try:
            ev = json.loads(line[i + len(PREFIX) :])
        except json.JSONDecodeError:
            continue
        if isinstance(ev, dict) and "event" in ev:
            events.append(ev)
    return events


def fired(events: list[dict], log: list[str]) -> bool:
    if any(e["event"] not in NON_FIRING for e in events):
        return True
    # a hook that ignored the protocol but did print something after loading still fired *something*,
    # but we cannot tell what, so we do not count free text as evidence the method ran.
    return False


# ---- hardcoded key --------------------------------------------------------------------------


def _hex_of(ev: dict) -> bytes | None:
    for k in ("hex", "key_hex"):
        if isinstance(ev.get(k), str):
            try:
                return bytes.fromhex(ev[k].replace(":", "").replace(" ", ""))
            except ValueError:
                return None
    if isinstance(ev.get("bytes"), list):
        try:
            return bytes(int(b) & 0xFF for b in ev["bytes"])
        except (TypeError, ValueError):
            return None
    return None


def hardcoded_key(finding: Finding, events: list[dict], source: str, sources_root=None) -> Outcome:
    key_events = [ev for ev in events if ev["event"] == "key"]
    # Keys seen entering SecretKeySpec are authoritative. A byte[] merely passed to the method ("via": "argument")
    # could be plaintext, so it only counts when nothing better was observed.
    primary = [e for e in key_events if e.get("via") != "argument"]
    keys = [b for ev in (primary or key_events) if (b := _hex_of(ev))]
    keys = [k for k in keys if len(k) in (16, 24, 32)]
    distinct = sorted({k.hex() for k in keys})
    sig = {"observed_keys": distinct, "calls": len([e for e in events if e["event"] == "call"])}
    if not keys:
        return Outcome(
            verdict=Verdict.UNVALIDATED,
            reason="method fired but no 16/24/32-byte key material was observed, so the claim can be neither proven nor refuted",
            signal=sig,
        )
    if len(distinct) > 1:
        return Outcome(
            verdict=Verdict.REFUTED,
            reason=f"key value differs across calls ({len(distinct)} distinct values): derived, not hardcoded",
            signal=sig,
        )
    consts = key_constants(source)
    for origin, raw in consts:
        if raw == keys[0]:
            sig["matched_constant"] = {"origin": origin, "hex": raw.hex(), "file": "(hooked class)"}
            return Outcome(
                verdict=Verdict.PROVEN,
                reason=f"observed {len(keys[0])}-byte key equals a static constant in the class ({origin})",
                signal=sig,
            )
    # Real apps very commonly call a shared crypto helper (what we hooked) from a DIFFERENT class that declares
    # the actual key constant at the call site -- confirmed on OWASP MASTG's UnCrackable-Level1.apk, where the
    # AES key string lives in the caller, not in the generic encrypt/decrypt utility we hook. A narrow, single-
    # class search would wrongly call this UNVALIDATED even though the observed key IS a real source constant.
    if sources_root is not None:
        match = _search_tree_for_key(Path(sources_root), keys[0], skip_source=source)
        if match is not None:
            origin, raw, rel_path = match
            sig["matched_constant"] = {"origin": origin, "hex": raw.hex(), "file": rel_path}
            return Outcome(
                verdict=Verdict.PROVEN,
                reason=f"observed {len(keys[0])}-byte key equals a static constant in {rel_path} ({origin}), "
                f"which calls the hooked method",
                signal=sig,
            )
    return Outcome(
        verdict=Verdict.UNVALIDATED,
        reason="a single key value was observed but it does not match any constant in the decompiled sources "
        "(could be loaded from a resource or native code, or not a constant at all)",
        signal=sig,
    )


_TREE_SEARCH_FILE_LIMIT = 4000  # a safety cap, not a realistic ceiling: decompiled trees rarely exceed this


def _search_tree_for_key(root: Path, key: bytes, skip_source: str) -> tuple[str, bytes, str] | None:
    """Best-effort fallback: scan other decompiled classes for a constant matching the observed key. Stops at the
    first match; capped so a pathologically large app can't make a single UNVALIDATED-vs-PROVEN decision slow.
    """
    base = root / "sources" if (root / "sources").is_dir() else root
    for i, path in enumerate(base.rglob("*.java")):
        if i >= _TREE_SEARCH_FILE_LIMIT:
            break
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        if text == skip_source:
            continue  # already checked (the hooked class itself)
        for origin, raw in key_constants(text):
            if raw == key:
                return origin, raw, str(path.relative_to(base))
    return None


# ---- cleartext HTTP -------------------------------------------------------------------------


def cleartext_http(finding: Finding, events: list[dict], source: str) -> Outcome:
    urls = [str(ev.get("url", "")) for ev in events if ev["event"] == "url"]
    parsed = [(u, urlparse(u)) for u in urls if u]
    clear = [u for u, p in parsed if p.scheme == "http" and (p.hostname or "").lower() not in LOOPBACK]
    sig = {"urls": urls[:20], "cleartext": clear[:20]}
    if clear:
        return Outcome(verdict=Verdict.PROVEN, reason=f"observed cleartext request to {clear[0]}", signal=sig)
    if parsed:
        return Outcome(
            verdict=Verdict.REFUTED,
            reason="every observed URL used https or a loopback host: " + ", ".join(u for u, _ in parsed[:3]),
            signal=sig,
        )
    return Outcome(
        verdict=Verdict.REFUTED,
        reason="method fired but was never called with an external URL",
        signal=sig,
    )


# ---- insecure RNG ---------------------------------------------------------------------------


def insecure_random(finding: Finding, events: list[dict], source: str) -> Outcome:
    rng = [ev for ev in events if ev["event"] == "random"]
    impls = sorted({str(ev.get("impl", "")) for ev in rng})
    simple = (finding.class_name or "").split(".")[-1]  # not the package: `com.x.auth.Confetti` is not security
    ctx = " ".join([finding.method or "", simple] + [str(ev.get("context", "")) for ev in rng])
    security_context = is_security_context(ctx)
    sig = {"impls": impls, "security_context": security_context}
    weak = [i for i in impls if i in ("java.util.Random", "Math.random", "java.lang.Math")]
    strong = [i for i in impls if "SecureRandom" in i]
    if weak and security_context:
        return Outcome(
            verdict=Verdict.PROVEN,
            reason=f"{weak[0]} observed in a security-relevant method context",
            signal=sig,
        )
    if strong and not weak:
        return Outcome(verdict=Verdict.REFUTED, reason="SecureRandom observed instead of a predictable RNG", signal=sig)
    if weak:
        return Outcome(
            verdict=Verdict.REFUTED,
            reason=f"{weak[0]} observed but not in a security-relevant context (no token/key/session/etc. involved)",
            signal=sig,
        )
    return Outcome(
        verdict=Verdict.REFUTED,
        reason="method fired but no java.util.Random or Math.random use was observed",
        signal=sig,
    )


# ---- TLS: trust manager that accepts anything -------------------------------------------------


def tls_trust_all(finding: Finding, events: list[dict], source: str) -> Outcome:
    chains = [e for e in events if e["event"] == "tls_chain"]
    bad = lambda e: bool(e.get("self_signed") or e.get("expired"))  # noqa: E731
    accepted_bad = [e for e in chains if e.get("accepted") and bad(e)]
    rejected = [e for e in chains if not e.get("accepted")]
    sig = {
        "chains": len(chains),
        "accepted_invalid": len(accepted_bad),
        "rejected": len(rejected),
        "example": (accepted_bad or rejected or chains or [{}])[0].get("subject"),
    }
    if accepted_bad:
        e = accepted_bad[0]
        why = "self-signed" if e.get("self_signed") else "expired"
        return Outcome(verdict=Verdict.PROVEN, reason=f"accepted a {why} certificate chain for {e.get('subject')}", signal=sig)
    if rejected:
        return Outcome(verdict=Verdict.REFUTED, reason="rejected a certificate chain: validation is in place", signal=sig)
    if chains:
        return Outcome(
            verdict=Verdict.UNVALIDATED,
            reason="only valid chains were observed: a trust-all manager and a correct one look identical. "
            "Exercise the app against an endpoint with an invalid certificate to decide.",
            signal=sig,
        )
    return Outcome(verdict=Verdict.UNVALIDATED, reason="method fired but no certificate information could be read", signal=sig)


# ---- TLS: hostname verifier that accepts any host ----------------------------------------------


def hostname_verifier(finding: Finding, events: list[dict], source: str) -> Outcome:
    calls = [e for e in events if e["event"] == "hostname"]
    mismatch = [e for e in calls if e.get("cert_matches") is False]
    sig = {"checks": len(calls), "mismatched_hosts": len(mismatch), "hosts": sorted({str(e.get("host")) for e in calls})[:10]}
    accepted = [e for e in mismatch if e.get("result")]
    if accepted:
        return Outcome(
            verdict=Verdict.PROVEN,
            reason=f"returned true for {accepted[0].get('host')}, which the server certificate does not cover",
            signal=sig,
        )
    if mismatch:
        return Outcome(verdict=Verdict.REFUTED, reason="rejected a hostname the certificate does not cover", signal=sig)
    if calls:
        return Outcome(
            verdict=Verdict.UNVALIDATED,
            reason="only hostnames covered by the certificate were seen: an allow-all verifier and a correct one look identical. "
            "Exercise the app against a host with a mismatched certificate to decide.",
            signal=sig,
        )
    return Outcome(verdict=Verdict.UNVALIDATED, reason="method fired but no hostname checks were logged", signal=sig)


SIGNALS = {
    FindingType.HARDCODED_KEY: hardcoded_key,
    FindingType.CLEARTEXT_HTTP: cleartext_http,
    FindingType.INSECURE_RANDOM: insecure_random,
    FindingType.TLS_TRUST_ALL: tls_trust_all,
    FindingType.HOSTNAME_VERIFIER: hostname_verifier,
}


def classify(finding: Finding, log: list[str], source: str, sources_root=None) -> Outcome:
    """Turn a runtime log into one of the four verdicts. Called only when the hook attached.

    `sources_root`, when given, lets a signal fall back to searching the whole decompiled tree (not just the
    hooked class) when the narrow, single-class check finds nothing -- currently used by hardcoded_key, see there.
    """
    events = parse_events(log)
    if not fired(events, log):
        n = len([ln for ln in log if PREFIX not in ln])  # protocol lines (ready) are not "unrelated"
        return Outcome(
            verdict=Verdict.UNREACHABLE,
            reason="hook attached but the target method never fired on the exercised paths"
            + (f" ({n} unrelated log lines)" if n else ""),
            signal={"events": len(events)},
        )
    fn = SIGNALS.get(finding.type)
    if fn is None:
        return Outcome(
            verdict=Verdict.UNVALIDATED,
            reason=f"no signal library entry for finding type {finding.type.value!r} in v1",
        )
    if fn is hardcoded_key:
        return hardcoded_key(finding, events, source, sources_root=sources_root)
    return fn(finding, events, source)


def is_security_context(text: str) -> bool:
    """Split identifiers into words (camelCase, snake_case) and look for security vocabulary."""
    words = {w.lower() for w in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+", text)}
    return bool(words & SECURITY_WORDS) or any(w.startswith("crypt") for w in words)
