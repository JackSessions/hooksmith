# HookSmith report

- **APK:** `vulnlab.apk`  sha256 `c9cf417b2d78a274…`
- **Package:** `com.hooksmith.vulnlab`
- **Run:** `run-20261006-055955`  started 2026-10-06T05:59:55+00:00
- **Generator:** template / `template` at temperature 0.0 (prompts `aeb3e7c164e2`)
- **Device:** {"executor": "avd", "serial": "emulator-5554", "model": "sdk_gphone64_x86_64", "android": "13", "sdk": "33", "abi": "x86_64", "rooted": true, "frida": "17.22.2"}

## Verdicts

| Verdict | Count | Meaning |
|---|---:|---|
| PROVEN | 5 | Hook attached. Method called. Observed behaviour matches the claim. Log kept as evidence. |
| REFUTED | 5 | Hook attached. Method called. Observed behaviour contradicts the claim. False positive, with evidence. |
| UNREACHABLE | 1 | Hook attached but the method never fired on the exercised paths. Possibly real, possibly dead code. |
| UNVALIDATED | 0 | Hook could not be generated or attached (obfuscation, native, jadx failure, hallucination). Reason recorded. |

**11 findings, 11 verdicts. No finding left without one.**

## Findings

| # | Finding | Target | Verdict | Why | Evidence |
|---:|---|---|---|---|---|
| 1 | Hardcoded AES key (`hardcoded_key`, high) | `com.hooksmith.vulnlab.Crypto.encrypt` | **PROVEN** | observed 16-byte key equals a static constant in the class (string) | `findings/VL-1/` |
| 2 | Hardcoded AES key (session) (`hardcoded_key`, high) | `com.hooksmith.vulnlab.SessionCrypto.seal` | **REFUTED** | key value differs across calls (4 distinct values): derived, not hardcoded | `findings/VL-2/` |
| 3 | Hardcoded legacy key (`hardcoded_key`, high) | `com.hooksmith.vulnlab.DeadCode.hiddenKey` | **UNREACHABLE** | hook attached but the target method never fired on the exercised paths | `findings/VL-3/` |
| 4 | Insecure RNG for session token (`insecure_random`, medium) | `com.hooksmith.vulnlab.TokenGen.newSessionToken` | **PROVEN** | java.util.Random observed in a security-relevant method context | `findings/VL-4/` |
| 5 | Insecure RNG (`insecure_random`, medium) | `com.hooksmith.vulnlab.Cosmetics.pickConfettiColor` | **REFUTED** | java.util.Random observed but not in a security-relevant context (no token/key/session/etc. involved) | `findings/VL-5/` |
| 6 | Cleartext HTTP traffic (`cleartext_http`, high) | `com.hooksmith.vulnlab.Api.fetch` | **PROVEN** | observed cleartext request to http://example.com/profile | `findings/VL-6/` |
| 7 | Cleartext HTTP traffic (`cleartext_http`, high) | `com.hooksmith.vulnlab.SafeApi.fetch` | **REFUTED** | every observed URL used https or a loopback host: https://example.com/, https://example.com/ | `findings/VL-7/` |
| 8 | TrustManager accepts any certificate (`tls_trust_all`, high) | `com.hooksmith.vulnlab.TrustAllManager.checkServerTrusted` | **PROVEN** | accepted a self-signed certificate chain for CN=*.badssl.com,O=BadSSL,L=San Francisco,ST=California,C=US | `findings/VL-8/` |
| 9 | TrustManager (platform delegate) (`tls_trust_all`, high) | `com.hooksmith.vulnlab.StrictTrustManager.checkServerTrusted` | **REFUTED** | rejected a certificate chain: validation is in place | `findings/VL-9/` |
| 10 | HostnameVerifier allows any hostname (`hostname_verifier`, high) | `com.hooksmith.vulnlab.AllowAllVerifier.verify` | **PROVEN** | returned true for wrong.host.badssl.com, which the server certificate does not cover | `findings/VL-10/` |
| 11 | HostnameVerifier (platform default) (`hostname_verifier`, high) | `com.hooksmith.vulnlab.StrictVerifier.verify` | **REFUTED** | rejected a hostname the certificate does not cover | `findings/VL-11/` |

## How to verify a PROVEN finding yourself

Each evidence folder holds `source.java` (what the hook was written from), `hook.js` (what ran), `runtime.log` (raw output) and `verdict.json` (what the signal library concluded). Re-run `hook.js` against the same APK with `frida -U -f <package> -l hook.js` to reproduce.
