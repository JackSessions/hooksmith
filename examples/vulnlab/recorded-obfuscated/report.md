# HookSmith report

- **APK:** `vulnlab-obfuscated.apk`  sha256 `9d017a8b4d577998…`
- **Package:** `com.hooksmith.vulnlab`
- **Run:** `run-20261006-214835`  started 2026-10-06T21:48:35+00:00
- **Generator:** template / `template` at temperature 0.0 (prompts `aeb3e7c164e2`)
- **Device:** {"executor": "avd", "serial": "emulator-5554", "model": "sdk_gphone64_x86_64", "android": "13", "sdk": "33", "abi": "x86_64", "rooted": true, "frida": "17.22.2"}

## Verdicts

| Verdict | Count | Meaning |
|---|---:|---|
| PROVEN | 3 | Hook attached. Method called. Observed behaviour matches the claim. Log kept as evidence. |
| REFUTED | 3 | Hook attached. Method called. Observed behaviour contradicts the claim. False positive, with evidence. |
| UNREACHABLE | 0 | Hook attached but the method never fired on the exercised paths. Possibly real, possibly dead code. |
| UNVALIDATED | 0 | Hook could not be generated or attached (obfuscation, native, jadx failure, hallucination). Reason recorded. |

**6 findings, 6 verdicts. No finding left without one.**

## Findings

| # | Finding | Target | Verdict | Why | Evidence |
|---:|---|---|---|---|---|
| 1 | HostnameVerifier that may accept any hostname (`hostname_verifier`, critical) | `a.verify` | **PROVEN** | returned true for wrong.host.badssl.com, which the server certificate does not cover | `findings/SCAN-003/` |
| 2 | TrustManager that may not validate certificate chains (`tls_trust_all`, critical) | `d.checkServerTrusted` | **REFUTED** | rejected a certificate chain: validation is in place | `findings/SCAN-005/` |
| 3 | TrustManager that may not validate certificate chains (`tls_trust_all`, critical) | `e.checkServerTrusted` | **PROVEN** | accepted a self-signed certificate chain for CN=*.badssl.com,O=BadSSL,L=San Francisco,ST=California,C=US | `findings/SCAN-006/` |
| 4 | Possible hardcoded cryptographic key (`hardcoded_key`, high) | `com.hooksmith.vulnlab.MainActivity.work` | **REFUTED** | key value differs across calls (5 distinct values): derived, not hardcoded | `findings/SCAN-001/` |
| 5 | Possible cleartext HTTP traffic (`cleartext_http`, high) | `b.a` | **PROVEN** | observed cleartext request to http://example.com/profile | `findings/SCAN-004/` |
| 6 | Possible insecure random number generation (`insecure_random`, medium) | `com.hooksmith.vulnlab.MainActivity.work` | **REFUTED** | java.util.Random observed but not in a security-relevant context (no token/key/session/etc. involved) | `findings/SCAN-002/` |

## How to verify a PROVEN finding yourself

Each evidence folder holds `source.java` (what the hook was written from), `hook.js` (what ran), `runtime.log` (raw output) and `verdict.json` (what the signal library concluded). Re-run `hook.js` against the same APK with `frida -U -f <package> -l hook.js` to reproduce.

## OWASP MASTG coverage

Finding types this run was able to test, and the MASTG methodology each one implements:

- `cleartext_http`: [MASTG-TEST-0019](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0019/), [MASTG-DEMO-0048](https://mas.owasp.org/MASTG/demos/android/MASVS-NETWORK/MASTG-DEMO-0048/MASTG-DEMO-0048/)
- `hardcoded_key`: [MASTG-TEST-0013](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0013/), [MASTG-TEST-0015](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0015/), [MASTG-DEMO-0017](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0017/MASTG-DEMO-0017/)
- `hostname_verifier`: [MASTG-TEST-0021](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0021/), [MASTG-DEMO-0055](https://mas.owasp.org/MASTG/demos/android/MASVS-NETWORK/MASTG-DEMO-0055/MASTG-DEMO-0055/)
- `insecure_random`: [MASTG-TEST-0016](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0016/), [MASTG-DEMO-0007](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0007/MASTG-DEMO-0007/)
- `tls_trust_all`: [MASTG-TEST-0020](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0020/), [MASTG-TEST-0021](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0021/), [MASTG-DEMO-0054](https://mas.owasp.org/MASTG/demos/android/MASVS-NETWORK/MASTG-DEMO-0054/MASTG-DEMO-0054/)
