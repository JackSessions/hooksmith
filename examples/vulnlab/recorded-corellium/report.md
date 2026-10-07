# HookSmith report

- **APK:** `vulnlab.apk`  sha256 `e5c453e9787f688a…`
- **Package:** `com.hooksmith.vulnlab`
- **Run:** `run-20261006-053110`  started 2026-10-06T05:31:10+00:00
- **Generator:** template / `template` at temperature 0.0 (prompts `f1a6742eda3e`)
- **Device:** {"executor": "adb", "serial": "10.11.1.1:5001", "model": "Corellium Generic", "android": "16", "sdk": "36", "abi": "arm64-v8a", "rooted": true, "frida": "17.22.2"}

## Verdicts

| Verdict | Count | Meaning |
|---|---:|---|
| PROVEN | 3 | Hook attached. Method called. Observed behaviour matches the claim. Log kept as evidence. |
| REFUTED | 3 | Hook attached. Method called. Observed behaviour contradicts the claim. False positive, with evidence. |
| UNREACHABLE | 1 | Hook attached but the method never fired on the exercised paths. Possibly real, possibly dead code. |
| UNVALIDATED | 0 | Hook could not be generated or attached (obfuscation, native, jadx failure, hallucination). Reason recorded. |

**7 findings, 7 verdicts. No finding left without one.**

## Findings

| # | Finding | Target | Verdict | Why | Evidence |
|---:|---|---|---|---|---|
| 1 | Hardcoded AES key (`hardcoded_key`, high) | `com.hooksmith.vulnlab.Crypto.encrypt` | **PROVEN** | observed 16-byte key equals a static constant in the class (string) | `findings/VL-1/` |
| 2 | Hardcoded AES key (session) (`hardcoded_key`, high) | `com.hooksmith.vulnlab.SessionCrypto.seal` | **REFUTED** | key value differs across calls (4 distinct values): derived, not hardcoded | `findings/VL-2/` |
| 3 | Hardcoded legacy key (`hardcoded_key`, high) | `com.hooksmith.vulnlab.DeadCode.hiddenKey` | **UNREACHABLE** | hook attached but the target method never fired on the exercised paths (1 unrelated log lines) | `findings/VL-3/` |
| 4 | Insecure RNG for session token (`insecure_random`, medium) | `com.hooksmith.vulnlab.TokenGen.newSessionToken` | **PROVEN** | java.util.Random observed in a security-relevant method context | `findings/VL-4/` |
| 5 | Insecure RNG (`insecure_random`, medium) | `com.hooksmith.vulnlab.Cosmetics.pickConfettiColor` | **REFUTED** | java.util.Random observed but not in a security-relevant context (no token/key/session/etc. involved) | `findings/VL-5/` |
| 6 | Cleartext HTTP traffic (`cleartext_http`, high) | `com.hooksmith.vulnlab.Api.fetch` | **PROVEN** | observed cleartext request to http://example.com/profile | `findings/VL-6/` |
| 7 | Cleartext HTTP traffic (`cleartext_http`, high) | `com.hooksmith.vulnlab.SafeApi.fetch` | **REFUTED** | every observed URL used https or a loopback host: https://example.com/, https://example.com/ | `findings/VL-7/` |

## How to verify a PROVEN finding yourself

Each evidence folder holds `source.java` (what the hook was written from), `hook.js` (what ran), `runtime.log` (raw output) and `verdict.json` (what the signal library concluded). Re-run `hook.js` against the same APK with `frida -U -f <package> -l hook.js` to reproduce.
