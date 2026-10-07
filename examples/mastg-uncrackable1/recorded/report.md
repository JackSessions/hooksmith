# HookSmith report

- **APK:** `UnCrackable-Level1.apk`  sha256 `1da8bf57d266109f…`
- **Package:** `owasp.mstg.uncrackable1`
- **Run:** `run-20261006-220051`  started 2026-10-06T22:00:51+00:00
- **Generator:** template / `template` at temperature 0.0 (prompts `aeb3e7c164e2`)
- **Device:** {"executor": "avd", "serial": "emulator-5554", "model": "sdk_gphone64_x86_64", "android": "13", "sdk": "33", "abi": "x86_64", "rooted": true, "frida": "17.22.2"}

## Verdicts

| Verdict | Count | Meaning |
|---|---:|---|
| PROVEN | 1 | Hook attached. Method called. Observed behaviour matches the claim. Log kept as evidence. |
| REFUTED | 0 | Hook attached. Method called. Observed behaviour contradicts the claim. False positive, with evidence. |
| UNREACHABLE | 0 | Hook attached but the method never fired on the exercised paths. Possibly real, possibly dead code. |
| UNVALIDATED | 0 | Hook could not be generated or attached (obfuscation, native, jadx failure, hallucination). Reason recorded. |

**1 findings, 1 verdicts. No finding left without one.**

## Findings

| # | Finding | Target | Verdict | Why | Evidence |
|---:|---|---|---|---|---|
| 1 | Possible hardcoded cryptographic key (`hardcoded_key`, high) | `sg.vantagepoint.a.a.a` | **PROVEN** | observed 16-byte key equals a static constant in sg/vantagepoint/uncrackable1/a.java (hex), which calls the hooked method | `findings/SCAN-001/` |

## How to verify a PROVEN finding yourself

Each evidence folder holds `source.java` (what the hook was written from), `hook.js` (what ran), `runtime.log` (raw output) and `verdict.json` (what the signal library concluded). Re-run `hook.js` against the same APK with `frida -U -f <package> -l hook.js` to reproduce.

## OWASP MASTG coverage

Finding types this run was able to test, and the MASTG methodology each one implements:

- `hardcoded_key`: [MASTG-TEST-0013](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0013/), [MASTG-TEST-0015](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0015/), [MASTG-DEMO-0017](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0017/MASTG-DEMO-0017/)
