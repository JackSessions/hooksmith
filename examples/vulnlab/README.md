# VulnLab

A tiny, deliberately vulnerable Android app that gives HookSmith one finding for every verdict. It does its work on
launch, so no UI interaction is needed.

| Finding | Class.method | Expected verdict | Why |
|---|---|---|---|
| VL-1 hardcoded key | `Crypto.encrypt` | PROVEN | the AES key is a string constant |
| VL-2 hardcoded key | `SessionCrypto.seal` | REFUTED | key is derived (PBKDF2, random salt), differs per call |
| VL-3 hardcoded key | `DeadCode.hiddenKey` | UNREACHABLE | looks awful, nothing ever calls it |
| VL-4 insecure RNG | `TokenGen.newSessionToken` | PROVEN | `java.util.Random` building a session token |
| VL-5 insecure RNG | `Cosmetics.pickConfettiColor` | REFUTED | `Random`, but for a confetti colour |
| VL-6 cleartext HTTP | `Api.fetch` | PROVEN | called with `http://example.com/profile` |
| VL-7 cleartext HTTP | `SafeApi.fetch` | REFUTED | called with `https://` |
| VL-8 TLS trust-all | `TrustAllManager.checkServerTrusted` | PROVEN | accepts the self-signed chain from `self-signed.badssl.com` |
| VL-9 TLS trust manager | `StrictTrustManager.checkServerTrusted` | REFUTED | platform delegate rejects `expired.badssl.com` |
| VL-10 hostname verifier | `AllowAllVerifier.verify` | PROVEN | returns true for `wrong.host.badssl.com` (cert is for `*.badssl.com`) |
| VL-11 hostname verifier | `StrictVerifier.verify` | REFUTED | platform default verifier rejects the same host |

VL-8 to VL-11 connect to the public [badssl.com](https://badssl.com) test hosts, so the device needs internet access.
If badssl.com is unreachable those findings come back UNREACHABLE, which is the honest result.

```bash
./build.sh                                   # needs the Android SDK build-tools (hooksmith avd setup installs them)
cd ../.. && uv run hooksmith run --report examples/vulnlab/findings.json --apk examples/vulnlab/vulnlab.apk \
    --executor avd --provider template
```

`--provider template` needs no LLM. Swap in `--provider worker` to have Workers AI write the hooks.
