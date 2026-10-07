# OWASP MASTG UnCrackable-Level1

The first of OWASP MASTG's well-known Android crackmes, shipped directly in the MASTG repo
(`Crackmes/Android/Level_01/UnCrackable-Level1.apk`). Run for real on a local AVD -- the "live demo on a real
MASTG app" HookSmith's SINCON talk promises, not just the project's own [VulnLab](../vulnlab/).

```bash
uv run hooksmith scan --apk UnCrackable-Level1.apk --out findings.json --include-test-classes
uv run hooksmith run --report findings.json --apk UnCrackable-Level1.apk \
    --package owasp.mstg.uncrackable1 --executor avd --provider template
```

| Finding | Target | Verdict | What was observed |
|---|---|---|---|
| Hardcoded AES key | `sg.vantagepoint.a.a.a` | **PROVEN** | the decrypted secret-code check uses a 16-byte key, `8d127684cbc37c17616d806cf50473cc`, hardcoded as a hex string -- not in the hooked class itself, but in the class that calls it (`sg.vantagepoint.uncrackable1.a`) |

## Two real bugs this app's own code surfaced (fixed, not worked around)

1. **A method sharing its class's own name was misparsed as a constructor.** The class is `sg.vantagepoint.a.a`
   (package `sg.vantagepoint.a`, simple name `a`), and it declares `public static byte[] a(byte[] key, byte[]
   data)` -- a perfectly ordinary static method that happens to share the class's simple name, which Java allows
   because it has a return type. HookSmith's regex-based Java reader originally treated any method named the
   same as its class as a constructor, folding it into `<init>` and pointing every hook at the wrong target. Fixed
   in `javasrc.py` by checking whether the method actually has a return type, not just a matching name.
2. **The obfuscation gate was blocking a perfectly hookable, unambiguous method.** `sg.vantagepoint.a.a.a` scores
   high on HookSmith's short-name obfuscation heuristic (both the class and the method are single letters), which
   used to decline it outright as UNVALIDATED. But the finding named this exact method, and it's the only
   candidate with that name in the class -- there's no ambiguity to protect against. Fixed in `decompile.py`: the
   gate now only applies when the method had to be *guessed*, not when it was given explicitly and resolves to
   one unambiguous candidate.
3. **The real key constant lives in a different class than the one being hooked** -- a very common real-world
   pattern (a shared crypto helper called from call sites that hold the actual key). The signal library's
   "does the observed key match a known constant" check originally only searched the hooked class's own source.
   Fixed in `signals.py`: it now falls back to searching the whole decompiled tree when the narrow check finds
   nothing, and records which file the match came from.

All three were found and fixed on this exact app, verified by re-running on a real device afterwards -- see
`recorded/` for the evidence (hook, runtime log, verdict) from that run, and `tests/test_mastg_uncrackable1.py`
for the hermetic regression tests built from it.

## What this app doesn't exercise

UnCrackable-Level1 also has root-detection and debugger-detection checks (the classic CTF goal is bypassing
them), which aren't finding types HookSmith's signal library covers in v1 -- `hooksmith scan` correctly didn't
surface them, since it only looks for patterns it can actually prove or refute at runtime.
