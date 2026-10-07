# HookSmith

**Prove or Delete: every static mobile finding exits with a runtime verdict.**

Static analysis hands you hundreds of findings per app. Proving one at runtime means writing a Frida hook, which
costs 30-40 minutes of skilled work, so under time pressure the step gets dropped and the report says "potential".
HookSmith makes the step cheap enough to do for every finding, and gives every finding exactly one of four verdicts:

| Verdict | Meaning |
|---|---|
| **PROVEN** | Hook attached. Method called. Observed behaviour matches the claim. Runtime log kept as evidence. |
| **REFUTED** | Hook attached. Method called. Observed behaviour contradicts the claim. A false positive, with evidence. |
| **UNREACHABLE** | Hook attached but the method never fired on the exercised paths. Possibly real, possibly dead code. |
| **UNVALIDATED** | Hook could not be generated or attached (obfuscation, native code, jadx failure, hallucination). The reason is recorded. |

No fifth bucket. No "probably fine". The schema works without the tool; the tool makes it affordable.

## Try it in 30 seconds (no device, no API keys)

```bash
uv sync
uv run hooksmith demo
```

`demo` replays a bundled sample app end to end through the real pipeline (LangGraph, validator, signal library,
evidence store, report): ten findings, all four verdicts, including an LLM hook the validator rejects twice and one
it rejects once and recovers.

## Just have an APK? No GUI, no external scanner report needed

HookSmith is a CLI (there is no GUI; `--help` on any command is the closest thing to one). If you own an app, or are
authorised to test it, and have no MobSF/Semgrep report, `scan` and `test` use a small built-in static pass instead:

```bash
uv sync --extra device
uv run hooksmith avd setup          # one-off, see below

uv run hooksmith test --apk app.apk --executor avd
```

`test` decompiles the APK, runs the built-in scanner (hardcoded keys, insecure RNG, cleartext HTTP, trust-all TLS,
allow-all hostnames -- the patterns the signal library can actually prove or refute), and feeds the result straight
into the pipeline: one command, one file dropped in, a verdict table out. It uses deterministic template hooks by
default (`--provider template`), so it needs no API key either; add `--provider worker` once you have deployed the
Worker (see below) to have an LLM write the hooks.

To see the candidates before running anything, or to feed a real MobSF/Semgrep report instead, use `scan` and `run`
separately:

```bash
uv run hooksmith scan --apk app.apk --out findings.json     # review findings.json, edit it, whatever you like
uv run hooksmith run --report findings.json --apk app.apk --executor avd
```

The built-in scanner is intentionally narrow and high-precision: it is not trying to be MobSF. It only flags the
exact patterns the signal library knows how to validate, so false positives are rare but so is broad coverage. Point
`--report` at a real scanner's output whenever you have one.
evidence store, report): ten findings, all four verdicts, including an LLM hook the validator rejects twice and one
it rejects once and recovers.

## How it works

```
 MobSF JSON + APK
        │
        ▼
    triage (dedup + severity order, once)
        │
        ▼
  ingest ─► decompile (jadx) ─► plan exercise ─► generate hook ─► static validate ──ok──► execute ─► classify ─► record ─┐
                │                                    ▲                │ fail                │           │              │
                │ class missing / native /           └─ retry once ───┘ (validator errors   │ no attach  │ signal       │
                │ obfuscated                            fed back)  two failures ──┐        │            │ library      │
                └──────────────────────────────── UNVALIDATED (reason stored) ◄────┴────────┘            │ decides      │
                                                                                               PROVEN / REFUTED / UNREACHABLE
                                                                                                                          │
                                                                                      (no findings left) ◄───────────────┘
                                                                                                │
                                                                                                ▼
                                                                          report (write bugs/<id>.md for PROVEN, once)
```

The pipeline is a [LangGraph](https://github.com/langchain-ai/langgraph) state machine (`src/hooksmith/graph.py`), with
**two agent-style nodes bracketing the per-finding loop** plus the loop itself:

| Stage | What | Where |
|---|---|---|
| **Triage** | runs once, before any finding touches a device: merges exact duplicates (same type + same class.method, common when more than one scanner rule fires on the same code) so they don't cost device time twice, and orders the rest by severity so a `--limit`-bounded or interrupted run spends its device time on what matters most | `triage.py` |
| Ingest | MobSF JSON (nested 4.x or flat), or a tiny native JSON for other scanners | `ingest.py` |
| Decompile | jadx once per run; class and method resolved; native/obfuscated/missing become UNVALIDATED | `decompile.py`, `javasrc.py` |
| Plan | deep links, exported activities and a monkey burst from the manifest. Optionally an LLM proposes the plan, but only allowlisted actions survive | `exercise.py` |
| Generate | Cloudflare Worker + Workers AI (Qwen 1.5 14B, temperature 0.1), any OpenAI-compatible endpoint, or offline templates | `providers.py`, `worker/` |
| Validate | six gating checks plus a dangerous-API policy check, before any device time is spent | `validator.py` |
| Execute | spawn the app suspended, attach, load hook, resume, exercise, collect (optionally screen-record: see `--record` below) | `executors/` |
| Classify | the signal library interprets the log; the LLM never decides a verdict | `signals.py` |
| Record | write the verdict to the evidence store; copy it onto any duplicates triage merged away | `graph.py` |
| **Report** | runs once, after every finding has a verdict: writes a grounded Markdown bug report for each PROVEN finding straight from the evidence already on disk -- no model, no new claims (see below) | `bugreport.py`, `impact.py`, `mastg.py` |

A raw MobSF report additionally goes through `swarm.py` *before* this graph even starts (see "Swarm triage" below) --
a separate, `Send`-based fan-out/fan-in subgraph that classifies, vendor-flags and prioritises every finding in
parallel, so the loop above only ever spends device time on findings it can actually test.

### The static validator

The LLM writes the hook; these checks decide whether it is allowed to run. Failing any one triggers a single
regeneration with the errors fed back. A second failure means UNVALIDATED.

1. Parses as JavaScript (`node --check`, because Frida runs modern JS; esprima as fallback)
2. Contains a `Java.perform(` call
3. `Java.use` targets exactly the finding's class
4. Hooks the requested method (`.method.implementation =`, overload-aware)
5. Produces observable output (`console.log` or `send`)
6. Calls the original implementation (a hook that does not breaks app flow and stops further firing)
7. *(extension)* Avoids dangerous APIs: `eval`, `Runtime.exec`, sockets, file writes, `Interceptor.replace`, memory writes

Advisory checks (never gating, stored with the evidence): method exists in the decompiled source; overload arity
matches; overloads disambiguated.

### The signal library (v1)

Hooks report through one line protocol, `HS|{"event": ...}`, so signals never parse free text.

| Finding type | PROVEN when | REFUTED when |
|---|---|---|
| Hardcoded cryptographic key | a 16/24/32-byte key seen at runtime equals a constant in the decompiled class (string, base64, hex or `byte[]` literal) | key value differs across calls: derived, not hardcoded |
| Cleartext HTTP transport | an `http://` URL to a non-loopback host is observed | only `https://` or loopback observed, or no external URL |
| Insecure RNG | `java.util.Random` / `Math.random` observed in a security-relevant method (identifier words like token, key, session, nonce) | `SecureRandom` observed, or no security context |
| TLS trust manager (`checkServerTrusted`) | the original call **accepted** a self-signed or expired chain | the original call **rejected** a chain (validation is in place) |
| TLS hostname verifier (`verify`) | returned `true` for a host the server certificate does not cover | returned `false` for such a host |

The two TLS signals are deliberately honest about what a hook can see: if the app only ever talked to well-configured
servers, a trust-all manager and a correct one look identical, so the verdict is UNVALIDATED with exactly that reason
and not a guess. Exercise the app against an endpoint with a bad certificate to decide.

A hook that never fires is UNREACHABLE. A hook that fires but gives the signal library nothing to decide on (for
example a key that matches no constant) is UNVALIDATED with that exact reason, not a guess.

## Swarm triage: a real app's MobSF report, not a hand-built one

A real app's MobSF report is noisy in a specific way: the same scanner rules fire on the app's own code and on
every bundled third-party SDK (analytics, fraud detection, MFA, crash reporting, ...), often dozens of them, and on
a heavily obfuscated release build the class names on both sides are equally unreadable (`A2.i`, `Jd.c`, ...). Point
`hooksmith run --report mobsf.json` at a raw MobSF report and, by default, it goes through `swarm.py` first: a real
[LangGraph `Send`-based fan-out/fan-in subgraph](https://langchain-ai.github.io/langgraph/concepts/low_level/#send),
not a sequential loop -- one parallel branch per raw finding, each one classifying its type, flagging whether the
class looks like the app's own code or a known vendor SDK package, and scoring its priority, before any of them
reach a device:

```
hooksmith run --report mobsf.json --apk app.apk --executor avd
  -> swarm triage: 9 testable (0 own-code, 6 vendor-likely), 1 skipped (no signal for that type yet)
```

**This never drops a finding outright.** Vendor-likely findings are annotated and deprioritised (lower severity +
vendor sorts after the same severity + own code), not discarded -- you can still see and validate them, just not
ahead of your own code. Findings of a type HookSmith has no signal for (anything outside the five in the table
above) are separated into `skipped`, with the reason stated, rather than silently fed into a pipeline that would
have to guess a verdict for them.

**Verified real limitation, not swept under the rug:** own-code detection compares a finding's class against the
app's declared manifest package. On a heavily R8-obfuscated app, the app's *own* classes can be repackaged outside
that declared package entirely (the same `defpackage`-style problem described under "Obfuscated apps" below, here
at classification time, before decompiling), so they come back tagged `own_code_likely: False` even though they
are the app's own code -- tested and confirmed against a synthetic report shaped like a real 49-finding scan of a
commercial app (`tests/test_swarm.py`). Severity-based priority still works correctly in that case; only the
own-code/vendor label is unreliable for that specific slice of findings.

Turn it off with `--no-swarm-triage` to feed every MobSF finding into the pipeline exactly as reported.

## Running against a device

### Local AVD (recommended; needs `/dev/kvm`)

```bash
uv sync --extra device            # adds the frida Python bindings
uv run hooksmith avd setup        # one-off: SDK cmdline-tools, emulator, API 33 Google APIs x86_64 image (~2 GB)
uv run hooksmith doctor
uv run hooksmith run --report mobsf.json --apk app.apk --executor avd --provider worker
```

The Google APIs image (not Play Store) matters: it allows `adb root`, which is what lets frida-server run. The
executor downloads the frida-server that matches your Python `frida` version. With Frida 17+ the Java bridge is no
longer built into the runtime, so hooks are bundled with `frida-java-bridge` through `frida-compile` (cached).

### Corellium

```bash
export CORELLIUM_API_TOKEN=...   CORELLIUM_PROJECT=...
uv run hooksmith run --report mobsf.json --apk app.apk --executor corellium
```

Creates (or reuses, with `--corellium-instance`) a virtual Android device through the REST API, then runs the same
ADB + Frida leg against it. Corellium exposes ADB on the instance's service IP over its VPN, so join Corellium
Connect first or pass `--corellium-adb host:port`.

> **Status:** the Corellium executor follows Corellium's public API client but has **not** been exercised against a
> live tenant. The AVD executor has (see the example below). Expect to adjust `flavor`/`os` for your plan.

### Any adb device

`--executor adb --serial <serial>` for a rooted phone or any existing emulator.

## The generator

`--provider worker` talks to the Cloudflare Worker in `worker/`:

```bash
cd worker && npm install
npx wrangler secret put HOOKSMITH_TOKEN
npx wrangler deploy
export HOOKSMITH_WORKER_URL=https://hooksmith.<you>.workers.dev  HOOKSMITH_WORKER_TOKEN=...
```

The Worker bundles the same prompt files as the CLI (`src/hooksmith/prompts/*.txt`); `tests/test_worker_parity.py`
proves both sides build byte-identical messages. Free tier covers a conference demo (10,000 Workers AI requests per
month, about USD 0.0005 per generation).

`--provider openai` accepts any OpenAI-compatible endpoint (Ollama, vLLM, LM Studio) via `--llm-url` / `--llm-model`.
`--provider template` uses deterministic offline hooks and needs no network at all.

## Evidence

```
runs/run-20261006-.../
  report.md  report.json  run.json  evidence.db
  bugs/<finding>.md      one grounded bug report per PROVEN finding (see below)
  findings/<finding>/
    source.java          the decompiled class the hook was written from
    hook.attempt1.js ... every generated hook, validated or not
    hook.js              the hook that actually ran
    validation.json      every check, for every attempt
    runtime.log          raw hook output
    verdict.json         verdict, reason, and what the signal library saw
    screen.mp4           screen recording, only if the run used --record
```

`run.json` records the APK hash, tool, model, temperature, prompt hash, Frida version and device, so a verdict can
be reproduced. `hooksmith evidence <run> <finding>` prints a bundle; `--executor replay --replay-from <run>` replays
recorded logs (that is how a pre-recorded device leg works on stage).

### What happens after a run: bug reports, written from impact

After every finding has a verdict, the `report` graph node writes `bugs/<id>.md` for each PROVEN one, structured
around **what an attacker can actually do**, not just what rule fired:

1. **Impact** -- a fixed, type-specific template (`impact.py`) filled in only with facts the signal library itself
   observed (the actual key bytes, the actual cleartext URL, the actual mismatched hostname, the actual self-signed
   cert's subject), explaining the attack an attacker in that position can mount. E.g. for a trust-all `TrustManager`:
   *"TLS's entire protection against interception rests on certificate validation; once it accepts anything, an
   attacker performing a machine-in-the-middle attack ... can present a certificate they generated themselves."*
2. **OWASP MASTG** -- the real MASTG-TEST (methodology) and MASTG-DEMO (worked example) ids this finding type
   corresponds to, each checked by fetching the live page, not guessed (see `mastg.py`).
3. What the signal library observed, exact repro steps (the real exercise plan + `frida -U -f <pkg> -l hook.js`),
   the runtime log, the hook itself, and a remediation suggestion.

**Deliberately not an LLM pass:** every sentence is pulled from evidence already on disk; nothing is invented or
re-judged. The CLI's final "what happens now" panel tells you what to do with each verdict bucket:

```
3 PROVEN      -> read runs/.../bugs/ (evidence, hook, exact repro steps, remediation) and file them
3 REFUTED     -> false positives, with proof. Safe to close in your scanner's report.
1 UNREACHABLE -> the hook never fired. Try --agent-plan, a longer --timeout, or --resume after exercising by hand
3 UNVALIDATED -> read findings/<id>/verdict.json for the reason (obfuscation, native, hallucination)
```

Regenerate reports for a finished run any time, or widen them to a full audit trail (including REFUTED, as "checked,
not vulnerable" records):

```bash
hooksmith bugreport runs/run-20261006-.../                       # PROVEN only, the default
hooksmith bugreport runs/run-20261006-.../ --verdicts PROVEN,REFUTED
hooksmith run ... --no-bug-reports                                # skip report generation entirely
```

### Proof for a demo: screen recording

`--record` (on `run` and `test`, adb-based executors -- avd/corellium/adb) captures the device's screen for the
duration of each finding's exercise and hook execution, and pulls it into `findings/<id>/screen.mp4`. The point is
an audience watching a live demo (or a reviewer afterwards) can see the actual taps happen on the actual VM screen
in sync with the "tap Login", "deeplink ..." lines the CLI prints live -- not just take the log on trust. Verified
on a real AVD: a 4-second and a 7-second H.264 1080x2400 clip, both landing in the evidence folder next to the hook
and the log that the recording is proof of.

```bash
hooksmith run --report mobsf.json --apk app.apk --executor avd --record
```

## Try it on a real app

`examples/vulnlab/` is a small deliberately vulnerable app with one finding in each bucket. `./build.sh` builds it
with the Android SDK build tools; `findings.json` lists the findings. See `examples/vulnlab/README.md`.

## Benchmark a model on OWASP MASTG

```bash
uv run hooksmith bench --provider template                       # the ceiling: known-good hooks
uv run hooksmith bench --provider worker --repeats 5 --out qwen.md   # your Workers AI Worker
uv run hooksmith bench --provider openai --llm-url http://localhost:11434/v1 --llm-model <any coding model>
```

It clones [OWASP MASTG](https://github.com/OWASP/mastg) (CC BY-SA 4.0) into the cache, never into this repo, and for
each supported demo asks the provider for a hook, runs the static validator and gives one retry with the errors. The
report shows first-pass and after-retry validity, the most common validator failures, and a **coverage list of MASTG
demos HookSmith cannot test yet**. It is static validation only: a hook that passes still has to survive a device.

## Use it as a test harness for your own app

Point HookSmith at an app you are authorised to test, along with your scanner's report, and let the exit code gate
your build.

```bash
# regression-test your app: pin the verdicts you expect, fail on any difference
hooksmith run --report mobsf.json --apk app.apk --executor avd --expect expected.json

# policy gates: fail the build on any PROVEN finding of high severity or above, and on too many unknowns
hooksmith run --report mobsf.json --apk app.apk --executor avd --fail-on PROVEN:high --max-unvalidated 5
```

`expected.json` maps a finding id (or `Class.method`) to one of the four verdicts (see `examples/vulnlab/expected.json`).
The run exits 1 and prints exactly what differed. `examples/ci/hooksmith.yml` is a GitHub Actions starting point
that uploads the evidence folder as a build artifact.

### Reaching the code (pathways)

The default plan launches the app, opens the manifest's deep links and exported activities, then **explores the UI**
and finishes with a short monkey burst. Exploration is navigation only (`src/hooksmith/ui.py`): it reads the screen with
`uiautomator`, taps controls that belong to the target package, presses Back if the app is left, and never taps
anything labelled like delete, log out, purchase or payment. It never types text or changes settings. An optional
agent planner (`--agent-plan`) can propose a plan, but only allowlisted steps survive.

### The hook-writer and repair loop

1. The model writes a hook (the prompt includes a worked example per finding type).
2. The static validator checks it; on failure the model gets the exact errors back, once.
3. The hook runs. If Frida rejects it on the device (class not found, no such overload) or it throws before the
   method ever fires, the real Frida error goes back to the model for **one** on-device repair.
4. After that the finding is UNVALIDATED with the Frida error as the reason. The loops are bounded; nothing
   retries forever.

Only the signal library decides verdicts. The model never does.

## What has and has not been run

| Part | Status |
|---|---|
| Pipeline (LangGraph), validator, signal library, evidence store, report | unit and golden tests, plus the bundled demo |
| ADB + Frida executor on a local **AVD** (Android 13, x86_64, Google APIs, Frida 17.22) | **run for real** on VulnLab: every finding lands in the expected bucket, including an obfuscated R8-release build (`tests/test_device_integration.py`, opt-in) |
| **Corellium**: a real Android 16 arm64 device, over ADB + the Corellium VPN | **run for real**: all 7 original VulnLab findings landed in the expected bucket. The Corellium **REST API client** (create/start/stop an instance) is tested against a mock only -- the live run used an already-running device, not the API-driven lifecycle |
| **Swarm triage** (`swarm.py`): LangGraph `Send` fan-out/fan-in over a raw MobSF report | real graph, run end to end through `run_assessment` against a real MobSF-shaped report, verdicts matching the non-swarm path exactly (`tests/test_demo_pipeline.py`); vendor/own-code heuristics tested against a report shaped like a real 49-finding commercial-app scan |
| **Bug reports** (impact + MASTG cross-references) | built from real recorded device evidence (VulnLab's TLS findings) and checked by eye; every MASTG URL verified by fetching the live page, not guessed |
| **`--record` screen recording** | run for real on the AVD: two real H.264 clips pulled and validated with `ffprobe` (not just checked for non-zero bytes) |
| The recorded logs from all of the above | replayed hermetically in CI (`tests/test_vulnlab_replay.py`, `tests/test_vulnlab_obfuscated.py`) |
| jadx decompile path | run for real on VulnLab, including an R8-obfuscated build (jadx 1.5.6) |
| Cloudflare Worker | typechecks, bundles (`wrangler deploy --dry-run`), prompts proven byte-identical to the CLI. **Not deployed** and Workers AI output quality (Qwen 1.5 14B) has **not** been measured here |
| OpenAI-compatible provider | request shape tested; not run against a model here |
| iOS | out of scope in v1 |

## Field notes (things that bit during the first real device run)

These are in the code now, and they are worth knowing if you write Frida tooling yourself.

1. **`console.log` is not a `message` in modern Frida.** Since Frida 15 it goes through `script.set_log_handler`.
   Register one, or your hook runs, prints to the host's stdout, and every finding looks UNREACHABLE.
2. **Frida 17 removed the Java bridge from the runtime.** Hooks that call `Java.perform` must be bundled with
   `frida-java-bridge` via `frida-compile`. The executor does this and caches the result.
3. **Hooks on the app's own classes can silently never fire** (framework hooks like `Random.nextInt` did fire). ART had
   compiled around the hooked methods. Calling `Java.deoptimizeEverything()` before installing hooks fixed it. The
   executor does that by default (`HOOKSMITH_DEOPT=0` turns it off).
4. **A byte[] argument is not necessarily a key.** The signal library trusts keys seen entering `SecretKeySpec` and
   only falls back to method arguments when nothing better was observed.
5. **Spawn, do not attach.** Crypto and config code often runs in `Application.onCreate`.

## Obfuscated apps

Tested for real against a VulnLab build run through R8 in release/minify mode (`examples/vulnlab/build-obfuscated.sh`):
every class and method renamed, two classes horizontally merged by R8, and every renamed class moved into Java's
default package (`-repackageclasses ''`, which a real release build's shrinker does routinely to save bytes). The
findings were produced by HookSmith's own `scan` command reading the obfuscated jadx output -- the same obfuscated
names a real scanner running against this APK would see.

| What R8 did | Result |
|---|---|
| Plain renaming (class `TrustAllManager` -> `e`, method names kept because they implement an interface) | **Works.** Resolved and hooked correctly: PROVEN. |
| Renaming into Java's **default package** (`-repackageclasses ''`) | **Works, after a real fix.** jadx represents this with a literal `package defpackage;` line (its own long-standing placeholder, confirmed against jadx's own jar), and a class name built from the jadx file path -- which both our own scanner and a tool like MobSF produce -- comes out as `defpackage.Foo`. `Java.use("defpackage.Foo")` doesn't exist and fails with `ClassNotFoundException`. `real_class_name()` in `javasrc.py` now recovers the true runtime name from the decompiled source instead of the file path. Verified on a real device: three findings went from a hard `ClassNotFoundException` to correct PROVEN/REFUTED verdicts (`tests/test_vulnlab_obfuscated.py`). |
| R8 **horizontal class merging** (two unrelated classes folded into one, dispatched by a synthetic `$r8$classId` field) | **Mostly works, with a real caveat.** The merged method still runs both original behaviours, so a hook on it sees both. If either one does the bad thing, the verdict is correctly PROVEN (verified: a trust-all verifier merged with a correct one still came back PROVEN) -- but HookSmith cannot tell you *which* of the two original findings was responsible, because that distinction no longer exists in the compiled code. |
| Renaming **both class and method** to short, information-free names (`class b { void a(...) }`) | **Declines, honestly.** `obfuscation_score()` crosses its threshold and the finding is UNVALIDATED with the reason stated, rather than attempting a hook with no semantic grounding for the model to go on. |
| **Method-level inlining** (R8 fully inlined several small classes' logic straight into the caller) | **Not handled, and currently gives a wrong verdict.** When R8 inlines two or more originally-separate methods into one (here, three different crypto calls ended up inside `MainActivity.work()`), HookSmith still hooks that one method, but its signals -- "did the key differ across calls", "was this a security-relevant call" -- see all of the inlined calls mixed together and can conclude REFUTED on a finding that is actually true. This is a real false negative, reproduced and recorded in `examples/vulnlab/recorded-obfuscated/`, not a hypothetical. Per-call-site (not per-method) hooking would fix it; v1 does not do that. |

## Known limitations

Acknowledged, not hidden. UNVALIDATED exists because these are real.

- **Native JNI methods:** all native findings are UNVALIDATED in v1; `Interceptor.attach` needs offsets the LLM cannot reliably produce.
- **Obfuscation:** see the table above for exactly what does and does not work, verified on a real device.
- **Hallucination past the validator:** the checks catch structural errors, not a well-formed hook on the wrong overload.
- **UI exercise gaps:** methods behind complex UI flows may never fire, so the verdict is UNREACHABLE, not a guess.
- **Android only.** iOS would need class-dump integration and a different hook format.
- Method lookup uses a small regex reader for jadx output, not a full Java parser.

## Development

```bash
uv sync --extra device
uv run pytest -q                    # unit + golden pipeline tests
uv run ruff check src tests
cd worker && npm install && ./node_modules/.bin/tsc --noEmit
```

## Authorised use only

HookSmith runs generated code inside a target app on a device you control. Use it on apps you are permitted to test,
on devices or virtual devices you own or rent for that purpose.

MIT licensed.
