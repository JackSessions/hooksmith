"""ADB + frida-server executor. The AVD and Corellium executors are thin lifecycle wrappers around this.

The device leg, per finding:
    spawn the app suspended -> attach -> load the hook -> resume -> exercise the app -> collect output
Spawning matters: crypto and config code often runs in Application.onCreate, before an attach could land.
"""

from __future__ import annotations

import hashlib
import json
import lzma
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

from ..models import ExecutionResult
from ..signals import PREFIX, parse_events
from .base import Executor, RunSpec

CACHE = Path(os.environ.get("HOOKSMITH_CACHE", Path.home() / ".cache" / "hooksmith"))
ABI_TO_FRIDA = {"x86_64": "x86_64", "x86": "x86", "arm64-v8a": "arm64", "armeabi-v7a": "arm"}
DEVICE_DIR = "/data/local/tmp"
SCREENRECORD_MAX_S = 180  # Android's hard per-invocation cap


class AdbError(RuntimeError):
    pass


class Adb:
    def __init__(self, serial: str | None = None, adb: str | None = None):
        self.adb = adb or shutil.which("adb") or str(Path.home() / "Android/Sdk/platform-tools/adb")
        self.serial = serial

    def _base(self) -> list[str]:
        return [self.adb] + (["-s", self.serial] if self.serial else [])

    def run(self, *args: str, timeout: int = 60, check: bool = True) -> subprocess.CompletedProcess:
        p = subprocess.run(self._base() + list(args), capture_output=True, text=True, timeout=timeout)
        if check and p.returncode != 0:
            raise AdbError(f"adb {' '.join(args)[:80]}: {(p.stderr or p.stdout).strip()[:300]}")
        return p

    def shell(self, cmd: str, timeout: int = 60, check: bool = False) -> str:
        return self.run("shell", cmd, timeout=timeout, check=check).stdout.strip()

    def getprop(self, name: str) -> str:
        return self.shell(f"getprop {name}")

    def wait_boot(self, timeout: int = 240) -> None:
        self.run("wait-for-device", timeout=timeout)
        end = time.time() + timeout
        while time.time() < end:
            if self.getprop("sys.boot_completed") == "1":
                return
            time.sleep(2)
        raise AdbError("device did not finish booting")

    def try_root(self) -> bool:
        p = self.run("root", check=False, timeout=30)
        time.sleep(1.5)
        try:
            self.run("wait-for-device", timeout=30)
        except Exception:  # noqa: BLE001
            pass
        out = self.shell("id")
        return (
            "uid=0" in out
            or "restarting adbd as root" in (p.stdout + p.stderr)
            or "already running as root" in (p.stdout + p.stderr)
        )


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---- frida-server ---------------------------------------------------------------------------


def frida_version() -> str:
    import frida  # imported lazily: the "device" extra

    return frida.__version__


def fetch_frida_server(version: str, arch: str) -> Path:
    CACHE.mkdir(parents=True, exist_ok=True)
    out = CACHE / f"frida-server-{version}-android-{arch}"
    if out.exists():
        return out
    url = f"https://github.com/frida/frida/releases/download/{version}/frida-server-{version}-android-{arch}.xz"
    with urllib.request.urlopen(url, timeout=120) as r:  # noqa: S310 - fixed https GitHub URL
        data = lzma.decompress(r.read())
    out.write_bytes(data)
    out.chmod(0o755)
    return out


# ---- Java bridge bundling (Frida >= 17 no longer ships it inside the runtime) --------------------

AGENT_DIR = CACHE / "agent"
# ART can compile/inline app methods so a Frida hook on them never fires (seen on x86_64 emulators). Deoptimising before
# any hook is installed fixes it. Set HOOKSMITH_DEOPT=0 to skip it (it slows the app down a little).
DEOPT = os.environ.get("HOOKSMITH_DEOPT", "1") != "0"
_DEOPT_JS = "Java.perform(function () { try { Java.deoptimizeEverything(); } catch (e) {} });\n" if DEOPT else ""
_BRIDGE_JS = 'import Java from "frida-java-bridge";\nglobalThis.Java = Java;\n' + _DEOPT_JS


def needs_bridge(version: str) -> bool:
    return int(version.split(".")[0]) >= 17


def bundle_hook(js: str) -> str:
    """Compile hook + frida-java-bridge into one script with frida-compile. Cached by content hash."""
    AGENT_DIR.mkdir(parents=True, exist_ok=True)
    pkg = AGENT_DIR / "package.json"
    if not (AGENT_DIR / "node_modules" / "frida-compile").exists():
        pkg.write_text(json.dumps({"name": "hooksmith-agent", "private": True, "type": "module"}))
        r = subprocess.run(
            ["npm", "install", "--no-audit", "--no-fund", "--silent", "frida-compile", "frida-java-bridge"],
            cwd=AGENT_DIR,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if r.returncode != 0:
            raise AdbError(f"npm install frida-compile failed: {r.stderr.strip()[-300:]}")
    key = hashlib.sha256(js.encode()).hexdigest()[:16]
    work = AGENT_DIR / "work" / key
    out = work / "out.js"
    if out.exists():
        return out.read_text()
    work.mkdir(parents=True, exist_ok=True)
    (work / "bridge.js").write_text(_BRIDGE_JS)
    (work / "hook.js").write_text(js)
    (work / "entry.js").write_text('import "./bridge.js";\nimport "./hook.js";\n')
    r = subprocess.run(
        [str(AGENT_DIR / "node_modules/.bin/frida-compile"), "entry.js", "-o", "out.js"],
        cwd=work,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if r.returncode != 0 or not out.exists():
        raise AdbError(f"frida-compile failed: {(r.stderr or r.stdout).strip()[-400:]}")
    return out.read_text()


# ---- the executor ---------------------------------------------------------------------------


class AdbFridaExecutor(Executor):
    name = "adb"

    def __init__(self, serial: str | None = None, adb: str | None = None, frida_port: int | None = None):
        self.adb = Adb(serial, adb)
        self.port = frida_port or free_port()
        self._device = None
        self.info: dict = {}

    # -- lifecycle -------------------------------------------------------------------------
    def prepare(self) -> dict:
        self.adb.wait_boot()
        rooted = self.adb.try_root()
        abi = self.adb.getprop("ro.product.cpu.abi")
        arch = ABI_TO_FRIDA.get(abi)
        if not arch:
            raise AdbError(f"unsupported device ABI {abi!r}")
        ver = frida_version()
        server = fetch_frida_server(ver, arch)
        self.adb.run("push", str(server), f"{DEVICE_DIR}/hs-frida-server", timeout=120)
        self.adb.shell(f"chmod 755 {DEVICE_DIR}/hs-frida-server")
        if rooted:
            self.adb.shell("setenforce 0")  # permissive on userdebug emulators; harmless failure elsewhere
        self.adb.shell("pkill -f hs-frida-server" if rooted else "su -c 'pkill -f hs-frida-server'")
        launch = f"{DEVICE_DIR}/hs-frida-server -l 127.0.0.1:{self.port}"
        cmd = f"nohup {launch} >/dev/null 2>&1 &" if rooted else f"su -c 'nohup {launch} >/dev/null 2>&1 &'"
        subprocess.Popen(self.adb._base() + ["shell", cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.adb.run("forward", f"tcp:{self.port}", f"tcp:{self.port}")
        import frida

        mgr = frida.get_device_manager()
        for _ in range(30):
            try:
                self._device = mgr.add_remote_device(f"127.0.0.1:{self.port}")
                self._device.enumerate_processes()
                break
            except Exception:  # noqa: BLE001
                time.sleep(1)
        else:
            raise AdbError("could not connect to frida-server on the device")
        self.info = {
            "executor": self.name,
            "serial": self.adb.serial,
            "model": self.adb.getprop("ro.product.model"),
            "android": self.adb.getprop("ro.build.version.release"),
            "sdk": self.adb.getprop("ro.build.version.sdk"),
            "abi": abi,
            "rooted": rooted,
            "frida": ver,
        }
        return self.info

    def install(self, apk_path: str) -> str | None:
        self.adb.run("install", "-r", "-g", "-t", apk_path, timeout=300)
        return None

    def close(self) -> None:
        try:
            self.adb.shell("pkill -f hs-frida-server")
            self.adb.run("forward", "--remove", f"tcp:{self.port}", check=False)
        except Exception:  # noqa: BLE001
            pass

    # -- exercising ------------------------------------------------------------------------
    def iter_exercise(self, spec: RunSpec):
        """Yield after each step so the caller can stop as soon as the hook has fired."""
        from ..exercise import plan_steps

        for step in spec.steps or plan_steps(spec.package, spec.manifest, spec.finding):
            kind, _, arg = step.partition(" ")
            try:
                if kind == "launch":
                    self.adb.shell(f"monkey -p {spec.package} -c android.intent.category.LAUNCHER 1", timeout=30)
                elif kind == "deeplink":
                    self.adb.shell(f"am start -W -a android.intent.action.VIEW -d '{arg}' {spec.package}", timeout=30)
                elif kind == "activity":
                    self.adb.shell(f"am start -W -n {spec.package}/{arg}", timeout=30)
                elif kind == "monkey":
                    # chunks of 20 events, so a hook that fires early does not wait for the whole burst
                    remaining = int(arg or 60)
                    while remaining > 0:
                        n = min(20, remaining)
                        self.adb.shell(
                            f"monkey -p {spec.package} --throttle 250 --ignore-crashes --ignore-timeouts "
                            f"--pct-syskeys 0 --pct-appswitch 0 {n}",
                            timeout=60,
                        )
                        remaining -= n
                        yield f"monkey {n}"
                    continue
                elif kind == "wait":
                    time.sleep(float(arg or 2))
                elif kind == "explore":
                    visited: set[str] = set()
                    for _ in range(min(int(arg or 6), 20)):
                        desc = self._explore_once(spec.package, visited)
                        yield f"explore {desc}"
                        if desc.startswith("nothing safe"):
                            break  # nothing new to tap: do not burn the rest of the budget on an empty screen
                    continue
                else:
                    continue
                yield step
            except Exception:  # noqa: BLE001 - one failed step must not stop the rest
                yield step + "  (failed)"

    def _explore_once(self, package: str, visited: set[str]) -> str:
        """Dump the screen, tap one safe unvisited control of the target app, or press Back if we left it."""
        from ..ui import parse_targets, pick

        out = self.adb.shell("uiautomator dump --compressed /sdcard/hs-ui.xml >/dev/null 2>&1; cat /sdcard/hs-ui.xml", timeout=30)
        targets = parse_targets(out, package)
        if not targets:
            focus = self.adb.shell("dumpsys window | grep -m1 mCurrentFocus")
            if package not in focus:
                self.adb.shell("input keyevent 4")  # BACK: we wandered out of the app
                return "back (left the app)"
            return "nothing safe to tap"
        t = pick(targets, visited)
        if t is None:
            self.adb.shell("input keyevent 4")
            return "back (screen exhausted)"
        visited.add(t.key)
        self.adb.shell(f"input tap {t.x} {t.y}")
        time.sleep(1.0)
        return f"tap {t.label or t.key}"

    def _pull_recording(self, remote: str, res: ExecutionResult) -> None:
        """Stop the in-flight screenrecord cleanly (SIGINT, not --time-limit's hard kill, so the mp4 container
        finalizes properly) and pull it to a local temp file. Sets res.screen; caller moves it into the evidence
        store. Best-effort: a failed recording never fails the finding it was recording.
        """
        self.adb.shell("pkill -INT -f screenrecord", timeout=10)
        time.sleep(1.5)  # give the device a moment to finish writing the container
        local_dir = Path(tempfile.mkdtemp(prefix="hooksmith-rec-"))
        local = local_dir / "screen.mp4"
        self.adb.run("pull", remote, str(local), timeout=60)
        self.adb.shell(f"rm -f {remote}")
        if local.exists() and local.stat().st_size > 0:
            res.screen = str(local)

    # -- one hook --------------------------------------------------------------------------
    def run(self, spec: RunSpec) -> ExecutionResult:
        import frida

        t0 = time.time()
        res = ExecutionResult(device=self.info)
        log: list[str] = []
        dev = self._device
        pid = session = script = None
        rec_remote: str | None = None
        try:
            source = spec.hook_js
            if needs_bridge(frida.__version__):
                source = bundle_hook(source)  # bridge + deoptimise prelude + hook
            else:
                source = _DEOPT_JS + source
            self.adb.shell(f"am force-stop {spec.package}")
            pid = dev.spawn([spec.package])
            session = dev.attach(pid)
            script = session.create_script(source)

            def on_message(message, data):  # noqa: ANN001
                if message["type"] == "log":
                    log.append(str(message["payload"]))
                elif message["type"] == "send":
                    p = message["payload"]
                    log.append(PREFIX + json.dumps(p) if isinstance(p, dict) else str(p))
                elif message["type"] == "error":
                    log.append(f"[frida error] {message.get('description', message)}")

            def on_log(level, text):  # noqa: ANN001
                # Frida >= 15 routes console.log() here, not through "message"
                log.append(str(text) if level == "info" else f"[frida {level}] {text}")

            script.set_log_handler(on_log)
            script.on("message", on_message)
            try:
                script.load()
            except Exception as exc:  # noqa: BLE001 - e.g. ClassNotFoundException, no such overload
                res.load_error = f"{type(exc).__name__}: {exc}"
                raise
            res.attached = True
            dev.resume(pid)

            if spec.record:
                rec_remote = f"{DEVICE_DIR}/hs-{_dev_safe(spec.finding.id)}.mp4"
                self.adb.shell(f"rm -f {rec_remote}")
                limit = min(spec.timeout_s + spec.settle_s + 10, SCREENRECORD_MAX_S)
                subprocess.Popen(
                    self.adb._base() + ["shell", f"screenrecord --time-limit {limit} {rec_remote}"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                time.sleep(1)  # let screenrecord actually start before the exercise plan begins

            end = t0 + spec.timeout_s
            settle_until = None

            def fired_now() -> bool:
                return any(e["event"] == "call" for e in parse_events(log))

            for step in self.iter_exercise(spec):
                res.exercised.append(step)
                if fired_now() and settle_until is None:
                    settle_until = time.time() + spec.settle_s
                if settle_until and time.time() >= settle_until:
                    break
                if time.time() >= end:
                    break
            while time.time() < end:  # exercise done: keep listening (background threads, delayed calls)
                time.sleep(0.5)
                if settle_until is None and fired_now():
                    settle_until = time.time() + spec.settle_s
                if settle_until and time.time() >= settle_until:
                    break
            errs = [ln for ln in log if ln.startswith(("[frida error]", "[frida warning]"))]
            if errs and not parse_events(log):
                res.error = errs[0]
        except Exception as exc:  # noqa: BLE001
            res.error = f"{type(exc).__name__}: {exc}"
        finally:
            for fn in (lambda: script and script.unload(), lambda: session and session.detach()):
                try:
                    fn()
                except Exception:  # noqa: BLE001
                    pass
            if rec_remote:
                try:
                    self._pull_recording(rec_remote, res)
                except Exception:  # noqa: BLE001 - recording is best-effort, never fail the finding over it
                    pass
            try:
                self.adb.shell(f"am force-stop {spec.package}")
            except Exception:  # noqa: BLE001
                pass
        res.log = log
        res.duration_s = round(time.time() - t0, 2)
        return res


def _dev_safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:80] or "rec"


def package_from_apk(apk: str) -> str | None:
    """Best-effort package name via aapt2/aapt if present on PATH or in the Android SDK."""
    for tool in ("aapt2", "aapt"):
        exe = shutil.which(tool) or next(iter(sorted((Path.home() / "Android/Sdk/build-tools").glob(f"*/{tool}"))), None)
        if exe:
            out = subprocess.run([str(exe), "dump", "badging", apk], capture_output=True, text=True).stdout
            m = re.search(r"package: name='([^']+)'", out)
            if m:
                return m.group(1)
    return None


_ = tempfile  # kept for downstream executors
