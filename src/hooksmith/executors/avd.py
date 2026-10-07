"""Android Virtual Device executor: boots a local headless emulator (KVM on Linux) and delegates to ADB+Frida.

`hooksmith avd setup` installs cmdline-tools, the emulator and an API 33 *Google APIs* x86_64 image. The Google APIs
image (not Play Store) matters: it allows `adb root`, which is what lets frida-server run without su tricks.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
import urllib.request
import zipfile
from pathlib import Path

from .adb import Adb, AdbError, AdbFridaExecutor

CMDLINE_TOOLS_URL = "https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"
DEFAULT_AVD = "hooksmith"
DEFAULT_API = 33


def sdk_root() -> Path:
    for var in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        if os.environ.get(var):
            return Path(os.environ[var])
    return Path.home() / "Android" / "Sdk"


def tool(*rel: str) -> str | None:
    p = sdk_root().joinpath(*rel)
    return str(p) if p.exists() else None


def sdk_tools() -> dict[str, str | None]:
    return {
        "sdkmanager": tool("cmdline-tools", "latest", "bin", "sdkmanager"),
        "avdmanager": tool("cmdline-tools", "latest", "bin", "avdmanager"),
        "emulator": tool("emulator", "emulator") or shutil.which("emulator"),
        "adb": tool("platform-tools", "adb") or shutil.which("adb"),
    }


def system_image(api: int = DEFAULT_API) -> str:
    return f"system-images;android-{api};google_apis;x86_64"


def _env() -> dict[str, str]:
    e = dict(os.environ)
    e["ANDROID_SDK_ROOT"] = str(sdk_root())
    e["ANDROID_HOME"] = str(sdk_root())
    return e


def setup_sdk(api: int = DEFAULT_API, name: str = DEFAULT_AVD, log=print) -> None:
    """Idempotent: download cmdline-tools if missing, install packages, create the AVD."""
    root = sdk_root()
    root.mkdir(parents=True, exist_ok=True)
    if not tool("cmdline-tools", "latest", "bin", "sdkmanager"):
        log(f"downloading Android command-line tools to {root} ...")
        zpath = root / "cmdline-tools.zip"
        urllib.request.urlretrieve(CMDLINE_TOOLS_URL, zpath)  # noqa: S310 - fixed https Google URL
        with zipfile.ZipFile(zpath) as z:
            z.extractall(root / "_tmp")
        (root / "cmdline-tools").mkdir(exist_ok=True)
        shutil.move(str(root / "_tmp" / "cmdline-tools"), str(root / "cmdline-tools" / "latest"))
        shutil.rmtree(root / "_tmp", ignore_errors=True)
        zpath.unlink(missing_ok=True)
        for f in (root / "cmdline-tools" / "latest" / "bin").iterdir():
            f.chmod(0o755)
    sdkm = tool("cmdline-tools", "latest", "bin", "sdkmanager")
    avdm = tool("cmdline-tools", "latest", "bin", "avdmanager")
    log("accepting licences and installing platform-tools, emulator and the system image (large download) ...")
    subprocess.run(f"yes | {sdkm} --licenses >/dev/null 2>&1", shell=True, env=_env(), timeout=300)  # noqa: S602
    subprocess.run(
        [sdkm, "platform-tools", "emulator", f"platforms;android-{api}", "build-tools;34.0.0", system_image(api)],
        env=_env(),
        check=True,
        timeout=3600,
    )
    listing = subprocess.run([avdm, "list", "avd", "-c"], env=_env(), capture_output=True, text=True).stdout.split()
    if name not in listing:
        log(f"creating AVD {name!r}")
        subprocess.run(
            [avdm, "create", "avd", "-n", name, "-k", system_image(api), "-d", "pixel_6", "--force"],
            input="no\n",
            text=True,
            env=_env(),
            check=True,
            timeout=300,
        )


class AvdExecutor(AdbFridaExecutor):
    name = "avd"

    def __init__(
        self,
        avd: str = DEFAULT_AVD,
        console_port: int = 5554,
        headless: bool = True,
        adb: str | None = None,
        boot_timeout: int = 300,
        keep_running: bool = False,
    ):
        tools = sdk_tools()
        super().__init__(serial=f"emulator-{console_port}", adb=adb or tools["adb"])
        self.avd, self.console_port, self.headless = avd, console_port, headless
        self.boot_timeout, self.keep_running = boot_timeout, keep_running
        self._emu: subprocess.Popen | None = None
        self._emulator = tools["emulator"]

    def _running(self) -> bool:
        out = subprocess.run([self.adb.adb, "devices"], capture_output=True, text=True).stdout
        return any(ln.startswith(self.adb.serial or "") and "device" in ln for ln in out.splitlines()[1:])

    def prepare(self) -> dict:
        if not self._running():
            if not self._emulator:
                raise AdbError("Android emulator not found. Run `hooksmith avd setup` (or set ANDROID_SDK_ROOT).")
            cmd = [
                self._emulator,
                "-avd",
                self.avd,
                "-port",
                str(self.console_port),
                "-no-audio",
                "-no-boot-anim",
                "-no-snapshot",
                "-gpu",
                "swiftshader_indirect",
                "-accel",
                "on",
                "-netdelay",
                "none",
            ]
            if self.headless:
                cmd.append("-no-window")
            self._emu = subprocess.Popen(cmd, env=_env(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.time() + 60
            while time.time() < deadline and not self._running():
                if self._emu.poll() is not None:
                    raise AdbError(f"emulator exited early (code {self._emu.returncode}); is /dev/kvm accessible?")
                time.sleep(2)
        self.adb.wait_boot(self.boot_timeout)
        return super().prepare()

    def close(self) -> None:
        super().close()
        if self._emu and not self.keep_running:
            try:
                Adb(self.adb.serial, self.adb.adb).run("emu", "kill", check=False, timeout=20)
                self._emu.wait(timeout=30)
            except Exception:  # noqa: BLE001
                self._emu.kill()
