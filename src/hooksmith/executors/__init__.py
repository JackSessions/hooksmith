from .base import Executor, RunSpec

__all__ = ["Executor", "RunSpec", "make_executor"]


def make_executor(kind: str, **kw) -> Executor:
    """Imports are lazy so `hooksmith run --executor none` works without frida installed."""
    if kind == "avd":
        from .avd import AvdExecutor

        return AvdExecutor(avd=kw.get("avd") or "hooksmith", adb=kw.get("adb"), headless=not kw.get("window", False))
    if kind == "adb":
        from .adb import AdbFridaExecutor

        return AdbFridaExecutor(serial=kw.get("serial"), adb=kw.get("adb"))
    if kind == "corellium":
        from .corellium import CorelliumExecutor

        return CorelliumExecutor(
            endpoint=kw.get("corellium_endpoint"),
            api_token=kw.get("corellium_token"),
            project=kw.get("corellium_project"),
            instance_id=kw.get("corellium_instance"),
            adb_target=kw.get("corellium_adb"),
        )
    if kind == "replay":
        from pathlib import Path

        from .replay import ReplayExecutor

        if not kw.get("replay_from"):
            raise ValueError("--replay-from RUN_DIR is required with --executor replay")
        return ReplayExecutor(Path(kw["replay_from"]))
    if kind == "none":
        from .replay import NullExecutor

        return NullExecutor()
    raise ValueError(f"unknown executor {kind!r}")
