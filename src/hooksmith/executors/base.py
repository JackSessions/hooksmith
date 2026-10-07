"""Executor interface: run one validated hook against the installed app and return what it printed."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ..manifest import Manifest
from ..models import ExecutionResult, Finding


@dataclass
class RunSpec:
    """Everything an executor needs to exercise one hook."""

    finding: Finding
    hook_js: str
    package: str
    manifest: Manifest = field(default_factory=Manifest)
    timeout_s: int = 45
    settle_s: int = 4  # keep listening this long after the first "call" event, then stop early
    steps: list[str] | None = None  # explicit exercise plan (see exercise.py); None = auto
    record: bool = False  # screen-record the device for this finding (adb-based executors only); see ExecutionResult.screen


class Executor(ABC):
    name = "base"

    def prepare(self) -> dict:
        """Boot/connect the device, start frida-server. Returns device info for the evidence bundle."""
        return {}

    def install(self, apk_path: str) -> str | None:
        """Install the APK once per run. Returns the package name if the executor can read it."""
        return None

    @abstractmethod
    def run(self, spec: RunSpec) -> ExecutionResult: ...

    def close(self) -> None:  # noqa: B027 - optional hook, not abstract
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
