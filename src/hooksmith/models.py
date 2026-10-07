"""Core data model. The four verdicts are the whole point of the tool: no fifth bucket."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    PROVEN = "PROVEN"  # hook attached, method called, behaviour matches the claim
    REFUTED = "REFUTED"  # hook attached, method called, behaviour contradicts the claim
    UNREACHABLE = "UNREACHABLE"  # hook attached, method never fired on exercised paths
    UNVALIDATED = "UNVALIDATED"  # hook could not be generated/attached; reason recorded


VERDICT_HELP = {
    Verdict.PROVEN: "Hook attached. Method called. Observed behaviour matches the claim. Log kept as evidence.",
    Verdict.REFUTED: "Hook attached. Method called. Observed behaviour contradicts the claim. False positive, with evidence.",
    Verdict.UNREACHABLE: "Hook attached but the method never fired on the exercised paths. Possibly real, possibly dead code.",
    Verdict.UNVALIDATED: "Hook could not be generated or attached (obfuscation, native, jadx failure, hallucination). Reason recorded.",
}


class FindingType(str, Enum):
    HARDCODED_KEY = "hardcoded_key"
    CLEARTEXT_HTTP = "cleartext_http"
    INSECURE_RANDOM = "insecure_random"
    TLS_TRUST_ALL = "tls_trust_all"  # X509TrustManager.checkServerTrusted that accepts bad chains
    HOSTNAME_VERIFIER = "hostname_verifier"  # HostnameVerifier.verify that accepts any host
    UNKNOWN = "unknown"


class Finding(BaseModel):
    id: str
    title: str
    type: FindingType = FindingType.UNKNOWN
    severity: str = "info"
    description: str = ""
    class_name: str | None = None  # dotted, e.g. com.example.crypto.Vault (inner: Outer$Inner)
    method: str | None = None  # None = let the decompile stage choose one
    param_types: list[str] | None = None  # optional, used to pick the right overload
    file_path: str | None = None
    lines: list[int] = Field(default_factory=list)
    source: str = "unknown"  # which scanner produced it
    raw: dict[str, Any] = Field(default_factory=dict)


class CheckResult(BaseModel):
    name: str
    passed: bool
    detail: str = ""
    gating: bool = True  # advisory checks never block execution


class ValidationResult(BaseModel):
    ok: bool
    checks: list[CheckResult]

    @property
    def errors(self) -> list[str]:
        return [f"{c.name}: {c.detail}" for c in self.checks if c.gating and not c.passed]

    @property
    def warnings(self) -> list[str]:
        return [f"{c.name}: {c.detail}" for c in self.checks if not c.gating and not c.passed]


class HookAttempt(BaseModel):
    n: int
    js: str
    raw: str = ""
    model: str = ""
    validation: ValidationResult | None = None


class ExecutionResult(BaseModel):
    attached: bool = False
    error: str | None = None
    log: list[str] = Field(default_factory=list)  # one entry per hook output line
    duration_s: float = 0.0
    device: dict[str, Any] = Field(default_factory=dict)
    exercised: list[str] = Field(default_factory=list)  # what we did to the app
    load_error: str | None = None  # the hook threw while loading (class/overload not found...): repairable
    screen: str | None = None  # path to a screen.mp4 in the evidence folder, if --record was used


class Outcome(BaseModel):
    verdict: Verdict
    reason: str
    signal: dict[str, Any] = Field(default_factory=dict)  # what the signal library saw
