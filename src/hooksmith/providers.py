"""Hook generators. All of them return *candidate* JavaScript; nothing here is trusted.

worker    the Cloudflare Worker + Workers AI (Qwen 1.5 14B) described in the talk
openai    any OpenAI-compatible endpoint (Ollama, vLLM, LM Studio, a hosted model)
template  deterministic, offline, no LLM: also the test double and the demo fallback
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Protocol

import httpx

from .javasrc import JavaClass, JavaMethod, overload_types
from .models import FindingType
from .prompts import build_messages, extract_js


@dataclass
class GenRequest:
    finding_type: FindingType
    class_name: str
    method: str  # "<init>" for constructors
    title: str
    source: str  # trimmed decompiled source sent to the model
    overload: list[str] | None = None
    errors: list[str] | None = None  # validator feedback on a regeneration
    previous: str | None = None


@dataclass
class GenResult:
    js: str
    raw: str
    model: str


class Provider(Protocol):
    name: str
    temperature: float

    def generate(self, req: GenRequest) -> GenResult: ...


def trim_source(jc: JavaClass, method: JavaMethod, max_chars: int = 7000) -> str:
    """Send the target method plus the class's field/constant lines, not the whole class."""
    head = []
    for line in jc.source.splitlines():
        s = line.strip()
        if s.startswith(("package ", "import ")) or (
            (" static " in f" {s} " or s.startswith(("private ", "public ", "protected ", "final ")))
            and "(" not in s.split("=")[0]
            and s.endswith(";")
        ):
            head.append(line)
    out = "\n".join(head[:60]) + "\n\n" + method.body
    return out[:max_chars]


def _post(client: httpx.Client, url: str, headers: dict, body: dict, retries: int = 2) -> dict:
    last: Exception | None = None
    for i in range(retries + 1):
        try:
            r = client.post(url, headers=headers, json=body, timeout=120)
            if r.status_code in (429, 502, 503, 504) and i < retries:
                continue
            r.raise_for_status()
            return r.json()
        except (httpx.HTTPError, ValueError) as exc:
            last = exc
    raise RuntimeError(f"LLM request failed: {last}")


class WorkerProvider:
    """POST the structured request to the Cloudflare Worker, which builds the prompt and calls Workers AI."""

    name = "worker"

    def __init__(self, url: str | None = None, token: str | None = None, temperature: float = 0.1):
        self.url = (url or os.environ.get("HOOKSMITH_WORKER_URL", "")).rstrip("/")
        self.token = token or os.environ.get("HOOKSMITH_WORKER_TOKEN", "")
        self.temperature = temperature
        if not self.url:
            raise ValueError("worker URL missing: pass --worker-url or set HOOKSMITH_WORKER_URL")
        self._client = httpx.Client()

    def generate(self, req: GenRequest) -> GenResult:
        data = _post(
            self._client,
            f"{self.url}/v1/generate",
            {"Authorization": f"Bearer {self.token}"} if self.token else {},
            {
                "finding_type": req.finding_type.value,
                "class_name": req.class_name,
                "method": req.method,
                "title": req.title,
                "source": req.source,
                "overload": req.overload,
                "errors": req.errors,
                "previous": req.previous,
                "temperature": self.temperature,
            },
        )
        raw = data.get("raw") or data.get("hook") or ""
        return GenResult(js=data.get("hook") or extract_js(raw), raw=raw, model=str(data.get("model", "worker")))

    def plan(self, finding, manifest, default):
        data = _post(
            self._client,
            f"{self.url}/v1/plan",
            {"Authorization": f"Bearer {self.token}"} if self.token else {},
            _plan_payload(finding, manifest, default),
        )
        return [str(x) for x in data.get("steps", [])]


def _plan_payload(finding, manifest, default):
    return {
        "package": manifest.package or "",
        "class_name": finding.class_name or "",
        "finding_type": finding.type.value,
        "deep_links": manifest.deep_links[:10],
        "activities": manifest.exported_activities[:20],
        "default": default,
    }


class OpenAICompatProvider:
    name = "openai"

    def __init__(
        self,
        base_url: str | None = None,
        model: str | None = None,
        api_key: str | None = None,
        temperature: float = 0.1,
    ):
        self.base = (base_url or os.environ.get("HOOKSMITH_LLM_URL", "http://localhost:11434/v1")).rstrip("/")
        self.model = model or os.environ.get("HOOKSMITH_LLM_MODEL", "qwen2.5-coder:14b")
        self.key = api_key or os.environ.get("HOOKSMITH_LLM_KEY", "")
        self.temperature = temperature
        self._client = httpx.Client()

    def generate(self, req: GenRequest) -> GenResult:
        msgs = build_messages(
            finding_type=req.finding_type,
            class_name=req.class_name,
            method=req.method,
            title=req.title,
            source=req.source,
            overload=req.overload,
            errors=req.errors,
            previous=req.previous,
        )
        data = _post(
            self._client,
            f"{self.base}/chat/completions",
            {"Authorization": f"Bearer {self.key}"} if self.key else {},
            {"model": self.model, "messages": msgs, "temperature": self.temperature, "max_tokens": 2048},
        )
        raw = data["choices"][0]["message"]["content"]
        return GenResult(js=extract_js(raw), raw=raw, model=self.model)

    def plan(self, finding, manifest, default):
        from .prompts import parse_plan, plan_messages

        p = _plan_payload(finding, manifest, default)
        msgs = plan_messages(
            package=p["package"],
            class_name=p["class_name"],
            finding_type=p["finding_type"],
            deep_links=p["deep_links"],
            activities=p["activities"],
            default=default,
        )
        data = _post(
            self._client,
            f"{self.base}/chat/completions",
            {"Authorization": f"Bearer {self.key}"} if self.key else {},
            {"model": self.model, "messages": msgs, "temperature": 0.2, "max_tokens": 400},
        )
        return parse_plan(data["choices"][0]["message"]["content"])


# ---- deterministic templates ----------------------------------------------------------------

_HEX = "function hex(b){var s='';for(var i=0;i<b.length;i++){s+=('0'+(b[i]&0xff).toString(16)).slice(-2);}return s;}"


def _target(req: GenRequest) -> tuple[str, str, str]:
    """(accessor, hook-opening, hook-closing) for the target method, overload-aware."""
    m = "$init" if req.method in ("<init>", "$init") else req.method
    if req.overload is not None:
        ov = ", ".join(repr(t) for t in req.overload)
        return (
            f"C.{m}.overload({ov})",
            f"C.{m}.overload({ov}).implementation = function () {{",
            "};",
        )
    return (
        f"C.{m}",
        f"C.{m}.overloads.forEach(function (ov) {{ ov.implementation = function () {{",
        "}; });",
    )


def _orig_expr(req: GenRequest) -> str:
    m = "$init" if req.method in ("<init>", "$init") else req.method
    return f"this.{m}.apply(this, arguments)" if req.overload is not None else "ov.apply(this, arguments)"


def _call_original(req: GenRequest) -> str:
    return f"var r = {_orig_expr(req)};"


_TLS_HELPERS = """function tlsInfo(chain, accepted) {
  var o = {event: "tls_chain", accepted: accepted};
  try {
    var leaf = Java.cast(chain[0], Java.use("java.security.cert.X509Certificate"));
    o.subject = String(leaf.getSubjectDN().getName()).slice(0, 120);
    o.issuer = String(leaf.getIssuerDN().getName()).slice(0, 120);
    o.self_signed = o.subject === o.issuer;
    try { leaf.checkValidity(); o.expired = false; } catch (e) { o.expired = true; }
    o.chain_len = chain.length;
  } catch (e) { o.err = String(e).slice(0, 120); }
  return o;
}"""

_HOST_HELPERS = """function hostMatch(pat, host) {
  pat = String(pat).toLowerCase(); host = String(host).toLowerCase();
  if (pat === host) return true;
  if (pat.indexOf("*.") === 0) { return host.slice(host.indexOf(".")) === pat.slice(1) && host.split(".").length === pat.split(".").length; }
  return false;
}
function certCoversHost(session, host) {
  try {
    var leaf = Java.cast(session.getPeerCertificates()[0], Java.use("java.security.cert.X509Certificate"));
    var sans = leaf.getSubjectAlternativeNames();
    if (sans !== null) {
      var it = sans.iterator();
      while (it.hasNext()) {
        var e = Java.cast(it.next(), Java.use("java.util.List"));
        if (hostMatch(e.get(1), host)) return true;
      }
    }
    var m = /CN=([^,]+)/.exec(String(leaf.getSubjectDN().getName()));
    return !!(m && hostMatch(m[1], host));
  } catch (e) { return null; }
}"""


def template_hook(req: GenRequest) -> str:
    m = "$init" if req.method in ("<init>", "$init") else req.method
    _, opening, closing = _target(req)
    orig = _call_original(req)
    log = lambda ev: f'console.log("HS|" + JSON.stringify({ev}));'  # noqa: E731
    t = req.finding_type
    body: list[str] = [_HEX, "Java.perform(function () {", f'  var C = Java.use("{req.class_name}");']
    if t == FindingType.HARDCODED_KEY:
        body += [
            "  var inTarget = 0;",
            '  var KS = Java.use("javax.crypto.spec.SecretKeySpec");',
            "  KS.$init.overload('[B', 'java.lang.String').implementation = function (k, alg) {",
            "    if (inTarget > 0) { try { " + log('{event: "key", hex: hex(k), algorithm: String(alg)}') + " } catch (e) {} }",
            "    return this.$init(k, alg);",
            "  };",
            f"  {opening}",
            "    inTarget++;",
            "    try {",
            "      " + log('{event: "call"}'),
            "      try { for (var i = 0; i < arguments.length; i++) { var a = arguments[i]; if (a && a.length !== undefined && typeof a !== 'string' && a.length > 0 && typeof a[0] === 'number') { "
            + log('{event: "key", hex: hex(a), via: "argument"}')
            + " } } } catch (e) {}",
            f"      {orig}",
            "      return r;",
            "    } finally { inTarget--; }",
            f"  {closing}",
        ]
    elif t == FindingType.CLEARTEXT_HTTP:
        body += [
            f"  {opening}",
            "    " + log('{event: "call"}'),
            "    try { for (var i = 0; i < arguments.length; i++) { var a = arguments[i]; if (a !== null && a !== undefined) { var s = String(a); if (/^[a-z][a-z0-9+.-]*:\\/\\//i.test(s)) { "
            + log('{event: "url", url: s}')
            + " } } } } catch (e) {}",
            f"    {orig}",
            "    try { if (r !== null && r !== undefined) { var rs = String(r); if (/^[a-z][a-z0-9+.-]*:\\/\\//i.test(rs)) { "
            + log('{event: "url", url: rs}')
            + " } } } catch (e) {}",
            "    return r;",
            f"  {closing}",
        ]
    elif t == FindingType.INSECURE_RANDOM:
        body += [
            "  var inTarget = 0;",
            '  var R = Java.use("java.util.Random");',
            "  ['nextInt', 'nextLong', 'nextBytes', 'nextDouble'].forEach(function (n) {",
            "    if (!R[n]) return;",
            "    R[n].overloads.forEach(function (ov2) {",
            "      ov2.implementation = function () {",
            "        if (inTarget > 0) { try { var impl = (String(this.getClass().getName()).indexOf('SecureRandom') !== -1) ? 'java.security.SecureRandom' : 'java.util.Random'; "
            + log(f'{{event: "random", impl: impl, context: "{m}"}}')
            + " } catch (e) {} }",
            "        return ov2.apply(this, arguments);",
            "      };",
            "    });",
            "  });",
            f"  {opening}",
            "    inTarget++;",
            "    try {",
            "      " + log('{event: "call"}'),
            f"      {orig}",
            "      return r;",
            "    } finally { inTarget--; }",
            f"  {closing}",
        ]
    elif t == FindingType.TLS_TRUST_ALL:
        body.insert(0, _TLS_HELPERS)
        body += [
            f"  {opening}",
            "    " + log('{event: "call"}'),
            "    var r;",
            "    try {",
            f"      r = {_orig_expr(req)};",
            "    } catch (e) {",
            '      try { console.log("HS|" + JSON.stringify(tlsInfo(arguments[0], false))); } catch (x) {}',
            "      throw e;",
            "    }",
            '    try { console.log("HS|" + JSON.stringify(tlsInfo(arguments[0], true))); } catch (x) {}',
            "    return r;",
            f"  {closing}",
        ]
    elif t == FindingType.HOSTNAME_VERIFIER:
        body.insert(0, _HOST_HELPERS)
        body += [
            f"  {opening}",
            "    " + log('{event: "call"}'),
            f"    {orig}",
            "    var cm = null;",
            "    try { cm = certCoversHost(arguments[1], arguments[0]); } catch (e) {}",
            '    try { console.log("HS|" + JSON.stringify({event: "hostname", host: String(arguments[0]), result: !!r, cert_matches: cm})); } catch (e) {}',
            "    return r;",
            f"  {closing}",
        ]
    else:
        body += [
            f"  {opening}",
            "    " + log('{event: "call"}'),
            f"    {orig}",
            "    return r;",
            f"  {closing}",
        ]
    body += ["  " + log('{event: "ready"}'), "});"]
    return "\n".join(body) + "\n"


class TemplateProvider:
    """No LLM. Produces a known-good hook per finding type, so the pipeline works offline."""

    name = "template"
    temperature = 0.0

    def generate(self, req: GenRequest) -> GenResult:
        js = template_hook(req)
        return GenResult(js=js, raw=js, model="template-v1")


def make_provider(kind: str, **kw) -> Provider:
    if kind == "worker":
        return WorkerProvider(url=kw.get("worker_url"), token=kw.get("worker_token"))
    if kind == "openai":
        return OpenAICompatProvider(base_url=kw.get("llm_url"), model=kw.get("llm_model"), api_key=kw.get("llm_key"))
    if kind == "template":
        return TemplateProvider()
    raise ValueError(f"unknown provider {kind!r}")


def overload_for(jc: JavaClass, method: JavaMethod) -> list[str] | None:
    """Frida overload() types for this method, or None to hook all overloads."""
    same = [m for m in jc.methods if m.name == method.name]
    if len(same) == 1 and not method.params:
        return []
    return overload_types(method, jc.source)


__all__ = [
    "GenRequest",
    "GenResult",
    "Provider",
    "WorkerProvider",
    "OpenAICompatProvider",
    "TemplateProvider",
    "make_provider",
    "trim_source",
    "overload_for",
    "template_hook",
    "json",
]
