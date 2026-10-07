import httpx

from hooksmith.exercise import validate_plan
from hooksmith.models import FindingType
from hooksmith.prompts import build_messages, extract_js, prompt_hash
from hooksmith.providers import GenRequest, WorkerProvider


def test_extract_js():
    assert extract_js("Sure!\n```javascript\nvar a=1;\n```\nbye") == "var a=1;"
    assert extract_js("```js\nvar a=1;") == "var a=1;"
    assert extract_js("var a=1;") == "var a=1;"


def test_validate_plan_allowlist():
    out = validate_plan(
        ["launch", "rm -rf /", "monkey 50", "monkey abc", "deeplink myapp://x?a=1", "deeplink a; reboot", "wait 2"]
    )
    assert out == ["launch", "monkey 50", "deeplink myapp://x?a=1", "wait 2"]
    assert validate_plan(["nope"]) == ["launch", "wait 3", "monkey 60"]


def test_prompt_contains_feedback_on_retry():
    m = build_messages(
        finding_type=FindingType.CLEARTEXT_HTTP,
        class_name="a.B",
        method="go",
        title="t",
        source="x",
        errors=["contains Java.perform: missing"],
        previous="old()",
    )
    assert "contains Java.perform: missing" in m[1]["content"] and "old()" in m[1]["content"]
    assert len(prompt_hash()) == 12


def test_worker_provider_roundtrip(monkeypatch):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = request.read().decode()
        return httpx.Response(200, json={"hook": "Java.perform(function(){});", "model": "qwen"})

    p = WorkerProvider(url="https://w.example", token="t0k")
    p._client = httpx.Client(transport=httpx.MockTransport(handler))
    r = p.generate(GenRequest(finding_type=FindingType.HARDCODED_KEY, class_name="a.B", method="m", title="t", source="s"))
    assert r.js.startswith("Java.perform") and r.model == "qwen"
    import json

    assert seen["auth"] == "Bearer t0k" and json.loads(seen["body"])["class_name"] == "a.B"
