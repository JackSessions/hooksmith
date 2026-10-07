"""Corellium client against a mocked API (the executor has not been run against a live tenant)."""

import json

import httpx
import pytest

from hooksmith.executors.corellium import CorelliumClient, CorelliumError, CorelliumExecutor


def client(handler):
    c = CorelliumClient("https://acme.enterprise.corellium.com", "apitok")
    c.http = httpx.Client(transport=httpx.MockTransport(handler))
    return c


def test_login_then_authorised_calls():
    seen = []

    def h(req: httpx.Request) -> httpx.Response:
        seen.append((req.method, req.url.path, req.headers.get("authorization"), req.read().decode()))
        if req.url.path == "/api/v1/tokens":
            return httpx.Response(200, json={"token": "T0K", "expiration": "x"})
        if req.url.path == "/api/v1/projects":
            return httpx.Response(200, json=[{"id": "p1"}])
        if req.url.path == "/api/v1/instances" and req.method == "POST":
            return httpx.Response(200, json={"id": "i1"})
        return httpx.Response(200, json={"id": "i1", "state": "on", "serviceIp": "10.11.1.2"})

    c = client(h)
    assert c.projects() == [{"id": "p1"}]
    assert c.create_instance("p1", "n", "ranchu", "13.0.0") == {"id": "i1"}
    c.start("i1")
    assert seen[0][:2] == ("POST", "/api/v1/tokens") and json.loads(seen[0][3]) == {"apiToken": "apitok"}
    assert all(s[2] == "T0K" for s in seen[1:])
    create = next(s for s in seen if s[0] == "POST" and s[1] == "/api/v1/instances")
    assert json.loads(create[3]) == {"project": "p1", "name": "n", "flavor": "ranchu", "os": "13.0.0"}
    assert any(s[1] == "/api/v1/instances/i1/start" for s in seen)


def test_http_errors_become_corellium_errors():
    c = client(lambda req: httpx.Response(401, text="nope"))
    with pytest.raises(CorelliumError):
        c.login()


def test_endpoint_normalisation_and_token_required(monkeypatch):
    assert CorelliumClient("https://app.corellium.com/", "t").api == "https://app.corellium.com/api/v1"
    assert CorelliumClient("https://app.corellium.com/api/v1", "t").api == "https://app.corellium.com/api/v1"
    monkeypatch.delenv("CORELLIUM_API_TOKEN", raising=False)
    with pytest.raises(CorelliumError):
        CorelliumExecutor()


def test_android_detection():
    from hooksmith.executors.corellium import is_android

    assert is_android({"flavor": "ranchu", "os": "13.0.0"}) is True
    assert is_android({"flavor": "iphone14pro", "type": "ios"}) is False
    assert is_android({"name": "x"}) is None
