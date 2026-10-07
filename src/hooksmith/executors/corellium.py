"""Corellium executor: virtual Android devices over Corellium's REST API, then ADB+Frida as usual.

Written against Corellium's public API client (github.com/corellium/corellium-api):
    POST {api}/tokens            {"apiToken": "..."}  ->  {"token": "...", "expiration": "..."}
    GET  {api}/projects
    POST {api}/instances         {"project", "name", "flavor", "os"}
    GET  {api}/instances/{id}    -> state, serviceIp, ...
    POST {api}/instances/{id}/start | /stop,  DELETE {api}/instances/{id}

Corellium exposes ADB on the instance's service IP (port 5001) over its VPN / Corellium Connect. Join the VPN, or
pass --corellium-adb host:port, and this executor `adb connect`s to it. NOTE: I have not run this against a live
tenant; it follows the documented client. Expect to adjust field names (flavor/os, project) for your plan.
"""

from __future__ import annotations

import os
import time

import httpx

from .adb import Adb, AdbError, AdbFridaExecutor


class CorelliumError(RuntimeError):
    pass


class CorelliumClient:
    def __init__(self, endpoint: str, api_token: str):
        self.api = endpoint.rstrip("/") + ("" if endpoint.rstrip("/").endswith("/api/v1") else "/api/v1")
        self._token_src = api_token
        self.http = httpx.Client(timeout=60)
        self._auth: str | None = None

    def login(self) -> None:
        r = self.http.post(f"{self.api}/tokens", json={"apiToken": self._token_src})
        if r.status_code >= 400:
            raise CorelliumError(f"login failed ({r.status_code}): {r.text[:200]}")
        self._auth = r.json()["token"]

    def _h(self) -> dict[str, str]:
        if not self._auth:
            self.login()
        return {"Authorization": str(self._auth)}

    def req(self, method: str, path: str, **kw) -> httpx.Response:
        r = self.http.request(method, f"{self.api}{path}", headers=self._h(), **kw)
        if r.status_code >= 400:
            raise CorelliumError(f"{method} {path} -> {r.status_code}: {r.text[:300]}")
        return r

    def projects(self) -> list[dict]:
        return self.req("GET", "/projects").json()

    def create_instance(self, project: str, name: str, flavor: str, os_version: str) -> dict:
        return self.req("POST", "/instances", json={"project": project, "name": name, "flavor": flavor, "os": os_version}).json()

    def instance(self, iid: str) -> dict:
        return self.req("GET", f"/instances/{iid}").json()

    def start(self, iid: str) -> None:
        self.req("POST", f"/instances/{iid}/start")

    def stop(self, iid: str) -> None:
        self.req("POST", f"/instances/{iid}/stop")

    def destroy(self, iid: str) -> None:
        self.req("DELETE", f"/instances/{iid}")


def describe(inst: dict) -> dict:
    """The few fields worth showing, tolerant of API differences."""
    keys = ("id", "name", "state", "type", "flavor", "os", "osbuild", "model", "cores", "serviceIp", "wifiIp")
    return {k: inst.get(k) for k in keys if inst.get(k) is not None}


def is_android(inst: dict) -> bool | None:
    """True/False when the instance says what it is, None when it does not."""
    blob = " ".join(str(inst.get(k, "")) for k in ("type", "flavor", "os", "model")).lower()
    if "ranchu" in blob or "android" in blob or "pixel" in blob or "nexus" in blob:
        return True
    if "ios" in blob or "iphone" in blob or "ipad" in blob:
        return False
    return None


class CorelliumExecutor(AdbFridaExecutor):
    name = "corellium"

    def __init__(
        self,
        endpoint: str | None = None,
        api_token: str | None = None,
        project: str | None = None,
        instance_id: str | None = None,
        flavor: str = "ranchu",
        os_version: str = "13.0.0",
        adb_target: str | None = None,
        destroy_on_close: bool = False,
        adb: str | None = None,
    ):
        self.endpoint = endpoint or os.environ.get("CORELLIUM_ENDPOINT", "https://app.corellium.com")
        token = api_token or os.environ.get("CORELLIUM_API_TOKEN", "")
        if not token:
            raise CorelliumError("set CORELLIUM_API_TOKEN (or pass --corellium-token)")
        super().__init__(serial=adb_target, adb=adb)
        self.client = CorelliumClient(self.endpoint, token)
        self.project = project or os.environ.get("CORELLIUM_PROJECT")
        self.instance_id = instance_id or os.environ.get("CORELLIUM_INSTANCE")
        self.flavor, self.os_version = flavor, os_version
        self.adb_target = adb_target
        self.destroy_on_close = destroy_on_close
        self._created = False

    def _wait_state(self, iid: str, want: str, timeout: int = 900) -> dict:
        end = time.time() + timeout
        while time.time() < end:
            info = self.client.instance(iid)
            if info.get("state") == want:
                return info
            if info.get("state") in ("deleting", "error"):
                raise CorelliumError(f"instance entered state {info.get('state')!r}")
            time.sleep(5)
        raise CorelliumError(f"instance did not reach state {want!r} in {timeout}s")

    def prepare(self) -> dict:
        self.client.login()
        if not self.instance_id:
            project = self.project
            if not project:
                projects = self.client.projects()
                if not projects:
                    raise CorelliumError("no Corellium project found; create one or set CORELLIUM_PROJECT")
                project = projects[0]["id"]
            inst = self.client.create_instance(project, f"hooksmith-{int(time.time())}", self.flavor, self.os_version)
            self.instance_id = inst["id"]
            self._created = True
        info = self.client.instance(self.instance_id)
        if is_android(info) is False:
            raise CorelliumError(
                f"instance {self.instance_id} is not an Android device ({describe(info)}). HookSmith v1 hooks Android Java only."
            )
        if info.get("state") != "on":
            if info.get("state") == "off":
                self.client.start(self.instance_id)
            info = self._wait_state(self.instance_id, "on")
        target = self.adb_target or (f"{info['serviceIp']}:5001" if info.get("serviceIp") else None)
        if not target:
            raise CorelliumError("instance has no serviceIp; join Corellium Connect (VPN) or pass --corellium-adb host:port")
        out = Adb(None, self.adb.adb).run("connect", target, check=False, timeout=30)
        if "connected" not in (out.stdout + out.stderr).lower():
            raise AdbError(f"adb connect {target} failed: {(out.stdout + out.stderr).strip()[:200]}")
        self.adb.serial = target
        meta = super().prepare()
        meta.update({"executor": self.name, "corellium_instance": self.instance_id, "flavor": self.flavor})
        return meta

    def close(self) -> None:
        super().close()
        try:
            if self.instance_id and self._created and self.destroy_on_close:
                self.client.destroy(self.instance_id)
            elif self.instance_id and self._created:
                self.client.stop(self.instance_id)
        except Exception:  # noqa: BLE001
            pass
