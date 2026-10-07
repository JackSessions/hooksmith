"""Bundled demo: a fake app, a MobSF-style report and recorded device logs.

`hooksmith demo` replays the recorded logs, so it needs no phone, no emulator and no network. It exists for the
talk (the Corellium leg is pre-recorded), for CI, and for trying the tool in thirty seconds.
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path

from ..providers import GenRequest, GenResult, TemplateProvider, template_hook


def demo_dir() -> Path:
    return Path(str(resources.files("hooksmith") / "demo"))


class DemoProvider:
    """TemplateProvider that plays an LLM having a bad day on two findings, to show the validator earning its keep."""

    name = "demo"
    temperature = 0.1
    model = "demo-llm (scripted)"

    def __init__(self) -> None:
        self._calls: dict[str, int] = {}
        self._inner = TemplateProvider()

    def generate(self, req: GenRequest) -> GenResult:
        n = self._calls[req.class_name] = self._calls.get(req.class_name, 0) + 1
        good = template_hook(req)
        if req.class_name.endswith("TokenGen") and n == 1:
            # hallucinated class name; the regeneration (with validator feedback) gets it right
            bad = good.replace(f'Java.use("{req.class_name}")', 'Java.use("com.demo.auth.TokenFactory")')
            return GenResult(js=bad, raw=bad, model=self.model)
        if req.class_name.endswith("PinStore"):
            # never calls the original method: would break app flow, and the validator says so, twice
            bad = good.replace("var r = this.protect.apply(this, arguments);", "var r = null;").replace(
                "var r = ov.apply(this, arguments);", "var r = null;"
            )
            return GenResult(js=bad, raw=bad, model=self.model)
        return GenResult(js=good, raw=good, model=self.model)
