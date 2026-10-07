import pytest

from hooksmith.models import FindingType
from hooksmith.providers import GenRequest, template_hook
from hooksmith.validator import validate_hook

CLS, M = "com.x.Vault", "encrypt"


def req(t, overload=None):
    return GenRequest(finding_type=t, class_name=CLS, method=M, title="t", source="", overload=overload)


@pytest.mark.parametrize(
    "t", [FindingType.HARDCODED_KEY, FindingType.CLEARTEXT_HTTP, FindingType.INSECURE_RANDOM, FindingType.UNKNOWN]
)
@pytest.mark.parametrize("overload", [None, [], ["[B"]])
def test_templates_pass_validation(t, overload):
    v = validate_hook(template_hook(req(t, overload)), CLS, M)
    assert v.ok, v.errors


def good():
    return template_hook(req(FindingType.CLEARTEXT_HTTP, ["java.lang.String"]))


def failing(js):
    return {c.name for c in validate_hook(js, CLS, M).checks if c.gating and not c.passed}


def test_each_check_catches_its_failure():
    g = good()
    assert "parses as JavaScript" in failing(g.replace("function", "functon", 1))
    assert "contains Java.perform" in failing(g.replace("Java.perform", "Java.performX"))
    assert "Java.use targets the correct class" in failing(g.replace(CLS, "com.x.Other"))
    assert "hooks the requested method" in failing(g.replace(f"C.{M}.overload", "C.other.overload"))
    assert "produces observable output" in failing(g.replace("console.log", "noop"))
    assert "calls the original implementation" in failing(g.replace(f"this.{M}.apply", "nothing"))


def test_dangerous_api_blocked():
    js = good().replace("return r;", "Runtime.getRuntime().exec('id'); return r;")
    assert "avoids dangerous APIs" in failing(js)


def test_empty_and_truncated():
    assert not validate_hook("", CLS, M).ok
    assert not validate_hook("Java.perform(function () {", CLS, M).ok


def test_modern_js_is_accepted():
    js = good().replace("var r =", "const r =").replace("return r;", "return r ?? null;")
    assert validate_hook(js, CLS, M).ok  # node --check, not esprima 2017


def test_regexp_exec_is_not_process_execution():
    js = good().replace("return r;", "var m = /CN=([^,]+)/.exec('CN=x'); return r;")
    assert "avoids dangerous APIs" not in failing(js)
    js2 = good().replace("return r;", "Java.use('java.lang.Runtime').getRuntime(); return r;")
    assert "avoids dangerous APIs" in failing(js2)
