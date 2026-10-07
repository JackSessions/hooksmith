from hooksmith.exercise import plan_steps, validate_plan
from hooksmith.manifest import Manifest
from hooksmith.models import Finding
from hooksmith.ui import parse_targets, pick

PKG = "com.x.app"


def node(text, pkg=PKG, bounds="[0,100][400,200]", clickable="true", enabled="true", rid="", desc=""):
    return (
        f'<node text="{text}" resource-id="{rid}" content-desc="{desc}" package="{pkg}" clickable="{clickable}" '
        f'enabled="{enabled}" bounds="{bounds}" />'
    )


def dump(*nodes):
    return '<?xml version="1.0"?><hierarchy rotation="0">' + "".join(nodes) + "</hierarchy>"


def test_only_safe_clickable_controls_of_the_target_app():
    xml = dump(
        node("Settings"),
        node("Delete account", bounds="[0,300][400,400]"),
        node("Buy premium", bounds="[0,500][400,600]"),
        node("Log out", bounds="[0,700][400,800]"),
        node("Other app", pkg="com.evil"),
        node("Disabled", enabled="false"),
        node("Static text", clickable="false"),
        node("Tiny", bounds="[0,0][5,5]"),
        node("Profile", bounds="[0,900][400,1000]"),
    )
    labels = [t.label for t in parse_targets(xml, PKG)]
    assert labels == ["Settings", "Profile"]


def test_denylist_covers_resource_ids_and_descriptions_too():
    xml = dump(node("", rid="com.x.app:id/btn_delete_all"), node("", desc="Sign out"), node("OK", bounds="[0,200][400,300]"))
    assert [t.label for t in parse_targets(xml, PKG)] == ["OK"]


def test_pick_is_stable_and_skips_visited():
    ts = parse_targets(dump(node("B", bounds="[0,300][400,400]"), node("A", bounds="[0,100][400,200]")), PKG)
    first = pick(ts, set())
    assert first.label == "A"  # top-most first: reproducible runs
    assert pick(ts, {first.key}).label == "B"
    assert pick(ts, {t.key for t in ts}) is None


def test_garbage_xml_is_harmless():
    assert parse_targets("not xml", PKG) == []


def test_explore_is_in_the_default_plan_and_survives_the_allowlist():
    steps = plan_steps(PKG, Manifest(package=PKG), Finding(id="x", title="t"))
    assert "explore 8" in steps and validate_plan(steps) == steps
    assert validate_plan(["explore abc", "explore 5"]) == ["explore 5"]
