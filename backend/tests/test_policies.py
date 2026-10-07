import pathlib

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
POLICIES = sorted((ROOT / "policies").rglob("*.yaml"))
EFFECTS = {"allow", "deny", "require_approval", "monitor"}

@pytest.mark.parametrize("path", POLICIES, ids=lambda p: p.name)
def test_policy_structure(path):
    p = yaml.safe_load(path.read_text())
    assert p["default_effect"] == "deny", "v0.1 only supports default deny"
    ids = [r["id"] for r in p["rules"]]
    assert len(ids) == len(set(ids)), "duplicate rule ids"
    prios = [r["priority"] for r in p["rules"]]
    assert len(prios) == len(set(prios)), "duplicate priorities"
    for r in p["rules"]:
        assert r["effect"] in EFFECTS, r["id"]
        assert r.get("reason"), f"{r['id']} needs a reason"
        assert "when" in r, r["id"]
    assert set(p["band_effects"]) == {"low", "medium", "high", "critical"}

def test_security_demo_has_headline_defences():
    p = yaml.safe_load((ROOT / "policies/examples/security-demo.yaml").read_text())
    byid = {r["id"]: r for r in p["rules"]}
    assert byid["deny-authority-from-untrusted-content"]["effect"] == "deny"   # taped sign
    assert byid["deny-bulk-export-when-tainted"]["effect"] == "deny"           # poisoned email
    assert byid["deny-containment"]["priority"] == min(r["priority"] for r in p["rules"])
    for r in p["rules"]:
        if r["effect"] == "allow":
            assert r["priority"] > byid["deny-authority-from-untrusted-content"]["priority"]

def test_untrusted_origins_never_in_allow_authority():
    p = yaml.safe_load((ROOT / "policies/examples/security-demo.yaml").read_text())
    untrusted = {"sensor_ocr", "email", "web", "external_document", "unknown", "model_generated"}
    text = yaml.dump([r for r in p["rules"] if r["effect"] == "allow"])
    assert not any(u in text for u in untrusted), "allow rules must not key off untrusted origins"
