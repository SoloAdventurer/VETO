from datetime import datetime, timezone

import pytest
from veto.policy.engine import Facts, PolicyEngine, PolicyError, validate_policy

BASE = {
    "version": "0.1", "policy_id": "t", "default_effect": "deny",
    "roles": {"r": {"allow_actions": ["READ_PERSONNEL", "UNLOCK_DOOR"]}},
    "rules": [],
}
PROV = {"origins": [], "authority_sources": [], "tainted": False, "lowest_trust": "none"}


def facts(verb="READ_PERSONNEL", role="r", **kw):
    return Facts(action={"agent_id": "a", "action": verb, "target": {"resource": "personnel", "id": "x"},
                         "parameters": kw.pop("parameters", {})},
                 agent={"id": "a", "role": role}, provenance=kw.pop("provenance", PROV), channel="autonomous",
                 now=datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc), **kw)


def engine(*rules):
    return PolicyEngine({**BASE, "rules": [{"reason": "r", **r} for r in rules]})


def rule(rid, prio, effect, when):
    return {"id": rid, "priority": prio, "effect": effect, "when": when}


def test_no_rules_means_default_deny():
    assert engine().evaluate(facts()).effect == "deny"


def test_allow_only_when_an_allow_rule_matches():
    e = engine(rule("a", 1, "allow", {"action": {"eq": "READ_PERSONNEL"}}))
    assert e.evaluate(facts()).effect == "allow"
    assert e.evaluate(facts("UNLOCK_DOOR")).effect == "deny"


def test_monitor_alone_is_not_enough_to_execute():
    assert engine(rule("m", 1, "monitor", {"action": {"eq": "READ_PERSONNEL"}})).evaluate(facts()).effect == "deny"


def test_deny_beats_everything_regardless_of_priority_order():
    e = engine(rule("deny", 99, "deny", {"action": {"eq": "READ_PERSONNEL"}}),
               rule("allow", 1, "allow", {"action": {"eq": "READ_PERSONNEL"}}))
    assert e.evaluate(facts()).effect == "deny"


def test_approval_beats_allow():
    e = engine(rule("allow", 1, "allow", {"action": {"eq": "READ_PERSONNEL"}}),
               rule("appr", 2, "require_approval", {"action": {"eq": "READ_PERSONNEL"}}))
    assert e.evaluate(facts()).effect == "require_approval"


def test_containment_and_unknown_agent_and_rbac_fail_closed():
    e = engine(rule("allow", 1, "allow", {"action": {"eq": "READ_PERSONNEL"}}))
    assert e.evaluate(facts(containment=True)).rule_id == "builtin:containment"
    assert e.evaluate(facts(role=None)).rule_id == "builtin:unknown-agent"
    assert e.evaluate(facts("DELETE_RECORD")).rule_id == "builtin:rbac"


def test_untrusted_authority_source_condition():
    e = engine(rule("d", 1, "deny", {"provenance": {"authority_source_in": ["sensor_ocr"]}}),
               rule("a", 2, "allow", {"action": {"eq": "READ_PERSONNEL"}}))
    tainted = {"origins": ["sensor_ocr"], "authority_sources": ["sensor_ocr"], "tainted": True,
               "lowest_trust": "sensor_ocr"}
    assert e.evaluate(facts(provenance=tainted)).effect == "deny"
    assert e.evaluate(facts()).effect == "allow"


def test_missing_values_fail_safe():
    e = engine(rule("a", 1, "allow", {"all": [{"action": {"eq": "READ_PERSONNEL"}},
                                              {"param.n": {"lte": 5}}]}))
    assert e.evaluate(facts()).effect == "deny"                      # param missing -> comparison false
    assert e.evaluate(facts(parameters={"n": 3})).effect == "allow"
    assert e.evaluate(facts(parameters={"n": True})).effect == "deny"  # bool is not a number here


def test_closed_grammar_rejects_unknown_conditions_and_operators():
    assert validate_policy({**BASE, "rules": [rule("x", 1, "allow", {"eval": "1+1"})]})
    assert validate_policy({**BASE, "rules": [rule("x", 1, "allow", {"action": {"regex": ".*"}})]})
    with pytest.raises(PolicyError):
        engine(rule("x", 1, "allow", {"__import__": "os"}))


def test_default_effect_must_be_deny():
    assert validate_policy({**BASE, "default_effect": "allow"})


def test_engine_is_deterministic():
    e = engine(rule("a", 1, "allow", {"action": {"eq": "READ_PERSONNEL"}}))
    assert {e.evaluate(facts()).effect for _ in range(50)} == {"allow"}
