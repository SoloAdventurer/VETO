"""Audited policy editing (DECISIONS D-028): propose, a different admin activates, everything is in the chain, and
no edit can remove the guarantees the rest of VETO relies on. SQLite always; PostgreSQL when VETO_TEST_PG_DSN is set."""

import copy

import pytest
import yaml
from conftest import BACKENDS
from fastapi.testclient import TestClient
from test_tenancy import LOCAL_ADMIN, PLATFORM, World, bearer, read
from veto.canonical import sha256_hex
from veto.gateway.app import create_app
from veto.paths import DEFAULT_POLICY
from veto.policy.lint import MAX_POLICY_CHARS, diff_policies, lint_policy


def base():
    return yaml.safe_load(DEFAULT_POLICY.read_text())


def dump(raw):
    return yaml.safe_dump(raw, sort_keys=False)


def blocking(raw=None, version="0.2"):
    """The shipped policy plus a rule that denies every READ_PERSONNEL (an easy, visible change)."""
    raw = copy.deepcopy(raw or base())
    raw["version"] = version
    raw["rules"].append({"id": "deny-read-personnel", "priority": 3, "effect": "deny",
                         "when": {"action": {"eq": "READ_PERSONNEL"}}, "reason": "reads are frozen"})
    return raw


@pytest.fixture
def world(target, monkeypatch):
    w = World(target, monkeypatch)
    for t in ("alpha", "beta"):                                       # a second admin: the proposer cannot activate
        w.c.post("/v1/admin/principals", json={"id": "admin-2", "roles": ["admin"]}, headers=bearer(w.keys[t]["admin"]))
        w.keys[t]["admin-2"] = w.c.post("/v1/admin/principals/admin-2/keys",
                                        headers=bearer(w.keys[t]["admin"])).json()["key"]
    return w


def pv(client, headers, resp):
    """The policy version recorded in the chain for a decision (the action response itself does not carry it)."""
    return client.get(f"/v1/actions/{resp['request_id']}", headers=headers).json()["policy_version"]


def propose(w, tenant, raw, who="admin"):
    text = raw if isinstance(raw, str) else dump(raw)
    return w.c.post("/v1/policy/proposals", json={"policy": text}, headers=w.h(tenant, who))


def activate(w, tenant, version, who="admin-2"):
    return w.c.post(f"/v1/policy/proposals/{version}/activate", headers=w.h(tenant, who))


# ---  the workflow
@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_a_proposal_changes_nothing_until_a_different_admin_activates_it(world):
    before = world.act("alpha", read()).json()
    assert before["decision"] != "block"
    r = propose(world, "alpha", blocking())
    assert r.status_code == 200 and r.json()["status"] == "proposed" and r.json()["diff"]["added"]
    v = r.json()["version"]
    assert world.act("alpha", read()).json()["decision"] != "block"            # still the old policy
    assert activate(world, "alpha", v, who="admin").status_code == 403        # proposers cannot approve themselves
    assert world.act("alpha", read()).json()["decision"] != "block"
    assert activate(world, "alpha", v).status_code == 200
    after = world.act("alpha", read()).json()
    assert after["decision"] == "block" and pv(world.c, world.h("alpha", "ops-agent-1"), after) .count("@0.2+") == 1
    assert world.act("beta", read()).json()["decision"] != "block"            # another tenant is untouched


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_activation_is_in_the_chain_with_the_full_text_and_its_hash(world):
    raw = blocking()
    v = propose(world, "alpha", raw).json()["version"]
    activate(world, "alpha", v)
    log = world.c.get("/v1/audit", headers=world.h("alpha", "admin")).json()
    actions = [r["requested_action"]["action"] for r in log if r["request_id"].startswith(("sys-", "log-"))]
    assert "POLICY_PROPOSED" in actions and "POLICY_ACTIVATED" in actions
    ev = next(r for r in log if r["requested_action"]["action"] == "POLICY_ACTIVATED")["requested_action"]["parameters"]
    assert ev["policy_sha256"] == sha256_hex(ev["policy_text"]) and yaml.safe_load(ev["policy_text"]) == raw
    assert ev["proposed_by"] == "tenant-admin"
    assert world.c.get("/v1/audit/verify", headers=world.h("alpha", "admin")).json()["ok"]


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_reject_then_activate_is_a_conflict(world):
    v = propose(world, "alpha", blocking()).json()["version"]
    assert world.c.post(f"/v1/policy/proposals/{v}/reject", json={"note": "no"},
                        headers=world.h("alpha", "admin-2")).status_code == 200
    assert activate(world, "alpha", v).status_code == 409
    assert world.act("alpha", read()).json()["decision"] != "block"
    again = world.c.post(f"/v1/policy/proposals/{v}/reject", headers=world.h("alpha", "admin-2"))
    assert again.status_code == 409


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_a_second_activation_supersedes_the_first(world):
    v1 = propose(world, "alpha", blocking(version="0.2")).json()["version"]
    activate(world, "alpha", v1)
    v2 = propose(world, "alpha", base() | {"version": "0.3"}).json()["version"]
    activate(world, "alpha", v2)
    assert world.act("alpha", read()).json()["decision"] != "block"
    history = world.c.get("/v1/policy", headers=world.h("alpha", "admin")).json()["history"]
    hist = {h["version"]: h["status"] for h in history}
    assert hist == {v1: "superseded", v2: "active"}


# ---  the lint is a gate
def _no_kill_switch(raw):
    raw["rules"] = [r for r in raw["rules"] if r["id"] != "deny-containment"]


def _kill_switch_not_first(raw):
    next(r for r in raw["rules"] if r["id"] == "deny-containment")["priority"] = 900


def _untrusted_allow(raw):
    raw["rules"].append({"id": "allow-from-email", "priority": 700, "effect": "allow",
                         "when": {"origin": {"eq": "email"}}, "reason": "trust the email"})


def _unconditional_allow(raw):
    raw["rules"].append({"id": "allow-all", "priority": 701, "effect": "allow", "when": {}, "reason": "yolo"})


def _default_allow(raw):
    raw["default_effect"] = "allow"


def _unknown_operator(raw):
    raw["rules"].append({"id": "evil", "priority": 702, "effect": "deny",
                         "when": {"action": {"eval": "__import__('os')"}}, "reason": "x"})


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
@pytest.mark.parametrize("mutate", [_no_kill_switch, _kill_switch_not_first, _untrusted_allow, _unconditional_allow,
                                    _default_allow, _unknown_operator])
def test_lint_rejects_policies_that_remove_a_guarantee(world, mutate):
    raw = base()
    raw["version"] = "bad"
    mutate(raw)
    r = propose(world, "alpha", raw)
    assert r.status_code == 422, r.text
    assert world.c.get("/v1/policy/proposals", headers=world.h("alpha", "admin")).json() == []   # nothing stored


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_malformed_and_oversized_policies_are_rejected(world):
    for text in ("", "   ", ": : :", "- a\n- b", "x" * (MAX_POLICY_CHARS + 1)):
        assert propose(world, "alpha", text).status_code == 422
    assert world.c.post("/v1/policy/proposals", json={}, headers=world.h("alpha", "admin")).status_code == 422


def test_lint_accepts_the_shipped_policy_and_reports_why_it_rejects():
    assert lint_policy(base()) == []
    raw = base()
    _untrusted_allow(raw)
    assert any("untrusted" in e for e in lint_policy(raw))


# ---  roles and tenants
@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_only_admins_edit_and_agents_cannot_even_read_the_policy(world):
    for who in ("ops-agent-1", "human-op", "human-ap", "human-view"):
        assert propose(world, "alpha", blocking(), who=who).status_code == 403
    v = propose(world, "alpha", blocking()).json()["version"]
    for who in ("ops-agent-1", "human-op", "human-ap", "human-view"):
        assert activate(world, "alpha", v, who=who).status_code == 403
    assert world.c.get("/v1/policy", headers=world.h("alpha", "ops-agent-1")).status_code == 403
    assert world.c.get("/v1/policy", headers=world.h("alpha", "human-view")).status_code == 200


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_tenants_cannot_see_or_activate_each_others_proposals(world):
    v = propose(world, "alpha", blocking()).json()["version"]
    assert world.c.get("/v1/policy/proposals", headers=world.h("beta", "admin")).json() == []
    assert world.c.get(f"/v1/policy/proposals/{v}", headers=world.h("beta", "admin")).status_code == 404
    assert activate(world, "beta", v).status_code == 404
    assert world.c.post(f"/v1/policy/proposals/{v}/reject", headers=world.h("beta", "admin")).status_code == 404
    assert world.act("beta", read()).json()["decision"] != "block"
    assert world.act("alpha", read()).json()["decision"] != "block"          # and it was never activated for alpha
    assert world.c.get("/v1/policy", headers=bearer(PLATFORM)).status_code == 403     # the platform has no tenant


# ---  processes and restarts
@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_another_process_picks_the_activation_up_from_the_chain(world, monkeypatch):
    other = TestClient(create_app(demo=True, bootstrap_key=LOCAL_ADMIN, platform_key=PLATFORM))
    assert other.post("/v1/actions", json=read(), headers=world.h("alpha", "ops-agent-1")).json()["decision"] != "block"
    v = propose(world, "alpha", blocking()).json()["version"]
    activate(world, "alpha", v)
    r = other.post("/v1/actions", json=read(), headers=world.h("alpha", "ops-agent-1")).json()
    assert r["decision"] == "block" and pv(other, world.h("alpha", "ops-agent-1"), r) .count("@0.2+") == 1


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_a_restart_keeps_the_activated_policy(world):
    activate(world, "alpha", propose(world, "alpha", blocking()).json()["version"])
    restarted = TestClient(create_app(demo=True, bootstrap_key=LOCAL_ADMIN, platform_key=PLATFORM))
    r = restarted.post("/v1/actions", json=read(), headers=world.h("alpha", "ops-agent-1")).json()
    assert r["decision"] == "block" and pv(restarted, world.h("alpha", "ops-agent-1"), r) .count("@0.2+") == 1
    assert restarted.get("/v1/audit/verify", headers=world.h("alpha", "admin")).json()["ok"]


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_a_tampered_activation_in_the_chain_forces_containment(world):
    other_app = create_app(demo=True, bootstrap_key=LOCAL_ADMIN, platform_key=PLATFORM)
    other = TestClient(other_app)
    other.post("/v1/actions", json=read(), headers=world.h("alpha", "ops-agent-1"))      # load alpha there
    svc = world.app.state.runtimes.get("alpha")
    forged = dump(base() | {"version": "evil"})
    svc._log_event("mallory", "POLICY_ACTIVATED", {"version": 99, "policy_sha256": "0" * 64, "policy_text": forged,
                                                   "policy_version": "evil", "previous_policy_version": "x",
                                                   "proposed_by": "mallory"}, "forged", prefix="sys")
    r = other.post("/v1/actions", json=read(), headers=world.h("alpha", "ops-agent-1")).json()
    assert r["decision"] == "block" and pv(other, world.h("alpha", "ops-agent-1"), r) != "evil"
    assert other.get("/v1/policy", headers=world.h("alpha", "admin")).json()["fault"] is True
    assert other.post("/v1/actions", json=read(), headers=world.h("beta", "ops-agent-1")).json()["decision"] != "block"


# ---  diff
def test_diff_reports_added_removed_changed_and_whether_it_loosens():
    old = base()
    assert diff_policies(old, copy.deepcopy(old))["loosens"] is False
    tighter = blocking(old)
    d = diff_policies(old, tighter)
    assert d["added"] == ["deny-read-personnel"] and d["removed"] == [] and not d["loosens"]
    looser = copy.deepcopy(old)
    looser["rules"] = [r for r in looser["rules"] if r["effect"] != "deny"][:]
    d = diff_policies(old, looser)
    assert d["loosens"] and any("removes deny" in x for x in d["reasons"])
    flipped = copy.deepcopy(old)
    next(r for r in flipped["rules"] if r["effect"] == "require_approval")["effect"] = "allow"
    assert diff_policies(old, flipped)["loosens"]


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_admins_can_read_the_effective_policy_before_any_edit_and_it_round_trips(world):
    got = world.c.get("/v1/policy", headers=world.h("alpha", "admin")).json()
    assert got["text"] == DEFAULT_POLICY.read_text() and got["history"] == []
    assert propose(world, "alpha", got["text"].replace("version: \"0.1\"", "version: \"0.1.1\"")).status_code == 200
