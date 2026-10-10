"""Authentication and authorisation (D-021): closes T6 (identity spoofing) and T7 (forged approvals / flooding)."""

import sqlite3
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from veto.auth.store import AuthError, PrincipalStore
from veto.gateway.app import create_app
from veto.gateway.scenarios import _action
from veto.gateway.service import GatewayService

ADMIN = "veto_test-bootstrap-admin-key-000000"


def bearer(key):
    return {"Authorization": f"Bearer {key}"}


@pytest.fixture
def env():
    store = PrincipalStore()
    svc = GatewayService()
    c = TestClient(create_app(svc, demo=True, store=store, bootstrap_key=ADMIN))
    admin = bearer(ADMIN)

    def mint(pid, roles):
        assert c.post("/v1/admin/principals", json={"id": pid, "roles": roles}, headers=admin).status_code == 200
        r = c.post(f"/v1/admin/principals/{pid}/keys", headers=admin).json()
        return r["key_id"], bearer(r["key"])

    class E:
        pass
    e = E()
    e.c, e.store, e.svc, e.admin, e.mint = c, store, svc, admin, mint
    e.ops = mint("ops-agent-1", ["agent"])[1]
    e.admin_agent = mint("admin-agent-1", ["agent"])[1]
    e.operator = mint("op-1", ["operator"])[1]
    e.approver = mint("appr-1", ["approver"])[1]
    e.viewer = mint("view-1", ["viewer"])[1]
    return e


def read_action(rid="emp-1042"):
    return _action("ops-agent-1", "READ_PERSONNEL", "personnel", rid, {}, why="lookup")


def test_no_key_or_bad_key_is_401_everywhere(env):
    c = env.c
    for method, path in [("get", "/v1/state"), ("get", "/v1/audit"), ("get", "/v1/requests"), ("post", "/v1/actions"),
                         ("post", "/v1/containment"), ("get", "/v1/admin/principals"),
                         ("get", "/v1/demo/scenarios"), ("post", "/v1/approvals/x")]:
        assert getattr(c, method)(path).status_code == 401, path
        assert getattr(c, method)(path, headers=bearer("veto_nope-nope-nope-nope-nope-0")).status_code == 401
        assert getattr(c, method)(path, headers={"Authorization": "Basic abc"}).status_code == 401
    assert c.get("/healthz").status_code == 200 and c.get("/v1/auth/info").json()["auth"] == "bearer"
    assert env.store.failures >= 1


def test_role_matrix(env):
    c = env.c
    # agents cannot read, approve, contain, administer or run demos
    for method, path in [("get", "/v1/state"), ("get", "/v1/audit"), ("get", "/v1/audit/verify"),
                         ("get", "/v1/requests"), ("get", "/v1/admin/principals"), ("get", "/v1/demo/scenarios")]:
        assert getattr(c, method)(path, headers=env.ops).status_code == 403, path
    assert c.post("/v1/containment", json={"active": True}, headers=env.ops).status_code == 403
    assert c.post("/v1/approvals/x", json={"outcome": "approved"}, headers=env.ops).status_code == 403
    # humans cannot submit actions as agents
    assert c.post("/v1/actions", json=read_action(), headers=env.operator).status_code == 403
    # viewer is read-only
    assert c.get("/v1/state", headers=env.viewer).status_code == 200
    assert c.post("/v1/containment", json={"active": True}, headers=env.viewer).status_code == 403
    assert c.post("/v1/approvals/x", json={"outcome": "approved"}, headers=env.viewer).status_code == 403
    # operator cannot approve; approver cannot contain; neither administers
    assert c.post("/v1/approvals/x", json={"outcome": "approved"}, headers=env.operator).status_code == 403
    assert c.post("/v1/containment", json={"active": True}, headers=env.approver).status_code == 403
    assert c.get("/v1/admin/principals", headers=env.operator).status_code == 403
    assert c.post("/v1/containment", json={"active": True}, headers=env.operator).status_code == 200


def test_agent_acts_as_itself_and_reads_only_its_own_requests(env):
    c = env.c
    r = c.post("/v1/actions", json=read_action(), headers=env.ops)
    assert r.status_code == 200 and r.json()["decision"] in ("allow", "allow_monitor")
    rid = r.json()["request_id"]
    assert c.get(f"/v1/actions/{rid}", headers=env.ops).status_code == 200
    assert c.get(f"/v1/actions/{rid}", headers=env.admin_agent).status_code == 404
    assert c.get(f"/v1/actions/{rid}", headers=env.viewer).status_code == 200


def test_impersonation_is_blocked_audited_and_not_executed(env):
    act = _action("admin-agent-1", "UPDATE_CLEARANCE", "personnel", "visitor-77", {"new_level": 1}, why="as admin")
    r = env.c.post("/v1/actions", json=act, headers=env.ops)
    assert r.status_code == 403
    body = r.json()
    assert body["decision"] == "block" and "Identity mismatch" in body["reason"]
    rec = env.svc.audit.latest_for_request(body["request_id"])
    assert rec["agent_id"] == "ops-agent-1"            # attributed to the key's real owner
    assert rec["policies_evaluated"][0]["rule_id"] == "builtin:identity-mismatch"
    assert rec.get("execution") is None and env.svc.view.clearance_of("visitor-77") == 0


def test_impersonation_scenario_counts_as_intercepted(env):
    res = env.c.post("/v1/demo/scenarios/impersonation", headers=env.operator).json()["results"][0]
    assert res["decision"] == "block"
    assert env.c.get("/v1/state", headers=env.viewer).json()["stats"]["unsafe_intercepted"] == 1


def test_approver_identity_comes_from_key_not_body(env):
    rid = env.c.post("/v1/demo/scenarios/clearance_request", headers=env.operator).json()["results"][0]["request_id"]
    r = env.c.post(f"/v1/approvals/{rid}", json={"approver_id": "someone-else", "outcome": "approved"},
                   headers=env.approver)
    assert r.json()["status"] == "executed"
    assert env.svc.audit.latest_for_request(rid)["human_decision"]["approver_id"] == "appr-1"


def test_revoked_and_disabled_keys_stop_working_immediately(env):
    key_id, h = env.mint("temp-viewer", ["viewer"])
    assert env.c.get("/v1/state", headers=h).status_code == 200
    assert env.c.delete(f"/v1/admin/keys/{key_id}", headers=env.admin).status_code == 200
    assert env.c.get("/v1/state", headers=h).status_code == 401
    assert env.c.delete(f"/v1/admin/keys/{key_id}", headers=env.admin).status_code == 404
    _, h2 = env.mint("temp-viewer-2", ["viewer"])
    assert env.c.post("/v1/admin/principals/temp-viewer-2/disable", headers=env.admin).status_code == 200
    assert env.c.get("/v1/state", headers=h2).status_code == 401
    assert env.c.post("/v1/admin/principals/temp-viewer-2/keys", headers=env.admin).status_code == 409


def test_key_rotation_old_key_dies_new_key_works(env):
    key_id, old = env.mint("rot-view", ["viewer"])
    new = bearer(env.c.post("/v1/admin/principals/rot-view/keys", headers=env.admin).json()["key"])
    env.c.delete(f"/v1/admin/keys/{key_id}", headers=env.admin)
    assert env.c.get("/v1/state", headers=old).status_code == 401
    assert env.c.get("/v1/state", headers=new).status_code == 200


def test_roles_validation_and_agent_exclusivity(env):
    s = PrincipalStore()
    with pytest.raises(AuthError):
        s.create_principal("mixed-1", ["agent", "approver"])
    with pytest.raises(AuthError):
        s.create_principal("badrole", ["root"])
    with pytest.raises(AuthError):
        s.create_principal("Bad Id", ["viewer"])
    s.create_principal("ok-one", ["viewer"])
    with pytest.raises(AuthError):
        s.create_principal("ok-one", ["viewer"])
    assert env.c.post("/v1/admin/principals", json={"id": "x1", "roles": ["agent", "admin"]},
                      headers=env.admin).status_code == 400


def test_keys_are_stored_hashed_and_never_listed(env):
    _, h = env.mint("hash-check", ["viewer"])
    key = h["Authorization"].split()[1]
    dump = "\n".join(env.store._db.iterdump())
    assert key not in dump and key[:11] in dump          # only a short display prefix is kept
    assert key not in env.c.get("/v1/admin/principals", headers=env.admin).text


def test_admin_changes_are_audited(env):
    env.mint("audited-one", ["viewer"])
    actions = [r["requested_action"]["action"] for r in env.svc.audit.all() if r["request_id"].startswith("sys-")]
    assert "CREATE_PRINCIPAL" in actions and "ISSUE_KEY" in actions
    assert env.c.get("/v1/audit/verify", headers=env.viewer).json()["ok"]


def test_demo_endpoints_404_when_demo_off():
    c = TestClient(create_app(GatewayService(), demo=False, store=PrincipalStore(), bootstrap_key=ADMIN))
    assert c.get("/v1/demo/scenarios", headers=bearer(ADMIN)).status_code in (404, 405)
    assert c.get("/v1/auth/me", headers=bearer(ADMIN)).json()["demo"] is False


def test_approval_flood_is_capped(env):
    # lower the cap, then submit clearance requests that need approval from the same agent
    env.svc.policy.raw.setdefault("approvals", {})["max_pending_per_agent"] = 2
    decisions = []
    for i in range(4):
        obs_id = env.svc.next_observation_id()
        env.svc.register_observation(
            {"schema_version": "0.1", "observation_id": obs_id, "source": "operator.console",
             "type": "operator_message", "timestamp": "2026-10-09T10:00:00Z", "data": {"text": "raise"}},
            agent_id="admin-agent-1", operator_channel=True)
        act = _action("admin-agent-1", "UPDATE_CLEARANCE", "personnel", f"emp-{2210 + i}", {"new_level": 2},
                      why="promotion", obs=[obs_id], inputs=[{"ref": obs_id, "origin": "operator_input"}],
                      channel="operator_session")
        decisions.append(env.c.post("/v1/actions", json=act, headers=env.admin_agent).json())
    assert [d["decision"] for d in decisions][:2] == ["require_approval", "require_approval"]
    assert decisions[2]["decision"] == "block" and "cap" in decisions[2]["reason"]
    # resolving one frees a slot
    env.c.post(f"/v1/approvals/{decisions[0]['request_id']}", json={"outcome": "rejected"}, headers=env.approver)
    assert env.svc._pending.__len__() == 1


def test_bootstrap_is_idempotent_and_validates_key():
    s = PrincipalStore()
    s.bootstrap(ADMIN)
    s.bootstrap(ADMIN)
    assert len(s.list_principals()) == 1 and len(s.list_principals()[0]["keys"]) == 1
    with pytest.raises(AuthError):
        s.bootstrap("short")
    assert s.authenticate(ADMIN).has("admin", "approver", "operator", "viewer")


def test_principals_persist_across_restart():
    path = Path(tempfile.mkdtemp()) / "auth.db"
    s = PrincipalStore(str(path))
    s.create_principal("persist-me", ["viewer"])
    _, key = s.issue_key("persist-me")
    s2 = PrincipalStore(str(path))
    assert s2.authenticate(key).id == "persist-me"
    assert sqlite3.connect(path).execute("SELECT count(*) FROM api_keys").fetchone()[0] == 1
