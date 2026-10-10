from fastapi.testclient import TestClient
from veto.auth.store import PrincipalStore
from veto.gateway.app import create_app
from veto.gateway.service import GatewayService

ADMIN = "veto_test-bootstrap-admin-key-000000"


def make():
    store = PrincipalStore()
    c = TestClient(create_app(GatewayService(), demo=True, store=store, bootstrap_key=ADMIN))
    c.headers.update({"Authorization": f"Bearer {ADMIN}"})
    return c


def client():
    return make()


def test_state_scenarios_and_audit_roundtrip():
    c = client()
    assert c.get("/healthz").json() == {"ok": True}
    names = [s["id"] for s in c.get("/v1/demo/scenarios").json()]
    assert {"taped_sign", "poisoned_email", "legit_unlock", "impersonation"} <= set(names)
    r = c.post("/v1/demo/scenarios/taped_sign").json()["results"][0]
    assert r["decision"] == "block"
    state = c.get("/v1/state").json()
    assert state["stats"]["unsafe_intercepted"] == 1 and state["chain"]["ok"]
    assert any(x["request_id"] == r["request_id"] for x in c.get("/v1/requests").json())
    assert c.get("/v1/audit/verify").json()["ok"]


def test_post_action_validates_and_blocks_bad_payloads():
    c = client()
    c.post("/v1/admin/principals", json={"id": "ops-agent-1", "roles": ["agent"]})
    key = c.post("/v1/admin/principals/ops-agent-1/keys").json()["key"]
    r = c.post("/v1/actions", json={"nonsense": 1}, headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 403 or r.json()["decision"] == "block"
    assert c.post("/v1/demo/scenarios/nope").status_code == 404


def test_approval_endpoint_flow_and_errors():
    c = client()
    rid = c.post("/v1/demo/scenarios/clearance_request").json()["results"][0]["request_id"]
    ok = c.post(f"/v1/approvals/{rid}", json={"outcome": "approved"}).json()
    assert ok["status"] == "executed"
    assert c.post(f"/v1/approvals/{rid}", json={"outcome": "approved"}).status_code == 409
    assert c.post("/v1/approvals/req-unknown", json={"outcome": "approved"}).status_code == 404


def test_containment_endpoint():
    c = client()
    assert c.post("/v1/containment", json={"active": True, "reason": "drill"}).json()["containment"]
    assert c.post("/v1/demo/scenarios/legit_export").json()["results"][0]["decision"] == "block"
    assert c.get("/v1/state").json()["containment"] is True


def test_agent_observation_endpoint_caps_trust():
    c = client()
    c.post("/v1/admin/principals", json={"id": "ops-agent-1", "roles": ["agent"]})
    h = {"Authorization": "Bearer " + c.post("/v1/admin/principals/ops-agent-1/keys").json()["key"]}
    obs = {"schema_version": "0.1", "observation_id": "o-1", "source": "db.personnel", "type": "db_record",
           "timestamp": "2026-10-09T10:00:00Z", "data": {}}
    r = c.post("/v1/observations", json=obs, headers=h).json()
    assert r["trusted"] is False and r["capped"] is True
    assert c.post("/v1/observations", json=obs, headers=h).status_code == 409  # duplicate id
