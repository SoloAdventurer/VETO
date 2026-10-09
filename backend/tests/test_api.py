from fastapi.testclient import TestClient
from veto.gateway.app import create_app
from veto.gateway.service import GatewayService


def client():
    return TestClient(create_app(GatewayService(), demo=True))


def test_state_scenarios_and_audit_roundtrip():
    c = client()
    assert c.get("/healthz").json() == {"ok": True}
    names = [s["id"] for s in c.get("/v1/demo/scenarios").json()]
    assert {"taped_sign", "poisoned_email", "legit_unlock"} <= set(names)
    r = c.post("/v1/demo/scenarios/taped_sign").json()["results"][0]
    assert r["decision"] == "block"
    state = c.get("/v1/state").json()
    assert state["stats"]["unsafe_intercepted"] == 1 and state["chain"]["ok"]
    assert any(x["request_id"] == r["request_id"] for x in c.get("/v1/requests").json())
    assert c.get("/v1/audit/verify").json()["ok"]


def test_post_action_validates_and_blocks_bad_payloads():
    c = client()
    assert c.post("/v1/actions", json={"nonsense": 1}).json()["decision"] == "block"
    assert c.post("/v1/demo/scenarios/nope").status_code == 404


def test_approval_endpoint_flow_and_errors():
    c = client()
    rid = c.post("/v1/demo/scenarios/clearance_request").json()["results"][0]["request_id"]
    own = c.post(f"/v1/approvals/{rid}", json={"approver_id": "admin-agent-1", "outcome": "approved"})
    assert own.status_code == 403
    ok = c.post(f"/v1/approvals/{rid}", json={"approver_id": "sup-1", "outcome": "approved"}).json()
    assert ok["status"] == "executed"
    assert c.post(f"/v1/approvals/{rid}", json={"approver_id": "sup-1", "outcome": "approved"}).status_code == 409
    assert c.post("/v1/approvals/req-unknown", json={"approver_id": "s", "outcome": "approved"}).status_code == 404


def test_containment_endpoint():
    c = client()
    assert c.post("/v1/containment", json={"active": True, "by": "op", "reason": "drill"}).json()["containment"]
    assert c.post("/v1/demo/scenarios/legit_export").json()["results"][0]["decision"] == "block"
    assert c.get("/v1/state").json()["containment"] is True


def test_agent_observation_endpoint_caps_trust():
    c = client()
    obs = {"schema_version": "0.1", "observation_id": "o-1", "source": "db.personnel", "type": "db_record",
           "timestamp": "2026-10-09T10:00:00Z", "data": {}}
    r = c.post("/v1/observations", json=obs, params={"agent_id": "ops-agent-1"}).json()
    assert r["trusted"] is False and r["capped"] is True
    assert c.post("/v1/observations", json=obs).status_code == 409   # duplicate id
