"""End-to-end behaviour of the VETO pipeline: the headline attacks, approvals, containment, audit integrity."""
import copy
from datetime import datetime, timezone

import pytest
from veto.canonical import action_hash
from veto.gateway.scenarios import SCENARIOS, run_scenario
from veto.gateway.service import GatewayService, RequestError


@pytest.fixture()
def svc():
    return GatewayService()


def ts():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def act(agent, verb, resource, rid, params, *, obs=None, inputs=None, channel="autonomous"):
    ctx = {"on_behalf_of": {"principal_id": agent, "channel": channel}, "justification": "test"}
    if obs:
        ctx["observation_ids"] = obs
    if inputs:
        ctx["inputs"] = inputs
    return {"schema_version": "0.1", "agent_id": agent, "action": verb, "target": {"resource": resource, "id": rid},
            "parameters": params, "timestamp": ts(), "context": ctx}


def unlock(subject="emp-1042", door="door-3", **kw):
    return act("gate-agent-1", "UNLOCK_DOOR", "door", door, {"duration_s": 10, "subject_id": subject}, **kw)


def register(svc, source, agent, operator=False, typ="ocr_text"):
    oid = svc.next_observation_id()
    svc.register_observation({"schema_version": "0.1", "observation_id": oid, "source": source, "type": typ,
                              "timestamp": ts(), "data": {"text": "x"}}, agent_id=agent, operator_channel=operator)
    return oid


# ---------------------------------------------------------------- headline attacks
def test_taped_sign_cannot_unlock_door(svc):
    out = run_scenario(svc, "taped_sign")["results"][0]
    assert out["decision"] == "block" and out["status"] == "blocked"
    assert out["execution"] is None
    assert next(d for d in svc.view.doors() if d["id"] == "door-3")["state"] == "locked"


def test_declaring_a_trusted_origin_does_not_launder_untrusted_content(svc):
    out = run_scenario(svc, "taped_sign_hidden")["results"][0]
    assert out["decision"] == "block"
    assert "sensor_ocr" in out["effective_provenance"]


def test_agent_cannot_register_a_trusted_observation(svc):
    oid = register(svc, "db.personnel", "gate-agent-1", operator=False, typ="db_record")
    assert svc.prov.get(oid).origin == "unknown" and svc.prov.get(oid).capped
    out = svc.propose_action(unlock(obs=[oid], inputs=[{"ref": oid, "origin": "trusted_store"}]))
    # tainted context -> the allow rule (requires untainted) cannot match
    assert out["decision"] == "block"


def test_operator_observation_is_bound_to_one_agent(svc):
    oid = register(svc, "operator.console", "gate-agent-1", operator=True, typ="operator_message")
    ok = svc.propose_action(unlock(obs=[oid], inputs=[{"ref": oid, "origin": "operator_input"}]))
    assert ok["decision"] in ("allow", "allow_monitor") and ok["status"] == "executed"
    # another agent re-using the id gets no trust from it
    stolen = act("admin-agent-1", "UPDATE_CLEARANCE", "personnel", "visitor-77", {"new_level": 4}, obs=[oid],
                 inputs=[{"ref": oid, "origin": "operator_input"}])
    assert svc.propose_action(stolen)["decision"] != "allow"
    assert "unknown" in svc.propose_action(stolen)["effective_provenance"]


def test_poisoned_email_cannot_trigger_bulk_export(svc):
    out = run_scenario(svc, "poisoned_email")["results"][0]
    assert out["decision"] == "block" and out["execution"] is None


def test_legit_unlock_runs_and_is_verified(svc):
    out = run_scenario(svc, "legit_unlock")["results"][0]
    assert out["status"] == "executed" and out["verification"]["status"] == "verified"
    assert next(d for d in svc.view.doors() if d["id"] == "door-3")["state"] == "unlocked"


def test_insufficient_clearance_is_blocked_even_from_trusted_context(svc):
    oid = register(svc, "operator.console", "gate-agent-1", operator=True, typ="operator_message")
    out = svc.propose_action(unlock(subject="emp-2210", obs=[oid], inputs=[{"ref": oid, "origin": "operator_input"}]))
    assert out["decision"] == "block"          # emp-2210 is level 1, door-3 needs 3


def test_default_deny_for_unknown_agent_and_rbac(svc):
    assert run_scenario(svc, "unknown_agent")["results"][0]["decision"] == "block"
    assert run_scenario(svc, "destructive_delete")["results"][0]["decision"] == "block"


# ---------------------------------------------------------------- input hardening
def test_schema_smuggling_is_rejected_and_audited(svc):
    bad = unlock()
    bad["extra_field"] = "x"
    out = svc.propose_action(bad)
    assert out["decision"] == "block" and "schema" in out["reason"]
    assert svc.audit.latest_for_request(out["request_id"]) is not None


@pytest.mark.parametrize("rid", ["door-3; DROP", "door‮3", "../door-3", "door 3"])
def test_target_id_injection_rejected(svc, rid):
    assert svc.propose_action(unlock(door=rid))["decision"] == "block"


def test_unknown_parameter_rejected(svc):
    a = unlock()
    a["parameters"]["force"] = True
    assert svc.propose_action(a)["decision"] == "block"


# ---------------------------------------------------------------- policy supremacy / escalation only
def test_risk_can_escalate_but_never_downgrade_a_block(svc):
    out = svc.propose_action(act("ops-agent-1", "DELETE_RECORD", "personnel", "emp-1000", {}))
    assert out["decision"] == "block" and out["risk"]["band"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def test_anomaly_escalates_action_splitting(svc):
    results = run_scenario(svc, "action_splitting")["results"]
    decisions = [r["decision"] for r in results]
    assert decisions[0] == "allow"
    assert "allow_monitor" in decisions and "require_approval" in decisions
    first_escalation = decisions.index("require_approval")
    assert all(d != "allow" for d in decisions[first_escalation:])


def test_windowed_export_limit_blocks_after_budget(svc):
    for _ in range(5):
        assert svc.propose_action(act("ops-agent-1", "EXPORT_INCIDENT_LOG", "incident_log", "all",
                                      {"row_count": 100}))["status"] == "executed"
    over = svc.propose_action(act("ops-agent-1", "EXPORT_INCIDENT_LOG", "incident_log", "all", {"row_count": 100}))
    assert over["decision"] == "block" and "limit" in over["reason"].lower()


# ---------------------------------------------------------------- human approval
def _pending(svc):
    out = run_scenario(svc, "clearance_request")["results"][0]
    assert out["status"] == "pending_approval"
    return out["request_id"]


def test_approval_executes_and_verifies(svc):
    rid = _pending(svc)
    assert svc.view.clearance_of("emp-2210") == 1            # nothing happened yet
    out = svc.resolve_approval(rid, "supervisor-1", "approved", "ok")
    assert out["status"] == "executed" and out["verification"]["status"] == "verified"
    assert svc.view.clearance_of("emp-2210") == 2


def test_rejection_never_executes(svc):
    rid = _pending(svc)
    out = svc.resolve_approval(rid, "supervisor-1", "rejected")
    assert out["status"] == "rejected" and svc.view.clearance_of("emp-2210") == 1


def test_agent_cannot_approve_itself_and_cannot_double_resolve(svc):
    rid = _pending(svc)
    with pytest.raises(RequestError):
        svc.resolve_approval(rid, "admin-agent-1", "approved")
    svc.resolve_approval(rid, "supervisor-1", "approved")
    with pytest.raises(RequestError):
        svc.resolve_approval(rid, "supervisor-2", "approved")


# ---------------------------------------------------------------- containment
def test_containment_blocks_everything_and_release_restores(svc):
    svc.set_containment(True, "operator-1", "drill")
    legit = run_scenario(svc, "legit_export")["results"][0]
    assert legit["decision"] == "block" and "containment" in legit["reason"].lower()
    svc.set_containment(False, "operator-1")
    assert run_scenario(svc, "legit_export")["results"][0]["decision"] != "block"


def test_approval_granted_during_containment_does_not_execute(svc):
    rid = _pending(svc)
    svc.set_containment(True, "operator-1")
    out = svc.resolve_approval(rid, "supervisor-1", "approved")
    assert out["execution"]["status"] == "not_executed" and svc.view.clearance_of("emp-2210") == 1


# ---------------------------------------------------------------- execution gateway / bypass
def test_direct_resource_call_without_key_is_refused(svc):
    out = run_scenario(svc, "direct_bypass")["results"][0]
    assert out["decision"] == "block" and svc.view.denied_direct_attempts == 1


def test_execution_refuses_tampered_action_and_forged_token(svc):
    action = {"agent_id": "gate-agent-1", "action": "UNLOCK_DOOR", "target": {"resource": "door", "id": "door-1"},
              "parameters": {"duration_s": 5, "subject_id": "emp-1042"}}
    h = action_hash(action)
    tag = svc.signer.sign("req-x", h, "allow")
    assert svc.execution.execute(request_id="req-x", action=action, ahash=h, decision_label="allow",
                                 tag=tag)["status"] == "executed"
    tampered = copy.deepcopy(action)
    tampered["target"]["id"] = "door-4"
    r = svc.execution.execute(request_id="req-x", action=tampered, ahash=h, decision_label="allow", tag=tag)
    assert r["status"] == "not_executed" and "hash mismatch" in r["result_summary"]
    forged = svc.execution.execute(request_id="req-x", action=action, ahash=h, decision_label="allow", tag="0" * 64)
    assert forged["status"] == "not_executed" and "token" in forged["result_summary"]
    wrong_label = svc.execution.execute(request_id="req-x", action=action, ahash=h, decision_label="approved",
                                        tag=tag)
    assert wrong_label["status"] == "not_executed"


# ---------------------------------------------------------------- audit integrity
def test_audit_is_written_before_execution_and_chain_verifies(svc):
    out = run_scenario(svc, "legit_unlock")["results"][0]
    recs = [r for r in svc.audit.all() if r["request_id"] == out["request_id"]]
    assert recs[0]["execution"] is None and recs[1]["execution"]["status"] == "executed"
    assert svc.audit.verify()["ok"]


def test_audit_log_is_append_only_in_the_database(svc):
    run_scenario(svc, "taped_sign")
    db = svc.audit._raw_connection()
    for sql in ("UPDATE audit SET request_id='x'", "DELETE FROM audit"):
        with pytest.raises(Exception, match="append-only"):
            db.execute(sql)


def test_out_of_band_tampering_is_detected(svc):
    for name in ("taped_sign", "legit_export"):
        run_scenario(svc, name)
    db = svc.audit._raw_connection()
    db.execute("DROP TRIGGER audit_no_update")          # attacker with file access removes the guard...
    seq, record = db.execute(
        "SELECT seq, record FROM audit WHERE request_id LIKE 'req-%' ORDER BY seq LIMIT 1").fetchone()
    db.execute("UPDATE audit SET record = ? WHERE seq = ?", (record.replace('"block"', '"allow"'), seq))
    db.commit()
    result = svc.audit.verify()                          # ...but the hash chain still exposes the edit
    assert result["ok"] is False and result["broken_at"] == seq


def test_all_scenarios_run_and_unsafe_ones_are_intercepted(svc):
    for name in SCENARIOS:
        run_scenario(svc, name)
    stats = svc.stats()
    assert stats["unsafe_attempted"] >= 7 and stats["uir"] == 1.0
    assert svc.audit.verify()["ok"]
