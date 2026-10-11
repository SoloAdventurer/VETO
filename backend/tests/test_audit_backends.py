"""One contract for every audit backend (SQLite always; PostgreSQL when VETO_TEST_PG_DSN is set, DECISIONS D-025)."""

import threading

import pytest
from conftest import BACKENDS
from veto.audit import open_audit
from veto.gateway.scenarios import run_scenario
from veto.gateway.service import GatewayService


def _record(rid="req-1", decision="block"):
    return {"schema_version": "0.1", "request_id": rid, "agent_id": "ops-agent-1",
            "requested_action": {"action": "READ_PERSONNEL"}, "action_hash": "a" * 64, "decision": decision,
            "policy_version": "t", "decision_reason": "t", "policies_evaluated": []}


def tamper(log, target):
    if target.startswith("postgres"):
        import psycopg
        with psycopg.connect(target, autocommit=True) as c:
            c.execute("ALTER TABLE audit DISABLE TRIGGER USER")
            c.execute("UPDATE audit SET record = replace(record, 'block', 'allow') WHERE seq = 2")
    else:
        db = log._raw_connection()
        db.execute("DROP TRIGGER audit_no_update")
        db.execute("UPDATE audit SET record = replace(record, 'block', 'allow') WHERE seq = 2")
        db.commit()


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_append_read_verify_and_persistence(target):
    log = open_audit(target)
    a, b = log.append(_record("req-1")), log.append(_record("req-2"))
    assert b["prev_hash"] == a["record_hash"] and b["seq"] > a["seq"]
    assert log.latest_for_request("req-2")["seq"] == b["seq"] and log.latest_for_request("nope") is None
    assert log.verify() == {"ok": True, "count": 2, "broken_at": None, "detail": "chain intact"}
    again = open_audit(target)                       # a new process opening the same store
    assert [r["request_id"] for r in again.all()] == ["req-1", "req-2"]
    c = again.append(_record("req-3"))
    assert c["prev_hash"] == b["record_hash"] and again.verify()["ok"]


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_rejects_schema_violations_and_stores_nothing(target):
    log = open_audit(target)
    with pytest.raises(ValueError):
        log.append({"request_id": "x"})
    assert log.all() == []


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_database_itself_refuses_update_delete(target):
    log = open_audit(target)
    log.append(_record())
    if target.startswith("postgres"):
        import psycopg
        with psycopg.connect(target, autocommit=True) as c:
            for sql in ("UPDATE audit SET record = 'x'", "DELETE FROM audit", "TRUNCATE audit"):
                with pytest.raises(psycopg.Error, match="append-only"):
                    c.execute(sql)
    else:
        import sqlite3
        db = log._raw_connection()
        for sql in ("UPDATE audit SET record = 'x'", "DELETE FROM audit"):
            with pytest.raises(sqlite3.DatabaseError, match="append-only"):
                db.execute(sql)
    assert log.verify()["ok"] and len(log.all()) == 1


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_out_of_band_edit_is_detected(target):
    log = open_audit(target)
    for i in range(3):
        log.append(_record(f"req-{i}"))
    tamper(log, target)
    v = log.verify()
    assert v["ok"] is False and v["broken_at"] == 2 and v["detail"] == "record_hash mismatch"


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_two_writers_share_one_linear_chain(target):
    if not target.startswith("postgres"):
        pytest.skip("SQLite is single-process by design")
    logs = [open_audit(target) for _ in range(4)]

    def work(log, n):
        for i in range(25):
            log.append(_record(f"req-{n}-{i}"))

    threads = [threading.Thread(target=work, args=(lg, n)) for n, lg in enumerate(logs)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert logs[0].verify() == {"ok": True, "count": 100, "broken_at": None, "detail": "chain intact"}


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_gateway_runs_and_restarts_safely_on_this_backend(target):
    svc = GatewayService(db_path=target)
    assert run_scenario(svc, "taped_sign")["results"][0]["decision"] == "block"
    assert run_scenario(svc, "legit_export")["results"][0]["status"] == "executed"
    svc.set_containment(True, "op", "drill")
    restarted = GatewayService(db_path=target)          # new process, same database
    assert restarted.containment is True and restarted.audit.verify()["ok"]
    assert restarted.propose_action(__import__("copy").deepcopy(
        {"schema_version": "0.1", "agent_id": "ops-agent-1", "action": "READ_PERSONNEL",
         "target": {"resource": "personnel", "id": "emp-1042"}, "parameters": {},
         "timestamp": "2026-10-11T10:00:00Z",
         "context": {"on_behalf_of": {"principal_id": "ops-agent-1", "channel": "autonomous"},
                     "justification": "x"}}))["decision"] == "block"
