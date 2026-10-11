"""Several gateway processes on one database behave as one gateway (DECISIONS D-026).

Every test builds two GatewayService objects on the same store, standing in for two processes: nothing in memory is
shared, only the database. SQLite always; PostgreSQL when VETO_TEST_PG_DSN is set."""

import threading
import time

import pytest
from conftest import BACKENDS
from veto.auth.store import AuthError, PrincipalStore
from veto.gateway.scenarios import _action
from veto.gateway.service import GatewayService, RequestError


class Clock:
    """Starts at the real time, because records written by other processes carry real timestamps."""

    def __init__(self):
        self.t = time.time()

    def __call__(self):
        return self.t


def pair(target, clock=None):
    clock = clock or time.time
    return GatewayService(db_path=target, clock=clock), GatewayService(db_path=target, clock=clock), clock


def export(agent, rows):
    return _action(agent, "EXPORT_INCIDENT_LOG", "incident_log", "all", {"row_count": rows}, why="export")


def read(agent="ops-agent-1"):
    return _action(agent, "READ_PERSONNEL", "personnel", "emp-1042", {}, why="read")


def clearance(i):
    return _action("admin-agent-1", "UPDATE_CLEARANCE", "personnel", f"emp-{1000 + i}", {"new_level": 2}, why="x")


def email(svc, agent="ops-agent-1"):
    oid = svc.next_observation_id()
    svc.register_observation({"schema_version": "0.1", "observation_id": oid, "source": "mail.inbox",
                              "type": "email", "timestamp": "2026-10-11T10:00:00Z", "data": {}},
                             agent_id=agent, operator_channel=False)
    return oid


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_containment_on_one_gateway_stops_the_other_at_once(target):
    a, b, _ = pair(target)
    assert b.propose_action(read())["decision"] in ("allow", "allow_monitor")
    a.set_containment(True, "operator", "drill")
    assert b.propose_action(read())["decision"] == "block"          # b never restarted, never told directly
    a.set_containment(False, "operator", "over")
    assert b.propose_action(read())["decision"] in ("allow", "allow_monitor")
    assert a.audit.verify()["ok"]


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_session_taint_follows_the_agent_across_gateways(target):
    a, b, _ = pair(target)
    email(a)                                                          # the agent reads a poisoned email via a ...
    r = b.propose_action(export("ops-agent-1", 50))                   # ... and acts through b, undeclared
    assert r["decision"] == "block" and r["effective_provenance"] == ["email"]
    b.reset_agent_context("ops-agent-1", "operator")                  # the operator resets on b
    assert a.propose_action(export("ops-agent-1", 50))["status"] == "executed"   # a sees the reset


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_an_approval_held_on_one_gateway_is_decided_on_the_other(target):
    a, b, _ = pair(target)
    r = a.propose_action(clearance(1))
    assert r["status"] == "pending_approval"
    done = b.resolve_approval(r["request_id"], "human-1", "approved")
    assert done["status"] == "executed"
    with pytest.raises(RequestError) as e:
        a.resolve_approval(r["request_id"], "human-2", "approved")      # a knows it is already decided
    assert e.value.status == 409
    assert not a._pending and not b._pending


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_pending_approval_cap_counts_across_gateways(target):
    a, b, _ = pair(target)
    cap = a.max_pending_per_agent
    for i in range(cap):
        assert (a if i % 2 else b).propose_action(clearance(i))["status"] == "pending_approval"
    over = a.propose_action(clearance(99))
    assert over["decision"] == "block" and "cap" in over["reason"].lower()


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_volume_limits_count_actions_from_every_gateway(target):
    a, b, _ = pair(target)
    for svc in (a, b, a, b, a):                                       # 5 x 100 rows = the 500-row hourly limit
        assert svc.propose_action(export("ops-agent-1", 100))["status"] == "executed"
    assert b.propose_action(export("ops-agent-1", 100))["decision"] == "block"
    assert a.propose_action(export("ops-agent-1", 100))["decision"] == "block"


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_approval_expiry_is_seen_by_both(target):
    clock = Clock()
    a, b, _ = pair(target, clock)
    r = a.propose_action(clearance(2))
    clock.t += a.approval_expiry_s + 5
    b.propose_action(read())                                           # any traffic on b sweeps the expiry
    with pytest.raises(RequestError) as e:
        a.resolve_approval(r["request_id"], "human-1", "approved")
    assert e.value.status == 409
    assert a.audit.latest_for_request(r["request_id"])["human_decision"]["outcome"] == "expired"


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_keys_and_revocations_are_shared(target):
    s1, s2 = PrincipalStore(target), PrincipalStore(target)
    s1.create_principal("ops-agent-1", ["agent"])
    key_id, key = s1.issue_key("ops-agent-1")
    assert s2.authenticate(key).id == "ops-agent-1"
    with pytest.raises(AuthError) as e:
        s2.create_principal("ops-agent-1", ["agent"])
    assert e.value.status == 409
    s1.revoke_key(key_id)
    assert s2.authenticate(key) is None                                # revoked on one, refused on the other


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_simultaneous_decisions_cannot_overspend_a_limit(target):
    if not target.startswith("postgres"):
        pytest.skip("cross-process locking is a PostgreSQL feature; SQLite is single-process")
    a, b, _ = pair(target)
    results: list[str] = []

    def work(svc):
        for _ in range(6):
            results.append(svc.propose_action(export("ops-agent-1", 100))["status"])

    threads = [threading.Thread(target=work, args=(s,)) for s in (a, b, a, b)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert results.count("executed") == 5, results                    # 500 rows allowed, never 600
    assert a.audit.verify()["ok"]
