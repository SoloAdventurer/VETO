"""Approval expiry, request rate limits, sign-in lockout and richer anomaly signals (D-022)."""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from veto.anomaly.detector import AnomalyDetector
from veto.auth.store import PrincipalStore
from veto.gateway.app import create_app
from veto.gateway.ratelimit import FailureLockout, TokenBucketLimiter
from veto.gateway.scenarios import _action, run_scenario
from veto.gateway.service import GatewayService, RequestError
from veto.policy.engine import validate_policy

ADMIN = "veto_test-bootstrap-admin-key-000000"


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def bearer(key):
    return {"Authorization": f"Bearer {key}"}


# ---------------------------------------------------------------- approval expiry
def pending_request(svc):
    return run_scenario(svc, "clearance_request")["results"][0]["request_id"]


def test_pending_approval_expires_to_block_and_never_executes():
    clock = Clock()
    svc = GatewayService(clock=clock)
    rid = pending_request(svc)
    assert svc.audit.latest_for_request(rid)["decision"] == "require_approval"
    clock.t += svc.approval_expiry_s - 1
    assert svc.requests_view()[0]["status"] == "pending_approval"      # not yet
    clock.t += 2
    row = next(r for r in svc.requests_view() if r["request_id"] == rid)
    assert row["status"] == "expired"
    assert row["human_decision"]["outcome"] == "expired" and row["human_decision"]["approver_id"] == "system"
    assert row["execution"]["status"] == "not_executed"
    assert svc.view.clearance_of("emp-2210") == 1                        # the change never happened
    assert svc.audit.verify()["ok"]


def test_expired_request_cannot_be_approved_late():
    clock = Clock()
    svc = GatewayService(clock=clock)
    rid = pending_request(svc)
    clock.t += svc.approval_expiry_s + 1
    with pytest.raises(RequestError) as exc:
        svc.resolve_approval(rid, "sup-1", "approved")
    assert exc.value.status == 409 and svc.view.clearance_of("emp-2210") == 1


def test_approving_before_expiry_still_works():
    clock = Clock()
    svc = GatewayService(clock=clock)
    rid = pending_request(svc)
    clock.t += svc.approval_expiry_s - 5
    assert svc.resolve_approval(rid, "sup-1", "approved")["status"] == "executed"


def test_expiry_frees_the_pending_cap_slot():
    clock = Clock()
    svc = GatewayService(clock=clock)
    svc.policy.raw.setdefault("approvals", {})["max_pending_per_agent"] = 1
    first = pending_request(svc)
    second = run_scenario(svc, "clearance_request")["results"][0]
    assert second["decision"] == "block" and "cap" in second["reason"]
    clock.t += svc.approval_expiry_s + 1
    third = run_scenario(svc, "clearance_request")["results"][0]
    assert third["decision"] == "require_approval"
    assert svc.audit.latest_for_request(first)["human_decision"]["outcome"] == "expired"


def test_expiry_survives_restart(tmp_path):
    db = str(tmp_path / "audit.db")
    clock = Clock()
    svc = GatewayService(db_path=db, clock=clock)
    rid = pending_request(svc)
    svc2 = GatewayService(db_path=db, clock=Clock(clock.t + svc.approval_expiry_s + 5))
    assert next(r for r in svc2.requests_view() if r["request_id"] == rid)["status"] == "expired"


@pytest.mark.parametrize("bad", [0, -5, True, "900", None])
def test_policy_rejects_bad_expiry(bad):
    raw = GatewayService().policy.raw
    errors = validate_policy({**raw, "approvals": {"expire_after_s": bad}})
    assert any("expire_after_s" in e for e in errors)


# ---------------------------------------------------------------- limiters
def test_token_bucket_burst_refill_and_isolation():
    clock = Clock()
    lim = TokenBucketLimiter(rate_per_min=60, burst=5, clock=clock)
    assert all(lim.allow("a")[0] for _ in range(5))
    ok, retry = lim.allow("a")
    assert not ok and 0 < retry <= 1.0
    assert lim.allow("b")[0]                       # separate key, separate bucket
    clock.t += 1.0
    assert lim.allow("a")[0] and not lim.allow("a")[0]
    clock.t += 3600
    assert sum(lim.allow("a")[0] for _ in range(10)) == 5     # refill never exceeds the burst size


def test_failure_lockout_blocks_then_releases():
    clock = Clock()
    lock = FailureLockout(max_failures=3, window_s=60, lockout_s=120, clock=clock)
    for _ in range(2):
        lock.record_failure("1.2.3.4")
    assert lock.blocked("1.2.3.4") == 0
    lock.record_failure("1.2.3.4")
    assert 0 < lock.blocked("1.2.3.4") <= 120
    assert lock.blocked("9.9.9.9") == 0
    clock.t += 121
    assert lock.blocked("1.2.3.4") == 0
    for _ in range(2):
        lock.record_failure("1.2.3.4")
    assert lock.blocked("1.2.3.4") == 0            # the count restarted after the lockout
    assert not hasattr(lock, "record_success")     # valid sign-ins must never reset a guesser's counter


def test_old_failures_age_out_of_the_window():
    clock = Clock()
    lock = FailureLockout(max_failures=3, window_s=60, lockout_s=120, clock=clock)
    lock.record_failure("ip")
    lock.record_failure("ip")
    clock.t += 61
    lock.record_failure("ip")
    assert lock.blocked("ip") == 0


# ---------------------------------------------------------------- API integration
PLATFORM = "veto_test-platform-admin-key-000000"


def api(**kw):
    clock = kw.pop("clock", Clock())
    c = TestClient(create_app(GatewayService(clock=clock), demo=True, store=PrincipalStore(), bootstrap_key=ADMIN,
                              clock=clock, platform_key=PLATFORM, **kw))
    return c, clock


def mint(c, pid, roles):
    c.post("/v1/admin/principals", json={"id": pid, "roles": roles}, headers=bearer(ADMIN))
    return bearer(c.post(f"/v1/admin/principals/{pid}/keys", headers=bearer(ADMIN)).json()["key"])


def test_agent_is_rate_limited_per_principal_with_retry_after():
    c, clock = api(agent_rate=(60, 3), auth_max_failures=1000)
    ops, gate = mint(c, "ops-agent-1", ["agent"]), mint(c, "gate-agent-1", ["agent"])
    act = _action("ops-agent-1", "READ_PERSONNEL", "personnel", "emp-1042", {}, why="x")
    codes = [c.post("/v1/actions", json=act, headers=ops).status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200] and codes[3:] == [429, 429]
    r = c.post("/v1/actions", json=act, headers=ops)
    assert r.status_code == 429 and int(r.headers["Retry-After"]) >= 1
    assert c.get("/v1/auth/me", headers=gate).status_code == 200                 # another agent is unaffected
    assert c.get("/v1/state", headers=bearer(ADMIN)).json()["auth"]["rate_limited"] >= 3
    clock.t += 5
    assert c.post("/v1/actions", json=act, headers=ops).status_code == 200


def test_rate_limited_requests_never_reach_the_pipeline_or_audit():
    c, _ = api(agent_rate=(60, 1), auth_max_failures=1000)
    ops = mint(c, "ops-agent-1", ["agent"])
    act = _action("ops-agent-1", "READ_PERSONNEL", "personnel", "emp-1042", {}, why="x")
    c.post("/v1/actions", json=act, headers=ops)
    before = c.get("/v1/audit/verify", headers=bearer(ADMIN)).json()["count"]
    assert c.post("/v1/actions", json=act, headers=ops).status_code == 429
    assert c.get("/v1/audit/verify", headers=bearer(ADMIN)).json()["count"] == before


def test_repeated_bad_keys_lock_the_client_out_even_with_a_valid_key():
    c, clock = api(auth_max_failures=3, auth_lockout_s=120)
    for _ in range(3):
        assert c.get("/v1/state", headers=bearer("veto_wrong-wrong-wrong-wrong-0000")).status_code == 401
    r = c.get("/v1/state", headers=bearer(ADMIN))
    assert r.status_code == 429 and int(r.headers["Retry-After"]) >= 1
    clock.t += 121
    assert c.get("/v1/state", headers=bearer(ADMIN)).status_code == 200
    assert c.get("/v1/platform/state", headers=bearer(PLATFORM)).json()["auth"]["lockouts"] >= 1
    assert "lockouts" not in c.get("/v1/state", headers=bearer(ADMIN)).json()["auth"]   # tenants never see the rest


def test_public_endpoints_never_lock_out_or_count():
    c, _ = api(auth_max_failures=2)
    for _ in range(10):
        assert c.get("/healthz").status_code == 200 and c.get("/v1/auth/info").status_code == 200


# ---------------------------------------------------------------- anomaly signals
def feed(det, agent, start, minutes, per_min, verb="READ_PERSONNEL"):
    t = start
    for _ in range(minutes):
        for i in range(per_min):
            det.observe(agent, verb, f"emp-{i}", t + i * 0.5)
        t += 60
    return t


def test_relative_volume_spike_is_flagged_for_a_quiet_agent():
    det, t0 = AnomalyDetector(), 1_800_000_000.0
    t = feed(det, "a", t0, minutes=10, per_min=1)
    for i in range(7):
        det.observe("a", "READ_PERSONNEL", "emp-1", t + i)
    res = det.score("a", "READ_PERSONNEL", "emp-1", t + 7)
    assert res["flagged"] and any("Volume spike" in r for r in res["reasons"])
    assert res["model_version"] == "heuristic-0.2"


def test_same_spike_without_a_baseline_is_not_called_a_volume_spike():
    det, t0 = AnomalyDetector(), 1_800_000_000.0
    for i in range(7):
        det.observe("a", "READ_PERSONNEL", "emp-1", t0 + i)
    res = det.score("a", "READ_PERSONNEL", "emp-1", t0 + 7)
    assert not any("Volume spike" in r for r in res["reasons"]) and not res["flagged"]


def test_steady_agent_is_never_flagged():
    det, t0 = AnomalyDetector(), 1_800_000_000.0
    t = feed(det, "a", t0, minutes=20, per_min=2)
    res = det.score("a", "READ_PERSONNEL", "emp-1", t)
    assert res["score"] < 0.3 and not res["flagged"] and res["reasons"] == []


SUNDAY_3AM = datetime(2026, 10, 11, 3, 0, tzinfo=timezone.utc).timestamp()
MONDAY_10AM = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc).timestamp()
HOURS = {"start": "08:00", "end": "18:00", "weekdays": [0, 1, 2, 3, 4]}


def test_working_hours_signal_only_when_declared():
    off = AnomalyDetector().score("a", "READ_PERSONNEL", "emp-1", SUNDAY_3AM)
    assert off["score"] == 0 and off["reasons"] == []
    on = AnomalyDetector(working_hours=HOURS)
    night = on.score("a", "READ_PERSONNEL", "emp-1", SUNDAY_3AM)
    assert night["score"] >= 0.3 and any("working hours" in r for r in night["reasons"])
    assert not night["flagged"]                       # alone it escalates risk a little; it never flags by itself
    day = on.score("a", "READ_PERSONNEL", "emp-1", MONDAY_10AM)
    assert day["score"] == 0 and day["reasons"] == []


def test_working_hours_window_may_wrap_midnight():
    night_shift = AnomalyDetector(working_hours={"start": "22:00", "end": "06:00", "weekdays": [0, 1, 2, 3, 4, 5, 6]})
    at_3am = night_shift.score("a", "READ_PERSONNEL", "emp-1", SUNDAY_3AM)
    at_10am = night_shift.score("a", "READ_PERSONNEL", "emp-1", MONDAY_10AM)
    assert at_3am["score"] == 0 and at_10am["score"] >= 0.3


@pytest.mark.parametrize("bad", [{"start": "8am", "end": "18:00", "weekdays": [0]},
                                 {"start": "08:00", "end": "25:00", "weekdays": [0]},
                                 {"start": "08:00", "end": "18:00", "weekdays": [7]},
                                 {"start": "08:00", "end": "18:00", "weekdays": []},
                                 {"start": "08:00", "end": "18:00"}, "always"])
def test_policy_rejects_bad_working_hours(bad):
    raw = GatewayService().policy.raw
    assert any("working_hours" in e for e in validate_policy({**raw, "anomaly": {"working_hours": bad}}))


def test_anomaly_reasons_reach_the_audit_trail_and_validate_against_the_schema():
    svc = GatewayService()
    run_scenario(svc, "action_splitting")
    recs = [r for r in svc.audit.all() if r.get("anomaly", {}).get("reasons")]
    assert recs and all(isinstance(x, str) for r in recs for x in r["anomaly"]["reasons"])
    assert svc.audit.verify()["ok"]
