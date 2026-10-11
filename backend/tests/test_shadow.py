"""Shadow mode: VETO decides and records, but never executes, holds or enforces anything (DECISIONS D-023)."""

import pytest
from fastapi.testclient import TestClient
from veto.auth.store import PrincipalStore
from veto.gateway.app import create_app
from veto.gateway.scenarios import SCENARIOS, run_scenario
from veto.gateway.service import GatewayService, RequestError

ADMIN = "veto_test-bootstrap-admin-key-000000"


def no_execution(svc):
    def boom(**kwargs):
        pytest.fail("the Execution Gateway must never run in shadow mode")
    svc.execution.execute = boom


def test_shadow_mode_never_executes_anything():
    svc = GatewayService(mode="shadow")
    no_execution(svc)
    for name in ("legit_unlock", "legit_export", "clearance_request", "action_splitting"):
        for r in run_scenario(svc, name)["results"]:
            assert r["execution"]["status"] == "not_executed" and r["status"].startswith("shadow_")
    assert svc.view.clearance_of("emp-2210") == 1
    assert all(d["state"] == "locked" for d in svc.view.doors())
    assert svc.audit.verify()["ok"]


def test_shadow_verdicts_match_enforcement_for_every_scenario():
    for name in SCENARIOS:
        if name == "direct_bypass":
            continue
        shadow = [r["decision"] for r in run_scenario(GatewayService(mode="shadow"), name)["results"]]
        enforce = [r["decision"] for r in run_scenario(GatewayService(mode="enforce"), name)["results"]]
        assert shadow == enforce, name


def test_shadow_status_names_say_what_would_have_happened():
    svc = GatewayService(mode="shadow")
    assert run_scenario(svc, "taped_sign")["results"][0]["status"] == "shadow_block"
    assert run_scenario(svc, "legit_export")["results"][0]["status"] == "shadow_allow"
    assert run_scenario(svc, "clearance_request")["results"][0]["status"] == "shadow_approval"


def test_shadow_verdicts_cannot_be_approved_into_execution():
    svc = GatewayService(mode="shadow")
    no_execution(svc)
    rid = run_scenario(svc, "clearance_request")["results"][0]["request_id"]
    with pytest.raises(RequestError) as exc:
        svc.resolve_approval(rid, "sup-1", "approved")
    assert exc.value.status == 409 and svc.view.clearance_of("emp-2210") == 1
    assert svc.stats()["pending_approvals"] == 0


def test_shadow_counts_would_be_executions_toward_limits():
    svc = GatewayService(mode="shadow")
    from veto.gateway.scenarios import _action
    def export(rows):
        return svc.propose_action(_action("ops-agent-1", "EXPORT_INCIDENT_LOG", "incident_log", "all",
                                          {"row_count": rows}, why="x"))
    for _ in range(5):
        assert export(100)["decision"] in ("allow", "allow_monitor")
    assert export(100)["decision"] == "block"                  # exactly what enforcement would do


def test_shadow_stats_do_not_claim_interceptions_it_did_not_make():
    svc = GatewayService(mode="shadow")
    from veto.gateway.scenarios import _action
    svc.propose_action(_action("ops-agent-1", "EXPORT_INCIDENT_LOG", "incident_log", "all", {"row_count": 10},
                               why="x"), {"scenario": "unsafe-but-allowed", "unsafe": True})
    s = svc.stats()
    assert s["unsafe_attempted"] == 1 and s["unsafe_intercepted"] == 0 and s["mode"] == "shadow"
    run_scenario(svc, "taped_sign")
    assert svc.stats()["unsafe_intercepted"] == 1              # a would-block counts as caught


def test_mode_is_recorded_in_the_audit_trail_and_validated():
    svc = GatewayService(mode="shadow")
    start = next(r for r in svc.audit.all() if r["requested_action"].get("action") == "SERVICE_START")
    assert start["requested_action"]["parameters"]["mode"] == "shadow"
    run_scenario(svc, "taped_sign")
    assert svc.audit.latest_for_request(
        next(r for r in svc.audit.all() if r["request_id"].startswith("req-"))["request_id"])["mode"] == "shadow"
    with pytest.raises(ValueError):
        GatewayService(mode="monitor-only")
    assert GatewayService().mode == "enforce"                   # enforcement is the default


def test_env_selects_the_mode_and_a_typo_is_an_error(monkeypatch):
    monkeypatch.setenv("VETO_MODE", "shadow")
    c = TestClient(create_app(demo=True, store=PrincipalStore(), bootstrap_key=ADMIN))
    assert c.get("/v1/state", headers={"Authorization": f"Bearer {ADMIN}"}).json()["mode"] == "shadow"
    monkeypatch.setenv("VETO_MODE", "shadw")
    with pytest.raises(ValueError):
        create_app(demo=True, store=PrincipalStore(), bootstrap_key=ADMIN)
