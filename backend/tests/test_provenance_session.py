"""T14: an agent that reads untrusted data and then acts without declaring it must still be tainted."""
import pathlib

import pytest
import yaml
from test_gateway import act, register, ts  # noqa: I001  (sibling test helpers)
from veto.gateway.scenarios import run_scenario
from veto.gateway.service import GatewayService, RequestError
from veto.paths import DEFAULT_POLICY
from veto.provenance.registry import ProvenanceRegistry


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


def policy_with_window(tmp_path: pathlib.Path, window) -> pathlib.Path:
    raw = yaml.safe_load(DEFAULT_POLICY.read_text())
    raw["provenance"] = {"session_taint_window_s": window}
    out = tmp_path / "p.yaml"
    out.write_text(yaml.safe_dump(raw))
    return out


def export_100():
    return act("ops-agent-1", "EXPORT_INCIDENT_LOG", "incident_log", "all", {"row_count": 100})   # declares nothing


def poison(svc, agent="ops-agent-1"):
    return register(svc, "mail.inbox", agent, operator=False, typ="email")


def test_the_gap_exists_without_session_taint(tmp_path):
    """Control experiment: with the feature off, the hidden-injection export goes through. This is T14."""
    svc = GatewayService(policy_with_window(tmp_path, 0))
    poison(svc)
    out = svc.propose_action(export_100())
    assert out["status"] == "executed" and out["effective_provenance"] == []


def test_session_taint_blocks_the_same_attack():
    svc = GatewayService()
    oid = poison(svc)
    out = svc.propose_action(export_100())
    assert out["decision"] == "block" and out["status"] == "blocked"
    assert out["effective_provenance"] == ["email"]
    rec = svc.audit.latest_for_request(out["request_id"])
    assert rec["provenance_detail"] == [{"ref": oid, "origin": "email", "via": "ambient"}]


def test_hidden_injection_scenario_is_intercepted():
    svc = GatewayService()
    out = run_scenario(svc, "hidden_injection")["results"][0]
    assert out["decision"] == "block" and svc.stats()["unsafe_intercepted"] == 1


def test_clean_agent_is_unaffected():
    svc = GatewayService()
    assert svc.propose_action(export_100())["status"] == "executed"


def test_taint_is_per_agent():
    svc = GatewayService()
    poison(svc, "ops-agent-1")
    other = act("admin-agent-1", "EXPORT_INCIDENT_LOG", "incident_log", "all", {"row_count": 100})
    assert svc.propose_action(other)["status"] == "executed"          # admin-agent-1 never read the email


def test_taint_covers_every_action_type_not_just_exports():
    svc = GatewayService()
    poison(svc, "gate-agent-1")
    out = svc.propose_action(act("gate-agent-1", "UNLOCK_DOOR", "door", "door-1",
                                 {"duration_s": 5, "subject_id": "emp-1042"}))
    assert out["decision"] == "block"        # even a fully legitimate clearance cannot pass in a tainted session


def test_operator_reset_clears_taint_and_is_audited():
    svc = GatewayService()
    poison(svc)
    assert svc.propose_action(export_100())["decision"] == "block"
    svc.reset_agent_context("ops-agent-1", "supervisor-1")
    assert svc.propose_action(export_100())["status"] == "executed"
    sys_rows = [r for r in svc.audit.all() if r["requested_action"].get("action") == "RESET_CONTEXT"]
    assert len(sys_rows) == 1 and sys_rows[0]["agent_id"] == "supervisor-1"
    with pytest.raises(RequestError):
        svc.reset_agent_context("nobody", "supervisor-1")


def test_new_untrusted_data_after_reset_taints_again():
    svc = GatewayService()
    poison(svc)
    svc.reset_agent_context("ops-agent-1", "supervisor-1")
    poison(svc)
    assert svc.propose_action(export_100())["decision"] == "block"


def test_taint_expires_after_the_window(tmp_path):
    clock = Clock()
    svc = GatewayService(policy_with_window(tmp_path, 60), clock=clock)
    poison(svc)
    clock.t += 30
    assert svc.propose_action(export_100())["decision"] == "block"
    clock.t += 31
    assert svc.propose_action(export_100())["status"] == "executed"


def test_agent_cannot_clear_its_own_taint_with_a_trusted_looking_observation():
    svc = GatewayService()
    poison(svc)
    register(svc, "operator.console", "ops-agent-1", operator=False, typ="operator_message")   # agent-channel: capped
    assert svc.propose_action(export_100())["decision"] == "block"


def test_declared_and_ambient_are_both_reported_once():
    svc = GatewayService()
    oid = poison(svc)
    a = export_100()
    a["context"]["observation_ids"] = [oid]
    out = svc.propose_action(a)
    rec = svc.audit.latest_for_request(out["request_id"])
    assert rec["provenance_detail"] == [{"ref": oid, "origin": "email", "via": "declared"}]


def test_registry_unit_ambient_window_and_reset():
    reg = ProvenanceRegistry()
    obs = {"observation_id": "o1", "source": "web.page", "type": "web_page", "timestamp": ts(), "data": {}}
    reg.register(obs, agent_id="a", operator_channel=False, now=100.0)
    assert [o.observation_id for o in reg.ambient("a", 150.0, 100)] == ["o1"]
    assert reg.ambient("a", 250.0, 100) == []
    assert reg.ambient("a", 150.0, 0) == []
    reg.reset_context("a")
    assert reg.ambient("a", 150.0, 100) == []
