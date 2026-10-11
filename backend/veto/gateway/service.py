"""Gateway service: orchestrates the VETO pipeline.

validate -> canonicalise+hash -> provenance -> counters/records -> anomaly -> risk -> policy -> combine
-> AUDIT (before execution) -> execute via Execution Gateway -> verify -> AUDIT (outcome).
Hard policy decides first; risk/anomaly can only escalate (invariants 2, 3, 6).
"""

from __future__ import annotations

import json
import secrets
import threading
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator

from veto import catalog
from veto.adapters.mock_security_ops import AccessDenied, MockSecurityOps
from veto.anomaly.detector import AnomalyDetector
from veto.audit.chain import AuditLog
from veto.canonical import action_hash, canonical_action
from veto.execution.gateway import DecisionSigner, ExecutionGateway
from veto.paths import DEFAULT_POLICY, SCHEMAS_DIR
from veto.policy.engine import Facts, PolicyEngine
from veto.policy.loader import load_policy
from veto.provenance.registry import DEFAULT_TAINT_WINDOW_S, ProvenanceRegistry
from veto.risk.scorer import score_risk
from veto.verification.verifier import verify_effect

DEFAULT_APPROVAL_EXPIRY_S = 3600.0
SEVERITY = {"allow": 0, "allow_monitor": 1, "require_approval": 2, "block": 3}
POLICY_TO_DECISION = {"allow": "allow", "monitor": "allow_monitor", "require_approval": "require_approval",
                      "deny": "block"}
ACTION_VALIDATOR = Draft202012Validator(json.loads((SCHEMAS_DIR / "action.schema.json").read_text("utf-8")))
OBS_VALIDATOR = Draft202012Validator(json.loads((SCHEMAS_DIR / "observation.schema.json").read_text("utf-8")))


class RequestError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def _epoch(iso: str) -> float:
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class GatewayService:
    def __init__(self, policy_path: Path | str | None = None, db_path: str = ":memory:",
                 clock: Callable[[], float] = time.time) -> None:
        self.clock = clock
        self.policy = load_policy(policy_path or DEFAULT_POLICY)
        self.engine = PolicyEngine(self.policy.raw)
        self.audit = AuditLog(db_path)
        self.prov = ProvenanceRegistry()
        self.anomaly = AnomalyDetector(working_hours=self.policy.raw.get("anomaly", {}).get("working_hours"))
        self.containment = False
        self.tags: dict[str, dict] = {}
        self._history: list[dict] = []        # executed actions, for windowed counters
        self._lock = threading.RLock()
        self._obs_n = 0
        # The access key exists only inside the Execution Gateway and the resource; this service never keeps it.
        access_key = secrets.token_hex(16)
        self.resource = MockSecurityOps(access_key)
        self.signer = DecisionSigner(secrets.token_bytes(32))
        self.execution = ExecutionGateway(self.resource, access_key, self.signer, lambda: self.containment)
        self.view = self.resource.trusted
        # request_id -> (agent_id, held_at) for requests awaiting a human: drives the T7 cap and approval expiry
        latest = {rec["request_id"]: rec for rec in self.audit.all()}
        self._pending: dict[str, tuple[str, float]] = {
            rid: (rec["agent_id"], _epoch(rec["timestamp"]))
            for rid, rec in latest.items() if status_of(rec) == "pending_approval"}

    @property
    def max_pending_per_agent(self) -> int:
        return self.policy.raw.get("approvals", {}).get("max_pending_per_agent", 10)

    @property
    def approval_expiry_s(self) -> float:
        return self.policy.raw.get("approvals", {}).get("expire_after_s", DEFAULT_APPROVAL_EXPIRY_S)

    @property
    def taint_window_s(self) -> float:
        return self.policy.raw.get("provenance", {}).get("session_taint_window_s", DEFAULT_TAINT_WINDOW_S)

    # ------------------------------------------------------------------ observations
    def next_observation_id(self) -> str:
        with self._lock:
            self._obs_n += 1
            return f"obs-{self._obs_n:05d}"

    def register_observation(self, obs: dict, *, agent_id: str | None, operator_channel: bool) -> dict:
        errors = [e.message for e in OBS_VALIDATOR.iter_errors(obs)]
        if errors:
            raise RequestError("invalid observation: " + "; ".join(errors[:3]))
        with self._lock:
            try:
                stored = self.prov.register(obs, agent_id=agent_id, operator_channel=operator_channel,
                                            now=self.clock())
            except ValueError as exc:
                raise RequestError(str(exc), 409) from exc
        return {"observation_id": stored.observation_id, "origin": stored.origin, "capped": stored.capped,
                "trusted": stored.origin in ("operator_input", "trusted_store")}

    # ------------------------------------------------------------------ helpers
    def _counters(self, agent_id: str, verb: str, params: dict, now_ts: float) -> dict[str, float]:
        out: dict[str, float] = {}
        for name, spec in self.policy.raw.get("limits", {}).items():
            def contrib(params_: dict, spec_: dict = spec) -> float:
                return 1.0 if spec_["metric"] == "count" else float(params_.get(spec_["param"], 0))
            total = sum(contrib(e["params"]) for e in self._history
                        if e["agent_id"] == agent_id and e["action"] == spec["action"]
                        and now_ts - e["ts"] <= spec["window"])
            if verb == spec["action"]:
                total += contrib(params)
            out[name] = total
        return out

    def _record_facts(self, verb: str, target: dict, params: dict) -> dict:
        if verb == "UNLOCK_DOOR":
            return {"personnel.clearance": {"value": self.view.clearance_of(params["subject_id"]),
                                            "door_requirement": self.view.door_requirement(target["id"])}}
        return {}

    def _append(self, rec: dict) -> dict:
        return self.audit.append(rec)

    def _reject_invalid(self, request_id: str, payload: dict, errors: list[str], rule_id: str) -> dict:
        agent = payload.get("agent_id") if isinstance(payload.get("agent_id"), str) else "unknown"
        rec = self._append({
            "schema_version": "0.1", "request_id": request_id, "agent_id": agent[:64],
            "requested_action": {k: payload.get(k) for k in ("action", "target", "parameters")},
            "action_hash": action_hash({k: v for k, v in payload.items() if isinstance(k, str)}
                                       if isinstance(payload, dict) else {}),
            "decision": "block", "decision_reason": "; ".join(errors[:3]),
            "policies_evaluated": [{"rule_id": rule_id, "result": "matched", "effect": "deny"}],
            "policy_version": self.policy.version, "containment_active": self.containment,
        })
        return self._response(rec)

    @staticmethod
    def _response(rec: dict) -> dict:
        return {"request_id": rec["request_id"], "decision": rec["decision"], "reason": rec.get("decision_reason"),
                "action_hash": rec["action_hash"], "risk": rec.get("risk"), "anomaly": rec.get("anomaly"),
                "effective_provenance": rec.get("effective_provenance", []),
                "human_decision": rec.get("human_decision"), "execution": rec.get("execution"),
                "verification": rec.get("verification"), "status": status_of(rec)}

    # ------------------------------------------------------------------ the pipeline
    def _reject_identity(self, request_id: str, payload: dict, actor: str) -> dict:
        """The key that signed this request belongs to `actor`, but the body claims another agent (T6)."""
        claimed = str(payload.get("agent_id"))[:64]
        rec = self._append({
            "schema_version": "0.1", "request_id": request_id, "agent_id": actor[:64],
            "requested_action": {k: payload.get(k) for k in ("action", "target", "parameters")},
            "action_hash": action_hash({k: v for k, v in payload.items() if isinstance(k, str)}),
            "decision": "block",
            "decision_reason": f"Identity mismatch: credentials of '{actor}' used to act as '{claimed}'",
            "policies_evaluated": [{"rule_id": "builtin:identity-mismatch", "result": "matched", "effect": "deny"}],
            "policy_version": self.policy.version, "containment_active": self.containment,
        })
        return {**self._response(rec), "identity_mismatch": True}

    def sweep_expired(self) -> int:
        """Auto-expire approvals nobody decided in time (policy approvals.expire_after_s): audited, never executed."""
        with self._lock:
            now = self.clock()
            due = [rid for rid, (_, held_at) in self._pending.items() if now - held_at >= self.approval_expiry_s]
            for rid in due:
                rec = self.audit.latest_for_request(rid)
                self._pending.pop(rid, None)
                if rec is None or rec["decision"] != "require_approval" or rec.get("human_decision"):
                    continue
                base = _strip_chain(rec)
                base["human_decision"] = {"approver_id": "system", "outcome": "expired", "timestamp": _iso_now(),
                                          "note": f"no decision within {self.approval_expiry_s:g}s; treated as block"}
                base["execution"] = {"status": "not_executed", "adapter": ExecutionGateway.ADAPTER,
                                     "result_summary": "approval expired"}
                self._append(base)
            return len(due)

    def propose_action(self, payload: dict, tags: dict | None = None, authenticated_as: str | None = None) -> dict:
        """`authenticated_as` is the agent id bound to the caller's API key; None only for in-process harness use."""
        with self._lock:
            self.sweep_expired()
            request_id = f"req-{uuid.uuid4().hex[:12]}"
            if tags:
                self.tags[request_id] = tags
            if not isinstance(payload, dict):
                raise RequestError("body must be a JSON object")
            if authenticated_as is not None and payload.get("agent_id") != authenticated_as:
                return self._reject_identity(request_id, payload, authenticated_as)
            schema_errors = [e.message for e in ACTION_VALIDATOR.iter_errors(payload)]
            if schema_errors:
                return self._reject_invalid(request_id, payload, ["schema: " + e for e in schema_errors],
                                            "builtin:schema")
            cat_errors = catalog.validate_action(payload)
            if cat_errors:
                return self._reject_invalid(request_id, payload, cat_errors, "builtin:catalog")

            now = datetime.now(timezone.utc)
            now_ts = self.clock()
            canon = canonical_action(payload)
            ahash = action_hash(payload)
            agent_id, verb = canon["agent_id"], canon["action"]
            target, params = canon["target"], canon["parameters"]
            ctx = payload["context"]
            agent_cfg = self.policy.raw.get("agents", {}).get(agent_id)
            role = agent_cfg["role"] if agent_cfg else None

            prov = self.prov.resolve(agent_id, ctx.get("observation_ids", []), ctx.get("inputs", []),
                                     now=now_ts, window_s=self.taint_window_s)
            counters = self._counters(agent_id, verb, params, now_ts)
            anomaly = self.anomaly.score(agent_id, verb, target["id"], now_ts)
            door_req = self.view.door_requirement(target["id"]) if target["resource"] == "door" else None
            risk = score_risk(
                action_sensitivity=catalog.CATALOG[verb]["sensitivity"],
                target_sensitivity=catalog.target_sensitivity(target["resource"], door_req),
                agent_risk=agent_cfg["base_risk"] if agent_cfg else 30,
                tainted=prov["tainted"], anomaly_score=anomaly["score"], bands=self.policy.raw["risk_bands"],
            )
            facts = Facts(action=canon, agent={"id": agent_id, "role": role}, provenance=prov,
                          channel=ctx["on_behalf_of"]["channel"], now=now, counters=counters,
                          containment=self.containment, records=self._record_facts(verb, target, params))
            pres = self.engine.evaluate(facts)
            policy_decision = POLICY_TO_DECISION[pres.effect]
            band_decision = POLICY_TO_DECISION[self.policy.raw["band_effects"][risk["band"].lower()]]
            decision = max(policy_decision, band_decision, key=lambda d: SEVERITY[d])
            reason = pres.reason
            if decision != policy_decision:
                reason = f"Escalated by risk band {risk['band']} ({risk['score']}): {pres.reason}"

            policies = list(pres.evaluated)
            if decision == "require_approval":
                pending = sum(1 for a, _ in self._pending.values() if a == agent_id)
                if pending >= self.max_pending_per_agent:
                    decision = "block"
                    reason = (f"Approval queue cap reached ({pending} pending for {agent_id}); "
                              "resolve existing requests first")
                    policies.append({"rule_id": "builtin:approval-cap", "result": "matched", "effect": "deny"})

            requested = {**canon, "justification": ctx["justification"][:500],
                         "channel": ctx["on_behalf_of"]["channel"], "principal_id": ctx["on_behalf_of"]["principal_id"]}
            rec = self._append({
                "schema_version": "0.1", "request_id": request_id, "agent_id": agent_id,
                "requested_action": requested, "action_hash": ahash,
                "observation_ids": [d["ref"] for d in prov["details"]],
                "effective_provenance": prov["authority_sources"],
                "provenance_detail": [{"ref": d["ref"], "origin": d["origin"], "via": d["via"]}
                                      for d in prov["details"]],
                "policies_evaluated": policies, "risk": risk, "anomaly": anomaly,
                "decision": decision, "decision_reason": reason, "human_decision": None,
                "execution": None, "verification": None,
                "policy_version": self.policy.version, "containment_active": self.containment,
            })
            self.anomaly.observe(agent_id, verb, target["id"], now_ts)
            if decision == "require_approval":
                self._pending[request_id] = (agent_id, now_ts)
            if decision in ("allow", "allow_monitor"):
                rec = self._execute(rec, "allow")
            return self._response(rec)

    def _execute(self, rec: dict, label: str) -> dict:
        """Run the Execution Gateway for an already-audited decision, verify, and audit the outcome."""
        action = {k: rec["requested_action"][k] for k in ("agent_id", "action", "target", "parameters")}
        tag = self.signer.sign(rec["request_id"], rec["action_hash"], label)
        res = self.execution.execute(request_id=rec["request_id"], action=action, ahash=rec["action_hash"],
                                     decision_label=label, tag=tag)
        verification = None
        if res["status"] == "executed":
            verification = verify_effect(action, res["raw"], self.view)
            self._history.append({"agent_id": action["agent_id"], "action": action["action"],
                                  "params": action["parameters"], "ts": self.clock()})
        snapshot = _strip_chain(rec)
        snapshot["execution"] = {"status": res["status"], "adapter": res["adapter"],
                                 "result_summary": res["result_summary"]}
        snapshot["verification"] = verification
        snapshot["containment_active"] = self.containment
        return self._append(snapshot)

    # ------------------------------------------------------------------ human approval
    def resolve_approval(self, request_id: str, approver_id: str, outcome: str, note: str = "") -> dict:
        if outcome not in ("approved", "rejected"):
            raise RequestError("outcome must be 'approved' or 'rejected'")
        with self._lock:
            self.sweep_expired()
            rec = self.audit.latest_for_request(request_id)
            if rec is None:
                raise RequestError("unknown request", 404)
            if rec["decision"] != "require_approval" or rec.get("human_decision"):
                raise RequestError("request is not awaiting approval", 409)
            if approver_id == rec["agent_id"]:
                raise RequestError("an agent cannot approve its own action", 403)
            self._pending.pop(request_id, None)
            base = _strip_chain(rec)
            base["human_decision"] = {"approver_id": approver_id[:64], "outcome": outcome, "timestamp": _iso_now(),
                                      "note": note[:500]}
            if outcome == "rejected":
                base["execution"] = {"status": "not_executed", "adapter": ExecutionGateway.ADAPTER,
                                     "result_summary": "rejected by approver"}
                return self._response(self._append(base))
            rec2 = self._append(base)                # approval is audited BEFORE execution
            return self._response(self._execute(rec2, "approved"))

    # ------------------------------------------------------------------ containment
    def set_containment(self, active: bool, by: str, reason: str = "") -> dict:
        with self._lock:
            self.containment = active
            rec = self._append({
                "schema_version": "0.1", "request_id": f"sys-{uuid.uuid4().hex[:12]}", "agent_id": by[:64],
                "requested_action": {"action": "SET_CONTAINMENT",
                                     "parameters": {"active": active, "reason": reason[:200]}},
                "action_hash": action_hash({"agent_id": by, "action": "SET_CONTAINMENT",
                                            "target": {"resource": "system", "id": "containment"},
                                            "parameters": {"active": active}}),
                "policies_evaluated": [{"rule_id": "builtin:containment", "result": "matched",
                                        "effect": "deny" if active else "allow"}],
                "decision": "block" if active else "allow",
                "decision_reason": ("Containment ENGAGED: all agent actions blocked" if active
                                    else "Containment released") + (f" ({reason})" if reason else ""),
                "policy_version": self.policy.version, "containment_active": active,
            })
            return {"containment": self.containment, "event_id": rec["event_id"]}

    def record_system_event(self, by: str, action: str, params: dict, reason: str) -> dict:
        """Audit an administrative action (principal/key management) so privileged changes leave evidence."""
        with self._lock:
            rec = self._append({
                "schema_version": "0.1", "request_id": f"sys-{uuid.uuid4().hex[:12]}", "agent_id": by[:64],
                "requested_action": {"action": action, "parameters": params},
                "action_hash": action_hash({"agent_id": by, "action": action,
                                            "target": {"resource": "system", "id": "auth"}, "parameters": params}),
                "policies_evaluated": [{"rule_id": "builtin:admin-action", "result": "matched", "effect": "allow"}],
                "decision": "allow", "decision_reason": reason[:300],
                "policy_version": self.policy.version, "containment_active": self.containment,
            })
            return {"event_id": rec["event_id"]}

    # ------------------------------------------------------------------ session taint control (T14)
    def reset_agent_context(self, agent_id: str, by: str, *, audited: bool = True) -> dict:
        """Operator clears an agent's session taint (start of a new, clean task). Audited unless the demo harness."""
        if agent_id not in self.policy.raw.get("agents", {}) and audited:
            raise RequestError("unknown agent", 404)
        with self._lock:
            self.prov.reset_context(agent_id)
            if audited:
                self._append({
                    "schema_version": "0.1", "request_id": f"sys-{uuid.uuid4().hex[:12]}", "agent_id": by[:64],
                    "requested_action": {"action": "RESET_CONTEXT", "parameters": {"agent_id": agent_id}},
                    "action_hash": action_hash({"agent_id": by, "action": "RESET_CONTEXT",
                                                "target": {"resource": "agent", "id": agent_id}, "parameters": {}}),
                    "policies_evaluated": [{"rule_id": "builtin:context-reset", "result": "matched",
                                            "effect": "allow"}],
                    "decision": "allow", "decision_reason": f"Session taint cleared for {agent_id} by {by}",
                    "policy_version": self.policy.version, "containment_active": self.containment,
                })
            return {"agent_id": agent_id, "tainted_by": []}

    def agents_view(self) -> list[dict]:
        now = self.clock()
        out = []
        for aid, cfg in self.policy.raw.get("agents", {}).items():
            amb = self.prov.ambient(aid, now, self.taint_window_s)
            out.append({"id": aid, "role": cfg["role"], "base_risk": cfg["base_risk"],
                        "tainted_by": [{"ref": o.observation_id, "source": o.source, "origin": o.origin} for o in amb]})
        return out

    # ------------------------------------------------------------------ direct-bypass attempt (demo of invariant 5)
    def attempt_direct_access(self, agent_id: str, tags: dict | None = None) -> dict:
        """An agent bypasses the gateway and calls the resource itself. It has no access key, so it fails."""
        with self._lock:
            request_id = f"req-{uuid.uuid4().hex[:12]}"
            if tags:
                self.tags[request_id] = tags
            action = {"agent_id": agent_id, "action": "EXPORT_INCIDENT_LOG",
                      "target": {"resource": "incident_log", "id": "all"}, "parameters": {"row_count": 600}}
            try:
                self.resource.execute("guessed-key", "EXPORT_INCIDENT_LOG", action["target"], action["parameters"],
                                      agent_id)
                refused, why = False, "resource accepted a call without the access key"
            except AccessDenied as exc:
                refused, why = True, str(exc)
            rec = self._append({
                "schema_version": "0.1", "request_id": request_id, "agent_id": agent_id[:64],
                "requested_action": {**action, "channel": "direct"}, "action_hash": action_hash(action),
                "policies_evaluated": [{"rule_id": "builtin:resource-access-key", "result": "matched",
                                        "effect": "deny"}],
                "decision": "block" if refused else "allow",
                "decision_reason": f"Direct resource access bypassing the gateway: {why}",
                "execution": {"status": "not_executed", "adapter": ExecutionGateway.ADAPTER, "result_summary": why},
                "policy_version": self.policy.version, "containment_active": self.containment,
            })
            return self._response(rec)

    # ------------------------------------------------------------------ read models
    def requests_view(self, limit: int = 200) -> list[dict]:
        """Latest snapshot per request, newest first, with derived status and demo tags."""
        self.sweep_expired()
        latest: dict[str, dict] = {}
        first: dict[str, dict] = {}
        n_events: dict[str, int] = {}
        for rec in self.audit.all():
            latest[rec["request_id"]] = rec
            first.setdefault(rec["request_id"], rec)
            n_events[rec["request_id"]] = n_events.get(rec["request_id"], 0) + 1
        out = []
        for rid, rec in latest.items():
            out.append({**rec, "status": status_of(rec), "first_seq": first[rid]["seq"], "first_timestamp":
                        first[rid]["timestamp"], "events": n_events[rid], "tags": self.tags.get(rid)})
        out.sort(key=lambda r: r["first_seq"], reverse=True)
        return out[:limit]

    def stats(self) -> dict:
        rows = self.requests_view(10_000)
        agent_rows = [r for r in rows if not r["request_id"].startswith("sys-")]
        by_status: dict[str, int] = {}
        for r in agent_rows:
            by_status[r["status"]] = by_status.get(r["status"], 0) + 1
        unsafe = [r for r in agent_rows if r.get("tags") and r["tags"].get("unsafe")]
        intercepted = [r for r in unsafe if r["status"] not in ("executed", "executed_unverified")]
        return {"total": len(agent_rows), "by_status": by_status,
                "pending_approvals": by_status.get("pending_approval", 0),
                "unsafe_attempted": len(unsafe), "unsafe_intercepted": len(intercepted),
                "uir": (len(intercepted) / len(unsafe)) if unsafe else None,
                "direct_access_denied": self.view.denied_direct_attempts}

    def state(self) -> dict:
        return {"containment": self.containment, "doors": self.view.doors(), "personnel": self.view.personnel(),
                "incident_total": self.view.incident_total(), "stats": self.stats(), "chain": self.audit.verify(),
                "agents": self.agents_view(), "taint_window_s": self.taint_window_s,
                "policy": {"id": self.policy.policy_id, "version": self.policy.version,
                           "rules": len(self.policy.raw["rules"]), "agents": self.policy.raw["agents"]}}


def _strip_chain(rec: dict) -> dict:
    """A record minus the fields the audit log assigns, so it can be re-appended as a new snapshot."""
    return {k: v for k, v in rec.items() if k not in ("seq", "event_id", "timestamp", "prev_hash", "record_hash")}


def status_of(rec: dict) -> str:
    hd, ex, ver = rec.get("human_decision"), rec.get("execution"), rec.get("verification")
    if rec["decision"] == "block":
        return "blocked"
    if rec["decision"] == "require_approval":
        if not hd:
            return "pending_approval"
        if hd["outcome"] in ("rejected", "expired"):
            return hd["outcome"]
    if ex is None:
        return "pending_execution"
    if ex["status"] == "executed":
        return "executed" if ver and ver["status"] == "verified" else "executed_unverified"
    return "failed" if ex["status"] == "failed" else "blocked"
