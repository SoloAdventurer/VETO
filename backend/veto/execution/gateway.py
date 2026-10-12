"""Execution Gateway: the only component that holds the resource access key (invariant 5).

It executes nothing unless (1) containment is off, (2) the decision token is valid for this exact request,
decision and action hash, and (3) the action it was handed still hashes to that value.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable

from veto.adapters.mock_security_ops import AccessDenied, MockSecurityOps, ResourceError
from veto.canonical import action_hash
from veto.execution.connectors import Router


class DecisionSigner:
    """Signs (request, hash, decision) so the Execution Gateway can verify a decision really came from VETO."""

    def __init__(self, key: bytes) -> None:
        self._key = key

    def sign(self, request_id: str, ahash: str, decision_label: str) -> str:
        msg = f"{request_id}|{ahash}|{decision_label}".encode()
        return hmac.new(self._key, msg, hashlib.sha256).hexdigest()

    def verify(self, request_id: str, ahash: str, decision_label: str, tag: str) -> bool:
        return hmac.compare_digest(self.sign(request_id, ahash, decision_label), tag)


class ExecutionGateway:
    ADAPTER = "mock_security_ops"

    def __init__(self, resource: MockSecurityOps, access_key: str, signer: DecisionSigner,
                 containment_active: Callable[[], bool], connectors: Router | None = None) -> None:
        self._resource = resource
        self._key = access_key
        self._signer = signer
        self._containment_active = containment_active
        self._connectors = connectors

    def ping_connector(self, row: dict) -> dict:
        if self._containment_active():
            return self._refuse("containment active: no outbound calls")
        try:
            return self._connectors.ping(row) if self._connectors else self._refuse("no connectors configured")
        except Exception as exc:
            return {"status": "failed", "adapter": "webhook", "result_summary": str(exc)[:200], "raw": None}

    def _refuse(self, why: str) -> dict:
        return {"status": "not_executed", "adapter": self.ADAPTER, "result_summary": why, "raw": None}

    def execute(self, *, request_id: str, action: dict, ahash: str, decision_label: str, tag: str) -> dict:
        if self._containment_active():
            return self._refuse("containment active: execution refused")
        if not self._signer.verify(request_id, ahash, decision_label, tag):
            return self._refuse("invalid decision token: execution refused")
        if action_hash(action) != ahash:
            return self._refuse("action hash mismatch: action changed after decision (possible tampering)")
        route = self._connectors.find(action["action"]) if self._connectors else None
        if route is not None:                                    # the tenant's own system, via its signed webhook
            return self._connectors.send(route, request_id=request_id, action=action, ahash=ahash,
                                         decision_label=decision_label)
        try:
            raw = self._resource.execute(self._key, action["action"], action["target"], action["parameters"],
                                         action["agent_id"])
        except ResourceError as exc:
            return {"status": "failed", "adapter": self.ADAPTER, "result_summary": str(exc), "raw": None}
        except AccessDenied as exc:  # pragma: no cover - the key is ours; defensive
            return {"status": "failed", "adapter": self.ADAPTER, "result_summary": str(exc), "raw": None}
        return {"status": "executed", "adapter": self.ADAPTER, "result_summary": _summarise(action["action"], raw),
                "raw": raw}


def _summarise(verb: str, raw: dict) -> str:
    return {
        "READ_PERSONNEL": lambda r: f"read record {r['id']}",
        "UPDATE_CLEARANCE": lambda r: f"clearance of {r['id']} set to {r['clearance']}",
        "EXPORT_INCIDENT_LOG": lambda r: f"exported {r['rows_returned']} incident rows",
        "UNLOCK_DOOR": lambda r: f"{r['door']} unlocked for {r['duration_s']}s",
        "SEND_EXTERNAL_MESSAGE": lambda r: "message queued",
        "DELETE_RECORD": lambda r: f"deleted {r['deleted']}",
    }[verb](raw)
