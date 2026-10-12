"""Webhook adapter for no-code automation tools (Zapier, Make, n8n; DECISIONS D-029).

A *hook* is a tenant-admin-defined mapping from an arbitrary JSON payload to one VETO action. The call goes through
the normal pipeline, so a hook adds no authority: whatever the automation relays is registered as an untrusted
observation (provenance is assigned by VETO, never by the caller), the action is taint-checked, risk-scored and
decided by the deterministic policy, audited before anything runs, and executed only by the Execution Gateway.

The template language is closed on purpose (invariant 7): `{field}` or `{a.b}` is replaced by a value from the
payload. No expressions, no functions, no includes.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

from veto import catalog

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,39}$")
FIELD = re.compile(r"\{([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*)\}")
MAX_PAYLOAD_BYTES = 32_768
MAX_SPEC_BYTES = 4_000
SPEC_KEYS = {"agent_id", "action", "target", "parameters", "source", "justification"}
# What the automation's content is declared to be. Every one is untrusted: a hook can never relay authority.
SOURCES = {
    "unknown": ("hook.", "tool_output"), "email": ("mail.hook.", "email"), "web": ("web.hook.", "web_page"),
    "external_document": ("docs.hook.", "document"), "sensor_ocr": ("sensor.hook.", "ocr_text"),
    "model_generated": ("agent.hook.", "tool_output"),
}


class HookError(Exception):
    def __init__(self, message: str, status: int = 422) -> None:
        super().__init__(message)
        self.status = status


def _check_template(text: str, where: str) -> None:
    rest = FIELD.sub("", text)
    if "{" in rest or "}" in rest:
        raise HookError(f"{where}: only {{field}} or {{a.b}} placeholders are allowed")


def validate_spec(spec: Any, agent_ids: set[str]) -> dict:
    """Return the normalised spec or raise HookError. `agent_ids` are the tenant's active agent principals."""
    if not isinstance(spec, dict):
        raise HookError("a hook must be a JSON object")
    if len(json.dumps(spec)) > MAX_SPEC_BYTES:
        raise HookError("hook definition is too large")
    unknown = sorted(set(spec) - SPEC_KEYS)
    if unknown:
        raise HookError("unknown field(s): " + ", ".join(unknown))
    agent = spec.get("agent_id")
    if not isinstance(agent, str) or agent not in agent_ids:
        raise HookError("agent_id must be an active principal with the agent role in this tenant")
    verb = spec.get("action")
    entry = catalog.CATALOG.get(verb) if isinstance(verb, str) else None
    if entry is None:
        raise HookError(f"unknown action '{verb}'")
    target = spec.get("target")
    if not isinstance(target, dict) or set(target) != {"resource", "id"} or not all(
            isinstance(v, str) and v for v in target.values()):
        raise HookError("target must be {resource, id}, both strings")
    if entry["resource"] not in ("*", target["resource"]):
        raise HookError(f"{verb} requires resource '{entry['resource']}'")
    params = spec.get("parameters", {})
    if not isinstance(params, dict) or set(params) != set(entry["params"]):
        raise HookError(f"parameters must be exactly: {', '.join(entry['params']) or '(none)'}")
    for where, mapping in (("target", target), ("parameters", params)):
        for k, v in mapping.items():
            if isinstance(v, str):
                _check_template(v, f"{where}.{k}")
            elif isinstance(v, bool) or not isinstance(v, (int, str)):
                raise HookError(f"{where}.{k} must be a string, an integer or a {{field}} placeholder")
    source = spec.get("source", "unknown")
    if source not in SOURCES:
        raise HookError("source must be one of: " + ", ".join(sorted(SOURCES)) + " (a hook cannot declare trust)")
    just = spec.get("justification", "")
    if not isinstance(just, str) or len(just) > 300:
        raise HookError("justification must be a string up to 300 characters")
    _check_template(just, "justification")
    return {"agent_id": agent, "action": verb, "target": dict(target), "parameters": dict(params),
            "source": source, "justification": just}


def _lookup(payload: dict, path: str) -> Any:
    node: Any = payload
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            raise HookError(f"payload is missing field '{path}'")
        node = node[part]
    return node


def _render(value: Any, payload: dict) -> Any:
    if not isinstance(value, str):
        return value
    whole = FIELD.fullmatch(value)
    if whole:                                                  # keeps the payload's own type (numbers stay numbers)
        got = _lookup(payload, whole.group(1))
        if isinstance(got, (dict, list)) or got is None:
            raise HookError(f"payload field '{whole.group(1)}' must be a string, number or boolean")
        return got

    def sub(m: re.Match) -> str:
        got = _lookup(payload, m.group(1))
        if isinstance(got, (dict, list)) or got is None:
            raise HookError(f"payload field '{m.group(1)}' must be a string, number or boolean")
        return str(got)
    return FIELD.sub(sub, value)


def build(name: str, spec: dict, payload: dict, observation_id: str) -> tuple[dict, dict]:
    """The observation to register and the action to propose for one call of the hook."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    prefix, obs_type = SOURCES[spec["source"]]
    observation = {"schema_version": "0.1", "observation_id": observation_id, "source": f"{prefix}{name}",
                   "type": obs_type, "timestamp": now, "data": payload}
    action = {
        "schema_version": "0.1", "agent_id": spec["agent_id"], "action": spec["action"],
        "target": {k: _render(v, payload) for k, v in spec["target"].items()},
        "parameters": {k: _render(v, payload) for k, v in spec["parameters"].items()},
        "timestamp": now,
        "context": {
            "on_behalf_of": {"principal_id": spec["agent_id"], "channel": "autonomous"},
            "justification": (_render(spec["justification"], payload) if spec["justification"]
                              else f"Webhook '{name}'")[:500],
            "observation_ids": [observation_id],
            "inputs": [{"ref": observation_id, "origin": spec["source"]}],
        },
    }
    return observation, action


def flat_response(hook: str, resp: dict) -> dict:
    """What a no-code tool can filter on without parsing nested JSON."""
    status = resp.get("status")
    return {"hook": hook, "request_id": resp["request_id"], "decision": resp["decision"], "status": status,
            "reason": resp.get("reason"), "executed": status in ("executed", "executed_unverified"),
            "verified": status == "executed",
            "pending_approval": status == "pending_approval", "blocked": resp["decision"] == "block",
            "action_hash": resp["action_hash"], "effective_provenance": resp.get("effective_provenance", [])}
