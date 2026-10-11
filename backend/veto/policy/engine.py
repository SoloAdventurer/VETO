"""Deterministic policy engine (docs/policy-format.md).

Pure function of (policy, facts). No I/O, no clock reads, no network, no randomness, no dynamic code.
Combination: deny > require_approval > monitor > allow. No matching allow -> deny (default deny).
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

EFFECT_ORDER = {"allow": 0, "monitor": 1, "require_approval": 2, "deny": 3}
COMBINATORS = {"all", "any", "not"}
LEAF_KEYS_EXACT = {"action", "target.resource", "target.id", "agent.id", "agent.role", "channel",
                   "provenance", "time", "counter", "record", "containment"}
OPS = {"eq", "in", "lt", "lte", "gt", "gte", "matches"}
PROVENANCE_KEYS = {"tainted", "authority_source_in", "lowest_trust_in"}
TIME_KEYS = {"between", "weekday_in"}
RECORD_OPS = {"gte_door_requirement"}


class PolicyError(Exception):
    pass


@dataclass(frozen=True)
class Facts:
    action: dict            # canonical: {agent_id, action, target:{resource,id}, parameters}
    agent: dict             # {"id": str, "role": str | None}
    provenance: dict        # {"origins": [...], "authority_sources": [...], "tainted": bool, "lowest_trust": str}
    channel: str
    now: datetime
    counters: dict[str, float] = field(default_factory=dict)
    containment: bool = False
    records: dict[str, dict] = field(default_factory=dict)  # trusted-store lookups, resolved by the caller


@dataclass
class PolicyResult:
    effect: str                 # allow | monitor | require_approval | deny
    reason: str
    rule_id: str | None
    evaluated: list[dict]


# ----------------------------------------------------------------------------- validation (closed grammar)

def validate_policy(policy: dict) -> list[str]:
    errors: list[str] = []
    if policy.get("default_effect") != "deny":
        errors.append("default_effect must be 'deny' in v0.1")
    seen: set[str] = set()
    for rule in policy.get("rules", []):
        rid = rule.get("id", "<missing id>")
        if rid in seen:
            errors.append(f"duplicate rule id {rid}")
        seen.add(rid)
        if rule.get("effect") not in EFFECT_ORDER:
            errors.append(f"{rid}: invalid effect {rule.get('effect')!r}")
        try:
            _validate_node(rule.get("when", {}))
        except PolicyError as exc:
            errors.append(f"{rid}: {exc}")
    window = policy.get("provenance", {}).get("session_taint_window_s", 0)
    if not isinstance(window, (int, float)) or isinstance(window, bool) or window < 0:
        errors.append("provenance.session_taint_window_s must be a non-negative number")
    cap = policy.get("approvals", {}).get("max_pending_per_agent", 10)
    if not isinstance(cap, int) or isinstance(cap, bool) or cap < 1:
        errors.append("approvals.max_pending_per_agent must be an integer >= 1")
    if "expire_after_s" in policy.get("approvals", {}):
        ttl = policy["approvals"]["expire_after_s"]
        if not isinstance(ttl, (int, float)) or isinstance(ttl, bool) or ttl <= 0:
            errors.append("approvals.expire_after_s must be a positive number of seconds")
    errors.extend(_validate_working_hours(policy.get("anomaly", {}).get("working_hours")))
    for name, spec in policy.get("limits", {}).items():
        for key in ("window", "action", "metric"):
            if key not in spec:
                errors.append(f"limit {name}: missing '{key}'")
        if spec.get("metric") == "sum" and "param" not in spec:
            errors.append(f"limit {name}: metric 'sum' needs 'param'")
    return errors


_HHMM = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


def _validate_working_hours(wh: Any) -> list[str]:
    if wh is None:
        return []
    if not isinstance(wh, dict):
        return ["anomaly.working_hours must be a mapping with start, end and weekdays"]
    errors = []
    for key in ("start", "end"):
        if not isinstance(wh.get(key), str) or not _HHMM.match(wh[key]):
            errors.append(f"anomaly.working_hours.{key} must be HH:MM (24h, UTC)")
    days = wh.get("weekdays")
    if (not isinstance(days, list) or not days
            or any(not isinstance(d, int) or isinstance(d, bool) or not 0 <= d <= 6 for d in days)):
        errors.append("anomaly.working_hours.weekdays must be a non-empty list of 0 (Mon) to 6 (Sun)")
    return errors


def _validate_ops(ops: Any, allowed: set[str], where: str) -> None:
    if not isinstance(ops, dict):
        return
    for op in ops:
        if op not in allowed:
            raise PolicyError(f"unknown operator '{op}' in {where}")


def _validate_node(node: Any) -> None:
    if isinstance(node, list):
        for item in node:
            _validate_node(item)
        return
    if not isinstance(node, dict):
        raise PolicyError(f"condition must be a mapping, got {type(node).__name__}")
    for key, val in node.items():
        if key in ("all", "any"):
            _validate_node(val)
        elif key == "not":
            _validate_node(val)
        elif key.startswith("param."):
            _validate_ops(val, OPS, key)
        elif key in LEAF_KEYS_EXACT:
            if key == "provenance":
                bad = set(val) - PROVENANCE_KEYS
                if bad:
                    raise PolicyError(f"unknown provenance keys {sorted(bad)}")
            elif key == "time":
                bad = set(val) - TIME_KEYS
                if bad:
                    raise PolicyError(f"unknown time keys {sorted(bad)}")
            elif key == "counter":
                for ops in val.values():
                    _validate_ops(ops, OPS, "counter")
            elif key == "record":
                for ops in val.values():
                    _validate_ops(ops, RECORD_OPS, "record")
            else:
                _validate_ops(val, OPS, key)
        else:
            raise PolicyError(f"unknown condition '{key}'")


# ----------------------------------------------------------------------------- evaluation

def _num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _apply_ops(value: Any, ops: Any) -> bool:
    if not isinstance(ops, dict):
        ops = {"eq": ops}
    for op, arg in ops.items():
        if op == "eq":
            ok = value == arg
        elif op == "in":
            ok = value in arg
        elif op == "matches":
            ok = isinstance(value, str) and fnmatch.fnmatchcase(value, arg)
        elif op in ("lt", "lte", "gt", "gte"):
            if not (_num(value) and _num(arg)):
                ok = False
            else:
                ok = {"lt": value < arg, "lte": value <= arg, "gt": value > arg, "gte": value >= arg}[op]
        else:
            raise PolicyError(f"unknown operator {op}")
        if not ok:
            return False
    return True


def _leaf(key: str, spec: Any, f: Facts) -> bool:
    if key == "action":
        return _apply_ops(f.action.get("action"), spec)
    if key == "target.resource":
        return _apply_ops(f.action.get("target", {}).get("resource"), spec)
    if key == "target.id":
        return _apply_ops(f.action.get("target", {}).get("id"), spec)
    if key == "agent.id":
        return _apply_ops(f.agent.get("id"), spec)
    if key == "agent.role":
        return _apply_ops(f.agent.get("role"), spec)
    if key == "channel":
        return _apply_ops(f.channel, spec)
    if key == "containment":
        return _apply_ops(f.containment, spec)
    if key.startswith("param."):
        return _apply_ops(f.action.get("parameters", {}).get(key[6:]), spec)
    if key == "provenance":
        for k, v in spec.items():
            if k == "tainted":
                ok = f.provenance["tainted"] == v
            elif k == "authority_source_in":
                ok = any(s in v for s in f.provenance["authority_sources"])
            else:  # lowest_trust_in
                ok = f.provenance["lowest_trust"] in v
            if not ok:
                return False
        return True
    if key == "time":
        for k, v in spec.items():
            if k == "between":
                hhmm = f.now.strftime("%H:%M")
                lo, hi = v
                ok = lo <= hhmm <= hi if lo <= hi else (hhmm >= lo or hhmm <= hi)
            else:  # weekday_in
                ok = f.now.strftime("%a").lower() in [str(x).lower()[:3] for x in v]
            if not ok:
                return False
        return True
    if key == "counter":
        return all(_apply_ops(f.counters.get(name), ops) for name, ops in spec.items())
    if key == "record":
        for name, ops in spec.items():
            rec = f.records.get(name)
            for op, expected in ops.items():
                if rec is None or rec.get("value") is None or rec.get("door_requirement") is None:
                    return False  # unknown trusted record -> condition not satisfied (fail safe)
                if op == "gte_door_requirement" and (rec["value"] >= rec["door_requirement"]) != expected:
                    return False
        return True
    raise PolicyError(f"unknown condition '{key}'")


def _eval(node: Any, f: Facts) -> bool:
    if isinstance(node, list):
        return all(_eval(n, f) for n in node)
    result = True
    for key, val in node.items():
        if key == "all":
            result = result and all(_eval(n, f) for n in val)
        elif key == "any":
            result = result and any(_eval(n, f) for n in val)
        elif key == "not":
            result = result and not _eval(val, f)
        else:
            result = result and _leaf(key, val, f)
    return result


class PolicyEngine:
    def __init__(self, policy: dict) -> None:
        errors = validate_policy(policy)
        if errors:
            raise PolicyError("; ".join(errors))
        self.policy = policy
        self.rules = sorted(policy.get("rules", []), key=lambda r: r["priority"])
        self.roles = policy.get("roles", {})

    def evaluate(self, f: Facts) -> PolicyResult:
        if f.containment:
            return PolicyResult("deny", "Emergency containment active", "builtin:containment",
                                [{"rule_id": "builtin:containment", "result": "matched", "effect": "deny"}])
        role = f.agent.get("role")
        if role is None:
            return PolicyResult("deny", f"Unknown agent '{f.agent.get('id')}'", "builtin:unknown-agent",
                                [{"rule_id": "builtin:unknown-agent", "result": "matched", "effect": "deny"}])
        verb = f.action.get("action")
        if verb not in self.roles.get(role, {}).get("allow_actions", []):
            return PolicyResult("deny", f"Role '{role}' is not permitted to request {verb}", "builtin:rbac",
                                [{"rule_id": "builtin:rbac", "result": "matched", "effect": "deny"}])

        evaluated: list[dict] = []
        matched: list[dict] = []
        errored = False
        for rule in self.rules:
            try:
                hit = _eval(rule.get("when", {}), f)
            except (PolicyError, KeyError, TypeError):
                evaluated.append({"rule_id": rule["id"], "result": "error", "effect": rule["effect"]})
                errored = True
                continue
            evaluated.append({"rule_id": rule["id"], "result": "matched" if hit else "not_matched",
                              "effect": rule["effect"]})
            if hit:
                matched.append(rule)
        if errored:
            return PolicyResult("deny", "Policy rule error (fail closed)", "builtin:rule-error", evaluated)

        controlling = max(matched, key=lambda r: (EFFECT_ORDER[r["effect"]], -r["priority"]), default=None)
        if controlling is None or (controlling["effect"] in ("allow", "monitor")
                                   and not any(r["effect"] == "allow" for r in matched)):
            return PolicyResult("deny", "No allow rule matched (default deny)", None, evaluated)
        return PolicyResult(controlling["effect"], controlling.get("reason", controlling["id"]),
                            controlling["id"], evaluated)
