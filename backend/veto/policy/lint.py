"""Safety lint and diff for policies (DECISIONS D-028).

`validate_policy` (engine.py) checks the closed grammar. The lint adds the structural guarantees the rest of VETO
relies on, so that no policy -- the shipped one, a tenant's first one, or a later edit -- can silently remove them:
  * shape: required sections present, unique ids and priorities, every rule explained
  * default deny with a kill-switch rule that outranks everything (containment must always win)
  * invariant 4: no allow rule may key off an untrusted origin
  * no unconditional allow rule
Offline and deterministic like the rest of this package (invariants 3 and 7).
"""

from __future__ import annotations

from typing import Any

import yaml

MAX_POLICY_CHARS = 64_000
UNTRUSTED = ("sensor_ocr", "email", "web", "external_document", "unknown", "model_generated")
BANDS = {"low", "medium", "high", "critical"}
REQUIRED_TOP = ("policy_id", "version", "default_effect", "risk_bands", "band_effects", "agents", "rules")


def lint_policy(raw: Any) -> list[str]:
    if not isinstance(raw, dict):
        return ["a policy must be a mapping"]
    errors = [f"missing top-level section '{k}'" for k in REQUIRED_TOP if k not in raw]
    if errors:
        return errors
    if not isinstance(raw["rules"], list) or not raw["rules"]:
        return ["rules must be a non-empty list"]
    if not isinstance(raw["agents"], dict) or not isinstance(raw["band_effects"], dict):
        return ["agents and band_effects must be mappings"]
    if set(raw["band_effects"]) != BANDS or set(raw["risk_bands"]) != BANDS:
        errors.append("risk_bands and band_effects must define exactly low, medium, high and critical")
    for aid, cfg in raw["agents"].items():
        if not isinstance(cfg, dict) or "role" not in cfg or not isinstance(cfg.get("base_risk"), (int, float)):
            errors.append(f"agent {aid}: needs a role and a numeric base_risk")
    ids: set[str] = set()
    prios: set[int] = set()
    for rule in raw["rules"]:
        if not isinstance(rule, dict):
            return errors + ["every rule must be a mapping"]
        rid = rule.get("id")
        if not isinstance(rid, str) or not rid:
            errors.append("every rule needs an id")
            continue
        if rid in ids:
            errors.append(f"duplicate rule id {rid}")
        ids.add(rid)
        prio = rule.get("priority")
        if not isinstance(prio, int) or isinstance(prio, bool):
            errors.append(f"{rid}: priority must be an integer")
        elif prio in prios:
            errors.append(f"{rid}: duplicate priority {prio}")
        else:
            prios.add(prio)
        if not rule.get("reason"):
            errors.append(f"{rid}: needs a reason")
        if "when" not in rule:
            errors.append(f"{rid}: needs a 'when' condition")
        elif rule.get("effect") == "allow":
            if _is_empty(rule["when"]):
                errors.append(f"{rid}: an allow rule must have at least one condition")
            hits = sorted(u for u in UNTRUSTED if u in yaml.safe_dump(rule["when"]))
            if hits:
                errors.append(f"{rid}: allow rules must not key off untrusted origins ({', '.join(hits)})")
    errors.extend(_kill_switch_errors(raw))
    return errors


def _is_empty(node: Any) -> bool:
    if node in (None, {}, []):
        return True
    if isinstance(node, dict) and set(node) <= {"all", "any"}:
        return all(_is_empty(v) for v in node.values())
    return False


def _kill_switch_errors(raw: dict) -> list[str]:
    rules = [r for r in raw["rules"] if isinstance(r, dict) and isinstance(r.get("priority"), int)]
    if not rules:
        return []
    lowest = min(r["priority"] for r in rules)
    for r in rules:
        if r.get("effect") == "deny" and r["priority"] == lowest and r.get("when") == {"containment": {"eq": True}}:
            return []
    return ["the highest-priority rule must be a deny whose condition is exactly {containment: {eq: true}} "
            "(the kill switch must always win)"]


def diff_policies(old: dict, new: dict) -> dict:
    """What a proposed policy changes, for the human who has to approve it, and whether it loosens anything."""
    o = {r["id"]: r for r in old.get("rules", [])}
    n = {r["id"]: r for r in new.get("rules", [])}
    added, removed = sorted(set(n) - set(o)), sorted(set(o) - set(n))
    changed = []
    for rid in sorted(set(o) & set(n)):
        fields = sorted(k for k in set(o[rid]) | set(n[rid]) if o[rid].get(k) != n[rid].get(k))
        if fields:
            changed.append({"id": rid, "fields": fields})
    other = sorted(k for k in set(old) | set(new) if k != "rules" and old.get(k) != new.get(k))
    loosens: list[str] = []
    for rid in added:
        if n[rid]["effect"] == "allow":
            loosens.append(f"adds allow rule {rid}")
    for rid in removed:
        if o[rid]["effect"] in ("deny", "require_approval"):
            loosens.append(f"removes {o[rid]['effect']} rule {rid}")
    strict = {"deny": 3, "require_approval": 2, "monitor": 1, "allow": 0}
    for c in changed:
        a, b = o[c["id"]], n[c["id"]]
        if strict.get(b["effect"], 0) < strict.get(a["effect"], 0):
            loosens.append(f"{c['id']}: {a['effect']} -> {b['effect']}")
        elif "when" in c["fields"] and b["effect"] == "allow":
            loosens.append(f"{c['id']}: conditions of an allow rule changed")
    for key in other:
        if key in ("limits", "approvals", "provenance", "band_effects", "risk_bands", "agents"):
            loosens.append(f"{key} changed (review the values)")
    return {"added": added, "removed": removed, "changed": changed, "other_sections": other,
            "loosens": bool(loosens), "reasons": loosens}
