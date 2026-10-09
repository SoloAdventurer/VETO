"""Action catalog (docs/action-schema.md). Core knows verbs generically; domain packs add entries."""

from __future__ import annotations

import re

ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")

# params: name -> ("int", min, max) | ("str", max_len). All declared params are required; unknown params are rejected.
CATALOG: dict[str, dict] = {
    "READ_PERSONNEL": {"resource": "personnel", "sensitivity": 8, "reversible": True, "params": {}},
    "UPDATE_CLEARANCE": {
        "resource": "personnel", "sensitivity": 25, "reversible": True,
        "params": {"new_level": ("int", 0, 5)},
    },
    "EXPORT_INCIDENT_LOG": {
        "resource": "incident_log", "sensitivity": 22, "reversible": False,
        "params": {"row_count": ("int", 1, 100000)},
    },
    "DELETE_RECORD": {"resource": "*", "sensitivity": 30, "reversible": False, "params": {}},
    "UNLOCK_DOOR": {
        "resource": "door", "sensitivity": 18, "reversible": True,
        "params": {"duration_s": ("int", 1, 300), "subject_id": ("str", 64)},
    },
    "SEND_EXTERNAL_MESSAGE": {
        "resource": "messaging", "sensitivity": 20, "reversible": False,
        "params": {"recipient_domain": ("str", 128), "body": ("str", 2000)},
    },
}


def validate_action(payload: dict) -> list[str]:
    """Semantic validation beyond JSON Schema. Returns a list of error strings (empty = valid)."""
    errors: list[str] = []
    verb = payload.get("action")
    entry = CATALOG.get(verb)
    if entry is None:
        return [f"unknown action verb '{verb}'"]
    target = payload.get("target", {})
    if entry["resource"] not in ("*", target.get("resource")):
        errors.append(f"{verb} requires resource '{entry['resource']}', got '{target.get('resource')}'")
    if not ID_RE.match(str(target.get("id", ""))):
        errors.append("target.id contains characters outside [A-Za-z0-9_.:-]")
    params = payload.get("parameters", {})
    for name in params:
        if name not in entry["params"]:
            errors.append(f"unknown parameter '{name}' for {verb}")
    for name, spec in entry["params"].items():
        if name not in params:
            errors.append(f"missing parameter '{name}' for {verb}")
            continue
        value = params[name]
        if spec[0] == "int":
            if isinstance(value, bool) or not isinstance(value, int) or not spec[1] <= value <= spec[2]:
                errors.append(f"parameter '{name}' must be an integer in [{spec[1]}, {spec[2]}]")
        elif not isinstance(value, str) or len(value) > spec[1]:
            errors.append(f"parameter '{name}' must be a string up to {spec[1]} chars")
    return errors


def target_sensitivity(resource: str, door_requirement: int | None) -> int:
    if resource == "door":
        return min(15, 5 * (door_requirement or 1))
    return {"personnel": 10, "incident_log": 10, "messaging": 8}.get(resource, 5)
