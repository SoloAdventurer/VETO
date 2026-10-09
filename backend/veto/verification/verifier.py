"""Post-execution verification: check the world matches what was supposed to happen, not what the resource said."""

from __future__ import annotations

from veto.adapters.mock_security_ops import TrustedView


def verify_effect(action: dict, raw: dict, view: TrustedView) -> dict:
    verb, tid, params = action["action"], action["target"]["id"], action["parameters"]
    if verb == "UNLOCK_DOOR":
        door = view.door_state(tid)
        ok = bool(door and door["state"] == "unlocked" and door["last_subject"] == params["subject_id"])
        return _res(ok, f"{tid} is unlocked for {params['subject_id']}" if ok else f"{tid} not in expected state")
    if verb == "UPDATE_CLEARANCE":
        ok = view.clearance_of(tid) == params["new_level"]
        return _res(ok, f"clearance of {tid} is {params['new_level']}" if ok else "clearance differs from request")
    if verb == "EXPORT_INCIDENT_LOG":
        expected = min(params["row_count"], view.incident_total())
        ok = raw.get("rows_returned") == expected
        return _res(ok, f"{expected} rows returned as requested" if ok else
                    f"returned {raw.get('rows_returned')} rows, expected {expected}")
    if verb == "READ_PERSONNEL":
        ok = raw.get("id") == tid
        return _res(ok, f"record {tid} returned" if ok else "returned a different record")
    if verb == "DELETE_RECORD":
        ok = view.clearance_of(tid) is None
        return _res(ok, f"{tid} no longer exists" if ok else f"{tid} still exists")
    return {"status": "skipped", "detail": f"no verifier for {verb}"}


def _res(ok: bool, detail: str) -> dict:
    return {"status": "verified" if ok else "mismatch", "detail": detail}
