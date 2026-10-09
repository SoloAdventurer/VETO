"""Mock security-operations resource with synthetic data (the thing VETO protects in the demo).

Writes and reads of protected data only work with the access key held by the Execution Gateway. Anyone else
(an agent calling the resource directly) is refused and counted. The read-only `TrustedView` is what the
decision side uses for clearance lookups; it has no mutating methods.
"""

from __future__ import annotations

import hmac
import time

FIRST = ["Amir", "Lena", "Omar", "Priya", "Jonas", "Maya", "Tariq", "Elena", "Samir", "Nora", "Ivan", "Hana"]
LAST = ["Okafor", "Lindqvist", "Haddad", "Moreau", "Tanaka", "Reyes", "Novak", "Barakat", "Silva", "Kowalski"]
UNITS = ["Operations", "Logistics", "Analysis", "Facilities", "Comms"]


class AccessDenied(Exception):
    pass


class ResourceError(Exception):
    pass


class TrustedView:
    """Read-only window onto resource state for the decision side and the dashboard."""

    def __init__(self, resource: MockSecurityOps) -> None:
        self._r = resource

    def clearance_of(self, person_id: str) -> int | None:
        rec = self._r._personnel.get(person_id)
        return rec["clearance"] if rec else None

    def door_requirement(self, door_id: str) -> int | None:
        door = self._r._doors.get(door_id)
        return door["requirement"] if door else None

    def door_state(self, door_id: str) -> dict | None:
        return next((d for d in self.doors() if d["id"] == door_id), None)

    def doors(self) -> list[dict]:
        now = time.time()
        out = []
        for did, d in self._r._doors.items():
            unlocked = d["unlocked_until"] > now
            out.append({"id": did, "name": d["name"], "requirement": d["requirement"],
                        "state": "unlocked" if unlocked else "locked",
                        "unlocked_until": d["unlocked_until"] if unlocked else None,
                        "last_subject": d["last_subject"]})
        return out

    def personnel(self) -> list[dict]:
        return [{"id": pid, **{k: v for k, v in rec.items()}} for pid, rec in self._r._personnel.items()]

    def incident_total(self) -> int:
        return len(self._r._incidents)

    def outbox_count(self) -> int:
        return len(self._r._outbox)

    @property
    def denied_direct_attempts(self) -> int:
        return self._r.denied_direct_attempts


class MockSecurityOps:
    def __init__(self, access_key: str) -> None:
        self._key = access_key
        self.denied_direct_attempts = 0
        self._personnel: dict[str, dict] = {}
        for i in range(60):
            clearance = 1 + (i * 7) % 4 if i % 5 else 2
            self._personnel[f"emp-{1000 + i}"] = {
                "name": f"{FIRST[i % len(FIRST)]} {LAST[(i * 3) % len(LAST)]}",
                "unit": UNITS[i % len(UNITS)], "clearance": clearance,
            }
        self._personnel["emp-1042"] = {"name": "Lena Haddad", "unit": "Operations", "clearance": 3}
        self._personnel["emp-2210"] = {"name": "Omar Silva", "unit": "Logistics", "clearance": 1}
        self._personnel["visitor-77"] = {"name": "Unregistered visitor", "unit": "none", "clearance": 0}
        self._doors = {
            "door-1": {"name": "Main Lobby", "requirement": 1, "unlocked_until": 0.0, "last_subject": None},
            "door-2": {"name": "Operations Floor", "requirement": 2, "unlocked_until": 0.0, "last_subject": None},
            "door-3": {"name": "Secure Archive", "requirement": 3, "unlocked_until": 0.0, "last_subject": None},
            "door-4": {"name": "Command Vault", "requirement": 4, "unlocked_until": 0.0, "last_subject": None},
        }
        self._incidents = [{"id": f"INC-{i:04d}", "severity": ("low", "medium", "high")[i % 3],
                            "summary": f"Synthetic incident record {i}"} for i in range(1, 601)]
        self._outbox: list[dict] = []
        self.trusted = TrustedView(self)

    def execute(self, key: str, verb: str, target: dict, params: dict, actor: str) -> dict:
        if not hmac.compare_digest(str(key), self._key):
            self.denied_direct_attempts += 1
            raise AccessDenied("resource refused request: invalid access key")
        tid = target["id"]
        if verb == "READ_PERSONNEL":
            rec = self._personnel.get(tid)
            if rec is None:
                raise ResourceError(f"no personnel record '{tid}'")
            return {"id": tid, **rec}
        if verb == "UPDATE_CLEARANCE":
            if tid not in self._personnel:
                raise ResourceError(f"no personnel record '{tid}'")
            self._personnel[tid]["clearance"] = params["new_level"]
            return {"id": tid, "clearance": params["new_level"]}
        if verb == "EXPORT_INCIDENT_LOG":
            rows = self._incidents[: params["row_count"]]
            return {"rows_returned": len(rows), "sample": rows[:2]}
        if verb == "UNLOCK_DOOR":
            door = self._doors.get(tid)
            if door is None:
                raise ResourceError(f"no door '{tid}'")
            door["unlocked_until"] = time.time() + params["duration_s"]
            door["last_subject"] = params["subject_id"]
            return {"door": tid, "state": "unlocked", "duration_s": params["duration_s"]}
        if verb == "SEND_EXTERNAL_MESSAGE":
            self._outbox.append({"to": params["recipient_domain"], "by": actor})
            return {"queued": True}
        if verb == "DELETE_RECORD":
            if self._personnel.pop(tid, None) is None:
                raise ResourceError(f"no record '{tid}'")
            return {"deleted": tid}
        raise ResourceError(f"unsupported verb {verb}")
