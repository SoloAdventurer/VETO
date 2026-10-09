"""Provenance: VETO, not the agent, decides where data came from (docs/action-schema.md).

Rules enforced here:
* An origin is derived from the registered observation's *source*, never from what the agent says.
* An agent may declare an origin for an input, but a declaration can only LOWER trust.
* Observations submitted through the agent-facing API can never be trusted; trusted origins exist only for
  observations registered over the operator channel and are bound to one agent.
"""

from __future__ import annotations

from dataclasses import dataclass

TRUSTED = {"operator_input", "trusted_store"}
RANK = {"operator_input": 3, "trusted_store": 3, "model_generated": 1,
        "external_document": 0, "email": 0, "web": 0, "sensor_ocr": 0, "unknown": 0}
SOURCE_RULES = [
    ("camera.", "sensor_ocr"), ("sensor.", "sensor_ocr"), ("mail.", "email"), ("web.", "web"),
    ("docs.", "external_document"), ("db.", "trusted_store"), ("operator.", "operator_input"),
    ("agent.", "model_generated"),
]


def origin_for_source(source: str) -> str:
    for prefix, origin in SOURCE_RULES:
        if source.startswith(prefix):
            return origin
    return "unknown"


def _lower(a: str, b: str) -> str:
    """The lower-trust of two origins (ties keep `a`)."""
    return b if RANK.get(b, 0) < RANK.get(a, 0) else a


@dataclass
class StoredObservation:
    observation_id: str
    source: str
    type: str
    origin: str
    bound_agent: str | None
    registered_by: str          # "agent" | "operator"
    capped: bool
    data: dict
    timestamp: str


class ProvenanceRegistry:
    def __init__(self) -> None:
        self._obs: dict[str, StoredObservation] = {}

    def register(self, obs: dict, *, agent_id: str | None, operator_channel: bool) -> StoredObservation:
        if obs["observation_id"] in self._obs:
            raise ValueError(f"observation id '{obs['observation_id']}' already registered")
        origin = origin_for_source(obs["source"])
        capped = False
        if origin in TRUSTED and not operator_channel:
            origin, capped = "unknown", True     # an agent cannot launder trust by naming a trusted source
        stored = StoredObservation(
            observation_id=obs["observation_id"], source=obs["source"], type=obs["type"], origin=origin,
            bound_agent=agent_id if operator_channel else None, registered_by="operator" if operator_channel
            else "agent", capped=capped, data=obs.get("data", {}), timestamp=obs["timestamp"],
        )
        self._obs[stored.observation_id] = stored
        return stored

    def get(self, observation_id: str) -> StoredObservation | None:
        return self._obs.get(observation_id)

    def resolve(self, agent_id: str, observation_ids: list[str], inputs: list[dict]) -> dict:
        declared = {i["ref"]: i["origin"] for i in inputs}
        refs = list(dict.fromkeys([*observation_ids, *declared]))
        details = []
        for ref in refs:
            obs = self._obs.get(ref)
            if obs is None:
                assigned = "unknown"                      # unregistered reference: nothing vouches for it
            elif obs.bound_agent is not None and obs.bound_agent != agent_id:
                assigned = "unknown"                      # someone else's trusted observation
            else:
                assigned = obs.origin
            final = _lower(assigned, declared[ref]) if ref in declared else assigned
            details.append({"ref": ref, "origin": final, "assigned": assigned, "declared": declared.get(ref)})
        origins = [d["origin"] for d in details]
        lowest = "none"
        for o in origins:
            if lowest == "none" or RANK.get(o, 0) < RANK.get(lowest, 0):
                lowest = o
        return {
            "origins": origins,
            "authority_sources": sorted(set(origins)),
            "tainted": any(o not in TRUSTED for o in origins),
            "lowest_trust": lowest,
            "details": details,
        }
