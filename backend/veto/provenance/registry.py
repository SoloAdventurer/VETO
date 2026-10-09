"""Provenance: VETO, not the agent, decides where data came from (docs/action-schema.md).

Rules enforced here:
* An origin is derived from the registered observation's *source*, never from what the agent says.
* An agent may declare an origin for an input, but a declaration can only LOWER trust.
* Observations submitted through the agent-facing API can never be trusted; trusted origins exist only for
  observations registered over the operator channel and are bound to one agent.
* Session taint (T14): every untrusted observation an agent ingested through VETO taints ALL of its later actions
  until the window expires or an operator resets its context. The agent cannot avoid this by not mentioning it.
  Boundary: this covers data that reaches the agent through VETO-registered channels; data ingested by other
  means is invisible to VETO (the planned MCP proxy, D-008, closes that route).
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
DEFAULT_TAINT_WINDOW_S = 900


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
    bound_agent: str | None     # operator observations: the one agent allowed to rely on them
    ingested_by: str | None     # agent-channel observations: the agent that took this data in
    registered_by: str          # "agent" | "operator"
    capped: bool
    data: dict
    timestamp: str
    seq: int
    registered_at: float


class ProvenanceRegistry:
    def __init__(self) -> None:
        self._obs: dict[str, StoredObservation] = {}
        self._seq = 0
        self._reset_seq: dict[str, int] = {}

    def register(self, obs: dict, *, agent_id: str | None, operator_channel: bool, now: float) -> StoredObservation:
        if obs["observation_id"] in self._obs:
            raise ValueError(f"observation id '{obs['observation_id']}' already registered")
        origin = origin_for_source(obs["source"])
        capped = False
        if origin in TRUSTED and not operator_channel:
            origin, capped = "unknown", True     # an agent cannot launder trust by naming a trusted source
        self._seq += 1
        stored = StoredObservation(
            observation_id=obs["observation_id"], source=obs["source"], type=obs["type"], origin=origin,
            bound_agent=agent_id if operator_channel else None,
            ingested_by=None if operator_channel else agent_id,
            registered_by="operator" if operator_channel else "agent", capped=capped,
            data=obs.get("data", {}), timestamp=obs["timestamp"], seq=self._seq, registered_at=now,
        )
        self._obs[stored.observation_id] = stored
        return stored

    def get(self, observation_id: str) -> StoredObservation | None:
        return self._obs.get(observation_id)

    def reset_context(self, agent_id: str) -> None:
        """Start a fresh task context: observations registered so far no longer taint this agent."""
        self._reset_seq[agent_id] = self._seq

    def ambient(self, agent_id: str, now: float, window_s: float) -> list[StoredObservation]:
        """Untrusted observations this agent ingested recently and has not had cleared (session taint)."""
        if window_s <= 0:
            return []
        floor = self._reset_seq.get(agent_id, 0)
        return [o for o in self._obs.values()
                if o.ingested_by == agent_id and o.seq > floor and now - o.registered_at <= window_s
                and o.origin not in TRUSTED]

    def resolve(self, agent_id: str, observation_ids: list[str], inputs: list[dict], *, now: float,
                window_s: float = DEFAULT_TAINT_WINDOW_S) -> dict:
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
            details.append({"ref": ref, "origin": final, "assigned": assigned, "declared": declared.get(ref),
                            "via": "declared"})
        for obs in self.ambient(agent_id, now, window_s):
            if obs.observation_id not in refs:
                details.append({"ref": obs.observation_id, "origin": obs.origin, "assigned": obs.origin,
                                "declared": None, "via": "ambient"})
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
            "ambient": [d["ref"] for d in details if d["via"] == "ambient"],
        }
