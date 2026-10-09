"""MVP behavioural anomaly detector: transparent heuristics over a sliding window.

Deliberately simple (burst rate, target breadth, never-seen action transitions). Tier 2 replaces this with an
Isolation Forest + n-gram sequence model behind the same interface (see DECISIONS D-016).
"""

from __future__ import annotations

from collections import defaultdict, deque

BASELINE_TRANSITIONS = {
    ("READ_PERSONNEL", "READ_PERSONNEL"), ("READ_PERSONNEL", "UNLOCK_DOOR"), ("UNLOCK_DOOR", "READ_PERSONNEL"),
    ("READ_PERSONNEL", "EXPORT_INCIDENT_LOG"), ("EXPORT_INCIDENT_LOG", "READ_PERSONNEL"),
    ("UNLOCK_DOOR", "UNLOCK_DOOR"), ("READ_PERSONNEL", "UPDATE_CLEARANCE"),
}


class AnomalyDetector:
    MODEL_VERSION = "heuristic-0.1"
    FLAG_THRESHOLD = 0.6

    def __init__(self, window_s: float = 60.0) -> None:
        self.window_s = window_s
        self._hist: dict[str, deque] = defaultdict(deque)

    def _recent(self, agent_id: str, now_ts: float) -> list[tuple[float, str, str]]:
        dq = self._hist[agent_id]
        while dq and now_ts - dq[0][0] > self.window_s:
            dq.popleft()
        return list(dq)

    def score(self, agent_id: str, verb: str, target_id: str, now_ts: float) -> dict:
        recent = self._recent(agent_id, now_ts)
        n = len(recent) + 1
        targets = {t for _, _, t in recent} | {target_id}
        burst = min(1.0, max(0.0, (n - 5) / 15))
        breadth = min(1.0, max(0.0, (len(targets) - 5) / 15))
        prev = recent[-1][1] if recent else None
        novel = 0.3 if prev is not None and (prev, verb) not in BASELINE_TRANSITIONS else 0.0
        value = round(max(burst, breadth, novel), 3)
        return {"score": value, "flagged": value >= self.FLAG_THRESHOLD, "model_version": self.MODEL_VERSION}

    def observe(self, agent_id: str, verb: str, target_id: str, now_ts: float) -> None:
        self._recent(agent_id, now_ts)
        self._hist[agent_id].append((now_ts, verb, target_id))
