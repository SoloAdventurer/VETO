"""MVP behavioural anomaly detector: transparent heuristics over a sliding window (model heuristic-0.2).

Signals, combined with max() so the score never exceeds the strongest one:
  * burst           - many requests in the short window (fixed thresholds)
  * breadth         - many distinct targets in the short window
  * novel transition- an action pair never seen in the baseline set
  * volume spike    - this minute's request count versus the agent's OWN recent per-minute baseline (z-score),
                      so a quiet agent that suddenly gets busy is caught even below the fixed burst thresholds
  * working hours   - only when the policy declares `anomaly.working_hours`; a soft signal that never flags alone
Every signal that fires adds a human-readable reason, which is stored in the audit record.
Tier 2 replaces this with an Isolation Forest + n-gram sequence model behind the same interface (DECISIONS D-016).
Pure function of its inputs and the timestamps it is given: no clock reads, no randomness (invariant 3).
"""

from __future__ import annotations

import math
from collections import defaultdict, deque
from datetime import datetime, timezone

BASELINE_TRANSITIONS = {
    ("READ_PERSONNEL", "READ_PERSONNEL"), ("READ_PERSONNEL", "UNLOCK_DOOR"), ("UNLOCK_DOOR", "READ_PERSONNEL"),
    ("READ_PERSONNEL", "EXPORT_INCIDENT_LOG"), ("EXPORT_INCIDENT_LOG", "READ_PERSONNEL"),
    ("UNLOCK_DOOR", "UNLOCK_DOOR"), ("READ_PERSONNEL", "UPDATE_CLEARANCE"),
}


class AnomalyDetector:
    MODEL_VERSION = "heuristic-0.2"
    FLAG_THRESHOLD = 0.6
    BUCKET_S = 60.0
    BASELINE_BUCKETS = 30        # minutes of history the per-agent baseline looks back over
    MIN_BASELINE_BUCKETS = 5     # no volume signal until the agent has this many minutes of history
    SPIKE_MIN_COUNT = 5          # ... and never for fewer than this many requests in the current minute
    Z_SPIKE = 3.0
    Z_CRITICAL = 6.0
    OFF_HOURS_SCORE = 0.35

    def __init__(self, window_s: float = 60.0, working_hours: dict | None = None) -> None:
        self.window_s = window_s
        self.working_hours = working_hours
        self._hist: dict[str, deque] = defaultdict(deque)
        self._counts: dict[str, dict[int, int]] = defaultdict(dict)    # agent -> minute bucket -> requests
        self._first_seen: dict[str, float] = {}

    def _recent(self, agent_id: str, now_ts: float) -> list[tuple[float, str, str]]:
        dq = self._hist[agent_id]
        while dq and now_ts - dq[0][0] > self.window_s:
            dq.popleft()
        return list(dq)

    def _volume_spike(self, agent_id: str, now_ts: float) -> tuple[float, str | None]:
        first = self._first_seen.get(agent_id)
        if first is None:
            return 0.0, None
        cur = int(now_ts // self.BUCKET_S)
        start = max(int(first // self.BUCKET_S), cur - self.BASELINE_BUCKETS)
        if cur - start < self.MIN_BASELINE_BUCKETS:
            return 0.0, None
        counts = self._counts[agent_id]
        series = [counts.get(i, 0) for i in range(start, cur)]       # idle minutes count as zero
        mean = sum(series) / len(series)
        std = max(math.sqrt(sum((x - mean) ** 2 for x in series) / len(series)), 1.0)
        this = counts.get(cur, 0) + 1
        if this < self.SPIKE_MIN_COUNT:
            return 0.0, None
        z = (this - mean) / std
        if z <= self.Z_SPIKE:
            return 0.0, None
        return (min(z / self.Z_CRITICAL, 1.0),
                f"Volume spike: {this} requests this minute vs {mean:.1f} avg (z={z:.1f})")

    def _off_hours(self, now_ts: float) -> tuple[float, str | None]:
        wh = self.working_hours
        if not wh:
            return 0.0, None
        dt = datetime.fromtimestamp(now_ts, timezone.utc)
        mins = dt.hour * 60 + dt.minute
        start = int(wh["start"][:2]) * 60 + int(wh["start"][3:])
        end = int(wh["end"][:2]) * 60 + int(wh["end"][3:])
        in_hours = start <= mins < end if start <= end else (mins >= start or mins < end)
        if dt.weekday() in wh["weekdays"] and in_hours:
            return 0.0, None
        return self.OFF_HOURS_SCORE, f"Outside working hours ({dt:%a %H:%M} UTC)"

    def score(self, agent_id: str, verb: str, target_id: str, now_ts: float) -> dict:
        recent = self._recent(agent_id, now_ts)
        n = len(recent) + 1
        targets = {t for _, _, t in recent} | {target_id}
        burst = min(1.0, max(0.0, (n - 5) / 15))
        breadth = min(1.0, max(0.0, (len(targets) - 5) / 15))
        prev = recent[-1][1] if recent else None
        novel = 0.3 if prev is not None and (prev, verb) not in BASELINE_TRANSITIONS else 0.0
        spike, spike_reason = self._volume_spike(agent_id, now_ts)
        off, off_reason = self._off_hours(now_ts)
        reasons = []
        if burst > 0:
            reasons.append(f"Burst: {n} requests in {self.window_s:g}s")
        if breadth > 0:
            reasons.append(f"Breadth: {len(targets)} distinct targets in {self.window_s:g}s")
        if novel > 0:
            reasons.append(f"Unusual transition: {prev} -> {verb}")
        reasons.extend(r for r in (spike_reason, off_reason) if r)
        value = round(max(burst, breadth, novel, spike, off), 3)
        return {"score": value, "flagged": value >= self.FLAG_THRESHOLD, "model_version": self.MODEL_VERSION,
                "reasons": reasons[:6]}

    def observe(self, agent_id: str, verb: str, target_id: str, now_ts: float) -> None:
        self._recent(agent_id, now_ts)
        self._hist[agent_id].append((now_ts, verb, target_id))
        self._first_seen.setdefault(agent_id, now_ts)
        counts = self._counts[agent_id]
        cur = int(now_ts // self.BUCKET_S)
        counts[cur] = counts.get(cur, 0) + 1
        for stale in [b for b in counts if b < cur - 2 * self.BASELINE_BUCKETS]:
            del counts[stale]
