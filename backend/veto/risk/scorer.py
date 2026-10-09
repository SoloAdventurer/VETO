"""Transparent additive risk score. Risk can only ESCALATE a policy decision (invariant 2)."""

from __future__ import annotations

BAND_NAMES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def band_for(score: int, bands: dict) -> str:
    for name in BAND_NAMES:
        lo, hi = bands[name.lower()]
        if lo <= score <= hi:
            return name
    return "CRITICAL"


def score_risk(*, action_sensitivity: int, target_sensitivity: int, agent_risk: int, tainted: bool,
               anomaly_score: float, bands: dict) -> dict:
    components = {
        "action_sensitivity": action_sensitivity,
        "target_sensitivity": target_sensitivity,
        "agent_risk": agent_risk,
        "environmental_risk": 15 if tainted else 0,
        "behavioral_anomaly": round(anomaly_score * 40),
    }
    total = min(100, sum(components.values()))
    return {"score": total, "band": band_for(total, bands), "components": components}
