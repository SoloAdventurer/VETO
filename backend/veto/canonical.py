"""Canonical form + hash of an action. Decision and execution are bound to this hash (invariant 5)."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Any

HASH_KEYS = ("agent_id", "action", "target", "parameters")


def _norm(value: Any) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value).strip()
    if isinstance(value, dict):
        return {unicodedata.normalize("NFC", str(k)): _norm(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_norm(v) for v in value]
    return value


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_action(payload: dict) -> dict:
    """The subset of an action that defines *what will happen* (justification etc. never affects the hash)."""
    return {k: _norm(payload[k]) for k in HASH_KEYS if k in payload}


def action_hash(payload: dict) -> str:
    return hashlib.sha256(canonical_json(canonical_action(payload)).encode("utf-8")).hexdigest()


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
