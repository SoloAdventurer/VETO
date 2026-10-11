"""Append-only, hash-chained audit log (invariant 6).

SQLite is the default backend (D-016); veto.audit.postgres adds PostgreSQL (D-025).
Triggers make UPDATE/DELETE fail at the database level, and every record carries prev_hash/record_hash so
tampering with the file itself is detectable by verify().
Records are validated against schemas/decision.schema.json before insert.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

from jsonschema import Draft202012Validator

from veto.canonical import canonical_json, sha256_hex
from veto.paths import SCHEMAS_DIR

GENESIS = "0" * 64
_SCHEMA = json.loads((SCHEMAS_DIR / "decision.schema.json").read_text(encoding="utf-8"))
_VALIDATOR = Draft202012Validator(_SCHEMA)

_DDL = """
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT UNIQUE NOT NULL,
  request_id TEXT NOT NULL,
  record TEXT NOT NULL,
  record_hash TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def seal(record: dict, prev_hash: str) -> dict:
    """Add the chain fields (id, time, prev_hash, record_hash) and validate against the decision schema.

    Shared by every storage backend, so the chain is computed identically wherever it is stored."""
    rec = dict(record)
    rec["event_id"] = f"evt-{uuid.uuid4().hex[:16]}"
    rec["timestamp"] = _now()
    rec["prev_hash"] = prev_hash
    rec["record_hash"] = sha256_hex(canonical_json({k: v for k, v in rec.items() if k != "record_hash"}))
    errors = sorted(_VALIDATOR.iter_errors(rec), key=lambda e: list(e.path))
    if errors:
        raise ValueError("audit record violates decision schema: " + "; ".join(e.message for e in errors[:3]))
    return rec


def verify_chain(records: list[dict]) -> dict:
    """Recompute the whole chain over records (each carrying its `seq`)."""
    prev = GENESIS
    count = 0
    for rec in records:
        count += 1
        body = {k: v for k, v in rec.items() if k not in ("record_hash", "seq")}
        if rec["prev_hash"] != prev:
            return {"ok": False, "count": count, "broken_at": rec["seq"], "detail": "prev_hash mismatch"}
        if sha256_hex(canonical_json(body)) != rec["record_hash"]:
            return {"ok": False, "count": count, "broken_at": rec["seq"], "detail": "record_hash mismatch"}
        prev = rec["record_hash"]
    return {"ok": True, "count": count, "broken_at": None, "detail": "chain intact"}


class AuditLog:
    """SQLite backend (default; single process)."""

    def __init__(self, path: str = ":memory:") -> None:
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.executescript(_DDL)
        self._lock = threading.Lock()

    def _last_hash(self) -> str:
        row = self._db.execute("SELECT record_hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        return row[0] if row else GENESIS

    def append(self, record: dict) -> dict:
        """Add chain fields, validate against the schema, insert. Returns the stored record (with seq)."""
        with self._lock:
            rec = seal(record, self._last_hash())
            cur = self._db.execute(
                "INSERT INTO audit (event_id, request_id, record, record_hash) VALUES (?, ?, ?, ?)",
                (rec["event_id"], rec["request_id"], canonical_json(rec), rec["record_hash"]),
            )
            self._db.commit()
            return {**rec, "seq": cur.lastrowid}

    def all(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute("SELECT seq, record FROM audit ORDER BY seq").fetchall()
        return [{**json.loads(r), "seq": s} for s, r in rows]

    def since(self, seq: int) -> list[dict]:
        """Records appended after `seq` (by this or any other process), oldest first."""
        with self._lock:
            rows = self._db.execute("SELECT seq, record FROM audit WHERE seq > ? ORDER BY seq", (seq,)).fetchall()
        return [{**json.loads(r), "seq": s} for s, r in rows]

    def exclusive(self):
        """Cross-process critical section around one decision. SQLite is single-process, so nothing to do."""
        return contextlib.nullcontext()

    def latest_for_request(self, request_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT seq, record FROM audit WHERE request_id = ? ORDER BY seq DESC LIMIT 1", (request_id,)
            ).fetchone()
        return {**json.loads(row[1]), "seq": row[0]} if row else None

    def verify(self) -> dict:
        """Recompute the whole chain. Returns {ok, count, broken_at (seq|None), detail}."""
        return verify_chain(self.all())

    def _raw_connection(self) -> sqlite3.Connection:
        """Test hook: lets tests simulate someone editing the database file out-of-band."""
        return self._db
