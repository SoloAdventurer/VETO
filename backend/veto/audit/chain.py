"""Append-only, hash-chained audit log (invariant 6), one chain per tenant (invariant 8, DECISIONS D-027).

SQLite is the default backend (D-016); veto.audit.postgres adds PostgreSQL (D-025).
Triggers make UPDATE/DELETE fail at the database level, and every record carries prev_hash/record_hash so
tampering with the file itself is detectable by verify().
Records are validated against schemas/decision.schema.json before insert.

Every log object is bound to ONE tenant at construction. Every query it runs filters on that tenant, the tenant is
part of each record's hashed body, and sequence numbers count per tenant, so one tenant's log can neither read nor
extend nor break another's. There is deliberately no method that takes a tenant argument.
"""

from __future__ import annotations

import contextlib
import json
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

from jsonschema import Draft202012Validator

from veto.canonical import canonical_json, sha256_hex
from veto.paths import SCHEMAS_DIR

GENESIS = "0" * 64
DEFAULT_TENANT = "default"
PLATFORM_TENANT = "_platform"
TENANT_RE = re.compile(r"^(?:[a-z][a-z0-9-]{1,39}|_platform)$")
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


def check_tenant(tenant: str) -> str:
    if not isinstance(tenant, str) or not TENANT_RE.match(tenant):
        raise ValueError(f"invalid tenant id {tenant!r}")
    return tenant


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def seal(record: dict, prev_hash: str, tenant: str = DEFAULT_TENANT) -> dict:
    """Add the chain fields (id, time, tenant, prev_hash, record_hash) and validate against the decision schema.

    Shared by every storage backend, so the chain is computed identically wherever it is stored."""
    rec = dict(record)
    rec["event_id"] = f"evt-{uuid.uuid4().hex[:16]}"
    rec["timestamp"] = _now()
    rec["tenant"] = tenant                          # inside the hashed body: a row moved between tenants fails verify
    rec["prev_hash"] = prev_hash
    rec["record_hash"] = sha256_hex(canonical_json({k: v for k, v in rec.items() if k != "record_hash"}))
    errors = sorted(_VALIDATOR.iter_errors(rec), key=lambda e: list(e.path))
    if errors:
        raise ValueError("audit record violates decision schema: " + "; ".join(e.message for e in errors[:3]))
    return rec


def verify_chain(records: list[dict], tenant: str = DEFAULT_TENANT) -> dict:
    """Recompute the whole chain over records (each carrying its `seq`)."""
    prev = GENESIS
    count = 0
    for rec in records:
        count += 1
        body = {k: v for k, v in rec.items() if k not in ("record_hash", "seq")}
        if rec.get("tenant", DEFAULT_TENANT) != tenant:
            return {"ok": False, "count": count, "broken_at": rec["seq"], "detail": "record belongs to another tenant"}
        if rec["prev_hash"] != prev:
            return {"ok": False, "count": count, "broken_at": rec["seq"], "detail": "prev_hash mismatch"}
        if sha256_hex(canonical_json(body)) != rec["record_hash"]:
            return {"ok": False, "count": count, "broken_at": rec["seq"], "detail": "record_hash mismatch"}
        prev = rec["record_hash"]
    return {"ok": True, "count": count, "broken_at": None, "detail": "chain intact"}


class AuditLog:
    """SQLite backend (default; single process). Bound to one tenant."""

    def __init__(self, path: str = ":memory:", tenant: str = DEFAULT_TENANT) -> None:
        self.tenant = check_tenant(tenant)
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.executescript(_DDL)
        cols = {r[1] for r in self._db.execute("PRAGMA table_info(audit)")}
        if "tenant" not in cols:                     # databases created before D-027: existing rows are 'default'
            self._db.execute("ALTER TABLE audit ADD COLUMN tenant TEXT NOT NULL DEFAULT 'default'")
        if "tseq" not in cols:
            self._db.execute("ALTER TABLE audit ADD COLUMN tseq INTEGER")      # NULL on legacy rows: seq is used
        self._db.execute("CREATE INDEX IF NOT EXISTS audit_tenant_req ON audit (tenant, request_id)")
        self._db.execute("CREATE INDEX IF NOT EXISTS audit_tenant_seq ON audit (tenant, seq)")
        self._db.execute("CREATE INDEX IF NOT EXISTS audit_tenant_tseq ON audit (tenant, COALESCE(tseq, seq))")
        self._db.commit()
        self._lock = threading.Lock()

    def _tail(self) -> tuple[str, int]:
        row = self._db.execute(
            "SELECT record_hash, COALESCE(tseq, seq) FROM audit WHERE tenant = ? ORDER BY seq DESC LIMIT 1",
            (self.tenant,)).fetchone()
        return (row[0], row[1]) if row else (GENESIS, 0)

    def append(self, record: dict) -> dict:
        """Add chain fields, validate against the schema, insert. Returns the stored record (with seq)."""
        with self._lock:
            prev, last = self._tail()
            rec = seal(record, prev, self.tenant)
            self._db.execute(
                "INSERT INTO audit (event_id, request_id, record, record_hash, tenant, tseq) VALUES (?, ?, ?, ?, ?, ?)",
                (rec["event_id"], rec["request_id"], canonical_json(rec), rec["record_hash"], self.tenant, last + 1),
            )
            self._db.commit()
            return {**rec, "seq": last + 1}

    def all(self) -> list[dict]:
        return self.since(0)

    def since(self, seq: int) -> list[dict]:
        """This tenant's records after its own sequence number `seq` (by this or any other process), oldest first."""
        with self._lock:
            rows = self._db.execute(
                "SELECT COALESCE(tseq, seq), record FROM audit WHERE tenant = ? AND COALESCE(tseq, seq) > ? "
                "ORDER BY seq", (self.tenant, seq)).fetchall()
        return [{**json.loads(r), "seq": s} for s, r in rows]

    def count(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM audit WHERE tenant = ?", (self.tenant,)).fetchone()[0]

    def exclusive(self):
        """Cross-process critical section around one decision. SQLite is single-process, so nothing to do."""
        return contextlib.nullcontext()

    def latest_for_request(self, request_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT COALESCE(tseq, seq), record FROM audit WHERE tenant = ? AND request_id = ? "
                "ORDER BY seq DESC LIMIT 1", (self.tenant, request_id)).fetchone()
        return {**json.loads(row[1]), "seq": row[0]} if row else None

    def verify(self) -> dict:
        """Recompute this tenant's whole chain. Returns {ok, count, broken_at (seq|None), detail}."""
        return verify_chain(self.all(), self.tenant)

    def _raw_connection(self) -> sqlite3.Connection:
        """Test hook: lets tests simulate someone editing the database file out-of-band."""
        return self._db
