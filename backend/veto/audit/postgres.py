"""PostgreSQL audit backend (DECISIONS D-025). Same contract and same chain as the SQLite backend.

* Append-only is enforced by the database: row triggers reject UPDATE and DELETE, a statement trigger rejects
  TRUNCATE. In production the gateway should also connect as a role that owns no table and has only INSERT and
  SELECT (see docs/postgres.md), so even DDL is out of its reach.
* Several gateway processes may share one log. Every append takes a transaction-scoped advisory lock, reads the
  newest hash and inserts under that lock, so the chain stays linear. A failed write raises: the caller fails closed.
"""

from __future__ import annotations

import contextlib
import json
import threading

import psycopg

from veto.audit.chain import GENESIS, seal, verify_chain
from veto.canonical import canonical_json

_LOCK_KEY = 7_412_001            # arbitrary constant shared by every VETO process using the same database
_EXCL_KEY = 7_412_002            # session lock held for a whole decision (see exclusive())
_DDL = f"""
SELECT pg_advisory_xact_lock({_LOCK_KEY});
CREATE TABLE IF NOT EXISTS audit (
  seq BIGSERIAL PRIMARY KEY,
  event_id TEXT UNIQUE NOT NULL,
  request_id TEXT NOT NULL,
  record TEXT NOT NULL,
  record_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_request_idx ON audit (request_id, seq DESC);
CREATE OR REPLACE FUNCTION audit_append_only() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'audit log is append-only'; END; $$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS audit_no_update ON audit;
CREATE TRIGGER audit_no_update BEFORE UPDATE OR DELETE ON audit FOR EACH ROW EXECUTE FUNCTION audit_append_only();
DROP TRIGGER IF EXISTS audit_no_truncate ON audit;
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit FOR EACH STATEMENT EXECUTE FUNCTION audit_append_only();
"""


class PostgresAuditLog:
    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._lock = threading.Lock()
        self._depth = 0
        self._db = psycopg.connect(dsn)
        with self._db.transaction():
            self._db.execute(_DDL)          # type: ignore[arg-type]

    def _conn(self) -> psycopg.Connection:
        if self._db.closed or self._db.broken:
            self._db = psycopg.connect(self._dsn)
        return self._db

    def append(self, record: dict) -> dict:
        with self._lock:
            db = self._conn()
            with db.transaction():
                db.execute("SELECT pg_advisory_xact_lock(%s)", (_LOCK_KEY,))
                row = db.execute("SELECT record_hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
                rec = seal(record, row[0] if row else GENESIS)
                seq = db.execute(
                    "INSERT INTO audit (event_id, request_id, record, record_hash) VALUES (%s, %s, %s, %s) "
                    "RETURNING seq", (rec["event_id"], rec["request_id"], canonical_json(rec), rec["record_hash"]),
                ).fetchone()[0]
            return {**rec, "seq": seq}

    def all(self) -> list[dict]:
        with self._lock:
            rows = self._conn().execute("SELECT seq, record FROM audit ORDER BY seq").fetchall()
            self._db.rollback()
        return [{**json.loads(r), "seq": s} for s, r in rows]

    def since(self, seq: int) -> list[dict]:
        with self._lock:
            rows = self._conn().execute("SELECT seq, record FROM audit WHERE seq > %s ORDER BY seq", (seq,)).fetchall()
            self._db.rollback()
        return [{**json.loads(r), "seq": s} for s, r in rows]

    @contextlib.contextmanager
    def exclusive(self):
        """Hold a database-wide lock for a whole decision (catch up, decide, append), so two gateway processes
        can never decide at the same time on stale state. Re-entrant within this process; released on error."""
        with self._lock:
            first = self._depth == 0
            if first:
                self._conn().execute("SELECT pg_advisory_lock(%s)", (_EXCL_KEY,))
                self._db.rollback()
            self._depth += 1
        try:
            yield
        finally:
            with self._lock:
                self._depth -= 1
                if self._depth == 0:
                    try:
                        self._conn().execute("SELECT pg_advisory_unlock(%s)", (_EXCL_KEY,))
                        self._db.rollback()
                    except psycopg.Error:
                        pass        # a dropped connection releases its session locks by itself

    def latest_for_request(self, request_id: str) -> dict | None:
        with self._lock:
            row = self._conn().execute(
                "SELECT seq, record FROM audit WHERE request_id = %s ORDER BY seq DESC LIMIT 1", (request_id,)
            ).fetchone()
            self._db.rollback()
        return {**json.loads(row[1]), "seq": row[0]} if row else None

    def verify(self) -> dict:
        return verify_chain(self.all())

    def close(self) -> None:
        self._db.close()
