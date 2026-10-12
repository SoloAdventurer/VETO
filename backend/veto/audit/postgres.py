"""PostgreSQL audit backend (DECISIONS D-025, tenant-scoped in D-027). Same contract and chain as SQLite.

* Append-only is enforced by the database: row triggers reject UPDATE and DELETE, a statement trigger rejects
  TRUNCATE. In production the gateway should also connect as a role that owns no table and has only INSERT and
  SELECT (see docs/postgres.md), so even DDL is out of its reach.
* Each log object is bound to one tenant: every query filters on it, appends take a per-tenant advisory lock (one
  tenant never waits for another), and row-level security restricts the connection to that tenant's rows, so a bug
  in this file still cannot read a neighbour's data.
* Several gateway processes may share one tenant's log; the lock keeps its chain linear. A failed write raises: the
  caller fails closed.
"""

from __future__ import annotations

import contextlib
import json
import os
import threading

import psycopg

from veto.audit.chain import DEFAULT_TENANT, GENESIS, check_tenant, seal, verify_chain
from veto.canonical import canonical_json

_LOCK_KEY = 7_412_001            # first half of the per-tenant advisory lock key (second half: hash of the tenant)
_EXCL_KEY = 7_412_002            # session lock held for a whole decision (see exclusive())
_DDL_LOCK = 7_412_900
_DDL = f"""
SELECT pg_advisory_xact_lock({_DDL_LOCK});
CREATE TABLE IF NOT EXISTS audit (
  seq BIGSERIAL PRIMARY KEY,
  event_id TEXT UNIQUE NOT NULL,
  request_id TEXT NOT NULL,
  record TEXT NOT NULL,
  record_hash TEXT NOT NULL
);
ALTER TABLE audit ADD COLUMN IF NOT EXISTS tenant TEXT NOT NULL DEFAULT 'default';
ALTER TABLE audit ADD COLUMN IF NOT EXISTS tseq BIGINT;
DROP INDEX IF EXISTS audit_request_idx;
CREATE INDEX IF NOT EXISTS audit_tenant_req_idx ON audit (tenant, request_id, seq DESC);
CREATE INDEX IF NOT EXISTS audit_tenant_seq_idx ON audit (tenant, seq);
CREATE INDEX IF NOT EXISTS audit_tenant_tseq_idx ON audit (tenant, (COALESCE(tseq, seq)));
CREATE OR REPLACE FUNCTION audit_append_only() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'audit log is append-only'; END; $$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS audit_no_update ON audit;
CREATE TRIGGER audit_no_update BEFORE UPDATE OR DELETE ON audit FOR EACH ROW EXECUTE FUNCTION audit_append_only();
DROP TRIGGER IF EXISTS audit_no_truncate ON audit;
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit FOR EACH STATEMENT EXECUTE FUNCTION audit_append_only();
ALTER TABLE audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_tenant_isolation ON audit;
CREATE POLICY audit_tenant_isolation ON audit
  USING (tenant = current_setting('veto.tenant', true))
  WITH CHECK (tenant = current_setting('veto.tenant', true));
"""


class PostgresAuditLog:
    def __init__(self, dsn: str, tenant: str = DEFAULT_TENANT, migrate: bool | None = None) -> None:
        self.tenant = check_tenant(tenant)
        self._dsn = dsn
        self._lock = threading.Lock()
        self._depth = 0
        self._db = self._connect()
        if migrate is None:
            migrate = os.environ.get("VETO_DB_MIGRATE", "1") != "0"      # least-privilege roles run with 0
        if migrate:
            with self._db.transaction():
                self._db.execute(_DDL)          # type: ignore[arg-type]
                self._db.execute("SELECT set_config('veto.tenant', %s, false)", (self.tenant,))

    def _connect(self) -> psycopg.Connection:
        """Every connection is pinned to this log's tenant; row-level security does the rest."""
        conn = psycopg.connect(self._dsn)
        conn.execute("SELECT set_config('veto.tenant', %s, false)", (self.tenant,))
        conn.commit()
        return conn

    def _conn(self) -> psycopg.Connection:
        if self._db.closed or self._db.broken:
            self._db = self._connect()
            self._depth = 0
        return self._db

    def append(self, record: dict) -> dict:
        with self._lock:
            db = self._conn()
            with db.transaction():
                db.execute("SELECT pg_advisory_xact_lock(%s, hashtext(%s))", (_LOCK_KEY, self.tenant))
                row = db.execute(
                    "SELECT record_hash, COALESCE(tseq, seq) FROM audit WHERE tenant = %s ORDER BY seq DESC LIMIT 1",
                    (self.tenant,)).fetchone()
                prev, last = (row[0], row[1]) if row else (GENESIS, 0)
                rec = seal(record, prev, self.tenant)
                db.execute(
                    "INSERT INTO audit (event_id, request_id, record, record_hash, tenant, tseq) "
                    "VALUES (%s, %s, %s, %s, %s, %s)",
                    (rec["event_id"], rec["request_id"], canonical_json(rec), rec["record_hash"], self.tenant,
                     last + 1))
            return {**rec, "seq": last + 1}

    def all(self) -> list[dict]:
        return self.since(0)

    def since(self, seq: int) -> list[dict]:
        with self._lock:
            rows = self._conn().execute(
                "SELECT COALESCE(tseq, seq), record FROM audit WHERE tenant = %s AND COALESCE(tseq, seq) > %s "
                "ORDER BY seq", (self.tenant, seq)).fetchall()
            self._db.rollback()
        return [{**json.loads(r), "seq": s} for s, r in rows]

    def count(self) -> int:
        with self._lock:
            n = self._conn().execute("SELECT COUNT(*) FROM audit WHERE tenant = %s", (self.tenant,)).fetchone()[0]
            self._db.rollback()
        return n

    def head(self) -> tuple[int, str] | None:
        with self._lock:
            row = self._conn().execute("SELECT COALESCE(tseq, seq), record FROM audit WHERE tenant = %s "
                                       "ORDER BY seq DESC LIMIT 1", (self.tenant,)).fetchone()
            self._db.rollback()
        return (row[0], json.loads(row[1])["record_hash"]) if row else None

    @contextlib.contextmanager
    def exclusive(self):
        """Hold this tenant's database-wide lock for a whole decision (catch up, decide, append), so two gateway
        processes can never decide for the same tenant at once on stale state. Re-entrant within this process,
        released on error. Other tenants are not blocked."""
        with self._lock:
            first = self._depth == 0
            if first:
                self._conn().execute("SELECT pg_advisory_lock(%s, hashtext(%s))", (_EXCL_KEY, self.tenant))
                self._db.rollback()
            self._depth += 1
        try:
            yield
        finally:
            with self._lock:
                self._depth -= 1
                if self._depth == 0:
                    try:
                        self._conn().execute("SELECT pg_advisory_unlock(%s, hashtext(%s))",
                                             (_EXCL_KEY, self.tenant))
                        self._db.rollback()
                    except psycopg.Error:
                        pass        # a dropped connection releases its session locks by itself

    def latest_for_request(self, request_id: str) -> dict | None:
        with self._lock:
            row = self._conn().execute(
                "SELECT COALESCE(tseq, seq), record FROM audit WHERE tenant = %s AND request_id = %s "
                "ORDER BY seq DESC LIMIT 1", (self.tenant, request_id)).fetchone()
            self._db.rollback()
        return {**json.loads(row[1]), "seq": row[0]} if row else None

    def verify(self) -> dict:
        return verify_chain(self.all(), self.tenant)

    def close(self) -> None:
        self._db.close()
