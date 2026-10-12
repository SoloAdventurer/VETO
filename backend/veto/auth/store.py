"""Tenants, principals and API keys (closes T6/T7; supersedes D-017; tenant-scoped in D-027).

* A tenant is one customer. A principal belongs to exactly one tenant (or is a platform administrator, tenant '').
  Principal ids are unique per tenant, so two customers can both have an `ops-agent-1`.
* The tenant is always read from the key. Every administrative method takes the caller's tenant as a required
  keyword and filters on it, so a tenant administrator cannot even name another tenant's principal or key.
* Agents hold exactly the `agent` role, so an agent key can never approve, contain, read the audit trail or administer
  anything. A platform administrator holds only `platform_admin` and can manage tenants but never act inside one.
* Keys are random 256-bit secrets shown once at creation. Only their SHA-256 hash is stored, so a leaked database
  does not leak usable keys. Keys can be revoked or rotated at any time and take effect on the next request.
* The store lives in SQLite (a path or ':memory:') or PostgreSQL (a postgresql:// URL) so several gateway processes
  can share it; a revocation or suspension is seen by every process on its next request (D-026).
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

DEFAULT_TENANT = "default"
PLATFORM = ""                                   # the "tenant" of platform administrators
TENANT_ROLES = {"agent", "operator", "approver", "viewer", "admin"}
ROLES = TENANT_ROLES | {"platform_admin"}
HUMAN_ROLES = TENANT_ROLES - {"agent"}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{1,63}$")
TENANT_ID_RE = re.compile(r"^[a-z][a-z0-9-]{1,39}$")
KEY_PREFIX = "veto_"

_DDL = """
CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
  created_at DOUBLE PRECISION NOT NULL, policy TEXT
);
CREATE TABLE IF NOT EXISTS principals (
  tenant TEXT NOT NULL, id TEXT NOT NULL, roles TEXT NOT NULL, disabled INTEGER NOT NULL DEFAULT 0,
  created_at DOUBLE PRECISION NOT NULL, PRIMARY KEY (tenant, id)
);
CREATE TABLE IF NOT EXISTS api_keys (
  key_id TEXT PRIMARY KEY, tenant TEXT NOT NULL, principal_id TEXT NOT NULL, key_hash TEXT UNIQUE NOT NULL,
  prefix TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL, last_used DOUBLE PRECISION,
  revoked_at DOUBLE PRECISION,
  FOREIGN KEY (tenant, principal_id) REFERENCES principals (tenant, id)
);
CREATE TABLE IF NOT EXISTS policy_versions (
  tenant TEXT NOT NULL, version INTEGER NOT NULL, policy TEXT NOT NULL, sha TEXT NOT NULL, created_by TEXT NOT NULL,
  created_at DOUBLE PRECISION NOT NULL, status TEXT NOT NULL, decided_by TEXT, decided_at DOUBLE PRECISION,
  diff TEXT NOT NULL, PRIMARY KEY (tenant, version)
);
CREATE TABLE IF NOT EXISTS webhooks (
  tenant TEXT NOT NULL, name TEXT NOT NULL, spec TEXT NOT NULL, created_by TEXT NOT NULL,
  created_at DOUBLE PRECISION NOT NULL, PRIMARY KEY (tenant, name)
);
CREATE TABLE IF NOT EXISTS connectors (
  tenant TEXT NOT NULL, name TEXT NOT NULL, meta TEXT NOT NULL, sealed TEXT NOT NULL, created_by TEXT NOT NULL,
  created_at DOUBLE PRECISION NOT NULL, PRIMARY KEY (tenant, name)
);
CREATE TABLE IF NOT EXISTS anchors (
  tenant TEXT NOT NULL, seq INTEGER NOT NULL, head_hash TEXT NOT NULL, digest TEXT NOT NULL, tsr TEXT NOT NULL,
  gen_time TEXT NOT NULL, tsa TEXT NOT NULL, signature_checked INTEGER NOT NULL, created_at DOUBLE PRECISION NOT NULL,
  PRIMARY KEY (tenant, seq)
);
CREATE TABLE IF NOT EXISTS hook_calls (
  tenant TEXT NOT NULL, hook TEXT NOT NULL, idem_key TEXT NOT NULL, request_id TEXT,
  created_at DOUBLE PRECISION NOT NULL, PRIMARY KEY (tenant, hook, idem_key)
);
CREATE TABLE IF NOT EXISTS platform_state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


class AuthError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class Principal:
    id: str
    roles: frozenset[str]
    key_id: str
    tenant: str = DEFAULT_TENANT
    suspended: bool = False

    def has(self, *roles: str) -> bool:
        return any(r in self.roles for r in roles)

    @property
    def rate_key(self) -> str:
        return f"{self.tenant}/{self.id}"


class _Sql:
    """The few calls the store needs, over SQLite or PostgreSQL (placeholders written as ? for both)."""

    def __init__(self, target: str) -> None:
        self.pg = target.startswith(("postgresql://", "postgres://"))
        if self.pg:
            import psycopg
            self._c = psycopg.connect(target, autocommit=True)
            self.integrity_error: type[Exception] = psycopg.errors.UniqueViolation
        else:
            self._c = sqlite3.connect(target, check_same_thread=False)
            self.integrity_error = sqlite3.IntegrityError
        self._migrate_legacy()
        for stmt in (x.strip() for x in _DDL.split(";")):
            if stmt:
                self._c.execute(stmt)
        self.commit()

    def columns(self, table: str) -> set[str]:
        if self.pg:
            rows = self._c.execute("SELECT column_name FROM information_schema.columns WHERE table_name = %s "
                                   "AND table_schema = current_schema()", (table,)).fetchall()
            return {r[0] for r in rows}
        return {r[1] for r in self._c.execute(f"PRAGMA table_info({table})")}     # noqa: S608 (constant names)

    def _migrate_legacy(self) -> None:
        """Databases from before D-027 have principals keyed by id alone; move them into the default tenant."""
        cols = self.columns("principals")
        if not cols or "tenant" in cols:
            return
        self._c.execute("ALTER TABLE principals RENAME TO principals_legacy")
        self._c.execute("ALTER TABLE api_keys RENAME TO api_keys_legacy")
        for stmt in (x.strip() for x in _DDL.split(";")):
            if stmt:
                self._c.execute(stmt)
        self._c.execute("INSERT INTO tenants (id, name, created_at) SELECT 'default', 'Default', MIN(created_at) "
                        "FROM principals_legacy")
        self._c.execute("INSERT INTO principals (tenant, id, roles, disabled, created_at) "
                        "SELECT 'default', id, roles, disabled, created_at FROM principals_legacy")
        self._c.execute("INSERT INTO api_keys (key_id, tenant, principal_id, key_hash, prefix, created_at, last_used, "
                        "revoked_at) SELECT key_id, 'default', principal_id, key_hash, prefix, created_at, last_used, "
                        "revoked_at FROM api_keys_legacy")
        self._c.execute("DROP TABLE api_keys_legacy")
        self._c.execute("DROP TABLE principals_legacy")
        self.commit()

    def execute(self, sql: str, params: tuple = ()):
        return self._c.execute(sql.replace("?", "%s") if self.pg else sql, params)

    def commit(self) -> None:
        if not self.pg:
            self._c.commit()

    def iterdump(self):
        """Everything stored, as text lines (test hook: proves no plaintext key is ever written)."""
        if not self.pg:
            yield from self._c.iterdump()
            return
        for label, query in (("principals", "SELECT * FROM principals"), ("api_keys", "SELECT * FROM api_keys")):
            for row in self.execute(query).fetchall():
                yield f"{label}: {row!r}"


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


class PrincipalStore:
    def __init__(self, path: str = ":memory:", clock: Callable[[], float] = time.time) -> None:
        self._db = _Sql(path)
        self._lock = threading.Lock()
        self._clock = clock
        self.failures = 0
        self.ensure_tenant(DEFAULT_TENANT, "Default")

    # ---------------------------------------------------------------- tenants (platform administration)
    def ensure_tenant(self, tenant_id: str, name: str, policy: str | None = None) -> bool:
        """Create the tenant if absent. Returns True if it was created."""
        if not TENANT_ID_RE.match(tenant_id or ""):
            raise AuthError("tenant id must match [a-z][a-z0-9-]{1,39}")
        with self._lock:
            if self._db.execute("SELECT 1 FROM tenants WHERE id = ?", (tenant_id,)).fetchone():
                return False
            try:
                self._db.execute("INSERT INTO tenants (id, name, created_at, policy) VALUES (?, ?, ?, ?)",
                                 (tenant_id, name[:120] or tenant_id, self._clock(), policy))
            except self._db.integrity_error:
                return False
            self._db.commit()
            return True

    def create_tenant(self, tenant_id: str, name: str, policy: str | None = None) -> None:
        if not self.ensure_tenant(tenant_id, name, policy):
            raise AuthError(f"tenant '{tenant_id}' already exists", 409)

    def get_tenant(self, tenant_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute("SELECT id, name, status, created_at, policy FROM tenants WHERE id = ?",
                                   (tenant_id,)).fetchone()
        return ({"id": row[0], "name": row[1], "status": row[2], "created_at": row[3], "policy": row[4]}
                if row else None)

    def list_tenants(self) -> list[dict]:
        """Metadata only (never the policy text, never any decision content)."""
        with self._lock:
            rows = self._db.execute("SELECT id, name, status, created_at FROM tenants ORDER BY created_at, id")
            return [{"id": r[0], "name": r[1], "status": r[2], "created_at": r[3]} for r in rows.fetchall()]

    def set_tenant_status(self, tenant_id: str, status: str) -> None:
        if status not in ("active", "suspended"):
            raise AuthError("status must be 'active' or 'suspended'")
        with self._lock:
            cur = self._db.execute("UPDATE tenants SET status = ? WHERE id = ?", (status, tenant_id))
            self._db.commit()
            if cur.rowcount == 0:
                raise AuthError("unknown tenant", 404)

    # ---------------------------------------------------------------- policy proposals (always inside one tenant)
    def add_policy_proposal(self, tenant: str, text: str, sha: str, by: str, diff_json: str) -> int:
        for _ in range(3):                                       # another process may take the number first
            with self._lock:
                version = self._db.execute("SELECT COALESCE(MAX(version), 0) + 1 FROM policy_versions "
                                           "WHERE tenant = ?", (tenant,)).fetchone()[0]
                try:
                    self._db.execute(
                        "INSERT INTO policy_versions (tenant, version, policy, sha, created_by, created_at, status, "
                        "diff) VALUES (?, ?, ?, ?, ?, ?, 'proposed', ?)",
                        (tenant, version, text, sha, by, self._clock(), diff_json))
                    self._db.commit()
                    return version
                except self._db.integrity_error:
                    continue
        raise AuthError("could not allocate a policy version; retry", 409)

    # ---------------------------------------------------------------- anchors (external timestamps of chain heads)
    def add_anchor(self, tenant: str, seq: int, head_hash: str, digest: str, tsr_b64: str, gen_time: str, tsa: str,
                   signature_checked: bool) -> bool:
        with self._lock:
            try:
                self._db.execute(
                    "INSERT INTO anchors (tenant, seq, head_hash, digest, tsr, gen_time, tsa, signature_checked, "
                    "created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (tenant, seq, head_hash, digest, tsr_b64, gen_time, tsa, int(signature_checked), self._clock()))
                self._db.commit()
                return True
            except self._db.integrity_error:        # another process anchored the same head first
                return False

    _ANCHOR_COLS = "seq, head_hash, digest, gen_time, tsa, signature_checked, created_at"

    @staticmethod
    def _anchor_row(r, with_receipt: bool = False) -> dict:
        out = {"seq": r[0], "head_hash": r[1], "digest": r[2], "gen_time": r[3], "tsa": r[4],
               "signature_checked": bool(r[5]), "created_at": r[6]}
        if with_receipt:
            out["tsr_base64"] = r[7]
        return out

    def list_anchors(self, tenant: str) -> list[dict]:
        with self._lock:
            rows = self._db.execute(f"SELECT {self._ANCHOR_COLS} FROM anchors WHERE tenant = ? "  # noqa: S608
                                    "ORDER BY seq", (tenant,)).fetchall()
        return [self._anchor_row(r) for r in rows]

    def get_anchor(self, tenant: str, seq: int) -> dict | None:
        with self._lock:
            row = self._db.execute(f"SELECT {self._ANCHOR_COLS}, tsr FROM anchors "  # noqa: S608
                                   "WHERE tenant = ? AND seq = ?", (tenant, seq)).fetchone()
        return self._anchor_row(row, True) if row else None

    def last_anchor(self, tenant: str) -> dict | None:
        with self._lock:
            row = self._db.execute(f"SELECT {self._ANCHOR_COLS} FROM anchors WHERE tenant = ? "  # noqa: S608
                                   "ORDER BY seq DESC LIMIT 1", (tenant,)).fetchone()
        return self._anchor_row(row) if row else None

    # ---------------------------------------------------------------- connectors (sealed; this class never opens them)
    def put_connector(self, tenant: str, name: str, meta: dict, sealed: str, by: str) -> None:
        import json
        with self._lock:
            self._db.execute(
                "INSERT INTO connectors (tenant, name, meta, sealed, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (tenant, name) DO UPDATE SET meta = excluded.meta, sealed = excluded.sealed, "
                "created_by = excluded.created_by, created_at = excluded.created_at",
                (tenant, name, json.dumps(meta), sealed, by, self._clock()))
            self._db.commit()

    def connector_rows(self, tenant: str) -> list[dict]:
        """Everything including the sealed blob. For the Execution Gateway's router only; never sent to a client."""
        import json
        with self._lock:
            rows = self._db.execute("SELECT name, meta, sealed FROM connectors WHERE tenant = ? ORDER BY name",
                                    (tenant,)).fetchall()
        return [{"name": r[0], "meta": json.loads(r[1]), "sealed": r[2]} for r in rows]

    def list_connectors(self, tenant: str) -> list[dict]:
        import json
        with self._lock:
            rows = self._db.execute("SELECT name, meta, created_by, created_at FROM connectors WHERE tenant = ? "
                                    "ORDER BY name", (tenant,)).fetchall()
        return [{"name": r[0], **json.loads(r[1]), "created_by": r[2], "created_at": r[3]} for r in rows]

    def delete_connector(self, tenant: str, name: str) -> bool:
        with self._lock:
            cur = self._db.execute("DELETE FROM connectors WHERE tenant = ? AND name = ?", (tenant, name))
            self._db.commit()
            return cur.rowcount > 0

    # ---------------------------------------------------------------- webhooks (always inside one tenant)
    def put_hook(self, tenant: str, name: str, spec_json: str, by: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO webhooks (tenant, name, spec, created_by, created_at) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT (tenant, name) DO UPDATE SET spec = excluded.spec, created_by = excluded.created_by, "
                "created_at = excluded.created_at", (tenant, name, spec_json, by, self._clock()))
            self._db.commit()

    def get_hook(self, tenant: str, name: str) -> dict | None:
        import json
        with self._lock:
            row = self._db.execute("SELECT spec, created_by, created_at FROM webhooks WHERE tenant = ? AND name = ?",
                                   (tenant, name)).fetchone()
        return {"name": name, "spec": json.loads(row[0]), "created_by": row[1], "created_at": row[2]} if row else None

    def list_hooks(self, tenant: str) -> list[dict]:
        import json
        with self._lock:
            rows = self._db.execute("SELECT name, spec, created_by, created_at FROM webhooks WHERE tenant = ? "
                                    "ORDER BY name", (tenant,)).fetchall()
        return [{"name": r[0], "spec": json.loads(r[1]), "created_by": r[2], "created_at": r[3]} for r in rows]

    def delete_hook(self, tenant: str, name: str) -> bool:
        with self._lock:
            cur = self._db.execute("DELETE FROM webhooks WHERE tenant = ? AND name = ?", (tenant, name))
            self._db.commit()
            return cur.rowcount > 0

    def claim_call(self, tenant: str, hook: str, key: str) -> tuple[bool, str | None]:
        """Idempotency: True if this caller owns (tenant, hook, key); otherwise False and the request id the first
        call produced (None while that call is still being decided)."""
        with self._lock:
            try:
                self._db.execute("INSERT INTO hook_calls (tenant, hook, idem_key, created_at) VALUES (?, ?, ?, ?)",
                                 (tenant, hook, key, self._clock()))
                self._db.commit()
                return True, None
            except self._db.integrity_error:
                row = self._db.execute("SELECT request_id FROM hook_calls WHERE tenant = ? AND hook = ? "
                                       "AND idem_key = ?", (tenant, hook, key)).fetchone()
                return False, row[0] if row else None

    def finish_call(self, tenant: str, hook: str, key: str, request_id: str | None) -> None:
        """Record the outcome of an owned call; None releases the key so the caller can retry."""
        with self._lock:
            if request_id is None:
                self._db.execute("DELETE FROM hook_calls WHERE tenant = ? AND hook = ? AND idem_key = ?",
                                 (tenant, hook, key))
            else:
                self._db.execute("UPDATE hook_calls SET request_id = ? WHERE tenant = ? AND hook = ? "
                                 "AND idem_key = ?", (request_id, tenant, hook, key))
            self._db.commit()

    _POLICY_COLS = "version, sha, created_by, created_at, status, decided_by, decided_at, diff"

    def get_policy_version(self, tenant: str, version: int, with_text: bool = False) -> dict | None:
        with self._lock:
            row = self._db.execute(
                f"SELECT {self._POLICY_COLS}, policy FROM policy_versions WHERE tenant = ? AND version = ?",  # noqa: S608
                (tenant, version)).fetchone()
        return self._policy_row(row, with_text) if row else None

    def list_policy_versions(self, tenant: str) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                f"SELECT {self._POLICY_COLS}, policy FROM policy_versions WHERE tenant = ? "  # noqa: S608
                "ORDER BY version DESC", (tenant,)).fetchall()
        return [self._policy_row(r, False) for r in rows]

    @staticmethod
    def _policy_row(r, with_text: bool) -> dict:
        import json
        out = {"version": r[0], "sha256": r[1], "created_by": r[2], "created_at": r[3], "status": r[4],
               "decided_by": r[5], "decided_at": r[6], "diff": json.loads(r[7])}
        if with_text:
            out["policy"] = r[8]
        return out

    def decide_policy_version(self, tenant: str, version: int, status: str, by: str) -> bool:
        """proposed -> active | rejected, once. Activating supersedes the previously active version."""
        if status not in ("active", "rejected"):
            raise AuthError("status must be 'active' or 'rejected'")
        with self._lock:
            cur = self._db.execute(
                "UPDATE policy_versions SET status = ?, decided_by = ?, decided_at = ? "
                "WHERE tenant = ? AND version = ? AND status = 'proposed'",
                (status, by, self._clock(), tenant, version))
            if cur.rowcount == 0:
                return False
            if status == "active":
                self._db.execute("UPDATE policy_versions SET status = 'superseded' WHERE tenant = ? AND version <> ? "
                                 "AND status = 'active'", (tenant, version))
            self._db.commit()
            return True

    def active_policy_text(self, tenant: str) -> str | None:
        with self._lock:
            row = self._db.execute("SELECT policy FROM policy_versions WHERE tenant = ? AND status = 'active' "
                                   "ORDER BY decided_at DESC LIMIT 1", (tenant,)).fetchone()
        return row[0] if row else None

    def platform_contained(self) -> bool:
        """Global kill switch: while on, every tenant's gateway blocks everything."""
        with self._lock:
            row = self._db.execute("SELECT value FROM platform_state WHERE key = 'containment'").fetchone()
        return bool(row) and row[0] == "1"

    def set_platform_contained(self, active: bool) -> None:
        with self._lock:
            self._db.execute("DELETE FROM platform_state WHERE key = 'containment'")
            self._db.execute("INSERT INTO platform_state (key, value) VALUES ('containment', ?)",
                             ("1" if active else "0",))
            self._db.commit()

    # ---------------------------------------------------------------- administration (always inside one tenant)
    def create_principal(self, pid: str, roles: list[str], *, tenant: str) -> None:
        roleset = set(roles)
        if not ID_RE.match(pid or ""):
            raise AuthError("principal id must match [a-z0-9][a-z0-9_.-]{1,63}")
        if not roleset or not roleset <= TENANT_ROLES:
            raise AuthError(f"roles must be a non-empty subset of {sorted(TENANT_ROLES)}")
        if "agent" in roleset and roleset != {"agent"}:
            raise AuthError("an agent principal cannot hold human roles (separation of duties)")
        self._insert_principal(pid, roleset, tenant)

    def create_platform_principal(self, pid: str) -> None:
        if not ID_RE.match(pid or ""):
            raise AuthError("principal id must match [a-z0-9][a-z0-9_.-]{1,63}")
        self._insert_principal(pid, {"platform_admin"}, PLATFORM)

    def _insert_principal(self, pid: str, roleset: set[str], tenant: str) -> None:
        with self._lock:
            if tenant != PLATFORM:
                t = self._db.execute("SELECT status FROM tenants WHERE id = ?", (tenant,)).fetchone()
                if t is None:
                    raise AuthError("unknown tenant", 404)
            if self._db.execute("SELECT 1 FROM principals WHERE tenant = ? AND id = ?", (tenant, pid)).fetchone():
                raise AuthError(f"principal '{pid}' already exists", 409)
            try:
                self._db.execute("INSERT INTO principals (tenant, id, roles, created_at) VALUES (?, ?, ?, ?)",
                                 (tenant, pid, ",".join(sorted(roleset)), self._clock()))
            except self._db.integrity_error as exc:         # another gateway process created it first
                raise AuthError(f"principal '{pid}' already exists", 409) from exc
            self._db.commit()

    def issue_key(self, pid: str, *, tenant: str) -> tuple[str, str]:
        """Returns (key_id, plaintext_key). The plaintext is never stored and cannot be shown again."""
        with self._lock:
            row = self._db.execute("SELECT disabled FROM principals WHERE tenant = ? AND id = ?",
                                   (tenant, pid)).fetchone()
            if row is None:
                raise AuthError("unknown principal", 404)
            if row[0]:
                raise AuthError("principal is disabled", 409)
            plaintext = KEY_PREFIX + secrets.token_urlsafe(32)
            key_id = "key-" + secrets.token_hex(6)
            self._db.execute(
                "INSERT INTO api_keys (key_id, tenant, principal_id, key_hash, prefix, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)", (key_id, tenant, pid, _hash(plaintext), plaintext[:11], self._clock()))
            self._db.commit()
            return key_id, plaintext

    def revoke_key(self, key_id: str, *, tenant: str) -> None:
        with self._lock:
            cur = self._db.execute(
                "UPDATE api_keys SET revoked_at = ? WHERE key_id = ? AND tenant = ? AND revoked_at IS NULL",
                (self._clock(), key_id, tenant))
            self._db.commit()
            if cur.rowcount == 0:
                raise AuthError("unknown or already revoked key", 404)

    def disable_principal(self, pid: str, *, tenant: str) -> None:
        with self._lock:
            cur = self._db.execute("UPDATE principals SET disabled = 1 WHERE tenant = ? AND id = ?", (tenant, pid))
            self._db.execute("UPDATE api_keys SET revoked_at = COALESCE(revoked_at, ?) "
                             "WHERE tenant = ? AND principal_id = ?", (self._clock(), tenant, pid))
            self._db.commit()
            if cur.rowcount == 0:
                raise AuthError("unknown principal", 404)

    def bootstrap(self, plaintext_key: str, pid: str = "bootstrap-admin", *, tenant: str = DEFAULT_TENANT) -> None:
        """Install a known tenant-admin key (from the environment). Idempotent. Intended for first start and demos."""
        self._bootstrap(plaintext_key, pid, tenant, HUMAN_ROLES)

    def bootstrap_platform(self, plaintext_key: str, pid: str = "platform-admin") -> None:
        """Install a known platform-administrator key (VETO_PLATFORM_KEY). Idempotent."""
        self._bootstrap(plaintext_key, pid, PLATFORM, {"platform_admin"})

    def _bootstrap(self, plaintext_key: str, pid: str, tenant: str, roles: set[str]) -> None:
        if not plaintext_key.startswith(KEY_PREFIX) or len(plaintext_key) < 24:
            raise AuthError(f"bootstrap key must start with '{KEY_PREFIX}' and be at least 24 characters")
        with self._lock:
            try:
                if not self._db.execute("SELECT 1 FROM principals WHERE tenant = ? AND id = ?",
                                        (tenant, pid)).fetchone():
                    self._db.execute("INSERT INTO principals (tenant, id, roles, created_at) VALUES (?, ?, ?, ?)",
                                     (tenant, pid, ",".join(sorted(roles)), self._clock()))
                if not self._db.execute("SELECT 1 FROM api_keys WHERE key_hash = ?",
                                        (_hash(plaintext_key),)).fetchone():
                    self._db.execute(
                        "INSERT INTO api_keys (key_id, tenant, principal_id, key_hash, prefix, created_at) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        ("key-bootstrap-" + secrets.token_hex(3), tenant, pid, _hash(plaintext_key),
                         plaintext_key[:11], self._clock()))
            except self._db.integrity_error:
                pass                                          # another process bootstrapped at the same moment
            self._db.commit()

    def has_principals(self) -> bool:
        with self._lock:
            return self._db.execute("SELECT 1 FROM principals LIMIT 1").fetchone() is not None

    def list_principals(self, *, tenant: str) -> list[dict]:
        """Never returns key material (only hash-derived metadata: id, 11-char prefix, timestamps)."""
        with self._lock:
            ps = self._db.execute("SELECT id, roles, disabled, created_at FROM principals WHERE tenant = ? "
                                  "ORDER BY created_at, id", (tenant,))
            out = []
            for pid, roles, disabled, created in ps.fetchall():
                keys = self._db.execute(
                    "SELECT key_id, prefix, created_at, last_used, revoked_at FROM api_keys "
                    "WHERE tenant = ? AND principal_id = ? ORDER BY created_at", (tenant, pid)).fetchall()
                out.append({"id": pid, "roles": roles.split(","), "disabled": bool(disabled), "created_at": created,
                            "keys": [{"key_id": k[0], "prefix": k[1], "created_at": k[2], "last_used": k[3],
                                      "revoked": k[4] is not None} for k in keys]})
            return out

    # ---------------------------------------------------------------- authentication
    def authenticate(self, plaintext: str | None) -> Principal | None:
        if not plaintext or not plaintext.startswith(KEY_PREFIX) or len(plaintext) > 256:
            self.failures += 1
            return None
        digest = _hash(plaintext)
        with self._lock:
            row = self._db.execute(
                "SELECT k.key_id, k.key_hash, k.revoked_at, p.id, p.roles, p.disabled, k.last_used, p.tenant, "
                "t.status FROM api_keys k JOIN principals p ON p.tenant = k.tenant AND p.id = k.principal_id "
                "LEFT JOIN tenants t ON t.id = p.tenant WHERE k.key_hash = ?", (digest,)).fetchone()
            if row is None or not hmac.compare_digest(row[1], digest) or row[2] is not None or row[5]:
                self.failures += 1
                return None
            now = self._clock()
            if row[6] is None or now - row[6] >= 30:          # one write per half minute, not per request
                self._db.execute("UPDATE api_keys SET last_used = ? WHERE key_id = ?", (now, row[0]))
                self._db.commit()
            return Principal(id=row[3], roles=frozenset(row[4].split(",")), key_id=row[0], tenant=row[7],
                             suspended=row[8] == "suspended")
