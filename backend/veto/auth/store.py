"""Principals and API keys (closes T6 identity spoofing, T7 forged approvals; supersedes D-017).

* A principal is an agent or a human with one or more roles. Agents hold exactly the `agent` role and nothing else,
  so an agent key can never approve, contain, read the audit trail or administer anything.
* Keys are random 256-bit secrets shown once at creation. Only their SHA-256 hash is stored, so a leaked database
  does not leak usable keys. Keys can be revoked or rotated at any time and take effect on the next request.
* Identity always comes from the key. Whatever a request body claims about who is acting is checked against it.
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

ROLES = {"agent", "operator", "approver", "viewer", "admin"}
HUMAN_ROLES = ROLES - {"agent"}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{1,63}$")
KEY_PREFIX = "veto_"

_DDL = """
CREATE TABLE IF NOT EXISTS principals (
  id TEXT PRIMARY KEY, roles TEXT NOT NULL, disabled INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
  key_id TEXT PRIMARY KEY, principal_id TEXT NOT NULL REFERENCES principals(id), key_hash TEXT UNIQUE NOT NULL,
  prefix TEXT NOT NULL, created_at REAL NOT NULL, last_used REAL, revoked_at REAL
);
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

    def has(self, *roles: str) -> bool:
        return any(r in self.roles for r in roles)


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


class PrincipalStore:
    def __init__(self, path: str = ":memory:", clock: Callable[[], float] = time.time) -> None:
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.executescript(_DDL)
        self._lock = threading.Lock()
        self._clock = clock
        self.failures = 0

    # ---------------------------------------------------------------- administration
    def create_principal(self, pid: str, roles: list[str]) -> None:
        roleset = set(roles)
        if not ID_RE.match(pid or ""):
            raise AuthError("principal id must match [a-z0-9][a-z0-9_.-]{1,63}")
        if not roleset or not roleset <= ROLES:
            raise AuthError(f"roles must be a non-empty subset of {sorted(ROLES)}")
        if "agent" in roleset and roleset != {"agent"}:
            raise AuthError("an agent principal cannot hold human roles (separation of duties)")
        with self._lock:
            if self._db.execute("SELECT 1 FROM principals WHERE id = ?", (pid,)).fetchone():
                raise AuthError(f"principal '{pid}' already exists", 409)
            self._db.execute("INSERT INTO principals (id, roles, created_at) VALUES (?, ?, ?)",
                             (pid, ",".join(sorted(roleset)), self._clock()))
            self._db.commit()

    def issue_key(self, pid: str) -> tuple[str, str]:
        """Returns (key_id, plaintext_key). The plaintext is never stored and cannot be shown again."""
        with self._lock:
            row = self._db.execute("SELECT disabled FROM principals WHERE id = ?", (pid,)).fetchone()
            if row is None:
                raise AuthError("unknown principal", 404)
            if row[0]:
                raise AuthError("principal is disabled", 409)
            plaintext = KEY_PREFIX + secrets.token_urlsafe(32)
            key_id = "key-" + secrets.token_hex(6)
            self._db.execute(
                "INSERT INTO api_keys (key_id, principal_id, key_hash, prefix, created_at) VALUES (?, ?, ?, ?, ?)",
                (key_id, pid, _hash(plaintext), plaintext[:11], self._clock()))
            self._db.commit()
            return key_id, plaintext

    def revoke_key(self, key_id: str) -> None:
        with self._lock:
            cur = self._db.execute("UPDATE api_keys SET revoked_at = ? WHERE key_id = ? AND revoked_at IS NULL",
                                   (self._clock(), key_id))
            self._db.commit()
            if cur.rowcount == 0:
                raise AuthError("unknown or already revoked key", 404)

    def disable_principal(self, pid: str) -> None:
        with self._lock:
            cur = self._db.execute("UPDATE principals SET disabled = 1 WHERE id = ?", (pid,))
            self._db.execute("UPDATE api_keys SET revoked_at = COALESCE(revoked_at, ?) WHERE principal_id = ?",
                             (self._clock(), pid))
            self._db.commit()
            if cur.rowcount == 0:
                raise AuthError("unknown principal", 404)

    def bootstrap(self, plaintext_key: str, pid: str = "bootstrap-admin") -> None:
        """Install a known admin key (from the environment). Idempotent. Intended for first start and demos."""
        if not plaintext_key.startswith(KEY_PREFIX) or len(plaintext_key) < 24:
            raise AuthError(f"bootstrap key must start with '{KEY_PREFIX}' and be at least 24 characters")
        with self._lock:
            if not self._db.execute("SELECT 1 FROM principals WHERE id = ?", (pid,)).fetchone():
                self._db.execute("INSERT INTO principals (id, roles, created_at) VALUES (?, ?, ?)",
                                 (pid, ",".join(sorted(HUMAN_ROLES)), self._clock()))
            if not self._db.execute("SELECT 1 FROM api_keys WHERE key_hash = ?", (_hash(plaintext_key),)).fetchone():
                self._db.execute(
                    "INSERT INTO api_keys (key_id, principal_id, key_hash, prefix, created_at) VALUES (?, ?, ?, ?, ?)",
                    ("key-bootstrap-" + secrets.token_hex(3), pid, _hash(plaintext_key), plaintext_key[:11],
                     self._clock()))
            self._db.commit()

    def has_principals(self) -> bool:
        with self._lock:
            return self._db.execute("SELECT 1 FROM principals LIMIT 1").fetchone() is not None

    def list_principals(self) -> list[dict]:
        """Never returns key material (only hash-derived metadata: id, 11-char prefix, timestamps)."""
        with self._lock:
            ps = self._db.execute("SELECT id, roles, disabled, created_at FROM principals ORDER BY created_at, id")
            out = []
            for pid, roles, disabled, created in ps.fetchall():
                keys = self._db.execute(
                    "SELECT key_id, prefix, created_at, last_used, revoked_at FROM api_keys WHERE principal_id = ? "
                    "ORDER BY created_at", (pid,)).fetchall()
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
                "SELECT k.key_id, k.key_hash, k.revoked_at, p.id, p.roles, p.disabled FROM api_keys k "
                "JOIN principals p ON p.id = k.principal_id WHERE k.key_hash = ?", (digest,)).fetchone()
            if row is None or not hmac.compare_digest(row[1], digest) or row[2] is not None or row[5]:
                self.failures += 1
                return None
            self._db.execute("UPDATE api_keys SET last_used = ? WHERE key_id = ?", (self._clock(), row[0]))
            self._db.commit()
            return Principal(id=row[3], roles=frozenset(row[4].split(",")), key_id=row[0])
