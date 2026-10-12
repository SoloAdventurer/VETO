"""Outbound connectors: how the Execution Gateway acts on a customer's own systems (DECISIONS D-030).

A connector is a signed HTTPS webhook. After VETO has decided and audited, the Execution Gateway (and only it) opens
the tenant's sealed connector definition and POSTs the decided action to the customer's endpoint, signed with a
per-connector secret, bound to the request id and action hash.

Secrets (URL, headers, signing secret) are sealed with AES-256-GCM under a key from the environment
(`VETO_SECRET_KEY`), with the tenant and connector name as associated data, so a sealed value copied to another
tenant or name does not open. Decryption happens only in this package (invariant 5; a test enforces it).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from veto import catalog
from veto.execution import netguard

KEY_ENV = "VETO_SECRET_KEY"
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,39}$")
HEADER_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,39}$")
RESERVED_HEADERS = {"host", "content-length", "content-type", "transfer-encoding", "connection", "user-agent",
                    "idempotency-key", "expect", "te", "upgrade", "cookie", "proxy-authorization"}
MAX_HEADERS = 3
MAX_HEADER_VALUE = 512
DEFAULT_TIMEOUT_S = 5.0
MAX_TIMEOUT_S = 10.0
BREAKER_FAILURES = 3
BREAKER_PAUSE_S = 30.0


class ConnectorError(Exception):
    def __init__(self, message: str, status: int = 422) -> None:
        super().__init__(message)
        self.status = status


# ------------------------------------------------------------------------------------------------ sealing
def _aesgcm():
    raw = os.environ.get(KEY_ENV, "")
    if len(raw) < 32:
        raise ConnectorError(f"secret storage is not configured (set {KEY_ENV} to at least 32 random characters)", 503)
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    except ImportError as exc:
        raise ConnectorError("the 'cryptography' package is required for connectors", 503) from exc
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"veto-connector-v1").derive(raw.encode())
    return AESGCM(key)


def available() -> bool:
    try:
        _aesgcm()
        return True
    except ConnectorError:
        return False


def _seal(tenant: str, name: str, blob: dict) -> str:
    nonce = secrets.token_bytes(12)
    ct = _aesgcm().encrypt(nonce, json.dumps(blob).encode(), f"{tenant}|{name}".encode())
    return base64.b64encode(nonce + ct).decode()


def _open(tenant: str, name: str, sealed: str) -> dict:
    """The only place a sealed definition is opened."""
    try:
        raw = base64.b64decode(sealed)
        return json.loads(_aesgcm().decrypt(raw[:12], raw[12:], f"{tenant}|{name}".encode()))
    except ConnectorError:
        raise
    except Exception as exc:                                       # wrong key, other tenant/name, tampering
        raise ConnectorError("sealed connector could not be opened", 500) from exc


# ------------------------------------------------------------------------------------------------ definitions
@dataclass
class Net:
    """The network seams. Production uses the defaults; tests inject a transport or resolver."""
    transport: Callable[..., tuple[int, bytes]] | None = None
    resolver: Callable[..., list] | None = None

    def resolve(self):
        import socket
        return self.resolver or socket.getaddrinfo

    def post(self, url: str, body: bytes, headers: dict[str, str], timeout: float) -> tuple[int, bytes]:
        if self.transport is not None:
            return self.transport(url, body, headers, timeout)
        return netguard.post(url, body, headers, timeout, resolver=self.resolve())


def validate_headers(headers: Any) -> dict[str, str]:
    if headers is None:
        return {}
    if not isinstance(headers, dict) or len(headers) > MAX_HEADERS:
        raise ConnectorError(f"headers must be an object with at most {MAX_HEADERS} entries")
    out = {}
    for k, v in headers.items():
        if not isinstance(k, str) or not HEADER_NAME_RE.match(k) or k.lower() in RESERVED_HEADERS or \
                k.lower().startswith("x-veto-"):
            raise ConnectorError(f"header name '{k}' is not allowed")
        if not isinstance(v, str) or not v or len(v) > MAX_HEADER_VALUE or any(ord(c) < 32 or ord(c) > 126 for c in v):
            raise ConnectorError(f"header '{k}' needs a printable ASCII value up to {MAX_HEADER_VALUE} characters")
        out[k] = v
    return out


def define(tenant: str, name: str, spec: dict, previous_sealed: str | None, net: Net) -> dict:
    """Validate a definition and seal it. Returns {sealed, meta, new_secret}. `new_secret` is the signing secret to
    show the admin once (None when an existing one was kept)."""
    if not NAME_RE.match(name):
        raise ConnectorError("connector names are 2-40 characters of a-z, 0-9, _ and -")
    unknown = sorted(set(spec) - {"url", "verbs", "headers", "timeout_s", "enabled", "rotate_secret"})
    if unknown:
        raise ConnectorError("unknown field(s): " + ", ".join(unknown))
    verbs = spec.get("verbs")
    if not isinstance(verbs, list) or not verbs or not all(isinstance(v, str) and v in catalog.CATALOG for v in verbs):
        raise ConnectorError("verbs must be a non-empty list of catalog actions")
    timeout = spec.get("timeout_s", DEFAULT_TIMEOUT_S)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0.5 <= timeout <= MAX_TIMEOUT_S:
        raise ConnectorError(f"timeout_s must be between 0.5 and {MAX_TIMEOUT_S:g}")
    try:
        host = netguard.validate_url(spec.get("url"), net.resolve())     # type: ignore[arg-type]
    except netguard.UnsafeTarget as exc:
        raise ConnectorError(f"url refused: {exc}") from exc
    headers = validate_headers(spec.get("headers"))
    previous = _open(tenant, name, previous_sealed) if previous_sealed else None
    new_secret = None
    if previous and not spec.get("rotate_secret"):
        signing = previous["signing_secret"]
    else:
        signing = new_secret = "vsec_" + secrets.token_urlsafe(32)
    sealed = _seal(tenant, name, {"url": spec["url"], "headers": headers, "signing_secret": signing})
    meta = {"host": host, "verbs": sorted(set(verbs)), "timeout_s": float(timeout),
            "enabled": bool(spec.get("enabled", True)),
            "fingerprint": hashlib.sha256(signing.encode()).hexdigest()[:8]}
    return {"sealed": sealed, "meta": meta, "new_secret": new_secret}


# ------------------------------------------------------------------------------------------------ calling
def signature(secret: str, timestamp: int, body: bytes) -> str:
    mac = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={mac}"


class Router:
    """Chooses a tenant's connector for a verb and calls it. Held by the Execution Gateway."""

    def __init__(self, tenant: str, rows: Callable[[], list[dict]], net: Net | None = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.tenant = tenant
        self._rows = rows
        self._net = net or Net()
        self._clock = clock
        self._fails: dict[str, int] = {}
        self._paused_until: dict[str, float] = {}

    def find(self, verb: str) -> dict | None:
        for row in self._rows():
            meta = row["meta"]
            if meta.get("enabled") and verb in meta.get("verbs", []):
                return row
        return None

    def _result(self, row: dict, status: str, summary: str) -> dict:
        return {"status": status, "adapter": f"webhook:{row['name']}", "result_summary": summary[:300],
                "raw": None, "external": True}

    def send(self, row: dict, *, request_id: str, action: dict, ahash: str, decision_label: str) -> dict:
        name = row["name"]
        if self._clock() < self._paused_until.get(name, 0.0):
            return self._result(row, "failed", f"connector '{name}' is paused after repeated failures; not called")
        try:
            blob = _open(self.tenant, name, row["sealed"])
        except ConnectorError as exc:
            return self._result(row, "failed", str(exc))
        payload = {"type": "veto.action", "request_id": request_id, "tenant": self.tenant, "decision": decision_label,
                   "action_hash": ahash,
                   "action": {k: action[k] for k in ("agent_id", "action", "target", "parameters")},
                   "issued_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        return self._post(row, blob, payload, request_id, ahash)

    def ping(self, row: dict) -> dict:
        blob = _open(self.tenant, row["name"], row["sealed"])
        payload = {"type": "veto.ping", "tenant": self.tenant,
                   "issued_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        return self._post(row, blob, payload, "ping", "")

    def _post(self, row: dict, blob: dict, payload: dict, request_id: str, ahash: str) -> dict:
        name = row["name"]
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ts = int(time.time())
        headers = {**blob["headers"], "Content-Type": "application/json", "User-Agent": "veto-gateway/0.1",
                   "X-VETO-Signature": signature(blob["signing_secret"], ts, body),
                   "X-VETO-Request-Id": request_id, "Idempotency-Key": request_id}
        if ahash:
            headers["X-VETO-Action-Hash"] = ahash
        try:
            status, data = self._net.post(blob["url"], body, headers,
                                          row["meta"].get("timeout_s", DEFAULT_TIMEOUT_S))
        except netguard.UnsafeTarget as exc:
            return self._result(row, "failed", f"connector '{name}' target not allowed: {exc}")
        except netguard.TransportError as exc:
            self._note_failure(name)
            suffix = "; the outcome is unknown, check the other system" if exc.sent else ""
            return self._result(row, "failed", f"connector '{name}' failed: {exc}{suffix}")
        if 200 <= status < 300:
            self._fails.pop(name, None)
            return self._result(row, "executed", _summary(data) or f"connector '{name}' accepted the action "
                                f"(HTTP {status})")
        if status >= 500:
            self._note_failure(name)
        return self._result(row, "failed", f"connector '{name}' returned HTTP {status}")

    def _note_failure(self, name: str) -> None:
        n = self._fails.get(name, 0) + 1
        self._fails[name] = n
        if n >= BREAKER_FAILURES:
            self._paused_until[name] = self._clock() + BREAKER_PAUSE_S
            self._fails[name] = 0


def _summary(data: bytes) -> str | None:
    try:
        obj = json.loads(data)
    except ValueError:
        return None
    s = obj.get("summary") if isinstance(obj, dict) else None
    return "".join(c for c in s if c.isprintable())[:300] if isinstance(s, str) and s else None
