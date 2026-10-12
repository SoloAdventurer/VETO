"""External timestamping of each tenant's audit chain (DECISIONS D-031).

The hash chain proves the log was not edited *unless the editor can recompute every later hash*. Someone with write
access to the database can do exactly that. So the current head of each chain is periodically sent to an independent
RFC 3161 time-stamp authority. The signed receipt proves the chain had this exact head at that time; a chain rewritten
afterwards cannot reproduce the anchored hash. Receipts are stored apart from the chain and are not themselves
audited (that would move the head and anchor forever).
"""

from __future__ import annotations

import base64
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from veto.audit import open_audit
from veto.audit.chain import PLATFORM_TENANT, verify_chain
from veto.audit.rfc3161 import (
    TimestampError,
    anchor_digest,
    build_request,
    check_reply,
    openssl_verify,
    parse_response,
)
from veto.execution import netguard


@dataclass
class AnchorConfig:
    tsa_url: str
    ca_file: str | None = None          # PEM file of the authority's certificate chain: verify signatures when set
    interval_s: float = 3600.0
    timeout_s: float = 10.0
    poster: Callable[[str, bytes, dict, float], tuple[int, bytes]] | None = None   # tests only


class Anchorer:
    def __init__(self, store, db_target: str, config: AnchorConfig) -> None:
        self._store, self._db, self.config = store, db_target, config
        self._logs: dict = {}
        self.last_error: dict[str, str] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self.tsa_host = urlsplit(config.tsa_url).hostname or "?"

    def _audit(self, tenant: str):
        with self._lock:
            if tenant not in self._logs:
                self._logs[tenant] = open_audit(self._db, tenant)
            return self._logs[tenant]

    def _post(self, body: bytes) -> tuple[int, bytes]:
        headers = {"Content-Type": "application/timestamp-query", "Accept": "application/timestamp-reply"}
        if self.config.poster:
            return self.config.poster(self.config.tsa_url, body, headers, self.config.timeout_s)
        try:
            return netguard.post(self.config.tsa_url, body, headers, self.config.timeout_s, allow_http=True)
        except (netguard.UnsafeTarget, netguard.TransportError) as exc:
            raise TimestampError(f"could not reach the timestamp authority: {exc}") from exc

    def anchor(self, tenant: str) -> dict | None:
        """Timestamp this tenant's current chain head. None if there is nothing new to anchor."""
        log = self._audit(tenant)
        head = log.head()
        if head is None:
            return None
        seq, head_hash = head
        last = self._store.last_anchor(tenant)
        if last and last["seq"] >= seq:
            return None
        # Never cement a broken chain: check only what was added since the last anchor (whose head the authority has
        # already vouched for), or the whole log the first time.
        if last:
            check = verify_chain(log.since(last["seq"]), tenant, prev=last["head_hash"])
        else:
            check = verify_chain(log.all(), tenant)
        if not check["ok"]:
            self.last_error[tenant] = f"chain is broken at {check['broken_at']} ({check['detail']}); not anchoring"
            raise TimestampError(self.last_error[tenant])
        digest = anchor_digest(tenant, seq, head_hash)
        request, nonce = build_request(digest)
        try:
            status, data = self._post(request)
            if status != 200:
                raise TimestampError(f"timestamp authority answered HTTP {status}")
            parsed = parse_response(data)
            check_reply(parsed, digest, nonce)
            if self.config.ca_file:
                openssl_verify(data, digest, self.config.ca_file)
        except TimestampError as exc:
            self.last_error[tenant] = str(exc)
            raise
        self._store.add_anchor(tenant, seq, head_hash, digest.hex(), base64.b64encode(data).decode(),
                               parsed.gen_time or "", self.tsa_host, bool(self.config.ca_file))
        self.last_error.pop(tenant, None)
        return self._store.get_anchor(tenant, seq)

    def tenants(self) -> list[str]:
        return [t["id"] for t in self._store.list_tenants()] + [PLATFORM_TENANT]

    def run_once(self) -> dict[str, str]:
        out = {}
        for tenant in self.tenants():
            try:
                got = self.anchor(tenant)
                out[tenant] = f"anchored {got['seq']}" if got else "nothing new"
            except Exception as exc:               # one tenant's failure must not stop the others
                out[tenant] = f"failed: {exc}"
                self.last_error.setdefault(tenant, str(exc))
        return out

    def verify(self, tenant: str) -> dict:
        """Does the log still agree with everything the authority has signed?"""
        log = self._audit(tenant)
        records = log.all()
        chain = verify_chain(records, tenant)
        by_seq = {r["seq"]: r for r in records}
        anchors = []
        for a in self._store.list_anchors(tenant):
            rec = by_seq.get(a["seq"])
            if rec is None:
                ok, detail = False, "the log is shorter than this anchor: records were removed"
            elif rec["record_hash"] != a["head_hash"]:
                ok, detail = False, "the record at this position differs from what was timestamped: log was rewritten"
            else:
                ok, detail = True, "matches the timestamped head"
            anchors.append({"seq": a["seq"], "gen_time": a["gen_time"], "ok": ok, "detail": detail,
                            "signature_checked": a["signature_checked"]})
        return {"ok": chain["ok"] and all(x["ok"] for x in anchors), "chain": chain, "anchors": anchors}

    def start(self) -> None:
        def loop() -> None:
            while not self._stop.wait(self.config.interval_s):
                self.run_once()
        self._thread = threading.Thread(target=loop, name="veto-anchor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()


def from_env(env: dict[str, str]) -> AnchorConfig | None:
    url = env.get("VETO_TSA_URL")
    if not url:
        return None
    return AnchorConfig(tsa_url=url, ca_file=env.get("VETO_TSA_CA") or None,
                        interval_s=float(env.get("VETO_ANCHOR_INTERVAL_S", "3600")))


def receipt(tenant: str, anchor: dict) -> dict:
    """Everything an auditor needs, with the command to check it on their own machine."""
    return {"tenant": tenant, "seq": anchor["seq"], "head_hash": anchor["head_hash"], "digest_sha256": anchor["digest"],
            "gen_time": anchor["gen_time"], "tsa": anchor["tsa"], "tsr_base64": anchor["tsr_base64"],
            "how_to_verify": ("1) save tsr_base64 decoded as receipt.tsr; 2) openssl ts -verify -in receipt.tsr "
                              f"-digest {anchor['digest']} -CAfile <authority certificate chain.pem>; 3) the digest is "
                              f"SHA-256 of \"veto-anchor-v1|{tenant}|{anchor['seq']}|{anchor['head_hash']}\"; "
                              "4) record number seq of your exported audit log must have that record_hash "
                              "(scripts/verify_receipt.py does steps 2-4)."),
            "created_by_clock": time.time()}
