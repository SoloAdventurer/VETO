"""Platform layer above tenants (DECISIONS D-027): the tenant registry of running gateways and the platform's own
audit chain.

The platform can create, suspend and resume tenants, issue a tenant's first admin key and engage a global kill
switch. It cannot act inside a tenant, and the only per-tenant facts it can see are counts and health (never decision
content). Its own actions are written to a hash-chained log of their own (tenant id `_platform`).
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable

from veto.audit import open_audit
from veto.audit.chain import PLATFORM_TENANT
from veto.auth.store import PrincipalStore
from veto.canonical import action_hash
from veto.gateway.service import GatewayService


class PlatformLog:
    def __init__(self, target: str) -> None:
        self.audit = open_audit(target, PLATFORM_TENANT)

    def event(self, actor: str, action: str, params: dict, reason: str) -> dict:
        return self.audit.append({
            "schema_version": "0.1", "request_id": f"sys-{uuid.uuid4().hex[:12]}", "agent_id": actor[:64],
            "requested_action": {"action": action, "parameters": params},
            "action_hash": action_hash({"agent_id": actor, "action": action,
                                        "target": {"resource": "platform", "id": "tenants"}, "parameters": params}),
            "policies_evaluated": [{"rule_id": "builtin:platform-admin", "result": "matched", "effect": "allow"}],
            "decision": "allow", "decision_reason": reason[:300], "policy_version": "platform",
            "containment_active": False})


class Runtimes:
    """One GatewayService per tenant, created on first use from the tenant's stored policy."""

    def __init__(self, store: PrincipalStore, db_target: str, mode: str, clock: Callable[[], float]) -> None:
        self._store, self._db, self._mode, self._clock = store, db_target, mode, clock
        self._by_tenant: dict[str, GatewayService] = {}
        self._lock = threading.Lock()

    def preload(self, tenant: str, svc: GatewayService) -> None:
        svc._platform_check = self._store.platform_contained
        self._by_tenant[tenant] = svc

    def _build(self, tenant: str) -> GatewayService:
        row = self._store.get_tenant(tenant)
        if row is None:
            raise KeyError(tenant)
        text = self._store.active_policy_text(tenant) or row["policy"]
        return GatewayService(db_path=self._db, mode=self._mode, tenant=tenant, policy_text=text,
                              platform_check=self._store.platform_contained)

    def get(self, tenant: str) -> GatewayService:
        with self._lock:
            if tenant not in self._by_tenant:
                self._by_tenant[tenant] = self._build(tenant)
            return self._by_tenant[tenant]

    def reset(self, tenant: str) -> GatewayService:
        """Demo only: a fresh in-memory gateway for this tenant."""
        with self._lock:
            old = self._by_tenant.get(tenant)
            svc = GatewayService(mode=old.mode if old else self._mode, tenant=tenant,
                                 policy_text=(self._store.get_tenant(tenant) or {}).get("policy"),
                                 platform_check=self._store.platform_contained)
            self._by_tenant[tenant] = svc
            return svc

    def peek(self, tenant: str) -> GatewayService | None:
        return self._by_tenant.get(tenant)

    def record_count(self, tenant: str) -> int:
        svc = self.peek(tenant)
        return svc.audit.count() if svc else open_audit(self._db, tenant).count()
