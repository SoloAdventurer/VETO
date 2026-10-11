"""FastAPI app: the Agent Gateway API (docs/action-schema.md) plus the dashboard's read models.

Authentication (DECISIONS D-021, supersedes D-017): every endpoint except /healthz and /v1/auth/info needs
`Authorization: Bearer veto_...`. Identity always comes from the key, never from the request body:
agents (role `agent`) propose actions and register observations as themselves; humans act as operator, approver,
viewer or admin. The demo endpoints (/v1/demo/*) exist only when VETO_DEMO=1 and still require the operator role.
"""

from __future__ import annotations

import json
import math
import os
import secrets
import sys
import time
from collections.abc import Callable
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from veto.auth.store import HUMAN_ROLES, AuthError, Principal, PrincipalStore
from veto.canonical import sha256_hex
from veto.gateway.platform import PlatformLog, Runtimes
from veto.gateway.ratelimit import FailureLockout, TokenBucketLimiter
from veto.gateway.scenarios import list_scenarios, run_scenario
from veto.gateway.service import GatewayService, RequestError
from veto.paths import UI_DIR
from veto.policy.lint import diff_policies
from veto.policy.loader import load_policy_text

READERS = ("viewer", "operator", "approver", "admin")


def _env_rate(name: str, default: tuple[float, int]) -> tuple[float, int]:
    """VETO_<NAME>=<requests per minute>[,<burst>]"""
    raw = os.environ.get(name)
    if not raw:
        return default
    parts = raw.split(",")
    return float(parts[0]), int(parts[1]) if len(parts) > 1 else default[1]


def create_app(service: GatewayService | None = None, demo: bool | None = None,
               store: PrincipalStore | None = None, bootstrap_key: str | None = None,
               clock: Callable[[], float] = time.time, agent_rate: tuple[float, int] | None = None,
               human_rate: tuple[float, int] | None = None, auth_max_failures: int | None = None,
               auth_lockout_s: float | None = None, platform_key: str | None = None) -> FastAPI:
    demo_enabled = demo if demo is not None else os.environ.get("VETO_DEMO", "1") == "1"
    _db = os.environ.get("VETO_DB", ":memory:")
    # With the audit log on PostgreSQL the keys default to the same database, so every gateway process shares them.
    _auth_default = _db if _db.startswith(("postgresql://", "postgres://")) else ":memory:"
    principals = store or PrincipalStore(os.environ.get("VETO_AUTH_DB", _auth_default))
    runtimes = Runtimes(principals, _db, os.environ.get("VETO_MODE", "enforce"), clock)
    if service is not None:
        runtimes.preload("default", service)
    else:
        runtimes.get("default")             # start the default tenant now: a bad VETO_MODE or policy fails at startup
    platform_log = PlatformLog(_db)
    pkey = platform_key or os.environ.get("VETO_PLATFORM_KEY")
    if pkey:
        principals.bootstrap_platform(pkey)
    key = bootstrap_key or os.environ.get("VETO_BOOTSTRAP_KEY")
    if key:
        principals.bootstrap(key)
    elif not principals.has_principals():
        key = "veto_" + secrets.token_urlsafe(24)
        principals.bootstrap(key)
        print(f"VETO: no principals exist. One-time bootstrap admin key (shown once): {key}", file=sys.stderr)

    public = {"/healthz", "/v1/auth/info"}
    # Agents get a tighter default than people (a dashboard polls about twice a second).
    arate = agent_rate or _env_rate("VETO_AGENT_RATE", (300.0, 60))
    hrate = human_rate or _env_rate("VETO_HUMAN_RATE", (1200.0, 240))
    agent_limiter = TokenBucketLimiter(arate[0], arate[1], clock)
    human_limiter = TokenBucketLimiter(hrate[0], hrate[1], clock)
    lockout = FailureLockout(
        max_failures=(auth_max_failures if auth_max_failures is not None
                      else int(os.environ.get("VETO_AUTH_MAX_FAILURES", "10"))),
        lockout_s=(auth_lockout_s if auth_lockout_s is not None
                   else float(os.environ.get("VETO_AUTH_LOCKOUT_S", "300"))),
        clock=clock)
    throttle: dict[str, int] = {}                  # rate-limited requests, counted per tenant

    def authenticate(request: Request) -> None:
        """Runs before request bodies are parsed, so unauthenticated callers always get 401, never 422."""
        if request.url.path in public:
            return
        client = request.client.host if request.client else "unknown"
        wait = lockout.blocked(client)
        if wait:
            raise HTTPException(429, "too many failed sign-ins; try again later", headers={"Retry-After": str(wait)})
        header = request.headers.get("authorization", "")
        token = header[7:].strip() if header.lower().startswith("bearer ") else None
        principal = principals.authenticate(token)
        if principal is None:
            lockout.record_failure(client)
            raise HTTPException(401, "missing, invalid or revoked API key", headers={"WWW-Authenticate": "Bearer"})
        if principal.suspended:
            raise HTTPException(403, "this tenant is suspended")
        allowed, retry = (agent_limiter if principal.has("agent") else human_limiter).allow(principal.rate_key)
        if not allowed:
            throttle[principal.tenant] = throttle.get(principal.tenant, 0) + 1
            raise HTTPException(429, "rate limit exceeded", headers={"Retry-After": str(max(1, math.ceil(retry)))})
        request.state.principal = principal

    app = FastAPI(title="VETO Gateway", version="0.1.0", dependencies=[Depends(authenticate)],
                  description="Autonomy does not imply authority. Agents propose; VETO decides.")
    app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
                       allow_methods=["*"], allow_headers=["*"])
    app.state.principals = principals
    app.state.runtimes = runtimes
    app.state.db_target = _db

    def guard(fn):
        try:
            return fn()
        except (RequestError, AuthError) as exc:
            raise HTTPException(status_code=exc.status, detail=str(exc)) from exc

    def who(request: Request, *roles: str) -> Principal:
        principal: Principal = request.state.principal
        if roles and not principal.has(*roles):
            raise HTTPException(403, "requires role: " + " or ".join(roles))
        return principal

    def svc(request: Request) -> GatewayService:
        """The calling tenant's gateway. The tenant comes from the API key and from nowhere else."""
        principal: Principal = request.state.principal
        if not principal.tenant:
            raise HTTPException(403, "platform administrators cannot act inside a tenant")
        try:
            return runtimes.get(principal.tenant)
        except KeyError as exc:
            raise HTTPException(404, "unknown tenant") from exc

    # ---- unauthenticated
    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.get("/v1/auth/info")
    def auth_info():
        return {"auth": "bearer", "demo": demo_enabled}

    @app.get("/v1/auth/me")
    def auth_me(request: Request):
        p = who(request)
        return {"id": p.id, "roles": sorted(p.roles), "tenant": p.tenant or None, "demo": demo_enabled}

    # ---- agent-facing (identity = the key)
    @app.post("/v1/observations")
    def post_observation(request: Request, payload: dict[str, Any]):
        """Agent-submitted observations can never be trusted (provenance is capped at 'unknown')."""
        p = who(request, "agent")
        return guard(lambda: svc(request).register_observation(payload, agent_id=p.id, operator_channel=False))

    @app.post("/v1/actions")
    def post_action(request: Request, payload: dict[str, Any]):
        p = who(request, "agent")
        resp = guard(lambda: svc(request).propose_action(payload, authenticated_as=p.id))
        if resp.get("identity_mismatch"):
            return JSONResponse(status_code=403, content=resp)
        return resp

    @app.get("/v1/actions/{request_id}")
    def get_action(request: Request, request_id: str):
        p = who(request, "agent", *READERS)
        rec = svc(request).audit.latest_for_request(request_id)
        if rec is None or (p.has("agent") and rec["agent_id"] != p.id):
            raise HTTPException(404, "unknown request")
        return rec

    # ---- operator / approver
    @app.post("/v1/operator/observations")
    def post_operator_observation(request: Request, payload: dict[str, Any], agent_id: str):
        who(request, "operator")
        return guard(lambda: svc(request).register_observation(payload, agent_id=agent_id, operator_channel=True))

    @app.post("/v1/operator/agents/{agent_id}/context-reset")
    def post_context_reset(request: Request, agent_id: str):
        p = who(request, "operator")
        return guard(lambda: svc(request).reset_agent_context(agent_id, p.id))

    @app.post("/v1/approvals/{request_id}")
    def post_approval(request: Request, request_id: str, payload: dict[str, Any]):
        p = who(request, "approver")
        return guard(lambda: svc(request).resolve_approval(
            request_id, p.id, str(payload.get("outcome", "")), str(payload.get("note", ""))))

    @app.post("/v1/containment")
    def post_containment(request: Request, payload: dict[str, Any]):
        p = who(request, "operator")
        return guard(lambda: svc(request).set_containment(bool(payload.get("active")), p.id,
                                                            str(payload.get("reason", ""))))

    # ---- read models
    @app.get("/v1/audit")
    def get_audit(request: Request, limit: int = 500):
        who(request, *READERS)
        return svc(request).audit.all()[-limit:]

    @app.get("/v1/audit/verify")
    def get_audit_verify(request: Request):
        who(request, *READERS)
        return svc(request).audit.verify()

    @app.get("/v1/requests")
    def get_requests(request: Request, limit: int = 200):
        who(request, *READERS)
        return svc(request).requests_view(limit)

    @app.get("/v1/state")
    def get_state(request: Request):
        p = who(request, *READERS)
        return {**svc(request).state(),
                "auth": {"rate_limited": throttle.get(p.tenant, 0)}}

    # ---- administration (every change is audited)
    @app.get("/v1/admin/principals")
    def admin_list(request: Request):
        p = who(request, "admin")
        return principals.list_principals(tenant=p.tenant)

    @app.post("/v1/admin/principals")
    def admin_create(request: Request, payload: dict[str, Any]):
        p = who(request, "admin")
        pid, roles = str(payload.get("id", "")), payload.get("roles") or []
        if not isinstance(roles, list):
            raise HTTPException(422, "roles must be a list")
        guard(lambda: principals.create_principal(pid, [str(r) for r in roles], tenant=p.tenant))
        svc(request).record_system_event(p.id, "CREATE_PRINCIPAL", {"id": pid, "roles": sorted(map(str, roles))},
                                           f"Principal {pid} created by {p.id}")
        return {"id": pid, "roles": sorted(map(str, roles))}

    @app.post("/v1/admin/principals/{pid}/keys")
    def admin_issue_key(request: Request, pid: str):
        p = who(request, "admin")
        key_id, plaintext = guard(lambda: principals.issue_key(pid, tenant=p.tenant))
        svc(request).record_system_event(p.id, "ISSUE_KEY", {"principal": pid, "key_id": key_id},
                                           f"Key {key_id} issued for {pid} by {p.id}")
        return {"principal": pid, "key_id": key_id, "key": plaintext, "note": "shown once; store it now"}

    @app.delete("/v1/admin/keys/{key_id}")
    def admin_revoke_key(request: Request, key_id: str):
        p = who(request, "admin")
        guard(lambda: principals.revoke_key(key_id, tenant=p.tenant))
        svc(request).record_system_event(p.id, "REVOKE_KEY", {"key_id": key_id}, f"Key {key_id} revoked by {p.id}")
        return {"revoked": key_id}

    @app.post("/v1/admin/principals/{pid}/disable")
    def admin_disable(request: Request, pid: str):
        p = who(request, "admin")
        guard(lambda: principals.disable_principal(pid, tenant=p.tenant))
        svc(request).record_system_event(p.id, "DISABLE_PRINCIPAL", {"id": pid},
                                           f"Principal {pid} disabled by {p.id}; keys revoked")
        return {"disabled": pid}

    # ---- policy editing (D-028): propose -> a different admin activates; every step is audited
    def _version_or_404(tenant: str, version: int) -> dict:
        row = principals.get_policy_version(tenant, version, with_text=True)
        if row is None:
            raise HTTPException(404, "unknown policy version")
        return row

    @app.get("/v1/policy")
    def get_policy(request: Request):
        who(request, *READERS)
        s = svc(request)
        t = request.state.principal.tenant
        text = principals.active_policy_text(t)
        return {"policy_id": s.policy.policy_id, "version": s.policy.version, "fault": s._policy_fault,
                "text": text, "history": principals.list_policy_versions(t)}

    @app.post("/v1/policy/proposals")
    def policy_propose(request: Request, payload: dict[str, Any]):
        p = who(request, "admin")
        text = payload.get("policy")
        if not isinstance(text, str) or not text.strip():
            raise HTTPException(422, "policy (YAML text) is required")
        s = svc(request)
        try:
            new = load_policy_text(text)                       # size, lint, grammar: a bad policy is never stored
        except Exception as exc:
            raise HTTPException(422, f"invalid policy: {exc}") from exc
        diff = diff_policies(s.policy.raw, new.raw)
        version = principals.add_policy_proposal(p.tenant, text, sha256_hex(text), p.id, json.dumps(diff))
        s.record_system_event(p.id, "POLICY_PROPOSED", {"version": version, "policy_sha256": sha256_hex(text),
                                                        "loosens": diff["loosens"]},
                              f"Policy v{version} proposed by {p.id}" + (" (loosens)" if diff["loosens"] else ""))
        return {"version": version, "status": "proposed", "diff": diff}

    @app.get("/v1/policy/proposals")
    def policy_list(request: Request):
        who(request, *READERS)
        return principals.list_policy_versions(request.state.principal.tenant)

    @app.get("/v1/policy/proposals/{version}")
    def policy_get(request: Request, version: int):
        who(request, *READERS)
        return _version_or_404(request.state.principal.tenant, version)

    @app.post("/v1/policy/proposals/{version}/activate")
    def policy_activate(request: Request, version: int):
        p = who(request, "admin")
        row = _version_or_404(p.tenant, version)
        if row["status"] != "proposed":
            raise HTTPException(409, f"version is {row['status']}, only a proposed version can be activated")
        if row["created_by"] == p.id:
            raise HTTPException(403, "a policy cannot be activated by the person who proposed it")
        result = guard(lambda: svc(request).activate_policy(
            row["policy"], version=version, by=p.id, proposed_by=row["created_by"]))
        principals.decide_policy_version(p.tenant, version, "active", p.id)
        return {"version": version, "status": "active", **result}

    @app.post("/v1/policy/proposals/{version}/reject")
    def policy_reject(request: Request, version: int, payload: dict[str, Any] | None = None):
        p = who(request, "admin")
        row = _version_or_404(p.tenant, version)
        if not principals.decide_policy_version(p.tenant, version, "rejected", p.id):
            raise HTTPException(409, f"version is {row['status']}, only a proposed version can be rejected")
        note = str((payload or {}).get("note", ""))[:300]
        svc(request).record_system_event(p.id, "POLICY_REJECTED", {"version": version, "note": note},
                                         f"Policy v{version} rejected by {p.id}")
        return {"version": version, "status": "rejected"}

    # ---- platform administration (tenants and the global kill switch; never any decision content)
    @app.post("/v1/platform/tenants")
    def platform_create_tenant(request: Request, payload: dict[str, Any]):
        p = who(request, "platform_admin")
        tid, name = str(payload.get("id", "")), str(payload.get("name", "")) or str(payload.get("id", ""))
        policy = payload.get("policy")
        if policy is not None:
            try:
                load_policy_text(str(policy))
            except Exception as exc:                                  # invalid policy: refuse, store nothing
                raise HTTPException(422, f"invalid policy: {exc}") from exc
        admin_id = str(payload.get("admin_id", "tenant-admin"))
        guard(lambda: principals.create_tenant(tid, name, str(policy) if policy is not None else None))
        guard(lambda: principals.create_principal(admin_id, sorted(HUMAN_ROLES), tenant=tid))
        key_id, plaintext = guard(lambda: principals.issue_key(admin_id, tenant=tid))
        platform_log.event(p.id, "CREATE_TENANT", {"tenant": tid, "admin": admin_id, "key_id": key_id,
                                                   "custom_policy": policy is not None}, f"Tenant {tid} created")
        return {"tenant": tid, "admin_id": admin_id, "key_id": key_id, "key": plaintext,
                "note": "shown once; store it now"}

    @app.get("/v1/platform/tenants")
    def platform_list_tenants(request: Request):
        who(request, "platform_admin")
        out = []
        for t in principals.list_tenants():
            live = runtimes.peek(t["id"])
            out.append({**t, "records": runtimes.record_count(t["id"]), "loaded": live is not None,
                        "containment": live.containment if live else None})
        return out

    @app.post("/v1/platform/tenants/{tenant_id}/{action}")
    def platform_tenant_status(request: Request, tenant_id: str, action: str):
        p = who(request, "platform_admin")
        if action not in ("suspend", "resume"):
            raise HTTPException(404, "unknown action")
        guard(lambda: principals.set_tenant_status(tenant_id, "suspended" if action == "suspend" else "active"))
        platform_log.event(p.id, action.upper() + "_TENANT", {"tenant": tenant_id}, f"Tenant {tenant_id} {action}ed")
        return {"tenant": tenant_id, "status": "suspended" if action == "suspend" else "active"}

    @app.post("/v1/platform/containment")
    def platform_containment(request: Request, payload: dict[str, Any]):
        p = who(request, "platform_admin")
        active = bool(payload.get("active"))
        reason = str(payload.get("reason", ""))[:200]
        platform_log.event(p.id, "PLATFORM_CONTAINMENT", {"active": active, "reason": reason},
                           "Platform-wide containment " + ("ENGAGED" if active else "released"))
        principals.set_platform_contained(active)             # audited first, then effective on every tenant
        return {"containment": active}

    @app.get("/v1/platform/state")
    def platform_state(request: Request):
        who(request, "platform_admin")
        return {"containment": principals.platform_contained(), "tenants": len(principals.list_tenants()),
                "auth": {"failures": principals.failures, "lockouts": lockout.lockouts,
                         "rate_limited": sum(throttle.values())},
                "chain": platform_log.audit.verify()}

    # ---- demo
    if demo_enabled:
        @app.get("/v1/demo/scenarios")
        def get_scenarios(request: Request):
            who(request, "operator")
            return list_scenarios()

        @app.post("/v1/demo/scenarios/{name}")
        def post_scenario(request: Request, name: str):
            who(request, "operator")
            try:
                return run_scenario(svc(request), name)
            except KeyError as exc:
                raise HTTPException(404, "unknown scenario") from exc

        @app.post("/v1/demo/reset")
        def post_reset(request: Request):
            principal = who(request, "operator")
            runtimes.reset(principal.tenant)
            return {"ok": True}

    if UI_DIR.is_dir():
        app.mount("/", StaticFiles(directory=str(UI_DIR), html=True), name="ui")
    return app


app = create_app()
