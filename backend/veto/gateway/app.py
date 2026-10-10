"""FastAPI app: the Agent Gateway API (docs/action-schema.md) plus the dashboard's read models.

Authentication (DECISIONS D-021, supersedes D-017): every endpoint except /healthz and /v1/auth/info needs
`Authorization: Bearer veto_...`. Identity always comes from the key, never from the request body:
agents (role `agent`) propose actions and register observations as themselves; humans act as operator, approver,
viewer or admin. The demo endpoints (/v1/demo/*) exist only when VETO_DEMO=1 and still require the operator role.
"""

from __future__ import annotations

import os
import secrets
import sys
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from veto.auth.store import AuthError, Principal, PrincipalStore
from veto.gateway.scenarios import list_scenarios, run_scenario
from veto.gateway.service import GatewayService, RequestError
from veto.paths import UI_DIR

READERS = ("viewer", "operator", "approver", "admin")


class _Holder:
    service: GatewayService


def create_app(service: GatewayService | None = None, demo: bool | None = None,
               store: PrincipalStore | None = None, bootstrap_key: str | None = None) -> FastAPI:
    holder = _Holder()
    holder.service = service or GatewayService(db_path=os.environ.get("VETO_DB", ":memory:"))
    demo_enabled = demo if demo is not None else os.environ.get("VETO_DEMO", "1") == "1"
    principals = store or PrincipalStore(os.environ.get("VETO_AUTH_DB", ":memory:"))
    key = bootstrap_key or os.environ.get("VETO_BOOTSTRAP_KEY")
    if key:
        principals.bootstrap(key)
    elif not principals.has_principals():
        key = "veto_" + secrets.token_urlsafe(24)
        principals.bootstrap(key)
        print(f"VETO: no principals exist. One-time bootstrap admin key (shown once): {key}", file=sys.stderr)

    public = {"/healthz", "/v1/auth/info"}

    def authenticate(request: Request) -> None:
        """Runs before request bodies are parsed, so unauthenticated callers always get 401, never 422."""
        if request.url.path in public:
            return
        header = request.headers.get("authorization", "")
        token = header[7:].strip() if header.lower().startswith("bearer ") else None
        principal = principals.authenticate(token)
        if principal is None:
            raise HTTPException(401, "missing, invalid or revoked API key", headers={"WWW-Authenticate": "Bearer"})
        request.state.principal = principal

    app = FastAPI(title="VETO Gateway", version="0.1.0", dependencies=[Depends(authenticate)],
                  description="Autonomy does not imply authority. Agents propose; VETO decides.")
    app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
                       allow_methods=["*"], allow_headers=["*"])
    app.state.principals = principals

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
        return {"id": p.id, "roles": sorted(p.roles), "demo": demo_enabled}

    # ---- agent-facing (identity = the key)
    @app.post("/v1/observations")
    def post_observation(request: Request, payload: dict[str, Any]):
        """Agent-submitted observations can never be trusted (provenance is capped at 'unknown')."""
        p = who(request, "agent")
        return guard(lambda: holder.service.register_observation(payload, agent_id=p.id, operator_channel=False))

    @app.post("/v1/actions")
    def post_action(request: Request, payload: dict[str, Any]):
        p = who(request, "agent")
        resp = guard(lambda: holder.service.propose_action(payload, authenticated_as=p.id))
        if resp.get("identity_mismatch"):
            return JSONResponse(status_code=403, content=resp)
        return resp

    @app.get("/v1/actions/{request_id}")
    def get_action(request: Request, request_id: str):
        p = who(request, "agent", *READERS)
        rec = holder.service.audit.latest_for_request(request_id)
        if rec is None or (p.has("agent") and rec["agent_id"] != p.id):
            raise HTTPException(404, "unknown request")
        return rec

    # ---- operator / approver
    @app.post("/v1/operator/observations")
    def post_operator_observation(request: Request, payload: dict[str, Any], agent_id: str):
        who(request, "operator")
        return guard(lambda: holder.service.register_observation(payload, agent_id=agent_id, operator_channel=True))

    @app.post("/v1/operator/agents/{agent_id}/context-reset")
    def post_context_reset(request: Request, agent_id: str):
        p = who(request, "operator")
        return guard(lambda: holder.service.reset_agent_context(agent_id, p.id))

    @app.post("/v1/approvals/{request_id}")
    def post_approval(request: Request, request_id: str, payload: dict[str, Any]):
        p = who(request, "approver")
        return guard(lambda: holder.service.resolve_approval(
            request_id, p.id, str(payload.get("outcome", "")), str(payload.get("note", ""))))

    @app.post("/v1/containment")
    def post_containment(request: Request, payload: dict[str, Any]):
        p = who(request, "operator")
        return guard(lambda: holder.service.set_containment(bool(payload.get("active")), p.id,
                                                            str(payload.get("reason", ""))))

    # ---- read models
    @app.get("/v1/audit")
    def get_audit(request: Request, limit: int = 500):
        who(request, *READERS)
        return holder.service.audit.all()[-limit:]

    @app.get("/v1/audit/verify")
    def get_audit_verify(request: Request):
        who(request, *READERS)
        return holder.service.audit.verify()

    @app.get("/v1/requests")
    def get_requests(request: Request, limit: int = 200):
        who(request, *READERS)
        return holder.service.requests_view(limit)

    @app.get("/v1/state")
    def get_state(request: Request):
        who(request, *READERS)
        return {**holder.service.state(), "auth": {"failures": principals.failures}}

    # ---- administration (every change is audited)
    @app.get("/v1/admin/principals")
    def admin_list(request: Request):
        who(request, "admin")
        return principals.list_principals()

    @app.post("/v1/admin/principals")
    def admin_create(request: Request, payload: dict[str, Any]):
        p = who(request, "admin")
        pid, roles = str(payload.get("id", "")), payload.get("roles") or []
        if not isinstance(roles, list):
            raise HTTPException(422, "roles must be a list")
        guard(lambda: principals.create_principal(pid, [str(r) for r in roles]))
        holder.service.record_system_event(p.id, "CREATE_PRINCIPAL", {"id": pid, "roles": sorted(map(str, roles))},
                                           f"Principal {pid} created by {p.id}")
        return {"id": pid, "roles": sorted(map(str, roles))}

    @app.post("/v1/admin/principals/{pid}/keys")
    def admin_issue_key(request: Request, pid: str):
        p = who(request, "admin")
        key_id, plaintext = guard(lambda: principals.issue_key(pid))
        holder.service.record_system_event(p.id, "ISSUE_KEY", {"principal": pid, "key_id": key_id},
                                           f"Key {key_id} issued for {pid} by {p.id}")
        return {"principal": pid, "key_id": key_id, "key": plaintext, "note": "shown once; store it now"}

    @app.delete("/v1/admin/keys/{key_id}")
    def admin_revoke_key(request: Request, key_id: str):
        p = who(request, "admin")
        guard(lambda: principals.revoke_key(key_id))
        holder.service.record_system_event(p.id, "REVOKE_KEY", {"key_id": key_id}, f"Key {key_id} revoked by {p.id}")
        return {"revoked": key_id}

    @app.post("/v1/admin/principals/{pid}/disable")
    def admin_disable(request: Request, pid: str):
        p = who(request, "admin")
        guard(lambda: principals.disable_principal(pid))
        holder.service.record_system_event(p.id, "DISABLE_PRINCIPAL", {"id": pid},
                                           f"Principal {pid} disabled by {p.id}; keys revoked")
        return {"disabled": pid}

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
                return run_scenario(holder.service, name)
            except KeyError as exc:
                raise HTTPException(404, "unknown scenario") from exc

        @app.post("/v1/demo/reset")
        def post_reset(request: Request):
            who(request, "operator")
            holder.service = GatewayService()
            return {"ok": True}

    if UI_DIR.is_dir():
        app.mount("/", StaticFiles(directory=str(UI_DIR), html=True), name="ui")
    return app


app = create_app()
