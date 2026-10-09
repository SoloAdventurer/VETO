"""FastAPI app: the Agent Gateway API (docs/action-schema.md) plus the dashboard's read models.

MVP caveats (DECISIONS D-017): no authentication yet. Agent identity, operator channel and approver identity are
taken at face value. The demo endpoints (/v1/demo/*) exist only when VETO_DEMO=1 (default on for the demo build).
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from veto.gateway.scenarios import list_scenarios, run_scenario
from veto.gateway.service import GatewayService, RequestError
from veto.paths import UI_DIR


class _Holder:
    service: GatewayService


def create_app(service: GatewayService | None = None, demo: bool | None = None) -> FastAPI:
    holder = _Holder()
    holder.service = service or GatewayService(db_path=os.environ.get("VETO_DB", ":memory:"))
    demo_enabled = demo if demo is not None else os.environ.get("VETO_DEMO", "1") == "1"
    app = FastAPI(title="VETO Gateway", version="0.1.0",
                  description="Autonomy does not imply authority. Agents propose; VETO decides.")
    app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
                       allow_methods=["*"], allow_headers=["*"])

    def guard(fn):
        try:
            return fn()
        except RequestError as exc:
            raise HTTPException(status_code=exc.status, detail=str(exc)) from exc

    # ---- agent-facing
    @app.post("/v1/observations")
    def post_observation(payload: dict[str, Any], agent_id: str | None = None):
        """Agent-submitted observations can never be trusted (provenance is capped at 'unknown')."""
        return guard(lambda: holder.service.register_observation(payload, agent_id=agent_id, operator_channel=False))

    @app.post("/v1/actions")
    def post_action(payload: dict[str, Any]):
        return guard(lambda: holder.service.propose_action(payload))

    @app.get("/v1/actions/{request_id}")
    def get_action(request_id: str):
        rec = holder.service.audit.latest_for_request(request_id)
        if rec is None:
            raise HTTPException(404, "unknown request")
        return rec

    # ---- operator / approver
    @app.post("/v1/operator/observations")
    def post_operator_observation(payload: dict[str, Any], agent_id: str):
        return guard(lambda: holder.service.register_observation(payload, agent_id=agent_id, operator_channel=True))

    @app.post("/v1/approvals/{request_id}")
    def post_approval(request_id: str, payload: dict[str, Any]):
        return guard(lambda: holder.service.resolve_approval(
            request_id, str(payload.get("approver_id", "")), str(payload.get("outcome", "")),
            str(payload.get("note", ""))))

    @app.post("/v1/containment")
    def post_containment(payload: dict[str, Any]):
        return guard(lambda: holder.service.set_containment(
            bool(payload.get("active")), str(payload.get("by", "operator"))[:64], str(payload.get("reason", ""))))

    # ---- read models
    @app.get("/v1/audit")
    def get_audit(limit: int = 500):
        return holder.service.audit.all()[-limit:]

    @app.get("/v1/audit/verify")
    def get_audit_verify():
        return holder.service.audit.verify()

    @app.get("/v1/requests")
    def get_requests(limit: int = 200):
        return holder.service.requests_view(limit)

    @app.get("/v1/state")
    def get_state():
        return holder.service.state()

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    # ---- demo
    if demo_enabled:
        @app.get("/v1/demo/scenarios")
        def get_scenarios():
            return list_scenarios()

        @app.post("/v1/demo/scenarios/{name}")
        def post_scenario(name: str):
            try:
                return run_scenario(holder.service, name)
            except KeyError as exc:
                raise HTTPException(404, "unknown scenario") from exc

        @app.post("/v1/demo/reset")
        def post_reset():
            holder.service = GatewayService()
            return {"ok": True}

    if UI_DIR.is_dir():
        app.mount("/", StaticFiles(directory=str(UI_DIR), html=True), name="ui")
    return app


app = create_app()
