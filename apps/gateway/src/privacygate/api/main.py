"""FastAPI app wiring (PG-033/034 skeleton). All errors use the API.md
envelope {"error": {"code", "message", "request_id"}}."""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from privacygate.api import audit, auth, devices, insights, policies
from privacygate.chain.client import ChainMismatch, ChainUnavailable, TxNotConfirmed
from privacygate.chain.permissions import AuthzUnavailable, PolicyDenied
from privacygate.chain.sync import DictPolicyStore
from privacygate.services.delivery import DeliveryQueue, KeyNotRegistered

STATUS_FOR: dict[str, int] = {}


def _rid() -> str:
    return uuid.uuid4().hex[:12]


def _err(code: str, message: str, status: int) -> JSONResponse:
    return JSONResponse(status_code=status, content={
        "error": {"code": code, "message": message, "request_id": _rid()}})


def create_app(chain_client: Any = None,
               queue: DeliveryQueue | None = None,
               chain_config: dict | None = None,
               repository: Any = None,
               data_key: bytes | None = None) -> FastAPI:
    app = FastAPI(title="PrivacyGate AI gateway")
    app.state.chain = chain_client
    app.state.queue = queue or DeliveryQueue()
    app.state.chain_config = chain_config or {
        "contract_address": "0x" + "00" * 20, "chain_id": 31337}
    app.state.devices = {}
    app.state.telemetry = []
    app.state.policy_store = DictPolicyStore()
    app.state.sessions = {}
    app.state.sync_events = []
    app.state.repository = repository
    app.state.data_key = data_key

    @app.exception_handler(AuthzUnavailable)
    async def _authz(_: Request, e: AuthzUnavailable) -> JSONResponse:
        return _err("AUTHZ_UNAVAILABLE", str(e) or "chain unavailable", 503)

    @app.exception_handler(ChainUnavailable)
    async def _chain(_: Request, e: ChainUnavailable) -> JSONResponse:
        return _err("AUTHZ_UNAVAILABLE", str(e) or "chain unavailable", 503)

    @app.exception_handler(ChainMismatch)
    async def _mismatch(_: Request, e: ChainMismatch) -> JSONResponse:
        return _err("CHAIN_MISMATCH", str(e), 503)

    @app.exception_handler(PolicyDenied)
    async def _denied(_: Request, e: PolicyDenied) -> JSONResponse:
        status = 410 if getattr(e, "reason", "") == "expired" else 403
        return _err("POLICY_DENIED", str(e), status)

    @app.exception_handler(KeyNotRegistered)
    async def _key(_: Request, e: KeyNotRegistered) -> JSONResponse:
        return _err("KEY_NOT_REGISTERED", str(e), 409)

    @app.exception_handler(TxNotConfirmed)
    async def _tx(_: Request, e: TxNotConfirmed) -> JSONResponse:
        return _err("TX_NOT_CONFIRMED", str(e), 409)

    @app.exception_handler(ValueError)
    async def _value(_: Request, e: ValueError) -> JSONResponse:
        return _err("INVALID_INPUT", str(e), 400)

    @app.exception_handler(KeyError)
    async def _missing(_: Request, e: KeyError) -> JSONResponse:
        return _err("RESOURCE_NOT_FOUND", str(e), 404)

    @app.exception_handler(HTTPException)
    async def _http(_: Request, e: HTTPException) -> JSONResponse:
        detail = e.detail if isinstance(e.detail, dict) else {"message": str(e.detail)}
        code = str(detail.get("code", "INVALID_INPUT"))
        default = {401: "NOT_AUTHENTICATED", 403: "POLICY_DENIED",
                   404: "RESOURCE_NOT_FOUND", 409: "ALREADY_EXISTS"}.get(e.status_code)
        return _err(detail.get("code", default or code),
                    str(detail.get("message", e.detail)), e.status_code)

    app.include_router(auth.router)
    app.include_router(devices.router)
    app.include_router(policies.router)
    app.include_router(insights.router)
    app.include_router(audit.router)
    return app


app = create_app()
