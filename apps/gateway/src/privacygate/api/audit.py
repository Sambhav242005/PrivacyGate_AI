"""Owner audit events + health/readiness (no secrets, no telemetry)."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request

from privacygate.api.auth import current_wallet
from privacygate.api.devices import _owner_of, _parse_cursor

router = APIRouter()


def _event_resource(event: dict, store: Any) -> str | None:
    """Resolve an event's resource_id: direct field, else policy lookup."""
    if event.get("resource_id"):
        return str(event["resource_id"])
    policy_id = event.get("policy_id")
    if policy_id is not None:
        pol = store.get_policy(policy_id)
        if pol and pol.get("resource_id"):
            return str(pol["resource_id"])
    return None


@router.get("/v1/audit/permission-events")
def permission_events(request: Request, resource_id: str,
                      limit: int = 50, cursor: str | None = None) -> dict:
    if limit > 100 or limit <= 0:
        raise HTTPException(status_code=400, detail={
            "code": "INVALID_INPUT", "message": "limit must be 1..100"})
    start = _parse_cursor(cursor)
    wallet = current_wallet(request)
    _owner_of(request, resource_id, wallet)
    store = request.app.state.policy_store
    rows = [e for e in request.app.state.sync_events
            if _event_resource(e, store) == resource_id]
    page = rows[start:start + limit]
    nxt = str(start + limit) if start + limit < len(rows) else None
    return {"items": page, "next_cursor": nxt}


@router.get("/v1/health")
def health() -> dict:
    return {"status": "ok"}


@router.get("/v1/ready")
def ready(request: Request) -> dict:
    chain = getattr(request.app.state, "chain", None)
    return {"gateway": "ready", "database": "ready", "mqtt": "unknown",
            "chain": "ready" if chain is not None else "not_configured"}
