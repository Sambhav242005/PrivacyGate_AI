"""Subscriber encrypted-insight retrieval. Fresh chain check on EVERY
read; envelopes only, never plaintext. Chain outage -> 503 fail-closed."""
from __future__ import annotations

import time

from fastapi import APIRouter, HTTPException, Request

from privacygate.api.auth import current_wallet
from privacygate.api.devices import _parse_cursor
from privacygate.chain.client import ChainUnavailable
from privacygate.chain.permissions import AuthzUnavailable, PolicyDenied
from privacygate.chain.sync import DictPolicyStore
from privacygate.services.delivery import KeyNotRegistered

router = APIRouter()


@router.get("/v1/insights")
def get_insights(request: Request, resource_id: str,
                 limit: int = 50, cursor: str | None = None) -> dict:
    if limit > 100 or limit <= 0:
        raise HTTPException(status_code=400, detail={
            "code": "INVALID_INPUT", "message": "limit must be 1..100"})
    _parse_cursor(cursor)
    wallet = current_wallet(request)
    chain = request.app.state.chain
    if chain is None:
        raise AuthzUnavailable("chain not configured")
    store: DictPolicyStore = request.app.state.policy_store
    pol = next((p for p in store.policies.values()
                if p["resource_id"] == resource_id
                and p["recipient_wallet"] == wallet
                and p["status"] == "ACTIVE"), None)
    if pol is None:
        raise HTTPException(status_code=404, detail={
            "code": "RESOURCE_NOT_FOUND",
            "message": "no active grant for this resource"})
    try:
        return request.app.state.queue.for_recipient(
            wallet, resource_id, chain, pol["policy_digest"],
            now_unix=int(time.time()), limit=limit, cursor=cursor)
    except ChainUnavailable as e:
        raise AuthzUnavailable(str(e)) from None
    except PolicyDenied as e:
        status = 410 if e.reason == "expired" else 403
        raise HTTPException(status_code=status, detail={
            "code": "POLICY_DENIED", "message": str(e)}) from None
    except KeyNotRegistered as e:
        raise HTTPException(status_code=409, detail={
            "code": "KEY_NOT_REGISTERED", "message": str(e)}) from None
    except ValueError as e:
        raise HTTPException(status_code=400, detail={
            "code": "INVALID_INPUT", "message": str(e)}) from None
