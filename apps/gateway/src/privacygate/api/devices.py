"""Owner device + telemetry routes. Raw readings decrypt ONLY here,
only for the confirmed on-chain resource owner. No public telemetry route."""
from __future__ import annotations

import time

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict

from privacygate.api.auth import current_wallet
from privacygate.chain.client import ChainUnavailable
from privacygate.chain.permissions import AuthzUnavailable, PolicyDenied
from privacygate.domain.schemas import DeviceEnrollRequest

router = APIRouter()


class KeyEnrollReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    x25519_public_key_b64: str
    wallet_address: str | None = None


def _parse_cursor(cursor: str | None) -> int:
    """Parse pagination cursor; 400 (never 500) on bad input."""
    if cursor is None or cursor == "":
        return 0
    try:
        start = int(cursor)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail={
            "code": "INVALID_INPUT",
            "message": "cursor must be a non-negative integer"}) from None
    if start < 0:
        raise HTTPException(status_code=400, detail={
            "code": "INVALID_INPUT",
            "message": "cursor must be a non-negative integer"})
    return start


def _owner_of(request: Request, resource_id: str, wallet: str) -> None:
    chain = request.app.state.chain
    if chain is None:
        raise AuthzUnavailable("chain not configured")
    try:
        owner = chain.get_owner(resource_id)
    except ChainUnavailable as e:
        raise AuthzUnavailable(str(e)) from e
    if owner.lower() != wallet:
        raise PolicyDenied("not resource owner")


@router.post("/v1/devices", status_code=201)
def enroll_device(body: DeviceEnrollRequest, request: Request) -> dict:
    wallet = current_wallet(request)
    _owner_of(request, body.resource_id, wallet)
    devs = request.app.state.devices
    if str(body.device_id) in devs:
        raise HTTPException(status_code=409, detail={
            "code": "ALREADY_EXISTS", "message": "device exists"})
    now = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    devs[str(body.device_id)] = {"resource_id": body.resource_id,
                                 "device_id": str(body.device_id),
                                 "name": body.name, "owner_wallet": wallet,
                                 "registered_at": now, "status": "ACTIVE"}
    d = devs[str(body.device_id)]
    return {"resource_id": d["resource_id"], "device_id": d["device_id"],
            "name": d["name"], "registered_at": d["registered_at"],
            "status": d["status"]}


@router.get("/v1/devices")
def list_devices(request: Request) -> dict:
    wallet = current_wallet(request)
    return {"items": [d for d in request.app.state.devices.values()
                      if d["owner_wallet"] == wallet]}


@router.get("/v1/resources/{resource_id}/telemetry")
def owner_telemetry(resource_id: str, request: Request,
                    limit: int = 100, cursor: str | None = None) -> dict:
    """Owner-only decrypt-on-read over Repository ciphertext rows."""
    import json

    from privacygate.security.crypto_store import build_aad, decrypt, load_data_key
    from privacygate.storage.repository import Repository

    if limit > 100 or limit <= 0:
        raise HTTPException(status_code=400, detail={
            "code": "INVALID_INPUT", "message": "limit must be 1..100"})
    start = _parse_cursor(cursor)
    wallet = current_wallet(request)
    _owner_of(request, resource_id, wallet)
    repo = getattr(request.app.state, "repository", None)
    if repo is None:
        repo = Repository()
        request.app.state.repository = repo
    key = getattr(request.app.state, "data_key", None)
    if key is None:
        try:
            key = load_data_key()
        except ValueError as e:
            raise AuthzUnavailable(f"data key not configured: {e}") from e
        request.app.state.data_key = key
    rows = repo.list_readings(resource_id)
    page = rows[start:start + limit]
    items = []
    for r in page:
        aad = build_aad(device_id=r["device_id"], sequence=r["sequence"],
                        resource_id=r["resource_id"])
        try:
            plain = json.loads(
                decrypt(key, r["nonce"], aad, r["ciphertext"]).decode("utf-8"))
        except Exception as e:
            raise HTTPException(status_code=500, detail={
                "code": "INTERNAL",
                "message": "telemetry decrypt failed"}) from e
        tel = plain.get("telemetry", {}) if isinstance(plain, dict) else {}
        items.append({"device_id": r["device_id"], "sequence": r["sequence"],
                      "issued_at": r["issued_at"],
                      "temp_c": tel.get("temp_c"),
                      "vibration_mm_s": tel.get("vibration_mm_s"),
                      "rpm": tel.get("rpm")})
    nxt = str(start + limit) if start + limit < len(rows) else None
    return {"items": items, "next_cursor": nxt}


@router.post("/v1/keys", status_code=200)
def enroll_key(body: KeyEnrollReq, request: Request) -> dict:
    from privacygate.services.delivery import DeliveryQueue
    from privacygate.storage.repository import Repository
    wallet = current_wallet(request)
    target = (body.wallet_address or wallet).lower()
    repo = getattr(request.app.state, "repository", None)
    if repo is None:
        repo = Repository()
        request.app.state.repository = repo
    try:
        repo.save_x25519_pubkey(target, body.x25519_public_key_b64, wallet)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail={
            "code": "POLICY_DENIED", "message": str(e)}) from None
    except ValueError as e:
        raise HTTPException(status_code=400, detail={
            "code": "INVALID_INPUT", "message": str(e)}) from None
    q: DeliveryQueue = request.app.state.queue
    try:
        return q.register_key(wallet, body.x25519_public_key_b64)
    except ValueError as e:
        raise HTTPException(status_code=400, detail={
            "code": "INVALID_INPUT", "message": str(e)}) from None
