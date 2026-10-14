"""Owner policy draft/digest + confirmed-chain sync routes."""
from __future__ import annotations

import json
import time
import uuid

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, model_validator

from privacygate.api.auth import current_wallet
from privacygate.api.devices import _owner_of
from privacygate.chain.client import ChainMismatch, ChainUnavailable, TxNotConfirmed
from privacygate.chain.permissions import AuthzUnavailable, PolicyDenied
from privacygate.chain.sync import DictPolicyStore, sync_policy
from privacygate.domain.policy import normalize_manifest, policy_digest
from privacygate.domain.schemas import PolicyManifestV1

router = APIRouter()


class PolicyCreateBody(PolicyManifestV1):
    """POST /v1/policies input: PolicyManifestV1 plus additive aliases.

    - Accepts API.md ``recipient_wallet`` (any hex case) as an alias of
      ``recipient_wallet_lowercase``; normalizes to lowercase.
    - Defaults missing ``policy_revision`` to 1 (API.md omits it for new drafts).
    - If both wallet fields are present they must agree (case-insensitive).
    """

    @model_validator(mode="before")
    @classmethod
    def _aliases(cls, data: object) -> object:
        if not isinstance(data, dict):
            return data
        d = dict(data)
        alias = d.pop("recipient_wallet", None)
        canon = d.get("recipient_wallet_lowercase")
        if canon is None:
            if alias is None:
                return d  # required-field validation still 422s
            d["recipient_wallet_lowercase"] = (
                str(alias).lower() if isinstance(alias, str) else alias
            )
        else:
            if isinstance(canon, str):
                d["recipient_wallet_lowercase"] = canon.lower()
            if (
                alias is not None
                and isinstance(alias, str)
                and alias.lower() != str(d["recipient_wallet_lowercase"]).lower()
            ):
                raise ValueError(
                    "recipient_wallet conflicts with recipient_wallet_lowercase"
                )
        if "policy_revision" not in d:
            d["policy_revision"] = 1
        return d


class SyncReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    transaction_hash: str


def _store(request: Request) -> DictPolicyStore:
    st = request.app.state.policy_store
    if not isinstance(st, DictPolicyStore):
        st = DictPolicyStore()
        request.app.state.policy_store = st
    return st


@router.post("/v1/policies", status_code=201)
def create_policy(body: PolicyCreateBody, request: Request) -> dict:
    wallet = current_wallet(request)
    _owner_of(request, body.resource_id, wallet)
    manifest = normalize_manifest(body.model_dump(mode="json"))
    digest = policy_digest(manifest)
    pid = str(uuid.uuid4())
    _store(request).put({"policy_id": pid, "resource_id": body.resource_id,
                         "owner_wallet": wallet,
                         "recipient_wallet": manifest["recipient_wallet_lowercase"],
                         "policy_revision": body.policy_revision,
                         "policy_json": json.dumps(manifest),
                         "policy_digest": digest,
                         "status": "DRAFT", "expires_at_unix": body.expires_at_unix})
    return {"policy_id": pid, "policy_revision": body.policy_revision,
            "policy_digest": digest, "status": "DRAFT",
            "onchain_grant_required": True}


@router.post("/v1/policies/{policy_id}/sync", status_code=200)
def sync_policy_route(policy_id: str, body: SyncReq, request: Request) -> dict:
    wallet = current_wallet(request)
    store = _store(request)
    pol = store.get_policy(policy_id)
    if pol is None:
        raise HTTPException(status_code=404, detail={
            "code": "RESOURCE_NOT_FOUND", "message": "unknown policy"})
    _owner_of(request, pol["resource_id"], wallet)
    chain = request.app.state.chain
    if chain is None:
        raise AuthzUnavailable("chain not configured")
    cfg = request.app.state.chain_config
    try:
        out = sync_policy(store=_store(request), chain_client=chain,
                          policy_id=policy_id, transaction_hash=body.transaction_hash,
                          contract_address=cfg["contract_address"],
                          expected_chain_id=cfg["chain_id"],
                          now_unix=int(time.time()))
    except ValueError as e:
        raise HTTPException(status_code=400, detail={
            "code": "INVALID_INPUT", "message": str(e)}) from None
    except KeyError:
        raise HTTPException(status_code=404, detail={
            "code": "RESOURCE_NOT_FOUND", "message": "unknown policy"}) from None
    except TxNotConfirmed as e:
        raise HTTPException(status_code=409, detail={
            "code": "TX_NOT_CONFIRMED", "message": str(e)}) from None
    except ChainMismatch as e:
        raise HTTPException(status_code=503, detail={
            "code": "CHAIN_MISMATCH", "message": str(e)}) from None
    except ChainUnavailable as e:
        raise AuthzUnavailable(str(e)) from None
    except PolicyDenied as e:
        raise HTTPException(status_code=403, detail={
            "code": "POLICY_DENIED", "message": str(e)}) from None
    if out["status"] == "REVOKED":
        pol = _store(request).get_policy(policy_id) or {}
        request.app.state.queue.invalidate_recipient(
            pol.get("resource_id", ""), pol.get("recipient_wallet", ""))
    now = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    request.app.state.sync_events.append(
        {"event_type": "GrantSet" if out["status"] == "ACTIVE" else "GrantRevoked",
         "block_number": out["confirmed_block"], "tx_hash": out["transaction_hash"],
         "contract_version": out["contract_version"], "observed_at": now,
         "policy_id": policy_id})
    return out


@router.get("/v1/policies")
def list_policies(request: Request, resource_id: str | None = None) -> dict:
    wallet = current_wallet(request)
    items = [p for p in _store(request).policies.values()
             if p["owner_wallet"] == wallet
             and (resource_id is None or p["resource_id"] == resource_id)]
    return {"items": items}
