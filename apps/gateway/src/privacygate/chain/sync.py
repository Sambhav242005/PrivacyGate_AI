"""PG-024 confirmed-chain sync: receipt confirmations + grant-view status.

Activation/revocation comes from confirmed on-chain state, never from
request intent or a bare tx hash. Works against any store with
get_policy/set_sync (DictPolicyStore provided for the API skeleton; the
PG-023 Repository gains set_sync in later work without touching models).
"""
from __future__ import annotations

import re
from typing import Any

from .client import ChainMismatch, TxNotConfirmed
from .permissions import PolicyDenied, authorize

TX_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
REQUIRED_CONFIRMATIONS = 1


class DictPolicyStore:
    """Minimal in-memory policy sync store for skeleton/tests."""

    def __init__(self) -> None:
        self.policies: dict[str, dict[str, Any]] = {}
        self.events: list[dict[str, Any]] = []

    def put(self, policy: dict[str, Any]) -> None:
        self.policies[policy["policy_id"]] = policy

    def get_policy(self, policy_id: str) -> dict[str, Any] | None:
        return self.policies.get(policy_id)

    def set_sync(self, policy_id: str, *, status: str, contract_version: int,
                 confirmed_block: int, tx_hash: str) -> None:
        p = self.policies[policy_id]
        p["status"] = status
        p["contract_version"] = contract_version
        p["confirmed_block"] = confirmed_block
        p["transaction_hash"] = tx_hash.lower()
        self.events.append({"policy_id": policy_id, "status": status,
                            "contract_version": contract_version,
                            "block_number": confirmed_block,
                            "tx_hash": tx_hash.lower()})


def verify_receipt(
    receipt: dict[str, Any] | None,
    *,
    expected_contract: str,
    current_block: int,
    required_confirmations: int = REQUIRED_CONFIRMATIONS,
) -> dict[str, Any]:
    if receipt is None:
        raise TxNotConfirmed("no receipt yet (not mined?)")
    if int(receipt.get("status", 0)) != 1:
        raise TxNotConfirmed("transaction failed or pending")
    if str(receipt.get("to", "")).lower() != expected_contract.lower():
        raise ChainMismatch("receipt is not for the registry contract")
    confs = int(current_block) - int(receipt.get("block_number", 0)) + 1
    if confs < required_confirmations:
        raise TxNotConfirmed(f"only {confs} confirmation(s), need {required_confirmations}")
    return receipt


def sync_policy(
    *,
    store: Any,
    chain_client: Any,
    policy_id: str,
    tx_hash: str,
    contract_address: str,
    expected_chain_id: int,
    now_unix: int | None = None,
    required_confirmations: int = REQUIRED_CONFIRMATIONS,
) -> dict[str, Any]:
    if not TX_RE.match(tx_hash or ""):
        raise ValueError("invalid transaction_hash")
    check = getattr(chain_client, "check_chain_id", None)
    if callable(check):
        check(expected_chain_id)
    receipt = chain_client.get_receipt(tx_hash)
    block = chain_client.current_block()
    verify_receipt(receipt, expected_contract=contract_address,
                   current_block=block,
                   required_confirmations=required_confirmations)
    policy = store.get_policy(policy_id)
    if policy is None:
        raise KeyError(f"unknown policy: {policy_id}")
    try:
        grant = authorize(chain_client, policy["resource_id"],
                          policy["recipient_wallet"],
                          policy["policy_digest"], now_unix)
    except PolicyDenied as e:
        if e.reason in ("inactive", "expired"):
            store.set_sync(policy_id, status="REVOKED",
                           contract_version=int(chain_client.get_grant(
                               policy["resource_id"],
                               policy["recipient_wallet"]).get("version", 0)),
                           confirmed_block=int(receipt["block_number"]),
                           tx_hash=tx_hash)
            p = store.get_policy(policy_id)
            return {"policy_id": policy_id, "status": "REVOKED",
                    "contract_version": p.get("contract_version", 0),
                    "confirmed_block": int(receipt["block_number"]),
                    "transaction_hash": tx_hash.lower()}
        raise
    store.set_sync(policy_id, status="ACTIVE",
                   contract_version=int(grant["version"]),
                   confirmed_block=int(receipt["block_number"]),
                   tx_hash=tx_hash)
    return {"policy_id": policy_id, "status": "ACTIVE",
            "contract_version": int(grant["version"]),
            "confirmed_block": int(receipt["block_number"]),
            "transaction_hash": tx_hash.lower()}
