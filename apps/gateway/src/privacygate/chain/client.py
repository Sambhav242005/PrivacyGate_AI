"""PG-024 chain client: web3 JSON-RPC read-only views + receipt lookup.

Carries ONLY authorization metadata (digests, expiry, version). Never sends
or returns raw telemetry, insights, or keys. All transport failures raise
ChainUnavailable so callers fail closed (503), never default-allow.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

RES_RE = re.compile(r"^0x[0-9a-f]{64}$")
WALLET_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
TX_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")

GETGRANT_ABI = [{
    "inputs": [
        {"name": "resourceId", "type": "bytes32"},
        {"name": "reader", "type": "address"},
    ],
    "name": "getGrant",
    "outputs": [
        {"name": "policyDigest", "type": "bytes32"},
        {"name": "expiresAt", "type": "uint64"},
        {"name": "version", "type": "uint32"},
        {"name": "active", "type": "bool"},
        {"name": "scope", "type": "uint8"},
    ],
    "stateMutability": "view",
    "type": "function",
}]
OWNEROF_ABI = [{
    "inputs": [{"name": "resourceId", "type": "bytes32"}],
    "name": "ownerOf",
    "outputs": [{"name": "", "type": "address"}],
    "stateMutability": "view",
    "type": "function",
}]


class ChainError(Exception):
    pass


class ChainUnavailable(ChainError):
    """RPC unreachable, timed out, or unexpected shape. Fail closed."""


class ChainMismatch(ChainError):
    """Wrong chain ID / contract address. Fail closed."""


class TxNotConfirmed(ChainError):
    """No receipt, failed status, or too few confirmations."""


@dataclass(frozen=True)
class ChainConfig:
    rpc_url: str
    contract_address: str
    chain_id: int
    timeout_s: float = 5.0

    def __post_init__(self) -> None:
        if not WALLET_RE.match(self.contract_address):
            raise ValueError("invalid contract address")


def _check_res(v: str) -> str:
    if not RES_RE.match(v or ""):
        raise ValueError("invalid resource_id")
    return v


def _check_wallet(v: str) -> str:
    if not WALLET_RE.match(v or ""):
        raise ValueError("invalid wallet address")
    return v.lower()


def _check_tx(v: str) -> str:
    if not TX_RE.match(v or ""):
        raise ValueError("invalid transaction_hash")
    return v


class ChainClient:
    """Thin wrapper over web3 (lazy import) with injectable fns for tests.

    Pass call_fn/receipt_fn/block_fn/chain_id_fn/owner_fn in tests to avoid
    any network. Production path uses web3.py HTTPProvider.
    """

    def __init__(
        self,
        config: ChainConfig,
        w3: Any | None = None,
        call_fn: Callable[[str, str], tuple] | None = None,
        owner_fn: Callable[[str], str] | None = None,
        receipt_fn: Callable[[str], dict | None] | None = None,
        block_fn: Callable[[], int] | None = None,
        chain_id_fn: Callable[[], int] | None = None,
    ) -> None:
        self.config = config
        self._w3 = w3
        self._call_fn = call_fn
        self._owner_fn = owner_fn
        self._receipt_fn = receipt_fn
        self._block_fn = block_fn
        self._chain_id_fn = chain_id_fn

    def _w3conn(self) -> Any:
        if self._w3 is not None:
            return self._w3
        try:
            import web3 as _w3mod
        except ImportError as e:
            raise ChainUnavailable("web3 not installed") from e
        try:
            w3 = _w3mod.Web3(_w3mod.HTTPProvider(
                self.config.rpc_url,
                request_kwargs={"timeout": self.config.timeout_s}))
            self._w3 = w3
            return w3
        except Exception as e:
            raise ChainUnavailable(f"chain connect failed: {e}") from e

    def get_grant(self, resource_id: str, reader_wallet: str) -> dict[str, Any]:
        _check_res(resource_id)
        reader = _check_wallet(reader_wallet)
        try:
            if self._call_fn is not None:
                digest, expires, version, active, scope = self._call_fn(resource_id, reader)
            else:
                w3 = self._w3conn()
                c = w3.eth.contract(address=self.config.contract_address,
                                    abi=GETGRANT_ABI)
                digest, expires, version, active, scope = c.functions.getGrant(
                    bytes.fromhex(resource_id[2:]), reader).call()
                digest = "0x" + bytes(digest).hex()
        except ChainUnavailable:
            raise
        except Exception as e:
            raise ChainUnavailable(f"getGrant failed: {e}") from e
        return {"policy_digest": str(digest).lower(), "expires_at": int(expires),
                "version": int(version), "active": bool(active), "scope": int(scope)}

    def get_owner(self, resource_id: str) -> str:
        _check_res(resource_id)
        try:
            if self._owner_fn is not None:
                return _check_wallet(self._owner_fn(resource_id))
            w3 = self._w3conn()
            c = w3.eth.contract(address=self.config.contract_address, abi=OWNEROF_ABI)
            return _check_wallet(c.functions.ownerOf(
                bytes.fromhex(resource_id[2:])).call())
        except ChainUnavailable:
            raise
        except Exception as e:
            raise ChainUnavailable(f"ownerOf failed: {e}") from e

    def get_receipt(self, tx_hash: str) -> dict[str, Any] | None:
        _check_tx(tx_hash)
        try:
            if self._receipt_fn is not None:
                return self._receipt_fn(tx_hash)
            w3 = self._w3conn()
            r = w3.eth.get_transaction_receipt(tx_hash)
            if r is None:
                return None
            d = dict(r)
            return {"status": int(d.get("status", 0)),
                    "block_number": int(d.get("blockNumber", 0)),
                    "to": str(d.get("to") or "").lower(),
                    "tx_hash": tx_hash.lower()}
        except ChainUnavailable:
            raise
        except Exception as e:
            raise ChainUnavailable(f"receipt lookup failed: {e}") from e

    def current_block(self) -> int:
        try:
            if self._block_fn is not None:
                return int(self._block_fn())
            return int(self._w3conn().eth.block_number)
        except ChainUnavailable:
            raise
        except Exception as e:
            raise ChainUnavailable(f"block height failed: {e}") from e

    def check_chain_id(self, expected: int) -> None:
        try:
            got = int(self._chain_id_fn()) if self._chain_id_fn else int(
                self._w3conn().eth.chain_id)
        except ChainUnavailable:
            raise
        except Exception as e:
            raise ChainUnavailable(f"chain id lookup failed: {e}") from e
        if got != int(expected):
            raise ChainMismatch(f"chain id {got} != expected {expected}")
