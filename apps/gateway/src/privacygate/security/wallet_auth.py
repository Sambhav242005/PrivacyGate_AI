"""PG-022 EIP-191 wallet challenge skeleton (stdlib + eth_account if present)."""
from __future__ import annotations

import re
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field

WALLET_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
CHALLENGE_TTL_S = 300
SESSION_TTL_S = 1800

_lock = threading.Lock()  # ponytail: global lock, per-wallet locks if contention matters
_challenges: dict[str, "Challenge"] = {}
_attempts: dict[str, list[float]] = {}


@dataclass
class Challenge:
    challenge_id: str
    wallet_address: str  # checksummed as supplied; compare lowercase
    nonce: str
    message: str
    expires_at: float
    consumed: bool = False


def build_message(wallet: str, domain: str, chain_id: int, nonce: str,
                  issued_at: str, expires_at: str) -> str:
    return (
        "PrivacyGate AI login\n"
        f"Domain: {domain}\n"
        f"Chain ID: {chain_id}\n"
        f"Wallet: {wallet}\n"
        f"Nonce: {nonce}\n"
        f"Issued At: {issued_at}\n"
        f"Expires At: {expires_at}"
    )


def _utc(ms_epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(ms_epoch))


def create_challenge(wallet_address: str, domain: str = "localhost",
                     chain_id: int = 31337) -> dict[str, str]:
    if not WALLET_RE.match(wallet_address):
        raise ValueError("invalid wallet address")
    now = time.time()
    nonce = secrets.token_hex(16)
    cid = str(uuid.uuid4())
    msg = build_message(wallet_address, domain, chain_id, nonce,
                        _utc(now), _utc(now + CHALLENGE_TTL_S))
    with _lock:
        _challenges[cid] = Challenge(cid, wallet_address, nonce, msg, now + CHALLENGE_TTL_S)
    return {"challenge_id": cid, "message_to_sign": msg,
            "expires_at": _utc(now + CHALLENGE_TTL_S)}


def verify_challenge(challenge_id: str, signature_hex: str) -> str:
    """Atomically consume challenge, recover signer, return wallet.

    TODO: no eth_account in env -> raises NotImplementedError; wire
    eth_account.messages.encode_defunct + Account.recover_message here.
    Caller must fail closed (401) on any exception.
    """
    try:
        from eth_account import Account
        from eth_account.messages import encode_defunct
    except ImportError as e:  # pragma: no cover - dep missing path
        raise NotImplementedError(
            "TODO: install eth-account for EIP-191 recovery") from e
    with _lock:
        ch = _challenges.get(challenge_id)
        if ch is None or ch.consumed or time.time() > ch.expires_at:
            if ch is not None:
                ch.consumed = True
            raise ValueError("bad/expired/reused challenge")
        ch.consumed = True
    recovered = Account.recover_message(encode_defunct(text=ch.message),
                                        signature=signature_hex)
    if recovered.lower() != ch.wallet_address.lower():
        raise ValueError("signature wallet mismatch")
    return recovered


def create_session_token() -> str:
    return secrets.token_urlsafe(32)


def session_cookie_attrs(secure: bool = False) -> dict[str, object]:
    return {"key": "pg_session", "httponly": True, "secure": secure,
            "samesite": "lax", "path": "/"}


def check_throttle(key: str, limit: int = 10, window_s: int = 60) -> bool:
    """True if allowed. Records attempt. Fail closed by caller on False."""
    now = time.time()
    with _lock:
        hits = [t for t in _attempts.get(key, []) if now - t < window_s]
        if len(hits) >= limit:
            _attempts[key] = hits
            return False
        hits.append(now)
        _attempts[key] = hits
        return True
