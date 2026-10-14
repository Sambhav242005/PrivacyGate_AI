"""PG-024 policy gate: fresh confirmed-state check. Fail closed.

Never authorizes from a caller-supplied tx hash alone; always reads the
current contract view via ChainClient, then checks digest, wallet,
resource, expiry, and scope==1. Any RPC problem -> AuthzUnavailable (503).
"""
from __future__ import annotations

import re
import time
from typing import Any

from .client import ChainUnavailable

WALLET_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
RES_RE = re.compile(r"^0x[0-9a-f]{64}$")
DIGEST_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")

SCOPE_READ_INSIGHT = 1


class AuthzUnavailable(Exception):
    """Chain state unreachable right now -> HTTP 503, no disclosure."""


class PolicyDenied(Exception):
    """Fresh chain state forbids disclosure -> HTTP 403 (410 if expired)."""

    def __init__(self, message: str, reason: str = "denied") -> None:
        super().__init__(message)
        self.reason = reason


def validate_grant(
    grant: dict[str, Any],
    *,
    reader_wallet: str,
    expected_digest: str,
    now_unix: int | None = None,
) -> dict[str, Any]:
    now = int(time.time()) if now_unix is None else int(now_unix)
    if not WALLET_RE.match(reader_wallet or ""):
        raise PolicyDenied("invalid reader wallet", "wallet")
    if not DIGEST_RE.match(expected_digest or ""):
        raise PolicyDenied("invalid expected digest", "digest")
    if int(grant.get("scope", 0)) != SCOPE_READ_INSIGHT:
        raise PolicyDenied("grant scope is not READ_INSIGHT", "scope")
    if not grant.get("active", False):
        raise PolicyDenied("grant not active (revoked or expired on-chain)", "inactive")
    if now >= int(grant.get("expires_at", 0)):
        raise PolicyDenied("grant expired", "expired")
    if str(grant.get("policy_digest", "")).lower() != expected_digest.lower():
        raise PolicyDenied("policy digest mismatch", "digest")
    return grant


def authorize(
    client: Any,
    resource_id: str,
    reader_wallet: str,
    expected_digest: str,
    now_unix: int | None = None,
) -> dict[str, Any]:
    """Fresh check against current confirmed contract view."""
    if not RES_RE.match(resource_id or ""):
        raise PolicyDenied("invalid resource_id", "resource")
    reader = reader_wallet.lower() if isinstance(reader_wallet, str) else reader_wallet
    try:
        grant = client.get_grant(resource_id, reader)
    except (AuthzUnavailable, PolicyDenied):
        raise
    except ChainUnavailable as e:
        raise AuthzUnavailable(str(e)) from e
    except Exception as e:  # fail closed on any unexpected transport error
        raise AuthzUnavailable(f"authorization check failed: {e}") from e
    return validate_grant(grant, reader_wallet=reader,
                          expected_digest=expected_digest, now_unix=now_unix)
