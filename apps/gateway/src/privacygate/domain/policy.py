"""PG-023 policy draft/digest skeleton. Pure stdlib: no FastAPI/DB imports."""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any

# scope 1 = READ_INSIGHT (only third-party scope in MVP)
SCOPE_READ_INSIGHT = 1
_SCOPE_NAME = {1: "READ_INSIGHT"}


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def normalize_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    """Sort + dedupe arrays, lowercase recipient. Returns new dict."""
    out = dict(manifest)
    out["recipient_wallet_lowercase"] = str(out["recipient_wallet_lowercase"]).lower()
    out["allowed_event_types"] = sorted(set(out["allowed_event_types"]))
    out["allowed_fields"] = sorted(set(out["allowed_fields"]))
    return out


def policy_digest(manifest: dict[str, Any]) -> str:
    """SHA-256 of canonical manifest JSON, 0x-prefixed lowercase hex."""
    return "0x" + hashlib.sha256(canonical_json(manifest)).hexdigest()


def is_expired(expires_at_unix: int, now_unix: int | None = None) -> bool:
    now = int(time.time()) if now_unix is None else now_unix
    return now >= int(expires_at_unix)


def check_scope(scope: int | str) -> None:
    """Accept numeric 1 or string READ_INSIGHT; reject everything else."""
    if isinstance(scope, str):
        if scope != "READ_INSIGHT":
            raise ValueError(f"unsupported scope: {scope}")
        return
    if scope != SCOPE_READ_INSIGHT:
        raise ValueError(f"unsupported scope: {scope} (want 1=READ_INSIGHT)")


def assert_policy_authorized(
    manifest: dict[str, Any],
    expected_digest: str,
    scope: int,
    now_unix: int | None = None,
) -> str:
    """Fail-closed gate for third-party delivery.

    Checks: scope==1, not expired, digest matches normalized manifest.
    Returns digest on success; raises ValueError otherwise.
    """
    check_scope(scope)
    check_scope(manifest.get("scope", ""))
    if is_expired(int(manifest["expires_at_unix"]), now_unix):
        raise ValueError("policy expired")
    digest = policy_digest(normalize_manifest(manifest))
    if digest.lower() != expected_digest.lower():
        raise ValueError("policy digest mismatch")
    return digest
