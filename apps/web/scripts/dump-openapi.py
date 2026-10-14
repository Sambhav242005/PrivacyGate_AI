"""Dump gateway OpenAPI + real Pydantic DTO schemas for the web api-docs page.

Reads ONLY (no server start, no gateway code changes):
    python apps/web/scripts/dump-openapi.py

Regenerate whenever routers, DTOs, or docs/API.md change, then commit
apps/web/src/lib/openapi.snapshot.json alongside the change.
"""
from __future__ import annotations

import datetime
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.dirname(HERE)  # apps/web
SNAPSHOT = os.path.join(WEB_DIR, "src", "lib", "openapi.snapshot.json")


def main() -> None:
    try:
        from privacygate.api.main import create_app
        from privacygate.domain.schemas import (
            InsightV1,
            PolicyManifestV1,
            SensorTelemetryV1,
            SignedTelemetryV1,
        )
    except ImportError as e:
        print(f"dump-openapi: cannot import gateway (run with gateway on PYTHONPATH): {e}",
              file=sys.stderr)
        raise SystemExit(2) from e

    spec = create_app().openapi()

    # Real Pydantic JSON schemas (never hand-written): domain DTOs that the
    # untyped `-> dict` route handlers cannot surface in /openapi.json.
    dto_schemas = {
        "SensorTelemetryV1": SensorTelemetryV1.model_json_schema(),
        "SignedTelemetryV1": SignedTelemetryV1.model_json_schema(),
        "InsightV1": InsightV1.model_json_schema(),
        "PolicyManifestV1": PolicyManifestV1.model_json_schema(),
    }

    # Per-endpoint notes derived from reading api/*.py + docs/API.md.
    # Auth model, status codes and error codes only -- no field types here.
    endpoint_notes = {
        "POST /v1/auth/challenge": {
            "auth": "public",
            "response_note": "Challenge text the wallet signs with EIP-191 personal_sign. Single-use, 5 minute TTL.",
            "errors": ["INVALID_INPUT (400)", "HTTPValidationError (422)"],
        },
        "POST /v1/auth/verify": {
            "auth": "challenge signature (consumes the challenge atomically)",
            "response_note": "Sets HttpOnly pg_session cookie. Returns wallet address and CSRF token.",
            "errors": ["NOT_AUTHENTICATED (401)"],
        },
        "GET /v1/me": {
            "auth": "pg_session cookie",
            "response_note": "Wallet address, roles and session expiry. No keys.",
            "errors": ["NOT_AUTHENTICATED (401)"],
        },
        "POST /v1/auth/logout": {
            "auth": "pg_session cookie if present (always 200)",
            "response_note": "Expires the cookie and server session.",
            "errors": [],
        },
        "POST /v1/devices": {
            "auth": "pg_session cookie + confirmed on-chain ownerOf(resource_id)",
            "response_note": "Untyped map: resource_id, device_id, name, registered_at, status. Never accepts a private key.",
            "errors": ["NOT_AUTHENTICATED (401)", "POLICY_DENIED (403)", "ALREADY_EXISTS (409)",
                       "HTTPValidationError (422)", "AUTHZ_UNAVAILABLE (503)"],
        },
        "GET /v1/devices": {
            "auth": "pg_session cookie (caller's own devices only)",
            "response_note": "List of the caller's enrolled devices.",
            "errors": ["NOT_AUTHENTICATED (401)"],
        },
        "GET /v1/resources/{resource_id}/telemetry": {
            "auth": "pg_session cookie + confirmed on-chain owner (owner only, fails closed)",
            "response_note": "Decrypted telemetry rows (device_id, sequence, issued_at, temp_c, vibration_mm_s, rpm), paged by cursor.",
            "errors": ["INVALID_INPUT (400)", "NOT_AUTHENTICATED (401)", "POLICY_DENIED (403)",
                       "INTERNAL (500)", "AUTHZ_UNAVAILABLE (503)"],
        },
        "POST /v1/keys": {
            "auth": "pg_session cookie (key bound to the authenticated wallet)",
            "response_note": "Registered wallet address, key id and timestamp. Rotation invalidates unread envelopes.",
            "errors": ["INVALID_INPUT (400)", "NOT_AUTHENTICATED (401)", "POLICY_DENIED (403)"],
        },
        "POST /v1/policies": {
            "auth": "pg_session cookie + confirmed on-chain ownerOf(resource_id)",
            "response_note": "Draft id, revision, canonical policy digest and DRAFT status. Grant still requires an owner-signed on-chain transaction.",
            "errors": ["NOT_AUTHENTICATED (401)", "POLICY_DENIED (403)", "HTTPValidationError (422)",
                       "AUTHZ_UNAVAILABLE (503)"],
        },
        "POST /v1/policies/{policy_id}/sync": {
            "auth": "pg_session cookie + confirmed on-chain owner of the policy resource",
            "response_note": "ACTIVE or REVOKED from confirmed chain state (never from request intent), with contract version and block.",
            "errors": ["INVALID_INPUT (400)", "NOT_AUTHENTICATED (401)", "POLICY_DENIED (403)",
                       "RESOURCE_NOT_FOUND (404)", "TX_NOT_CONFIRMED (409)",
                       "CHAIN_MISMATCH (503)", "AUTHZ_UNAVAILABLE (503)"],
        },
        "GET /v1/policies": {
            "auth": "pg_session cookie (caller's own drafts only)",
            "response_note": "Local drafts and chain-sync status. Never shared with other wallets.",
            "errors": ["NOT_AUTHENTICATED (401)"],
        },
        "GET /v1/insights": {
            "auth": "pg_session cookie + fresh confirmed READ_INSIGHT grant on every read",
            "response_note": "Per-recipient encrypted envelopes only (ciphertext + AAD). 410 when the grant expired. 503 with zero disclosure on chain outage.",
            "errors": ["INVALID_INPUT (400)", "NOT_AUTHENTICATED (401)", "POLICY_DENIED (403/410)",
                       "RESOURCE_NOT_FOUND (404)", "KEY_NOT_REGISTERED (409)", "AUTHZ_UNAVAILABLE (503)"],
        },
        "GET /v1/audit/permission-events": {
            "auth": "pg_session cookie + confirmed on-chain owner",
            "response_note": "Confirmed grant/revoke summaries. No policy JSON or telemetry.",
            "errors": ["INVALID_INPUT (400)", "NOT_AUTHENTICATED (401)", "POLICY_DENIED (403)",
                       "AUTHZ_UNAVAILABLE (503)"],
        },
        "GET /v1/health": {
            "auth": "public",
            "response_note": "Process liveness only.",
            "errors": [],
        },
        "GET /v1/ready": {
            "auth": "public",
            "response_note": "Dependency states (gateway, database, mqtt, chain) without secret config.",
            "errors": [],
        },
    }

    snapshot = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source": "privacygate.api.main:create_app().openapi()",
        "openapi": spec,
        "dto_schemas": dto_schemas,
        "endpoint_notes": endpoint_notes,
    }
    with open(SNAPSHOT, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=1)
        f.write("\n")
    print(f"dump-openapi: wrote {SNAPSHOT} "
          f"({len(spec['paths'])} paths, {len(dto_schemas)} dto schemas)")


if __name__ == "__main__":
    main()
