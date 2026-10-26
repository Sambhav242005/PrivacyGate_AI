"""Loopback FastAPI gateway. Run privacygate_v2.api:app with PG_V2_CONFIG."""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

from fastapi import FastAPI, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

from .schemas import DeviceBody, EmptyBody, KeyBody, LoginBody, PolicyBody, SimulatorBody
from .security import canonical, digest, unb64, verify_password
from .service import Gateway, GatewayError, initialize_accounts, load_config

__all__ = ["app", "create_app", "initialize_accounts"]
COOKIE = "pg_v2_session"


def create_app(config_or_path: dict | str | Path | None = None, ledger_client=None) -> FastAPI:
    config = load_config(config_or_path)
    gateway = Gateway(config, ledger_client)
    app = FastAPI(title="PrivacyGate native v2", version="2.0.0", docs_url=None, redoc_url=None)
    app.state.gateway = gateway
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[config["origin"]],
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "X-CSRF-Token", "X-Operation-ID"],
    )
    secure_cookie = urlparse(config["origin"]).hostname not in {"127.0.0.1", "localhost", "::1"}
    cursor_key = unb64(config["raw_key_b64"], 32)

    def error(request: Request, code: str, status: int, message: str):
        return JSONResponse(
            {
                "error": {
                    "code": code,
                    "message": message,
                    "request_id": getattr(request.state, "request_id", str(uuid4())),
                }
            },
            status_code=status,
            headers={"Cache-Control": "no-store"},
        )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        request.state.request_id = str(uuid4())
        try:
            host = urlparse("//" + request.headers.get("host", ""))
            valid_host = (
                host.hostname in {"127.0.0.1", "localhost", "::1", "testserver"}
                and host.username is None
            )
        except ValueError:
            valid_host = False
        if not valid_host:
            return error(request, "HOST_DENIED", 400, "Host not allowed")
        if request.method == "POST":
            if request.headers.get("origin") != config["origin"]:
                return error(request, "ORIGIN_DENIED", 403, "Origin not allowed")
            if request.headers.get("content-type", "").split(";")[0] != "application/json":
                return error(request, "INVALID_REQUEST", 415, "JSON body required")
            chunks, size = [], 0
            async for chunk in request.stream():
                size += len(chunk)
                if size > 16384:
                    return error(request, "REQUEST_TOO_LARGE", 413, "Request too large")
                chunks.append(chunk)
            request._body = b"".join(chunks)
        gateway.repo.cleanup()
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    @app.exception_handler(GatewayError)
    async def gateway_error(request: Request, exc: GatewayError):
        return error(request, exc.code, exc.status, exc.message)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        return error(request, "INVALID_REQUEST", 422, "Request validation failed")

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        return error(
            request,
            "NOT_FOUND" if exc.status_code == 404 else "INVALID_REQUEST",
            exc.status_code,
            "Request not available",
        )

    @app.exception_handler(Exception)
    async def internal_error(request: Request, exc: Exception):
        return error(request, "INTERNAL_ERROR", 500, "Request could not be completed")

    def session(request: Request, mutate: bool = False):
        token = request.cookies.get(COOKIE, "")
        row = gateway.repo.one(
            "SELECT * FROM sessions WHERE token_hash=? AND expires_at>?",
            (digest(token.encode()), int(time.time())),
        )
        if not row:
            raise GatewayError("UNAUTHENTICATED", 401, "Authentication required")
        if mutate and not secrets.compare_digest(
            request.headers.get("x-csrf-token", ""), row["csrf_token"]
        ):
            raise GatewayError("CSRF_DENIED", 403, "CSRF token required")
        return {
            **gateway.account(row["account_id"]),
            "expires_at": row["expires_at"],
            "csrf_token": row["csrf_token"],
        }

    def require_role(account: dict, role: str):
        if account["role"] != role:
            raise GatewayError(f"{role.upper()}_REQUIRED")

    def cursor_encode(after: int, context: dict):
        payload = canonical({"after": after, **context})
        signature = hmac.new(cursor_key, payload, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(payload + signature).decode().rstrip("=")

    def cursor_decode(cursor: str | None, context: dict) -> int:
        if cursor is None:
            return 0
        try:
            if len(cursor) > 2048:
                raise ValueError()
            decoded = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
            payload, signature = decoded[:-32], decoded[-32:]
            if not hmac.compare_digest(
                hmac.new(cursor_key, payload, hashlib.sha256).digest(), signature
            ):
                raise ValueError()
            value = json.loads(payload)
            after = value.pop("after")
            if value != context or type(after) is not int or after < 0:
                raise ValueError()
            return after
        except (ValueError, TypeError, KeyError, OverflowError):
            raise GatewayError("INVALID_CURSOR", 422, "Invalid pagination cursor") from None

    @app.post("/v2/auth/login")
    def login(body: LoginBody, request: Request, response: Response):
        address = request.client.host if request.client else "unknown"
        gateway.rate_limit("ip:" + digest(address.encode()), 30, 300)
        gateway.rate_limit("login:" + digest((address + "|" + body.username).encode()), 10, 300)
        account = gateway.repo.one("SELECT * FROM accounts WHERE username=?", (body.username,))
        if not verify_password(
            body.password, account["password_hash"] if account else gateway.dummy_password
        ):
            raise GatewayError("INVALID_CREDENTIALS", 401, "Invalid credentials")
        token, csrf, expires = (
            secrets.token_urlsafe(32),
            secrets.token_urlsafe(32),
            int(time.time()) + 1800,
        )
        with gateway.repo.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = request.cookies.get(COOKIE)
            if previous:
                db.execute("DELETE FROM sessions WHERE token_hash=?", (digest(previous.encode()),))
            db.execute(
                "INSERT INTO sessions VALUES(?,?,?,?)",
                (digest(token.encode()), account["account_id"], csrf, expires),
            )
        response.set_cookie(
            COOKIE, token, max_age=1800, httponly=True, samesite="strict", secure=secure_cookie
        )
        return {
            **{k: account[k] for k in ("account_id", "username", "role")},
            "expires_at": expires,
            "csrf_token": csrf,
        }

    @app.get("/v2/me")
    def me(request: Request):
        return session(request)

    @app.post("/v2/auth/logout")
    def logout(body: EmptyBody, request: Request, response: Response):
        session(request, True)
        gateway.repo.execute(
            "DELETE FROM sessions WHERE token_hash=?", (digest(request.cookies[COOKIE].encode()),)
        )
        response.delete_cookie(COOKIE, httponly=True, samesite="strict", secure=secure_cookie)
        return {"ok": True}

    @app.get("/v2/accounts")
    def accounts(request: Request):
        require_role(session(request), "owner")
        return {
            "items": gateway.repo.all(
                "SELECT account_id,username,role FROM accounts ORDER BY username"
            )
        }

    @app.get("/v2/devices")
    def devices(request: Request):
        account = session(request)
        require_role(account, "owner")
        gateway.reconcile(account["account_id"])
        return {
            "items": [
                gateway.device_view(d)
                for d in gateway.repo.all(
                    "SELECT * FROM devices WHERE owner_id=? AND registered=1 ORDER BY rowid",
                    (account["account_id"],),
                )
            ]
        }

    @app.post("/v2/devices")
    def create_device(body: DeviceBody, request: Request):
        return gateway.register_device(
            session(request, True), body.name, request.headers.get("x-operation-id")
        )

    @app.get("/v2/resources/{resource_id}/telemetry")
    def telemetry(
        resource_id: str,
        request: Request,
        limit: int = Query(20, ge=1, le=100),
        cursor: str | None = None,
    ):
        account = session(request)
        gateway.owned_device(resource_id, account)
        context = {
            "resource_id": resource_id,
            "account_id": account["account_id"],
            "kind": "telemetry",
        }
        after = cursor_decode(cursor, context)
        rows = gateway.repo.all(
            "SELECT * FROM telemetry WHERE resource_id=? AND id>? ORDER BY id LIMIT ?",
            (resource_id, after, limit + 1),
        )
        items = []
        for row in rows[:limit]:
            aad = canonical(
                {
                    "resource_id": resource_id,
                    "device_id": row["device_id"],
                    "sequence": row["sequence"],
                }
            )
            items.append(
                json.loads(gateway.raw_cipher.decrypt(row["nonce"], row["ciphertext"], aad))
            )
        return {
            "items": items,
            "next_cursor": cursor_encode(rows[limit - 1]["id"], context)
            if len(rows) > limit
            else None,
        }

    @app.post("/v2/simulator")
    def simulator(body: SimulatorBody, request: Request):
        return gateway.simulate(session(request, True), body.resource_id, body.mode, body.count)

    @app.get("/v2/keys")
    def get_key(request: Request):
        account = session(request)
        require_role(account, "reader")
        return gateway.repo.one(
            "SELECT key_id,key_version,x25519_public_key_b64 FROM reader_keys WHERE account_id=?",
            (account["account_id"],),
        )

    @app.post("/v2/keys")
    def create_key(body: KeyBody, request: Request):
        return gateway.enroll_key(session(request, True), body.x25519_public_key_b64, body.replace)

    @app.post("/v2/policies")
    def policies_create(body: PolicyBody, request: Request):
        return gateway.create_policy(
            session(request, True), body.model_dump(), request.headers.get("x-operation-id")
        )

    @app.get("/v2/policies")
    def policies_list(resource_id: str, request: Request):
        return {"items": gateway.list_policies(session(request), resource_id)}

    @app.post("/v2/policies/{policy_id}/revoke")
    def revoke(policy_id: str, body: EmptyBody, request: Request):
        return gateway.revoke(
            session(request, True), policy_id, request.headers.get("x-operation-id")
        )

    @app.get("/v2/operations/{transaction_id}")
    def operation(transaction_id: str, request: Request):
        account = session(request)
        require_role(account, "owner")
        row = gateway.repo.one(
            "SELECT * FROM outbox WHERE transaction_id=? AND signer_id=?",
            (transaction_id, account["account_id"]),
        )
        if not row:
            raise GatewayError("NOT_FOUND", 404)
        if row["receipt_json"] is None:
            with gateway.lock("signer", account["account_id"]):
                try:
                    gateway._commit(row)
                except GatewayError as exc:
                    if exc.code != "OPERATION_EXPIRED":
                        raise
            row = gateway.repo.one("SELECT * FROM outbox WHERE transaction_id=?", (transaction_id,))
        saved = json.loads(row["receipt_json"]) if row["receipt_json"] else None
        if saved and saved.get("failure_code"):
            return {
                "transaction_id": transaction_id,
                "status": "FAILED",
                "code": saved["failure_code"],
                "receipt": None,
            }
        return {
            "transaction_id": transaction_id,
            "status": "COMMITTED" if row["receipt_json"] else "PENDING",
            "receipt": saved,
        }

    @app.get("/v2/insights")
    def insights(
        resource_id: str,
        request: Request,
        limit: int = Query(20, ge=1, le=100),
        cursor: str | None = None,
    ):
        account = session(request)
        require_role(account, "reader")
        gateway.rate_limit("read:" + account["account_id"], 120, 60)
        context = {
            "resource_id": resource_id,
            "account_id": account["account_id"],
            "kind": "insights",
        }
        after = cursor_decode(cursor, context)
        observation = gateway.chain_state(resource_id, account["account_id"])
        grant = observation.get("grant")
        policy = gateway.repo.one(
            "SELECT * FROM policies WHERE resource_id=? AND recipient_id=? AND policy_digest=?",
            (resource_id, account["account_id"], grant["policy_digest"] if grant else ""),
        )
        if not policy or not gateway.authorized(policy, observation):
            raise GatewayError("POLICY_DENIED")
        key = gateway.repo.one(
            "SELECT * FROM reader_keys WHERE account_id=?", (account["account_id"],)
        )
        if not key:
            return {"items": [], "next_cursor": None}
        rows = gateway.repo.all(
            "SELECT * FROM deliveries WHERE resource_id=? AND recipient_id=? AND policy_digest=? AND policy_version=? AND key_version=? AND id>? ORDER BY id LIMIT ?",
            (
                resource_id,
                account["account_id"],
                policy["policy_digest"],
                policy["version"],
                key["key_version"],
                after,
                limit + 1,
            ),
        )
        return {
            "items": [json.loads(r["envelope_json"]) for r in rows[:limit]],
            "next_cursor": cursor_encode(rows[limit - 1]["id"], context)
            if len(rows) > limit
            else None,
        }

    @app.get("/v2/audit")
    def audit(resource_id: str, request: Request):
        account = session(request)
        gateway.owned_device(resource_id, account)
        gateway.reconcile(account["account_id"])
        rows = gateway.repo.all(
            "SELECT receipt_json FROM outbox WHERE signer_id=? AND receipt_json IS NOT NULL ORDER BY created_at,rowid",
            (account["account_id"],),
        )
        receipts = [json.loads(r["receipt_json"]) for r in rows]
        return {
            "items": [
                r for r in receipts if r.get("resource_id") == resource_id and "block_height" in r
            ]
        }

    @app.get("/v2/health")
    def health():
        return {"status": "ok"}

    @app.get("/v2/ready")
    def ready():
        try:
            owner = gateway.repo.one("SELECT account_id FROM accounts WHERE role='owner' LIMIT 1")
            gateway.chain.next_nonce(owner["account_id"])
            chain = "ok"
        except Exception:  # noqa: BLE001 - readiness reports every chain availability failure
            chain = "unavailable"
        return {"gateway": "ok", "database": "ok", "chain": chain}

    return app


@asynccontextmanager
async def missing_configuration(_app):
    raise RuntimeError("PG_V2_CONFIG is required")
    yield


# Importing helpers for setup must not create a runtime or reveal config contents.
app = create_app() if os.environ.get("PG_V2_CONFIG") else FastAPI(lifespan=missing_configuration)
