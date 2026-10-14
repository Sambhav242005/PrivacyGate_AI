"""Wallet session routes (PG-022). Sessions are cookie-bound; the
X-Wallet-Address header is never trusted alone (PG-043 A1)."""
from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict

router = APIRouter()
WALLET_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


class ChallengeReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    wallet_address: str


class VerifyReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    challenge_id: str
    signature_hex: str


def _unauthenticated() -> HTTPException:
    return HTTPException(status_code=401, detail={
        "code": "NOT_AUTHENTICATED", "message": "wallet login required"})


def current_wallet(request: Request) -> str:
    """Resolve caller wallet from pg_session cookie only.

    The X-Wallet-Address header is accepted solely as a consistency hint:
    it must match the session wallet, otherwise 401. A header with no
    matching session is never sufficient (no spoofing).
    """
    sessions = getattr(request.app.state, "sessions", None) or {}
    cookie = request.cookies.get("pg_session", "")
    header = request.headers.get("x-wallet-address", "")
    header = header.lower() if header and WALLET_RE.match(header) else ""
    if cookie:
        wallet = sessions.get(cookie)
        if isinstance(wallet, str) and WALLET_RE.match(wallet):
            if header and header != wallet.lower():
                raise _unauthenticated()
            return wallet.lower()
        if WALLET_RE.match(cookie) and sessions.get(cookie.lower()):
            # dev-skeleton compat: cookie carries wallet, sessions[wallet] set
            if header and header != cookie.lower():
                raise _unauthenticated()
            return cookie.lower()
    if header and sessions.get(header):
        return header
    raise _unauthenticated()


@router.post("/v1/auth/challenge", status_code=200)
def challenge(body: ChallengeReq) -> dict:
    from privacygate.security.wallet_auth import create_challenge
    if not WALLET_RE.match(body.wallet_address):
        raise HTTPException(status_code=400, detail={
            "code": "INVALID_INPUT", "message": "invalid wallet address"})
    return create_challenge(body.wallet_address)


@router.post("/v1/auth/verify", status_code=200)
def verify(body: VerifyReq, request: Request, response: Response) -> dict:
    from privacygate.security.wallet_auth import (
        create_session_token,
        session_cookie_attrs,
        verify_challenge,
    )
    try:
        wallet = verify_challenge(body.challenge_id, body.signature_hex).lower()
    except Exception:
        raise HTTPException(status_code=401, detail={
            "code": "NOT_AUTHENTICATED",
            "message": "bad/expired/reused challenge"}) from None
    sessions = request.app.state.sessions
    old = sessions.get(wallet)
    if isinstance(old, str) and old in sessions:
        sessions.pop(old, None)  # rotate: drop previous token
    token = create_session_token()
    sessions[token] = wallet
    sessions[wallet] = token
    response.set_cookie(value=token, **session_cookie_attrs())  # type: ignore[arg-type]
    return {"wallet_address": wallet, "expires_at": "", "csrf_token": "dev-skeleton"}


@router.get("/v1/me")
def me(request: Request) -> dict:
    return {"wallet_address": current_wallet(request),
            "roles": [], "expires_at": ""}


@router.post("/v1/auth/logout", status_code=200)
def logout(request: Request, response: Response) -> dict:
    sessions = getattr(request.app.state, "sessions", None) or {}
    try:
        wallet = current_wallet(request)
    except HTTPException:
        wallet = ""
    if wallet:
        sessions.pop(wallet, None)
        for tok in [t for t, w in list(sessions.items()) if w == wallet]:
            sessions.pop(tok, None)
    cookie = request.cookies.get("pg_session", "")
    if cookie:
        sessions.pop(cookie, None)
    response.delete_cookie("pg_session", path="/")
    return {}
