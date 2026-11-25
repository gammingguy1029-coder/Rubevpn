"""Authenticated dashboard access with signed cookies and CSRF protection."""
from __future__ import annotations

import hmac
import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, SecretStr, field_validator

from ..config import SecuritySettings
from ..monitoring.models import ErrorCode
from ..security.auth import create_session_token, verify_password, verify_session_token

logger = logging.getLogger(__name__)

SESSION_COOKIE = "rubevpn_session"
CSRF_COOKIE = "rubevpn_csrf"
CSRF_HEADER = "X-CSRF-Token"
MAX_FAILED_ATTEMPTS = 10
RATE_LIMIT_WINDOW_SECONDS = 60


class LoginRequest(BaseModel):
    username: str
    password: SecretStr

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        value = value.strip()
        if not value or len(value) > 64:
            raise ValueError("invalid username")
        return value


class _FailedAttempts:
    def __init__(self) -> None:
        self._hits: dict[str, list[float]] = defaultdict(list)

    def is_limited(self, key: str) -> bool:
        now = time.monotonic()
        self._hits[key] = [hit for hit in self._hits[key] if now - hit < RATE_LIMIT_WINDOW_SECONDS]
        return len(self._hits[key]) >= MAX_FAILED_ATTEMPTS

    def record(self, key: str) -> None:
        self._hits[key].append(time.monotonic())

    def clear(self, key: str) -> None:
        self._hits.pop(key, None)


_failed_attempts = _FailedAttempts()
router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


def _error(code: ErrorCode, message: str, status: int, recovery: str) -> HTTPException:
    return HTTPException(
        status_code=status,
        detail={
            "code": code.value,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "recovery_action": recovery,
        },
    )


def get_security(request: Request) -> SecuritySettings:
    return request.app.state.security


def csrf_is_valid(request: Request) -> bool:
    cookie = request.cookies.get(CSRF_COOKIE)
    header = request.headers.get(CSRF_HEADER)
    return bool(cookie and header and hmac.compare_digest(cookie, header))


def require_admin(request: Request) -> dict[str, Any]:
    security = get_security(request)
    claims = verify_session_token(security.session_secret, request.cookies.get(SESSION_COOKIE))
    if claims is None or claims.get("sub") != security.username:
        raise _error(
            ErrorCode.AUTH_REQUIRED,
            "Administrative authentication is required.",
            401,
            "Sign in through the dashboard login form.",
        )
    return claims


def require_csrf(request: Request) -> None:
    if not csrf_is_valid(request):
        raise _error(
            ErrorCode.CSRF_FAILED,
            "CSRF token missing or invalid.",
            403,
            "Reload the dashboard and retry the request.",
        )


@router.post("/login")
def login(payload: LoginRequest, request: Request) -> JSONResponse:
    require_csrf(request)
    security = get_security(request)
    client_key = request.client.host if request.client else "unknown"
    if _failed_attempts.is_limited(client_key):
        raise _error(
            ErrorCode.AUTH_RATE_LIMITED,
            "Too many failed sign-in attempts. Try again shortly.",
            429,
            "Wait one minute before retrying.",
        )
    supplied = payload.password.get_secret_value()
    if len(supplied) > 1024:
        _failed_attempts.record(client_key)
        raise _error(
            ErrorCode.AUTH_FAILED,
            "Invalid username or password.",
            401,
            "Check the credentials configured in the environment.",
        )
    valid_user = hmac.compare_digest(
        payload.username.encode("utf-8"), security.username.encode("utf-8")
    )
    valid_password = verify_password(security.password_hash, supplied)
    if not (valid_user and valid_password):
        _failed_attempts.record(client_key)
        logger.warning(
            "login_failed",
            extra={"event": "AUTH_FAILED", "username": payload.username, "client": client_key},
        )
        raise _error(
            ErrorCode.AUTH_FAILED,
            "Invalid username or password.",
            401,
            "Check the credentials configured in the environment.",
        )
    _failed_attempts.clear(client_key)
    token = create_session_token(security.session_secret, security.username, security.session_ttl_seconds)
    response = JSONResponse({"authenticated": True, "username": security.username})
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        samesite="strict",
        secure=security.cookie_secure,
        max_age=security.session_ttl_seconds,
        path="/",
    )
    if CSRF_COOKIE not in request.cookies:
        response.set_cookie(
            CSRF_COOKIE,
            request.cookies.get(CSRF_COOKIE) or _new_csrf(),
            httponly=False,
            samesite="strict",
            secure=security.cookie_secure,
            path="/",
        )
    logger.info("login_succeeded", extra={"event": "AUTH_SUCCESS", "username": security.username})
    return response


def _new_csrf() -> str:
    import secrets

    return secrets.token_urlsafe(32)


@router.post("/logout")
def logout(request: Request, _claims: dict[str, Any] = Depends(require_admin)) -> JSONResponse:
    require_csrf(request)
    response = JSONResponse({"authenticated": False})
    response.delete_cookie(SESSION_COOKIE, path="/")
    logger.info("logout_succeeded", extra={"event": "AUTH_LOGOUT"})
    return response


@router.get("/session")
def session(claims: dict[str, Any] = Depends(require_admin)) -> dict[str, object]:
    return {"authenticated": True, "username": claims.get("sub"), "expires_at": claims.get("exp")}
