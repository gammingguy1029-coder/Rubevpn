"""RubeVPN application factory and wiring."""
from __future__ import annotations

import logging
import platform
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .api import auth as auth_api
from .api import connection as connection_api
from .api import health as health_api
from .api import status as status_api
from .config import ConfigError, load_security_settings, load_settings
from .monitoring.events import REQUEST_ID, EventBuffer, configure_logging
from .monitoring.models import ErrorCode
from .services.host_capabilities import probe_capabilities
from .services.vpn_provider import UnavailableProvider
from .services.windows_wireguard import WireGuardWindowsProvider

logger = logging.getLogger(__name__)
DASHBOARD_DIR = Path(__file__).resolve().parents[2] / "dashboard"


def select_provider(settings, capabilities=None):
    """Use the real Windows provider only when explicitly configured.

    The honest fallback reports measured host capabilities instead of assuming
    every host is ineligible.
    """
    capabilities = capabilities or probe_capabilities(settings)
    if settings.vpn.provider == "wireguard" and platform.system() == "Windows":
        return WireGuardWindowsProvider(settings)
    return UnavailableProvider(
        settings,
        public_endpoint=capabilities.public_endpoint,
        privileged=capabilities.privileged,
        wireguard_installed=capabilities.wireguard_installed,
        inbound_udp=capabilities.inbound_udp,
    )


_STATUS_TO_CODE: dict[int, ErrorCode] = {
    400: ErrorCode.CFG_INVALID,
    401: ErrorCode.AUTH_REQUIRED,
    403: ErrorCode.CSRF_FAILED,
    404: ErrorCode.CFG_INVALID,
    405: ErrorCode.CFG_INVALID,
    422: ErrorCode.CFG_INVALID,
    429: ErrorCode.AUTH_RATE_LIMITED,
}


def _error_response(request: Request, code: ErrorCode, message: str, status_code: int,
                    recovery: str, context: dict[str, object] | None = None) -> JSONResponse:
    """One error envelope for every failure path, with a correlation ID."""
    return JSONResponse(
        status_code=status_code,
        content={
            "code": code.value,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "context": context or {},
            "recovery_action": recovery,
            "request_id": getattr(request.state, "request_id", None),
        },
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = load_settings()
    security = load_security_settings()
    events = EventBuffer()
    configure_logging(settings.logging.level, settings.logging.format, events)
    capabilities = probe_capabilities(settings)
    provider = select_provider(settings, capabilities)
    app.state.settings = settings
    app.state.security = security
    app.state.events = events
    app.state.capabilities = capabilities
    app.state.provider = provider
    app.state.started_monotonic = time.monotonic()
    logger.info(
        "application_started",
        extra={
            "event": "STARTING",
            "app_version": settings.app_version,
            "provider": type(provider).__name__,
            "environment": settings.environment,
        },
    )
    yield
    logger.info("application_shutdown", extra={"event": "SHUTDOWN"})


def create_app() -> FastAPI:
    app = FastAPI(
        title="RubeVPN",
        version="1.0.0-m1",
        docs_url=None,
        redoc_url=None,
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        request.state.request_id = request_id
        token = REQUEST_ID.set(request_id)
        try:
            response = await call_next(request)
        finally:
            REQUEST_ID.reset(token)
        response.headers["X-Request-ID"] = request_id
        security = getattr(request.app.state, "security", None)
        if security is not None and auth_api.CSRF_COOKIE not in request.cookies:
            response.set_cookie(
                auth_api.CSRF_COOKIE,
                secrets.token_urlsafe(32),
                httponly=False,
                samesite="strict",
                secure=security.cookie_secure,
                path="/",
            )
        return response

    @app.exception_handler(ConfigError)
    async def config_error_handler(request: Request, exc: ConfigError) -> JSONResponse:
        logger.error("configuration_error", extra={"event": "CFG_INVALID", "detail": exc.message})
        return _error_response(request, ErrorCode.CFG_INVALID, exc.message, 500,
                               exc.recovery_action, exc.context)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        locations = [error.get("loc", ()) for error in exc.errors()]
        return _error_response(
            request, ErrorCode.CFG_INVALID, "Request validation failed.", 422,
            "Check the request fields and retry.",
            {"fields": [list(map(str, location)) for location in locations]},
        )

    @app.exception_handler(HTTPException)
    async def http_error_handler(request: Request, exc: HTTPException) -> JSONResponse:
        detail = exc.detail
        if isinstance(detail, dict) and detail.get("code"):
            try:
                code = ErrorCode(str(detail["code"]))
            except ValueError:
                code = _STATUS_TO_CODE.get(exc.status_code, ErrorCode.INTERNAL_ERROR)
            message = str(detail.get("message", "Request failed."))
            recovery = str(detail.get("recovery_action", "Check the request and retry."))
            context = detail.get("context", {}) or {}
        else:
            code = _STATUS_TO_CODE.get(exc.status_code, ErrorCode.INTERNAL_ERROR)
            message = str(detail)
            recovery = "Check the request and retry."
            context = {}
        logger.warning("http_error", extra={
            "event": code.value, "status_code": exc.status_code, "detail": message,
        })
        return _error_response(request, code, message, exc.status_code, recovery, context)

    @app.exception_handler(Exception)
    async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.error(
            "unhandled_error",
            extra={
                "event": "INTERNAL_ERROR",
                "error_type": type(exc).__name__,
                "detail": str(exc),
            },
        )
        return _error_response(
            request, ErrorCode.INTERNAL_ERROR, "An internal error occurred.", 500,
            "Check the structured event log for the error code and context.",
        )

    app.include_router(health_api.router)
    app.include_router(auth_api.router)
    app.include_router(status_api.router)
    app.include_router(connection_api.router)
    app.mount("/static", StaticFiles(directory=DASHBOARD_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        return FileResponse(DASHBOARD_DIR / "index.html")

    return app


app = create_app()
