"""RubeVPN application factory and wiring."""
from __future__ import annotations

import logging
import platform
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .api import auth as auth_api
from .api import health as health_api
from .api import status as status_api
from .config import ConfigError, load_security_settings, load_settings
from .monitoring.events import EventBuffer, configure_logging
from .monitoring.models import ErrorCode
from .services.vpn_provider import UnavailableProvider
from .services.windows_wireguard import WireGuardWindowsProvider

logger = logging.getLogger(__name__)
DASHBOARD_DIR = Path(__file__).resolve().parents[2] / "dashboard"


def select_provider(settings):
    """Use the real Windows provider only when explicitly configured."""
    if settings.vpn.provider == "wireguard" and platform.system() == "Windows":
        return WireGuardWindowsProvider(settings)
    return UnavailableProvider(settings)


def _error_response(code: ErrorCode, message: str, status_code: int, recovery: str,
                    context: dict[str, object] | None = None) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "code": code.value,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "context": context or {},
            "recovery_action": recovery,
        },
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = load_settings()
    security = load_security_settings()
    events = EventBuffer()
    configure_logging(settings.logging.level, settings.logging.format, events)
    provider = select_provider(settings)
    app.state.settings = settings
    app.state.security = security
    app.state.events = events
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
    async def ensure_csrf_cookie(request: Request, call_next):
        response = await call_next(request)
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
    async def config_error_handler(_request: Request, exc: ConfigError) -> JSONResponse:
        logger.error("configuration_error", extra={"event": "CFG_INVALID", "detail": exc.message})
        return _error_response(
            ErrorCode.CFG_INVALID,
            exc.message,
            500,
            exc.recovery_action,
            exc.context,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
        locations = [error.get("loc", ()) for error in exc.errors()]
        return _error_response(
            ErrorCode.CFG_INVALID,
            "Request validation failed.",
            422,
            "Check the request fields and retry.",
            {"fields": [list(map(str, location)) for location in locations]},
        )

    @app.exception_handler(Exception)
    async def unhandled_error_handler(_request: Request, exc: Exception) -> JSONResponse:
        logger.error(
            "unhandled_error",
            extra={
                "event": "INTERNAL_ERROR",
                "error_type": type(exc).__name__,
                "detail": str(exc),
            },
        )
        return _error_response(
            ErrorCode.INTERNAL_ERROR,
            "An internal error occurred.",
            500,
            "Check the structured event log for the error code and context.",
        )

    app.include_router(health_api.router)
    app.include_router(auth_api.router)
    app.include_router(status_api.router)
    app.mount("/static", StaticFiles(directory=DASHBOARD_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        return FileResponse(DASHBOARD_DIR / "index.html")

    return app


app = create_app()
