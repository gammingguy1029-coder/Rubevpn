"""Authenticated monitoring endpoints backed by real provider data."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request

from ..monitoring.health import build_snapshot
from ..monitoring.models import MonitoringSnapshot
from .auth import require_admin

router = APIRouter(prefix="/api/v1", tags=["status"])


@router.get("/status", response_model=MonitoringSnapshot)
def status(request: Request, _claims: dict[str, Any] = Depends(require_admin)) -> MonitoringSnapshot:
    return build_snapshot(
        request.app.state.settings,
        request.app.state.provider,
        request.app.state.events,
        request.app.state.started_monotonic,
    )


@router.get("/events")
def events(request: Request, _claims: dict[str, Any] = Depends(require_admin)) -> dict[str, object]:
    return {"events": request.app.state.events.recent(50)}


@router.get("/diagnostics")
def diagnostics(request: Request, _claims: dict[str, Any] = Depends(require_admin)) -> dict[str, object]:
    return {"checks": [check.model_dump(mode="json") for check in request.app.state.provider.diagnostics()]}
