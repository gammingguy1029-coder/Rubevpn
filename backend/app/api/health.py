"""Public liveness endpoint (no secrets, no internal host details)."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Request

router = APIRouter(tags=["health"])


@router.get("/health")
def health(request: Request) -> dict[str, object]:
    return {
        "status": "ok",
        "app_version": request.app.state.settings.app_version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
