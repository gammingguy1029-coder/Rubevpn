"""Authenticated connection control and device enrollment endpoints."""
from __future__ import annotations

import subprocess
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..monitoring.models import ErrorCode
from ..services import tunnel_controller as controller
from .auth import require_admin, require_csrf

router = APIRouter(prefix="/api/v1", tags=["connection"])


class DeviceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)


def _error(code: ErrorCode, message: str, status: int = 500,
           recovery: str = "Check the structured event log for details.") -> HTTPException:
    return HTTPException(status_code=status, detail={
        "code": code.value,
        "message": message,
        "recovery_action": recovery,
    })


@router.get("/connection")
def get_connection(_claims: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
    return controller.state()


@router.post("/connection/start")
def start_connection(_claims: dict[str, Any] = Depends(require_admin),
                     _csrf: None = Depends(require_csrf)) -> dict[str, Any]:
    try:
        return controller.start()
    except (OSError, subprocess.SubprocessError) as exc:
        raise _error(ErrorCode.INTERNAL_ERROR, str(exc)[:300]) from exc


@router.post("/connection/stop")
def stop_connection(_claims: dict[str, Any] = Depends(require_admin),
                    _csrf: None = Depends(require_csrf)) -> dict[str, Any]:
    try:
        return controller.stop()
    except Exception as exc:
        raise _error(ErrorCode.INTERNAL_ERROR, str(exc)[:300]) from exc


@router.get("/devices")
def get_devices(_claims: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
    return {"devices": controller.list_devices()}


@router.post("/devices")
def create_device(payload: DeviceCreate,
                  _claims: dict[str, Any] = Depends(require_admin),
                  _csrf: None = Depends(require_csrf)) -> dict[str, Any]:
    try:
        return controller.add_device(payload.name)
    except ValueError as exc:
        raise _error(ErrorCode.CFG_INVALID, str(exc), 400,
                     "Use a name with letters, digits, spaces, '-' or '_'.") from exc
    except Exception as exc:
        raise _error(ErrorCode.INTERNAL_ERROR, str(exc)[:300]) from exc


@router.delete("/devices/{device_id}")
def delete_device(device_id: str,
                  _claims: dict[str, Any] = Depends(require_admin),
                  _csrf: None = Depends(require_csrf)) -> dict[str, Any]:
    try:
        return controller.remove_device(device_id)
    except ValueError as exc:
        raise _error(ErrorCode.CFG_INVALID, str(exc), 400,
                     "Supply a device id from the device list.") from exc
    except Exception as exc:
        raise _error(ErrorCode.INTERNAL_ERROR, str(exc)[:300]) from exc
