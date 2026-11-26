"""Data models shared by monitoring, API, and dashboard."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class StatusValue(str, Enum):
    STARTING = "STARTING"
    ONLINE = "ONLINE"
    DEGRADED = "DEGRADED"
    OFFLINE = "OFFLINE"
    EXPIRED = "EXPIRED"
    ERROR = "ERROR"


class ErrorCode(str, Enum):
    CFG_INVALID = "CFG_INVALID"
    MISSING_DEPENDENCY = "MISSING_DEPENDENCY"
    INSTALL_FAILED = "INSTALL_FAILED"
    DNS_FAILURE = "DNS_FAILURE"
    UDP_UNREACHABLE = "UDP_UNREACHABLE"
    PUBLIC_ENDPOINT_MISSING = "PUBLIC_ENDPOINT_MISSING"
    WIREGUARD_SERVICE_FAILURE = "WIREGUARD_SERVICE_FAILURE"
    HANDSHAKE_FAILED = "HANDSHAKE_FAILED"
    AUTH_FAILED = "AUTH_FAILED"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    CSRF_FAILED = "CSRF_FAILED"
    AUTH_RATE_LIMITED = "AUTH_RATE_LIMITED"
    SERVER_EXPIRED = "SERVER_EXPIRED"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    CLIENT_DISCONNECTED = "CLIENT_DISCONNECTED"
    DASHBOARD_API_FAILURE = "DASHBOARD_API_FAILURE"
    NO_PRIVILEGE = "NO_PRIVILEGE"
    PORT_CONFLICT = "PORT_CONFLICT"
    ACL_FAILURE = "ACL_FAILURE"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class DiagnosticCheck(BaseModel):
    name: str
    status: str = Field(pattern=r"^(PASS|FAIL|SKIP)$")
    code: ErrorCode
    message: str
    recovery_action: str
    checked_at: datetime


class ErrorInfo(BaseModel):
    code: ErrorCode
    message: str
    timestamp: datetime
    context: dict[str, Any] = Field(default_factory=dict)
    recovery_action: str


class HealthReport(BaseModel):
    status: StatusValue
    checked_at: datetime
    details: str


class MonitoringSnapshot(BaseModel):
    app_version: str
    status: StatusValue
    session_status: StatusValue
    uptime_seconds: int
    session_expires_at: datetime | None = None
    admin_session_expires_at: datetime | None = None
    connected_clients: int | None = None
    data_available: bool = False
    last_health_check: datetime | None = None
    diagnostics: list[DiagnosticCheck] = Field(default_factory=list)
    errors: list[ErrorInfo] = Field(default_factory=list)
    notes: str = ""
    refresh_seconds: int = 5
    generated_at: datetime
