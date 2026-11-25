"""Aggregate real provider observations into the dashboard snapshot."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from ..config import AppSettings
from ..services.vpn_provider import VpnProvider
from .events import EventBuffer
from .models import ErrorInfo, MonitoringSnapshot, StatusValue


def build_snapshot(settings: AppSettings, provider: VpnProvider, events: EventBuffer,
                   started_monotonic: float) -> MonitoringSnapshot:
    checks = provider.diagnostics()
    report = provider.health_check()
    errors = [
        ErrorInfo(
            code=check.code,
            message=check.message,
            timestamp=check.checked_at,
            context={"check": check.name},
            recovery_action=check.recovery_action,
        )
        for check in checks
        if check.status == "FAIL"
    ]
    return MonitoringSnapshot(
        app_version=settings.app_version,
        status=report.status,
        session_status=StatusValue.OFFLINE if report.status != StatusValue.ONLINE else report.status,
        uptime_seconds=max(0, int(time.monotonic() - started_monotonic)),
        session_expires_at=None,
        connected_clients=provider.connected_clients(),
        data_available=provider.data_available(),
        last_health_check=report.checked_at,
        diagnostics=checks,
        errors=errors,
        notes="No VPN session exists on this host. Client counts are null rather than fabricated.",
        refresh_seconds=settings.dashboard.refresh_seconds,
        generated_at=datetime.now(timezone.utc),
    )
