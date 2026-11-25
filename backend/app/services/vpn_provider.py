"""VPN provider abstraction.

M1 exposes only an UnavailableProvider. It reports the real, measured
limitations of the current host and never invents a client or a handshake.
A future WireGuardHostProvider implements the same interface on an
authorized host without changing the API or dashboard.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol

from ..config import AppSettings
from ..monitoring.models import DiagnosticCheck, ErrorCode, HealthReport, StatusValue


def _now() -> datetime:
    return datetime.now(timezone.utc)


class VpnProvider(Protocol):
    def status(self) -> StatusValue: ...

    def connected_clients(self) -> int | None: ...

    def diagnostics(self) -> list[DiagnosticCheck]: ...

    def health_check(self) -> HealthReport: ...

    def data_available(self) -> bool: ...


class UnavailableProvider:
    """Honest provider for hosts that cannot terminate a public VPN tunnel."""

    def __init__(self, settings: AppSettings, *, public_endpoint: bool = False, privileged: bool = False,
                 wireguard_installed: bool = False, inbound_udp: bool = False) -> None:
        self.settings = settings
        self.public_endpoint = public_endpoint
        self.privileged = privileged
        self.wireguard_installed = wireguard_installed
        self.inbound_udp = inbound_udp
        self.port = settings.vpn.endpoint_port

    def status(self) -> StatusValue:
        return StatusValue.OFFLINE

    def connected_clients(self) -> int | None:
        return None

    def data_available(self) -> bool:
        return False

    def diagnostics(self) -> list[DiagnosticCheck]:
        now = _now()
        checks: list[DiagnosticCheck] = []
        if not self.public_endpoint:
            checks.append(DiagnosticCheck(
                name="public_endpoint",
                status="FAIL",
                code=ErrorCode.PUBLIC_ENDPOINT_MISSING,
                message="No public IPv4 endpoint is bound to this host. The visible address is a shared outbound NAT address.",
                recovery_action="Deploy on an authorized host with a static public IPv4 address.",
                checked_at=now,
            ))
        if not self.inbound_udp:
            checks.append(DiagnosticCheck(
                name="inbound_udp",
                status="FAIL",
                code=ErrorCode.UDP_UNREACHABLE,
                message=f"Inbound UDP on port {self.port} is not reachable. NAT maps ephemeral source ports, not the configured port.",
                recovery_action="Use a host with inbound UDP forwarding for the WireGuard port.",
                checked_at=now,
            ))
        if not self.privileged:
            checks.append(DiagnosticCheck(
                name="ip_forwarding",
                status="FAIL",
                code=ErrorCode.NO_PRIVILEGE,
                message="IP forwarding and NAT cannot be enabled without administrator/root privileges.",
                recovery_action="Provision the VPN host with the privileges required to configure forwarding.",
                checked_at=now,
            ))
        if not self.wireguard_installed:
            checks.append(DiagnosticCheck(
                name="wireguard_service",
                status="FAIL",
                code=ErrorCode.WIREGUARD_SERVICE_FAILURE,
                message="WireGuard userspace tools/service are not installed on this host.",
                recovery_action="Install WireGuard on the authorized VPN host before enabling the provider.",
                checked_at=now,
            ))
        if not checks:
            checks.append(DiagnosticCheck(
                name="provider",
                status="SKIP",
                code=ErrorCode.CFG_INVALID,
                message="No WireGuard host provider is configured for this milestone.",
                recovery_action="Configure a WireGuardHostProvider on an authorized host.",
                checked_at=now,
            ))
        return checks

    def health_check(self) -> HealthReport:
        return HealthReport(
            status=self.status(),
            checked_at=_now(),
            details="VPN endpoint unavailable: no real tunnel or handshake data exists on this host.",
        )
