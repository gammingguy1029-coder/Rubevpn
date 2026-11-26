"""Read-only probes for what this host is actually capable of.

The dashboard must report measured facts, not a hard-coded "ineligible"
assumption. These helpers are shared by the application and the preflight
script so both surfaces agree. No function here changes system state.
"""
from __future__ import annotations

import ctypes
import os
import platform
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..config import AppSettings
from .windows_wireguard import (
    CommandRunner,
    SystemCommandRunner,
    discover_paths,
    ip_forwarding_enabled,
)


@dataclass(frozen=True)
class HostCapabilities:
    elevated: bool
    ip_forwarding: bool
    wireguard_installed: bool
    endpoint_configured: bool
    endpoint_bound_locally: bool
    # Inbound UDP cannot be proven from this host; only an external probe can.
    inbound_udp: bool = False

    @property
    def privileged(self) -> bool:
        return self.elevated and self.ip_forwarding

    @property
    def public_endpoint(self) -> bool:
        return self.endpoint_configured and self.endpoint_bound_locally


def is_admin() -> bool:
    if platform.system() == "Windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def wireguard_installed(paths: Any | None = None) -> bool:
    paths = paths or discover_paths()
    return paths.wg_exe is not None


def endpoint_bound_locally(endpoint: str | None) -> bool:
    """True when the configured endpoint resolves to a local interface address.

    Uses a UDP connect (which sends no packets) to find the primary outbound
    address, plus local name resolution. No external HTTP service is needed.
    """
    if not endpoint:
        return False
    try:
        target = socket.gethostbyname(endpoint)
    except OSError:
        return False
    local: set[str] = set()
    try:
        local.add(socket.gethostbyname(socket.gethostname()))
        local.update(
            info[4][0]
            for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
        )
    except OSError:
        pass
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))  # TEST-NET-1: no traffic is sent
        local.add(probe.getsockname()[0])
    except OSError:
        pass
    finally:
        probe.close()
    return target in local


def probe_capabilities(settings: AppSettings, *, runner: CommandRunner | None = None,
                       paths: Any | None = None) -> HostCapabilities:
    """Collect host capabilities once; never writes to disk or system state."""
    paths = paths or discover_paths()
    active_runner = runner or SystemCommandRunner()
    endpoint = settings.vpn.endpoint_host
    return HostCapabilities(
        elevated=is_admin(),
        ip_forwarding=ip_forwarding_enabled(active_runner),
        wireguard_installed=wireguard_installed(paths),
        endpoint_configured=bool(endpoint),
        endpoint_bound_locally=endpoint_bound_locally(endpoint),
    )
