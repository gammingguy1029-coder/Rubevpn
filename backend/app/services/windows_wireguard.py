"""Windows WireGuard integration behind the provider interface.

All operational values come from real `wg.exe` / Windows service observations.
When WireGuard is absent or the service is down, this provider reports OFFLINE
and returns null client counts instead of inventing data.
"""
from __future__ import annotations

import base64
import os
import re
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Protocol

from ..config import AppSettings
from ..monitoring.models import DiagnosticCheck, ErrorCode, HealthReport, StatusValue

HANDSHAKE_WINDOW = timedelta(seconds=180)
# One dashboard refresh polls several endpoints at once. Reuse a single set of
# system observations for this long so a poll spawns one command set, not one
# per endpoint.
OBSERVATION_TTL_SECONDS = 1.0
_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")


class WireGuardError(Exception):
    def __init__(self, code: ErrorCode, message: str, recovery_action: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.recovery_action = recovery_action


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass
class Observation:
    """One coherent, time-bounded set of real WireGuard host observations."""

    state: str
    peers: list[str]
    handshakes: dict[str, datetime]
    ip_forwarding: bool
    observed_at: float


class CommandRunner(Protocol):
    def run(self, args: list[str], *, input_text: str | None = None,
            timeout: int = 10) -> CommandResult: ...


class SystemCommandRunner:
    def run(self, args: list[str], *, input_text: str | None = None,
            timeout: int = 10) -> CommandResult:
        try:
            completed = subprocess.run(
                args, input=input_text, capture_output=True, text=True,
                timeout=timeout, shell=False,
            )
        except subprocess.TimeoutExpired:
            return CommandResult(124, "", "command timed out")
        except OSError as exc:
            return CommandResult(127, "", type(exc).__name__)
        return CommandResult(completed.returncode, completed.stdout, completed.stderr)


@dataclass
class WireGuardPaths:
    wg_exe: Path | None
    wireguard_exe: Path | None
    config_dir: Path

    def config_path(self, interface_name: str) -> Path:
        return self.config_dir / f"{interface_name}.conf"


def discover_paths(runner: CommandRunner | None = None, *,
                   program_files: str | None = None,
                   program_data: str | None = None) -> WireGuardPaths:
    """Locate WireGuard for Windows. Never creates or modifies anything."""
    pf = program_files or os.getenv("ProgramFiles", r"C:\Program Files")
    fx86 = r"C:\Program Files (x86)"
    roots = [Path(pf) / "WireGuard"]
    if fx86.lower() not in pf.lower():
        roots.append(Path(fx86) / "WireGuard")
    wg_exe = None
    wireguard_exe = None
    for root in roots:
        candidate = root / "wg.exe"
        if candidate.is_file():
            wg_exe = candidate
            manager = root / "wireguard.exe"
            wireguard_exe = manager if manager.is_file() else None
            break
    pd = program_data or os.getenv("ProgramData", r"C:\ProgramData")
    return WireGuardPaths(wg_exe, wireguard_exe, Path(pd) / "RubeVPN" / "wireguard")


def is_valid_wireguard_key(value: str) -> bool:
    if not _KEY_RE.match(value):
        return False
    try:
        return len(base64.b64decode(value, validate=True)) == 32
    except (ValueError, TypeError):
        return False


def generate_private_key(paths: WireGuardPaths, runner: CommandRunner) -> str:
    if paths.wg_exe is None:
        raise WireGuardError(
            ErrorCode.WIREGUARD_SERVICE_FAILURE,
            "wg.exe was not found; cannot generate a key.",
            "Install WireGuard for Windows on the authorized host.",
        )
    result = runner.run([str(paths.wg_exe), "genkey"])
    key = result.stdout.strip()
    if result.returncode != 0 or not is_valid_wireguard_key(key):
        raise WireGuardError(
            ErrorCode.WIREGUARD_SERVICE_FAILURE,
            "Key generation failed or produced an invalid key.",
            "Verify the WireGuard installation and retry.",
        )
    return key


def derive_public_key(paths: WireGuardPaths, private_key: str, runner: CommandRunner) -> str:
    if paths.wg_exe is None:
        raise WireGuardError(
            ErrorCode.WIREGUARD_SERVICE_FAILURE,
            "wg.exe was not found; cannot derive a public key.",
            "Install WireGuard for Windows on the authorized host.",
        )
    if not is_valid_wireguard_key(private_key):
        raise WireGuardError(
            ErrorCode.CFG_INVALID,
            "The supplied private key is not a valid WireGuard key.",
            "Generate a fresh keypair with the setup script.",
        )
    result = runner.run([str(paths.wg_exe), "pubkey"], input_text=private_key + "\n")
    key = result.stdout.strip()
    if result.returncode != 0 or not is_valid_wireguard_key(key):
        raise WireGuardError(
            ErrorCode.WIREGUARD_SERVICE_FAILURE,
            "Public key derivation failed.",
            "Verify the WireGuard installation and retry.",
        )
    return key


def service_name(interface_name: str) -> str:
    return f"WireGuardTunnel${interface_name}"


def service_status(interface_name: str, runner: CommandRunner) -> str:
    result = runner.run(["sc.exe", "query", service_name(interface_name)])
    if result.returncode != 0:
        return "ABSENT"
    if "RUNNING" in result.stdout.upper():
        return "RUNNING"
    if "STOPPED" in result.stdout.upper():
        return "STOPPED"
    return "UNKNOWN"


def parse_peers(output: str) -> list[str]:
    return [line.strip() for line in output.splitlines() if is_valid_wireguard_key(line.strip())]


def local_tzinfo() -> timezone | None:
    """The host's current local timezone, used to interpret wg.exe timestamps."""
    return datetime.now().astimezone().tzinfo


def parse_handshakes(output: str) -> dict[str, datetime]:
    """Parse `wg show <iface> latest handshakes` output.

    `wg.exe` prints timestamps in the host's local timezone, not UTC. Attaching
    UTC here would make recency checks off by the UTC offset on non-UTC hosts.
    """
    handshakes: dict[str, datetime] = {}
    local_tz = local_tzinfo()
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 3 or not is_valid_wireguard_key(parts[0]):
            continue
        try:
            stamp = datetime.strptime(f"{parts[1]} {parts[2]}", "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
        handshakes[parts[0]] = stamp.replace(tzinfo=local_tz)
    return handshakes


def ip_forwarding_enabled(runner: CommandRunner) -> bool:
    result = runner.run([
        "reg", "query", r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
        "/v", "IPEnableRouter",
    ])
    if result.returncode != 0:
        return False
    return re.search(r"0x1\b", result.stdout) is not None


class WireGuardWindowsProvider:
    """Real Windows WireGuard observations; never fabricates connection state."""

    def __init__(self, settings: AppSettings, runner: CommandRunner | None = None,
                 paths: WireGuardPaths | None = None,
                 observation_ttl: float = OBSERVATION_TTL_SECONDS) -> None:
        self.settings = settings
        self.runner = runner or SystemCommandRunner()
        self.paths = paths or discover_paths()
        self.interface = settings.vpn.interface_name
        self.observation_ttl = max(0.0, observation_ttl)
        self._observation: Observation | None = None

    def _observed(self) -> Observation:
        """Return one cached observation, refreshing it after the TTL expires."""
        now = time.monotonic()
        cached = self._observation
        if cached is not None and now - cached.observed_at < self.observation_ttl:
            return cached
        state, peers, handshakes = self._state()
        observation = Observation(
            state=state,
            peers=peers,
            handshakes=handshakes,
            ip_forwarding=ip_forwarding_enabled(self.runner),
            observed_at=now,
        )
        self._observation = observation
        return observation

    def _show(self, field: str) -> str:
        if self.paths.wg_exe is None:
            raise WireGuardError(
                ErrorCode.WIREGUARD_SERVICE_FAILURE,
                "WireGuard command-line tools are not installed.",
                "Install WireGuard for Windows on the authorized host.",
            )
        result = self.runner.run([str(self.paths.wg_exe), "show", self.interface, field])
        if result.returncode != 0:
            raise WireGuardError(
                ErrorCode.WIREGUARD_SERVICE_FAILURE,
                f"wg show {field} failed for interface {self.interface}.",
                "Check that the tunnel service is installed and running.",
            )
        return result.stdout

    def _observations(self) -> tuple[list[str], dict[str, datetime]]:
        return parse_peers(self._show("peers")), parse_handshakes(self._show("latest handshakes"))

    def _state(self) -> tuple[str, list[str], dict[str, datetime]]:
        if self.paths.wg_exe is None:
            return "NO_TOOLS", [], {}
        state = service_status(self.interface, self.runner)
        if state != "RUNNING":
            return state, [], {}
        try:
            peers, handshakes = self._observations()
        except WireGuardError:
            return "SHOW_FAILED", [], {}
        return state, peers, handshakes

    @staticmethod
    def _recent(handshakes: dict[str, datetime]) -> list[str]:
        threshold = datetime.now(timezone.utc) - HANDSHAKE_WINDOW
        return [key for key, stamp in handshakes.items() if stamp >= threshold]

    def data_available(self) -> bool:
        return self._observed().state == "RUNNING"

    def status(self) -> StatusValue:
        observed = self._observed()
        if observed.state in {"NO_TOOLS", "ABSENT", "STOPPED", "UNKNOWN", "SHOW_FAILED"}:
            return StatusValue.OFFLINE
        if not observed.peers:
            return StatusValue.DEGRADED
        return StatusValue.ONLINE if self._recent(observed.handshakes) else StatusValue.DEGRADED

    def connected_clients(self) -> int | None:
        observed = self._observed()
        if observed.state != "RUNNING":
            return None
        return len(self._recent(observed.handshakes))

    def diagnostics(self) -> list[DiagnosticCheck]:
        now = datetime.now(timezone.utc)
        observed = self._observed()
        checks: list[DiagnosticCheck] = []
        if not self.settings.vpn.endpoint_host:
            checks.append(DiagnosticCheck(
                name="public_endpoint", status="FAIL", code=ErrorCode.PUBLIC_ENDPOINT_MISSING,
                message="No public endpoint is configured for the WireGuard host.",
                recovery_action="Set vpn.endpoint_host to the host's public IPv4 address.",
                checked_at=now,
            ))
        if self.paths.wg_exe is None:
            checks.append(DiagnosticCheck(
                name="wireguard_tools", status="FAIL", code=ErrorCode.WIREGUARD_SERVICE_FAILURE,
                message="wg.exe was not found on this Windows host.",
                recovery_action="Install WireGuard for Windows.", checked_at=now,
            ))
        else:
            checks.append(DiagnosticCheck(
                name="tunnel_service",
                status="PASS" if observed.state == "RUNNING" else "FAIL",
                code=ErrorCode.WIREGUARD_SERVICE_FAILURE,
                message=f"Tunnel service {service_name(self.interface)} is {observed.state}.",
                recovery_action="Install and start the tunnel service with scripts/setup_windows.py --apply.",
                checked_at=now,
            ))
        if not observed.ip_forwarding:
            checks.append(DiagnosticCheck(
                name="ip_forwarding", status="FAIL", code=ErrorCode.NO_PRIVILEGE,
                message="IPv4 forwarding is disabled or cannot be read.",
                recovery_action="Run the elevated setup with --apply to enable forwarding and NAT.",
                checked_at=now,
            ))
        if observed.state == "RUNNING":
            recent = self._recent(observed.handshakes)
            checks.append(DiagnosticCheck(
                name="handshake",
                status="PASS" if recent else "FAIL",
                code=ErrorCode.HANDSHAKE_FAILED,
                message=f"{len(recent)} of {len(observed.peers)} peers completed a recent handshake.",
                recovery_action="Confirm the Android profile endpoint/port and inbound UDP access.",
                checked_at=now,
            ))
        return checks

    def health_check(self) -> HealthReport:
        return HealthReport(
            status=self.status(),
            checked_at=datetime.now(timezone.utc),
            details=f"Windows WireGuard interface {self.interface}; "
                    f"client count from wg.exe only.",
        )
