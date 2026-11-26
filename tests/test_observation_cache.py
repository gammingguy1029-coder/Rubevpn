"""Tests for the short-lived observation cache in WireGuardWindowsProvider.

A dashboard poll touches status(), connected_clients(), data_available(),
health_check() and diagnostics().  Without an observation cache each of those
re-runs sc.exe / wg.exe / reg query.  These tests pin the subprocess count down
to one set of observations per TTL window while keeping the reported values
correct.
"""
from __future__ import annotations

import base64
import time
from datetime import datetime, timezone
from pathlib import Path

from backend.app.config import load_settings
from backend.app.monitoring.models import StatusValue
from backend.app.services.windows_wireguard import (
    CommandResult,
    WireGuardPaths,
    WireGuardWindowsProvider,
)

ROOT = Path(__file__).resolve().parents[1]

try:  # tests/ is not necessarily an importable package
    from tests.test_windows_wireguard import (
        KEY_ONE,
        SETTINGS,
        FakeRunner,
        make_paths,
        online_responses,
    )
except ImportError:
    SETTINGS = load_settings(ROOT / "config" / "settings.example.json")
    KEY_ONE = base64.b64encode(b"\x01" * 32).decode()

    class FakeRunner:
        def __init__(self, responses: dict[tuple[str, ...], CommandResult]):
            self.responses = responses
            self.calls: list[tuple[list[str], str | None]] = []

        def run(self, args, *, input_text=None, timeout=10):
            self.calls.append((args, input_text))
            return self.responses.get(tuple(args), CommandResult(1, "", "unmocked"))

    def make_paths(tmp_path: Path) -> WireGuardPaths:
        return WireGuardPaths(
            wg_exe=Path("wg.exe"),
            wireguard_exe=Path("wireguard.exe"),
            config_dir=tmp_path,
        )

    def online_responses(handshake_time: datetime) -> FakeRunner:
        stamp = handshake_time.strftime("%Y-%m-%d %H:%M:%S")
        return FakeRunner({
            ("sc.exe", "query", "WireGuardTunnel$RubeVPN"):
                CommandResult(0, "STATE : RUNNING", ""),
            ("wg.exe", "show", "RubeVPN", "peers"): CommandResult(0, KEY_ONE + "\n", ""),
            ("wg.exe", "show", "RubeVPN", "latest handshakes"):
                CommandResult(0, f"{KEY_ONE}\t{stamp}\n", ""),
            ("reg", "query", r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
             "/v", "IPEnableRouter"): CommandResult(0, "IPEnableRouter REG_DWORD 0x1", ""),
        })


# The four subprocesses a single WireGuard observation is allowed to spawn.
OBSERVATION_COMMANDS = {
    "service_status": ["sc.exe", "query", "WireGuardTunnel$RubeVPN"],
    "peers": ["wg.exe", "show", "RubeVPN", "peers"],
    "handshakes": ["wg.exe", "show", "RubeVPN", "latest handshakes"],
    "ip_forwarding": [
        "reg", "query",
        r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
        "/v", "IPEnableRouter",
    ],
}


def _count_calls(calls, command: list[str]) -> int:
    """Count recorded command invocations by their argument list."""
    return sum(1 for args, _input_text in calls if args == command)


def _command_counts(runner: FakeRunner) -> dict[str, int]:
    return {
        name: _count_calls(runner.calls, command)
        for name, command in OBSERVATION_COMMANDS.items()
    }


def test_all_public_methods_share_one_observation_within_ttl(tmp_path: Path) -> None:
    runner = online_responses(datetime.now().astimezone())
    provider = WireGuardWindowsProvider(SETTINGS, runner, make_paths(tmp_path))

    # Simulate several dashboard polls: every public method is called on each.
    for _ in range(4):
        assert provider.status() == StatusValue.ONLINE
        assert provider.connected_clients() == 1
        assert provider.data_available() is True
        assert provider.health_check().status == StatusValue.ONLINE
        checks = {check.name: check for check in provider.diagnostics()}
        assert checks["tunnel_service"].status == "PASS"
        assert checks["handshake"].status == "PASS"

    counts = _command_counts(runner)
    assert counts == {name: 1 for name in OBSERVATION_COMMANDS}, counts
    assert len(runner.calls) == len(OBSERVATION_COMMANDS)


def test_zero_ttl_expires_cache_and_reruns_commands(tmp_path: Path) -> None:
    runner = online_responses(datetime.now().astimezone())
    provider = WireGuardWindowsProvider(
        SETTINGS, runner, make_paths(tmp_path), observation_ttl=0
    )

    assert provider.status() == StatusValue.ONLINE
    first = _command_counts(runner)
    assert all(count >= 1 for count in first.values()), first

    time.sleep(0.005)
    assert provider.connected_clients() == 1
    second = _command_counts(runner)
    assert all(second[name] > first[name] for name in first), (first, second)

    time.sleep(0.005)
    assert provider.data_available() is True
    third = _command_counts(runner)
    assert all(third[name] > second[name] for name in second), (second, third)

    time.sleep(0.005)
    assert provider.health_check().status == StatusValue.ONLINE
    fourth = _command_counts(runner)
    assert all(fourth[name] > third[name] for name in third), (third, fourth)
