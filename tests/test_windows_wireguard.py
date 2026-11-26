"""Windows WireGuard provider tests using injected command results only."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path

from backend.app.config import load_settings
from backend.app.monitoring.models import ErrorCode, StatusValue
from backend.app.services.windows_wireguard import (
    CommandResult,
    WireGuardError,
    WireGuardPaths,
    WireGuardWindowsProvider,
    derive_public_key,
    generate_private_key,
    parse_handshakes,
    parse_peers,
)

ROOT = Path(__file__).resolve().parents[1]
SETTINGS = load_settings(ROOT / "config" / "settings.example.json")
KEY_ONE = base64.b64encode(b"\x01" * 32).decode()
KEY_TWO = base64.b64encode(b"\x02" * 32).decode()


class FakeRunner:
    def __init__(self, responses: dict[tuple[str, ...], CommandResult]):
        self.responses = responses
        self.calls: list[tuple[list[str], str | None]] = []

    def run(self, args, *, input_text=None, timeout=10):
        self.calls.append((args, input_text))
        return self.responses.get(tuple(args), CommandResult(1, "", "unmocked"))


def make_paths(tmp_path: Path) -> WireGuardPaths:
    return WireGuardPaths(wg_exe=Path("wg.exe"), wireguard_exe=Path("wireguard.exe"),
                          config_dir=tmp_path)


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


def test_parse_peers_and_handshakes() -> None:
    assert parse_peers(f"{KEY_ONE}\nnot-a-key\n{KEY_TWO}\n") == [KEY_ONE, KEY_TWO]
    parsed = parse_handshakes(f"{KEY_ONE}\t2026-11-25 15:30:00\n{KEY_TWO}\tnever\n")
    assert list(parsed) == [KEY_ONE]
    assert parsed[KEY_ONE].year == 2026


def test_handshakes_use_local_timezone(monkeypatch) -> None:
    """wg.exe prints local time; stamping it UTC would skew recency checks."""
    from backend.app.services import windows_wireguard as wg

    offset = timezone(timedelta(hours=5, minutes=30))
    monkeypatch.setattr(wg, "local_tzinfo", lambda: offset)
    parsed = wg.parse_handshakes(f"{KEY_ONE}\t2026-11-26 12:00:00\n")
    observed = parsed[KEY_ONE]
    assert observed.utcoffset() == timedelta(hours=5, minutes=30)
    assert observed.astimezone(timezone.utc).hour == 6


def test_status_offline_without_tools(tmp_path: Path) -> None:
    provider = WireGuardWindowsProvider(SETTINGS, FakeRunner({}), make_paths(tmp_path))
    assert provider.status() == StatusValue.OFFLINE
    assert provider.connected_clients() is None
    assert provider.data_available() is False
    codes = {check.code for check in provider.diagnostics()}
    assert ErrorCode.WIREGUARD_SERVICE_FAILURE in codes
    assert ErrorCode.PUBLIC_ENDPOINT_MISSING in codes


def test_status_online_only_with_recent_handshake(tmp_path: Path) -> None:
    provider = WireGuardWindowsProvider(
        SETTINGS, online_responses(datetime.now().astimezone()), make_paths(tmp_path)
    )
    assert provider.status() == StatusValue.ONLINE
    assert provider.connected_clients() == 1
    assert provider.data_available() is True
    checks = {check.name: check for check in provider.diagnostics()}
    assert checks["handshake"].status == "PASS"
    assert checks["tunnel_service"].status == "PASS"


def test_stale_handshake_is_degraded(tmp_path: Path) -> None:
    old = datetime.now().astimezone() - timedelta(days=2)
    provider = WireGuardWindowsProvider(SETTINGS, online_responses(old), make_paths(tmp_path))
    assert provider.status() == StatusValue.DEGRADED
    assert provider.connected_clients() == 0
    handshake = {check.name: check for check in provider.diagnostics()}["handshake"]
    assert handshake.status == "FAIL"
    assert handshake.code == ErrorCode.HANDSHAKE_FAILED


def test_service_stopped_returns_no_client_data(tmp_path: Path) -> None:
    runner = FakeRunner({
        ("sc.exe", "query", "WireGuardTunnel$RubeVPN"): CommandResult(0, "STATE : STOPPED", ""),
    })
    provider = WireGuardWindowsProvider(SETTINGS, runner, make_paths(tmp_path))
    assert provider.status() == StatusValue.OFFLINE
    assert provider.connected_clients() is None


def test_key_generation_rejects_invalid_output(tmp_path: Path) -> None:
    runner = FakeRunner({("wg.exe", "genkey"): CommandResult(0, "not-a-key\n", "")})
    try:
        generate_private_key(make_paths(tmp_path), runner)
    except WireGuardError as exc:
        assert exc.code == ErrorCode.WIREGUARD_SERVICE_FAILURE
    else:
        raise AssertionError("invalid key output must be rejected")


def test_public_key_derivation_uses_private_key_on_stdin(tmp_path: Path) -> None:
    runner = FakeRunner({("wg.exe", "pubkey"): CommandResult(0, KEY_TWO + "\n", "")})
    assert derive_public_key(make_paths(tmp_path), KEY_ONE, runner) == KEY_TWO
    assert runner.calls[0][1] == KEY_ONE + "\n"
