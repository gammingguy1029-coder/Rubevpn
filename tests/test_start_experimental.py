"""Tests for the one-click startup helpers and error reporting."""
from __future__ import annotations

import socket
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import start_experimental as starter  # noqa: E402


def test_tunnel_id_regex_keeps_hex_characters() -> None:
    match = starter.TUNNEL_ID_RE.search("Tunnel 33697e7f - waiting for connection...")
    assert match is not None
    assert match.group(1) == "33697e7f"


def test_format_error_is_structured() -> None:
    error = starter.StartupError("PORT_CONFLICT", "port busy", "choose another port",
                                 {"port": 51820})
    rendered = starter.format_error(error)
    assert "[ERROR] PORT_CONFLICT" in rendered
    assert "port busy" in rendered
    assert "choose another port" in rendered
    assert "port=51820" in rendered
    assert "timestamp" in rendered


def test_tail_log_returns_last_lines(tmp_path: Path) -> None:
    log = tmp_path / "server.log"
    log.write_text("\n".join(f"line-{n}" for n in range(20)), encoding="utf-8")
    tail = starter.tail_log(log, lines=3)
    assert tail.splitlines() == ["line-17", "line-18", "line-19"]


def test_udp_port_available_detects_occupied_port() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    port = sock.getsockname()[1]
    assert starter.udp_port_available(port) is False
    sock.close()
    assert starter.udp_port_available(port) is True


def test_write_server_env_includes_verification_peer(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(starter, "CFG", tmp_path)
    server = {"private_key": "A" * 44, "public_key": "B" * 44}
    client = {"private_key": "C" * 44, "public_key": "D" * 44}
    verify = {"private_key": "E" * 44, "public_key": "F" * 44}
    starter.write_server_env(server, client, verify)
    content = (tmp_path / "server.env").read_text(encoding="ascii")
    assert "RUBEVPN_WG_VERIFY_PUBLIC_KEY=" + "F" * 44 in content
    assert "RUBEVPN_WG_LISTEN_PORT=51820" in content


def test_ensure_binary_refreshes_outdated_copy(tmp_path: Path, monkeypatch) -> None:
    tools = tmp_path / "tools"
    cfg = tmp_path / "cfg"
    tools.mkdir()
    cfg.mkdir()
    source = tools / "server.exe"
    source.write_bytes(b"new-binary")
    stale = cfg / "server.exe"
    stale.write_bytes(b"old-binary")
    monkeypatch.setattr(starter, "TOOLS", tools)
    monkeypatch.setattr(starter, "CFG", cfg)
    result = starter.ensure_binary("server.exe")
    assert result.read_bytes() == b"new-binary"
    assert starter.ensure_binary("server.exe").read_bytes() == b"new-binary"


def test_online_banner(capsys) -> None:
    starter.print_online("1.2.3.4:51820", 111, 222, 89)
    output = capsys.readouterr().out
    assert "RUBEVPN SERVICE ONLINE" in output
    assert "Handshake: verified (reply_bytes=89)" in output
    assert "server.log" in output
    assert "tunnel.log" in output


def test_read_mtu_defaults_to_1420(monkeypatch) -> None:
    monkeypatch.delenv("RUBEVPN_WG_MTU", raising=False)
    assert starter.read_mtu() == 1420


@pytest.mark.parametrize("value", ["1200", "1400", "1500"])
def test_read_mtu_accepts_valid_values(monkeypatch, value: str) -> None:
    monkeypatch.setenv("RUBEVPN_WG_MTU", value)
    assert starter.read_mtu() == int(value)


@pytest.mark.parametrize("value", ["abc", "", "12.5"])
def test_read_mtu_rejects_non_integer(monkeypatch, capsys, value: str) -> None:
    monkeypatch.setenv("RUBEVPN_WG_MTU", value)
    with pytest.raises(SystemExit) as exc:
        starter.read_mtu()
    assert exc.value.code == 1
    rendered = capsys.readouterr().err
    assert "[ERROR] CFG_INVALID" in rendered
    assert "RUBEVPN_WG_MTU" in rendered
    assert "recovery:  Set RUBEVPN_WG_MTU to an integer from 1200 to 1500" in rendered


@pytest.mark.parametrize("value", ["1199", "1501", "0"])
def test_read_mtu_rejects_out_of_range(monkeypatch, capsys, value: str) -> None:
    monkeypatch.setenv("RUBEVPN_WG_MTU", value)
    with pytest.raises(SystemExit) as exc:
        starter.read_mtu()
    assert exc.value.code == 1
    rendered = capsys.readouterr().err
    assert "[ERROR] CFG_INVALID" in rendered
    assert "outside the supported range 1200..1500" in rendered
    assert "recovery:  Set RUBEVPN_WG_MTU to an integer from 1200 to 1500" in rendered


def test_write_server_env_includes_mtu(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(starter, "CFG", tmp_path)
    monkeypatch.setenv("RUBEVPN_WG_MTU", "1400")
    keys = {"private_key": "A" * 44, "public_key": "B" * 44}
    starter.write_server_env(keys, keys, keys)
    content = (tmp_path / "server.env").read_text(encoding="ascii")
    assert "RUBEVPN_WG_MTU=1400" in content


def test_write_android_profile_includes_mtu(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(starter, "CFG", tmp_path)
    monkeypatch.setenv("RUBEVPN_WG_MTU", "1400")
    server = {"private_key": "A" * 44, "public_key": "B" * 44}
    client = {"private_key": "C" * 44, "public_key": "D" * 44}
    content = starter.write_android_profile(server, client, "1.2.3.4:51820")
    assert "MTU = 1400" in content
    assert "MTU = 1400" in (tmp_path / "phone.conf").read_text(encoding="ascii")


def test_ensure_binary_syncs_speedtest(tmp_path: Path, monkeypatch) -> None:
    tools = tmp_path / "tools"
    cfg = tmp_path / "cfg"
    tools.mkdir()
    cfg.mkdir()
    source = tools / "speedtest.exe"
    source.write_bytes(b"new-probe")
    stale = cfg / "speedtest.exe"
    stale.write_bytes(b"old-probe")
    monkeypatch.setattr(starter, "TOOLS", tools)
    monkeypatch.setattr(starter, "CFG", cfg)
    result = starter.ensure_binary("speedtest.exe")
    assert result.read_bytes() == b"new-probe"
    assert starter.ensure_binary("speedtest.exe").read_bytes() == b"new-probe"


def test_run_speedtest_uses_verification_env(tmp_path: Path, monkeypatch, capsys) -> None:
    tools = tmp_path / "tools"
    cfg = tmp_path / "cfg"
    tools.mkdir()
    cfg.mkdir()
    (tools / "speedtest.exe").write_bytes(b"probe")
    monkeypatch.setattr(starter, "TOOLS", tools)
    monkeypatch.setattr(starter, "CFG", cfg)
    captured: dict[str, object] = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        captured["env"] = kwargs["env"]
        return SimpleNamespace(returncode=0, stdout="PROBE_OK 42 Mbps\n", stderr="")

    monkeypatch.setattr(starter.subprocess, "run", fake_run)
    server = {"public_key": "B" * 44}
    verify = {"private_key": "E" * 44}
    starter.run_speedtest(server, verify, "1.2.3.4:51820")
    env = captured["env"]
    assert env["RUBEVPN_WG_PRIVATE_KEY"] == "E" * 44
    assert env["RUBEVPN_WG_SERVER_PUBLIC_KEY"] == "B" * 44
    assert env["RUBEVPN_WG_LOCAL_ADDRESS"] == "10.0.0.3"
    assert env["RUBEVPN_TEST_ENDPOINT"] == "1.2.3.4:51820"
    assert "PROBE_OK 42 Mbps" in capsys.readouterr().out


def test_run_speedtest_failure_is_structured(tmp_path: Path, monkeypatch, capsys) -> None:
    tools = tmp_path / "tools"
    cfg = tmp_path / "cfg"
    tools.mkdir()
    cfg.mkdir()
    (tools / "speedtest.exe").write_bytes(b"probe")
    monkeypatch.setattr(starter, "TOOLS", tools)
    monkeypatch.setattr(starter, "CFG", cfg)

    def fake_run(args, **kwargs):
        return SimpleNamespace(returncode=1, stdout="partial", stderr="probe error")

    monkeypatch.setattr(starter.subprocess, "run", fake_run)
    with pytest.raises(SystemExit) as exc:
        starter.run_speedtest({"public_key": "B" * 44}, {"private_key": "E" * 44},
                              "1.2.3.4:51820")
    assert exc.value.code == 1
    rendered = capsys.readouterr().err
    assert "[ERROR] SPEEDTEST_FAILED" in rendered
    assert "recovery:" in rendered
    assert "optional" in rendered
