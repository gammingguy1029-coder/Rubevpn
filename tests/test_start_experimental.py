"""Tests for the one-click startup helpers and error reporting."""
from __future__ import annotations

import socket
import sys
from pathlib import Path

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


def test_online_banner(capsys) -> None:
    starter.print_online("1.2.3.4:51820", 111, 222, 89)
    output = capsys.readouterr().out
    assert "RUBEVPN SERVICE ONLINE" in output
    assert "Handshake: verified (reply_bytes=89)" in output
    assert "server.log" in output
    assert "tunnel.log" in output
