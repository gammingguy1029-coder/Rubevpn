"""Tests for the one-click startup helpers and error reporting."""
from __future__ import annotations

import json
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
    monkeypatch.setenv("RUBEVPN_SKIP_BINARY_VERIFY", "1")  # fixture bytes are not the pinned binary
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
    monkeypatch.setenv("RUBEVPN_SKIP_BINARY_VERIFY", "1")  # fixture bytes are not the pinned binary
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
    monkeypatch.setenv("RUBEVPN_SKIP_BINARY_VERIFY", "1")  # fixture bytes are not the pinned binary
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
    monkeypatch.setenv("RUBEVPN_SKIP_BINARY_VERIFY", "1")  # fixture bytes are not the pinned binary

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


def test_safe_stop_pid_refuses_recycled_pid(monkeypatch) -> None:
    killed: list[list[str]] = []
    monkeypatch.setattr(starter, "process_alive", lambda pid: True)
    monkeypatch.setattr(starter, "_process_creation_ticks", lambda pid: 999)
    monkeypatch.setattr(starter.subprocess, "run",
                        lambda args, **kwargs: killed.append(list(args)))

    starter.safe_stop_pid(4242, ("server.exe",), 111)
    assert killed == [], "a recycled PID must never be killed"

    starter.safe_stop_pid(4242, ("server.exe",), 999)
    assert len(killed) == 1
    assert "4242" in killed[0]


def test_write_state_records_process_identity(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(starter, "STATE", tmp_path / "state.json")
    starter.write_state(11, 22, "1.2.3.4:51820", "abc", 111, 222)
    data = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    assert data["processes"][0]["created_ticks"] == 111
    assert data["processes"][1]["created_ticks"] == 222
    assert data["endpoint"] == "1.2.3.4:51820"


@pytest.mark.parametrize("env", [
    {"CI": "true"}, {"GITHUB_ACTIONS": "true"}, {"RUBEVPN_NO_QR": "1"},
])
def test_qr_opening_is_suppressed_on_headless_runners(monkeypatch, env) -> None:
    for name in ("CI", "GITHUB_ACTIONS", "RUBEVPN_NO_QR"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    assert starter._qr_opening_enabled() is False


def test_qr_opening_enabled_on_interactive_host(monkeypatch) -> None:
    for name in ("CI", "GITHUB_ACTIONS", "RUBEVPN_NO_QR"):
        monkeypatch.delenv(name, raising=False)
    assert starter._qr_opening_enabled() is True


def test_pinggy_client_version_is_pinned() -> None:
    assert starter.PINGGY_PACKAGE.startswith("pinggy@")
    assert starter.PINGGY_PACKAGE.split("@", 1)[1]


def test_show_status_reports_recycled_pid_without_spawning(tmp_path: Path, monkeypatch,
                                                           capsys) -> None:
    monkeypatch.setattr(starter, "STATE", tmp_path / "state.json")
    (tmp_path / "state.json").write_text(json.dumps({
        "endpoint": "udp://1.2.3.4:51820",
        "processes": [{"pid": 5, "name": "server.exe", "created_ticks": 1}],
    }), encoding="utf-8")
    monkeypatch.setattr(starter, "process_alive", lambda pid: True)
    monkeypatch.setattr(starter, "_process_creation_ticks", lambda pid: 2)

    starter.show_status()
    output = capsys.readouterr().out
    assert "PID RECYCLED" in output
    assert "udp://1.2.3.4:51820" in output


def test_default_device_migration_creates_one_device(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(starter, "CFG", tmp_path)
    keys = {"private_key": "A" * 44, "public_key": "B" * 44}
    record = starter.ensure_default_device(keys)
    assert record["id"] == "phone"
    assert record["ip"] == "10.0.0.2"
    assert len(starter.list_devices()) == 1
    assert starter.ensure_default_device(keys)["id"] == "phone"
    assert len(starter.list_devices()) == 1


def test_add_device_assigns_unique_ips_and_revocation(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(starter, "CFG", tmp_path)
    monkeypatch.setattr(starter, "ensure_binary", lambda name: Path("keygen.exe"))
    counter = {"n": 0}

    def fake_run(_args, **_kwargs):
        counter["n"] += 1
        key = chr(ord("A") + counter["n"]) * 44
        return SimpleNamespace(returncode=0, stdout=json.dumps(
            {"private_key": key, "public_key": key}), stderr="")

    monkeypatch.setattr(starter, "_run", fake_run)
    first = starter.add_device("Laptop")
    second = starter.add_device("Tablet")
    assert first["id"] == "laptop"
    assert second["id"] == "tablet"
    assert first["ip"] == "10.0.0.2"
    assert second["ip"] == "10.0.0.4"  # 10.0.0.3 is reserved for verification
    assert len(starter.list_devices()) == 2

    assert starter.remove_device("laptop") is True
    assert len(starter.list_devices()) == 1
    assert starter.remove_device("../laptop") is False


def test_write_server_env_includes_all_device_peers(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(starter, "CFG", tmp_path)
    devices = [
        {"public_key": "B" * 44, "ip": "10.0.0.2"},
        {"public_key": "C" * 44, "ip": "10.0.0.4"},
    ]
    starter.write_server_env(
        {"private_key": "A" * 44}, {"public_key": "B" * 44},
        {"public_key": "D" * 44}, 1420, devices,
    )
    content = (tmp_path / "server.env").read_text(encoding="ascii")
    assert "RUBEVPN_WG_PEERS_JSON=" in content
    assert '"allowed_ip":"10.0.0.2/32"' in content
    assert '"allowed_ip":"10.0.0.4/32"' in content
    assert f"RUBEVPN_WG_STATUS_FILE={tmp_path / starter.STATUS_FILE_NAME}" in content


def test_write_device_profile_uses_device_key_and_address(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(starter, "CFG", tmp_path)
    monkeypatch.setattr(starter, "_write_qr", lambda content, path: None)
    device = {"id": "laptop", "private_key": "E" * 44, "ip": "10.0.0.4",
              "public_key": "F" * 44}
    content = starter.write_device_profile(
        device, {"public_key": "B" * 44}, "1.2.3.4:51820", 1400)
    profile = (tmp_path / "devices" / "laptop.conf").read_text(encoding="ascii")
    assert profile == content
    assert f"PrivateKey = {'E' * 44}" in profile
    assert "Address = 10.0.0.4/32" in profile
    assert "MTU = 1400" in profile


def test_read_server_status_is_honest_when_missing(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(starter, "CFG", tmp_path)
    assert starter.read_server_status() == {"updated_at": None, "peers": []}


def test_start_tunnel_delegates_to_selected_provider(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(starter, "CFG", tmp_path)
    seen = {}

    def fake_start(cfg, port, package):
        seen.update(cfg=cfg, port=port, package=package)
        return 4321

    fake = SimpleNamespace(
        start=fake_start,
        info=SimpleNamespace(name="playit", static_endpoint=True, expiry_minutes=None),
    )
    monkeypatch.setattr(starter, "_TUNNEL_PROVIDER", fake)
    monkeypatch.setattr(starter, "_process_creation_ticks", lambda pid: 99)

    assert starter.start_tunnel() == (4321, 99)
    assert seen["port"] == starter.LISTEN_PORT
    assert seen["package"] == starter.PINGGY_PACKAGE


def test_wait_for_endpoint_delegates_and_reports_errors(monkeypatch) -> None:
    fake = SimpleNamespace(
        wait_for_endpoint=lambda cfg, handle, timeout, alive: "1.2.3.4:51820",
        info=SimpleNamespace(name="playit", static_endpoint=True, expiry_minutes=None),
    )
    monkeypatch.setattr(starter, "_TUNNEL_PROVIDER", fake)
    assert starter.wait_for_endpoint(9) == "1.2.3.4:51820"


def test_write_state_records_selected_provider(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(starter, "STATE", tmp_path / "state.json")
    fake = SimpleNamespace(
        info=SimpleNamespace(name="playit", static_endpoint=True, expiry_minutes=None),
    )
    monkeypatch.setattr(starter, "_TUNNEL_PROVIDER", fake)
    starter.write_state(11, 22, "1.2.3.4:51820")
    data = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    assert data["provider"] == "playit"
    assert data["static_endpoint"] is True
    assert data["processes"][1]["name"] == "playitd"


def test_show_status_reports_relay(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(starter, "STATE", tmp_path / "state.json")
    (tmp_path / "state.json").write_text(json.dumps({
        "endpoint": "udp://1.2.3.4:51820",
        "provider": "playit",
        "static_endpoint": True,
        "processes": [],
    }), encoding="utf-8")
    starter.show_status()
    output = capsys.readouterr().out
    assert "Relay    : playit (static)" in output


def test_ensure_binary_rejects_tampered_bundle(tmp_path: Path, monkeypatch, capsys) -> None:
    tools = tmp_path / "tools"
    cfg = tmp_path / "cfg"
    tools.mkdir()
    cfg.mkdir()
    (tools / "server.exe").write_bytes(b"tampered")
    monkeypatch.setattr(starter, "TOOLS", tools)
    monkeypatch.setattr(starter, "CFG", cfg)
    monkeypatch.delenv("RUBEVPN_SKIP_BINARY_VERIFY", raising=False)

    with pytest.raises(SystemExit) as exc:
        starter.ensure_binary("server.exe")
    assert exc.value.code == 1
    assert "[ERROR] BINARY_INTEGRITY_FAILED" in capsys.readouterr().err
