"""Windows setup script tests: idempotency, no secret leakage, safe cleanup."""
from __future__ import annotations

import base64
import json
import sys
from collections import deque
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import setup_windows  # noqa: E402
from backend.app.config import load_settings  # noqa: E402
from backend.app.services.windows_wireguard import CommandResult, WireGuardPaths  # noqa: E402

SERVER_KEY = base64.b64encode(b"\x11" * 32).decode()
CLIENT_KEY = base64.b64encode(b"\x22" * 32).decode()
SERVER_PUB = base64.b64encode(b"\x33" * 32).decode()
CLIENT_PUB = base64.b64encode(b"\x44" * 32).decode()


class SimpleRunner:
    def __init__(self, by_command: dict[str, list[CommandResult]]):
        self.by_command = {key: deque(values) for key, values in by_command.items()}
        self.calls: list[str] = []

    def run(self, args, *, input_text=None, timeout=10):
        self.calls.append(args[0])
        queue = self.by_command.get(args[0], deque())
        return queue.popleft() if queue else CommandResult(1, "", "unmocked")


def settings(tmp_path: Path):
    raw = json.loads((ROOT / "config" / "settings.example.json").read_text(encoding="utf-8"))
    raw["vpn"]["endpoint_host"] = "vpn.example.com"
    path = tmp_path / "settings.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return load_settings(path)


def paths(tmp_path: Path) -> WireGuardPaths:
    return WireGuardPaths(Path("wg.exe"), Path("wireguard.exe"), tmp_path / "store")


def make_runner() -> SimpleRunner:
    return SimpleRunner({
        "wg.exe": [
            CommandResult(0, SERVER_KEY + "\n", ""),
            CommandResult(0, CLIENT_KEY + "\n", ""),
            CommandResult(0, SERVER_PUB + "\n", ""),
            CommandResult(0, CLIENT_PUB + "\n", ""),
            CommandResult(0, SERVER_PUB + "\n", ""),
            CommandResult(0, CLIENT_PUB + "\n", ""),
        ],
        "icacls": [CommandResult(0, "", "")] * 8,
        "reg": [CommandResult(1, "", "not found")] * 4,
        "netsh": [CommandResult(0, "", "")] * 4,
        "powershell": [CommandResult(0, "", "")] * 4,
        "sc.exe": [CommandResult(1060, "", "not found")] * 4,
        "wireguard.exe": [CommandResult(0, "", "")] * 4,
    })


def patch_environment(monkeypatch) -> None:
    monkeypatch.setattr(setup_windows, "_is_admin", lambda: True)
    monkeypatch.setattr(setup_windows.platform, "system", lambda: "Windows")


def test_plan_mode_creates_nothing(tmp_path: Path, monkeypatch) -> None:
    patch_environment(monkeypatch)
    target = paths(tmp_path)
    report = setup_windows.run_setup(settings(tmp_path), target, make_runner(), apply=False)
    assert report["mode"] == "plan"
    assert report["ready"] is True
    assert not target.config_dir.exists()
    assert any(item["status"] == "PLAN" for item in report["actions"])


def test_apply_mode_is_idempotent_and_hides_keys(tmp_path: Path, monkeypatch) -> None:
    patch_environment(monkeypatch)
    target = paths(tmp_path)
    config = settings(tmp_path)

    first = setup_windows.run_setup(config, target, make_runner(), apply=True)
    assert first["ready"] is True, first["blocking"]
    server_conf = target.config_path(config.vpn.interface_name)
    client_conf = target.config_dir / setup_windows.CLIENT_CONFIG_FILE
    assert server_conf.is_file() and client_conf.is_file()
    assert (target.config_dir / setup_windows.SERVER_KEY_FILE).read_text(encoding="utf-8") == SERVER_KEY
    assert SERVER_KEY not in json.dumps(first)
    assert CLIENT_KEY not in json.dumps(first)

    before = {path.name: path.read_bytes() for path in target.config_dir.glob("*.conf")}
    second = setup_windows.run_setup(config, target, make_runner(), apply=True)
    assert second["ready"] is True
    after = {path.name: path.read_bytes() for path in target.config_dir.glob("*.conf")}
    assert before == after, "existing configuration must never be overwritten"
    assert any(item["status"] == "SKIP" for item in second["actions"])


def test_client_config_is_full_tunnel_with_explicit_dns(tmp_path: Path, monkeypatch) -> None:
    patch_environment(monkeypatch)
    target = paths(tmp_path)
    setup_windows.run_setup(settings(tmp_path), target, make_runner(), apply=True)
    content = (target.config_dir / setup_windows.CLIENT_CONFIG_FILE).read_text(encoding="utf-8")
    assert "AllowedIPs = 0.0.0.0/0" in content
    assert "Endpoint = vpn.example.com:51820" in content
    assert "PersistentKeepalive = 25" in content
    assert "DNS = 1.1.1.1" in content


def test_supplied_public_key_skips_client_key_generation(tmp_path: Path, monkeypatch) -> None:
    patch_environment(monkeypatch)
    target = paths(tmp_path)
    runner = make_runner()
    setup_windows.run_setup(settings(tmp_path), target, runner, apply=True,
                            client_public_key=CLIENT_PUB)
    assert not (target.config_dir / setup_windows.CLIENT_KEY_FILE).exists()
    assert runner.calls.count("wg.exe") >= 2  # server key + server pubkey only


def test_cleanup_removes_only_owned_artifacts(tmp_path: Path, monkeypatch) -> None:
    patch_environment(monkeypatch)
    monkeypatch.setattr(setup_windows, "service_status", lambda *_args: "ABSENT")
    target = paths(tmp_path)
    setup_windows.run_setup(settings(tmp_path), target, make_runner(), apply=True)
    result = setup_windows.run_cleanup(settings(tmp_path), target, make_runner())
    assert set(result["removed"]) >= {
        setup_windows.SERVER_KEY_FILE,
        setup_windows.CLIENT_KEY_FILE,
        setup_windows.CLIENT_CONFIG_FILE,
    }
    assert not (target.config_dir / setup_windows.SERVER_KEY_FILE).exists()
    assert not (target.config_dir / setup_windows.STATE_FILE).exists()
