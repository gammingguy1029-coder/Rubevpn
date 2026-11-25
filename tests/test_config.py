"""Configuration validation tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.app.config import ConfigError, load_settings

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "config" / "settings.example.json"


def write_config(tmp_path: Path, data: dict) -> Path:
    path = tmp_path / "settings.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_example_config_is_valid() -> None:
    settings = load_settings(EXAMPLE)
    assert settings.vpn.provider == "unavailable"
    assert settings.vpn.endpoint_port == 51820
    assert settings.vpn.allowed_ipv4 == ["0.0.0.0/0"]
    assert settings.dashboard.refresh_seconds == 5


def test_missing_config_raises_coded_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as exc:
        load_settings(tmp_path / "missing.json")
    assert exc.value.code == "CFG_INVALID"
    assert "settings.example.json" in exc.value.recovery_action


def test_secret_key_in_config_is_rejected(tmp_path: Path) -> None:
    raw = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    raw["vpn"]["private_key"] = "should-never-be-here"
    with pytest.raises(ConfigError) as exc:
        load_settings(write_config(tmp_path, raw))
    assert exc.value.code == "CFG_INVALID"
    assert "environment variable" in exc.value.recovery_action


def test_pem_and_wireguard_keys_are_rejected(tmp_path: Path) -> None:
    raw = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    raw["notes"] = "-----BEGIN PRIVATE KEY-----"
    with pytest.raises(ConfigError):
        load_settings(write_config(tmp_path, raw))
    raw["notes"] = "A" * 43 + "="
    with pytest.raises(ConfigError):
        load_settings(write_config(tmp_path, raw))


@pytest.mark.parametrize("network", ["10.0.0.1/24", "2001:db8::/32", "not-a-network"])
def test_invalid_ipv4_networks_are_rejected(tmp_path: Path, network: str) -> None:
    raw = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    raw["vpn"]["allowed_ipv4"] = [network]
    with pytest.raises(ConfigError):
        load_settings(write_config(tmp_path, raw))


def test_invalid_dns_is_rejected(tmp_path: Path) -> None:
    raw = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    raw["vpn"]["dns"] = ["999.999.999.999"]
    with pytest.raises(ConfigError):
        load_settings(write_config(tmp_path, raw))


def test_invalid_port_is_rejected(tmp_path: Path) -> None:
    raw = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    raw["vpn"]["endpoint_port"] = 70000
    with pytest.raises(ConfigError):
        load_settings(write_config(tmp_path, raw))
