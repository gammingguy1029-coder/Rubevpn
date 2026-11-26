"""Tests for the pluggable public UDP relay providers (pinggy / playit)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import tunnel_providers as tp  # noqa: E402


# 1. select_provider -----------------------------------------------------------

def test_select_provider_reads_portable_config(monkeypatch) -> None:
    monkeypatch.delenv("RUBEVPN_TUNNEL_PROVIDER", raising=False)
    monkeypatch.setattr(tp, "load_portable", lambda: {"tunnel_provider": "playit"})
    provider = tp.select_provider()
    assert isinstance(provider, tp.PlayitProvider)


def test_select_provider_defaults_to_pinggy(monkeypatch) -> None:
    monkeypatch.delenv("RUBEVPN_TUNNEL_PROVIDER", raising=False)
    monkeypatch.setattr(tp, "load_portable", lambda: {})
    provider = tp.select_provider()
    assert isinstance(provider, tp.PinggyProvider)
    assert provider.info.name == "pinggy"


def test_select_provider_reads_playit_from_env(monkeypatch) -> None:
    monkeypatch.setenv("RUBEVPN_TUNNEL_PROVIDER", "playit")
    provider = tp.select_provider()
    assert isinstance(provider, tp.PlayitProvider)
    assert provider.info.name == "playit"


def test_select_provider_rejects_unknown_name() -> None:
    with pytest.raises(tp.TunnelError) as exc_info:
        tp.select_provider("bogus")
    assert exc_info.value.code == "TUNNEL_PROVIDER_INVALID"


# 2. PinggyProvider command ----------------------------------------------------

def test_pinggy_command_posix_uses_default_host(monkeypatch) -> None:
    monkeypatch.delenv("RUBEVPN_TUNNEL_HOST", raising=False)
    monkeypatch.setattr(tp.os, "name", "posix")
    provider = tp.PinggyProvider()
    joined = " ".join(provider._command(51820, "pinggy@0.6.10"))
    assert "npx -y pinggy@0.6.10" in joined
    assert "-R0:localhost:51820" in joined
    assert "udp@free.pinggy.io" in joined


def test_pinggy_command_posix_uses_custom_host(monkeypatch) -> None:
    monkeypatch.setenv("RUBEVPN_TUNNEL_HOST", "ap.free.pinggy.io")
    monkeypatch.setattr(tp.os, "name", "posix")
    provider = tp.PinggyProvider()
    joined = " ".join(provider._command(51820, "pinggy@0.6.10"))
    assert "udp@ap.free.pinggy.io" in joined
    assert "udp@free.pinggy.io" not in joined


# 3. PinggyProvider.wait_for_endpoint ------------------------------------------

def test_pinggy_wait_for_endpoint_resolves_host(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "tunnel.log").write_text(
        "Tunnel established\nudp://abc.a.free.pinggy.io:43210\n", encoding="utf-8")
    monkeypatch.setattr(tp.socket, "gethostbyname", lambda host: "1.2.3.4")
    provider = tp.PinggyProvider()
    endpoint = provider.wait_for_endpoint(
        tmp_path, tp.TunnelHandle(pid=123), 2, lambda pid: True)
    assert endpoint == "1.2.3.4:43210"


def test_pinggy_wait_for_endpoint_timeout(tmp_path: Path) -> None:
    (tmp_path / "tunnel.log").write_text("still waiting\n", encoding="utf-8")
    with pytest.raises(tp.TunnelError) as exc_info:
        tp.PinggyProvider().wait_for_endpoint(
            tmp_path, tp.TunnelHandle(pid=123), 0.2, lambda pid: True)
    assert exc_info.value.code == "TUNNEL_TIMEOUT"


def test_pinggy_wait_for_endpoint_dead_process(tmp_path: Path) -> None:
    with pytest.raises(tp.TunnelError) as exc_info:
        tp.PinggyProvider().wait_for_endpoint(
            tmp_path, tp.TunnelHandle(pid=123), 2, lambda pid: False)
    assert exc_info.value.code == "TUNNEL_FAILED"


# 4. PlayitProvider.wait_for_endpoint ------------------------------------------

def test_playit_wait_for_endpoint_resolves_static_host(tmp_path: Path, monkeypatch) -> None:
    secret = tmp_path / "playit.toml"
    secret.write_text('secret = "abc"\nendpoint = "edge.playit.gg:41234"\n', encoding="utf-8")
    monkeypatch.setattr(tp.shutil, "which", lambda name: None)
    monkeypatch.setattr(tp.socket, "gethostbyname", lambda host: "1.2.3.4")
    provider = tp.PlayitProvider(
        secret_path=secret, endpoint="edge.playit.gg:41234", binary="playitd")
    endpoint = provider.wait_for_endpoint(
        tmp_path, tp.TunnelHandle(pid=123), 2, lambda pid: True)
    assert endpoint == "1.2.3.4:41234"


def test_playit_wait_for_endpoint_rejects_invalid_endpoint(tmp_path: Path, monkeypatch) -> None:
    secret = tmp_path / "playit.toml"
    secret.write_text('secret = "abc"\n', encoding="utf-8")
    monkeypatch.setattr(tp.shutil, "which", lambda name: None)
    provider = tp.PlayitProvider(secret_path=secret, endpoint="nope", binary="playitd")
    with pytest.raises(tp.TunnelError) as exc_info:
        provider.wait_for_endpoint(tmp_path, tp.TunnelHandle(pid=123), 2, lambda pid: True)
    assert exc_info.value.code == "PLAYIT_ENDPOINT_INVALID"


# 5. PlayitProvider.start ------------------------------------------------------

def test_playit_start_missing_secret(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(tp.shutil, "which", lambda name: None)
    provider = tp.PlayitProvider(
        secret_path=tmp_path / "missing.toml",
        endpoint="edge.playit.gg:41234",
        binary="playitd",
    )
    with pytest.raises(tp.TunnelError) as exc_info:
        provider.start(tmp_path, 51820, "ignored")
    assert exc_info.value.code == "PLAYIT_SECRET_MISSING"


def test_playit_start_missing_binary(tmp_path: Path, monkeypatch) -> None:
    secret = tmp_path / "playit.toml"
    secret.write_text('secret = "abc"\n', encoding="utf-8")
    monkeypatch.delenv("RUBEVPN_PLAYIT_BIN", raising=False)
    monkeypatch.setattr(tp.shutil, "which", lambda name: None)
    monkeypatch.setattr(tp, "_default_secret_path", lambda: tmp_path / "empty" / "playit.toml")
    provider = tp.PlayitProvider(
        secret_path=secret, endpoint="edge.playit.gg:41234", binary=None)
    with pytest.raises(tp.TunnelError) as exc_info:
        provider.start(tmp_path, 51820, "ignored")
    assert exc_info.value.code == "PLAYIT_BINARY_MISSING"


# 6. _endpoint_from_file -------------------------------------------------------

def test_endpoint_from_file_parses_playit_toml(tmp_path: Path) -> None:
    secret = tmp_path / "playit.toml"
    secret.write_text(
        'secret = "supersecret"\nendpoint = "edge.playit.gg:41234"\n', encoding="utf-8")
    assert tp._endpoint_from_file(secret) == "edge.playit.gg:41234"
