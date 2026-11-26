"""Host capability probing must reflect reality, not hard-coded ineligibility."""
from __future__ import annotations

from pathlib import Path

from backend.app.config import load_settings
from backend.app.monitoring.models import ErrorCode
from backend.app.services import host_capabilities as hc
from backend.app.services.host_capabilities import probe_capabilities
from backend.app.services.vpn_provider import UnavailableProvider

ROOT = Path(__file__).resolve().parents[1]
SETTINGS = load_settings(ROOT / "config" / "settings.example.json")


def test_probe_reports_measured_capabilities(monkeypatch) -> None:
    class Paths:
        wg_exe = Path("wg.exe")

    monkeypatch.setattr(hc, "is_admin", lambda: True)
    monkeypatch.setattr(hc, "ip_forwarding_enabled", lambda _runner: True)
    monkeypatch.setattr(hc, "discover_paths", lambda: Paths())
    monkeypatch.setattr(hc, "endpoint_bound_locally", lambda endpoint: endpoint == "203.0.113.5")

    settings = SETTINGS.model_copy(deep=True)
    settings.vpn.endpoint_host = "203.0.113.5"
    caps = probe_capabilities(settings)

    assert caps.elevated is True
    assert caps.ip_forwarding is True
    assert caps.privileged is True
    assert caps.wireguard_installed is True
    assert caps.endpoint_configured is True
    assert caps.endpoint_bound_locally is True
    assert caps.public_endpoint is True
    assert caps.inbound_udp is False  # never claimed without an external probe


def test_probe_on_runner_is_honestly_ineligible(monkeypatch) -> None:
    class Paths:
        wg_exe = None

    monkeypatch.setattr(hc, "is_admin", lambda: False)
    monkeypatch.setattr(hc, "ip_forwarding_enabled", lambda _runner: False)
    monkeypatch.setattr(hc, "discover_paths", lambda: Paths())
    monkeypatch.setattr(hc, "endpoint_bound_locally", lambda endpoint: False)

    caps = probe_capabilities(SETTINGS)
    assert caps.privileged is False
    assert caps.public_endpoint is False
    assert caps.wireguard_installed is False


def test_unavailable_provider_uses_caps_instead_of_all_fail() -> None:
    provider = UnavailableProvider(
        SETTINGS, public_endpoint=True, privileged=True,
        wireguard_installed=True, inbound_udp=True,
    )
    codes = {check.code for check in provider.diagnostics()}
    assert ErrorCode.NO_PRIVILEGE not in codes
    assert ErrorCode.PUBLIC_ENDPOINT_MISSING not in codes
    assert ErrorCode.WIREGUARD_SERVICE_FAILURE not in codes
    assert ErrorCode.UDP_UNREACHABLE not in codes


def test_select_provider_forwards_capabilities(monkeypatch) -> None:
    from backend.app import main

    class Caps:
        elevated = ip_forwarding = wireguard_installed = True
        endpoint_configured = endpoint_bound_locally = True
        privileged = public_endpoint = True
        inbound_udp = True

    seen = {}

    def fake_probe(settings):
        return Caps()

    def fake_unavailable(settings, **kwargs):
        seen.update(kwargs)
        return object()

    monkeypatch.setattr(main, "probe_capabilities", fake_probe)
    monkeypatch.setattr(main, "UnavailableProvider", fake_unavailable)
    provider = main.select_provider(SETTINGS)
    assert provider is not None
    assert seen["privileged"] is True
    assert seen["public_endpoint"] is True
