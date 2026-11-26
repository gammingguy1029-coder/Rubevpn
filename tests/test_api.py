"""API authentication, real status data, and dashboard tests."""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app.main import create_app

ROOT = Path(__file__).resolve().parents[1]
GOOD_PASSWORD = "correct-horse-battery"
WG_KEY = "B" * 43 + "="


@pytest.fixture
def client() -> TestClient:
    with TestClient(create_app()) as test_client:
        yield test_client


def sign_in(client: TestClient, password: str = GOOD_PASSWORD, username: str = "admin",
            with_csrf: bool = True):
    client.get("/")
    headers = {}
    if with_csrf:
        csrf = client.cookies.get("rubevpn_csrf")
        assert csrf, "CSRF cookie must be set by the server"
        headers["X-CSRF-Token"] = csrf
    return client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password},
        headers=headers,
    )


def test_health_is_public_and_reports_version(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["app_version"]
    assert "timestamp" in body


def test_status_requires_authentication(client: TestClient) -> None:
    response = client.get("/api/v1/status")
    assert response.status_code == 401
    assert response.json()["code"] == "AUTH_REQUIRED"


def test_wrong_password_is_rejected(client: TestClient) -> None:
    response = sign_in(client, password="definitely-wrong")
    assert response.status_code == 401
    assert response.json()["code"] == "AUTH_FAILED"
    assert client.get("/api/v1/status").status_code == 401


def test_non_ascii_username_is_rejected_cleanly(client: TestClient) -> None:
    response = sign_in(client, username="ådmin")
    assert response.status_code == 401
    assert response.json()["code"] == "AUTH_FAILED"


def test_csrf_token_is_required(client: TestClient) -> None:
    response = sign_in(client, with_csrf=False)
    assert response.status_code == 403
    assert response.json()["code"] == "CSRF_FAILED"


def test_authenticated_status_contains_only_real_data(client: TestClient) -> None:
    response = sign_in(client)
    assert response.status_code == 200, response.text
    status = client.get("/api/v1/status")
    assert status.status_code == 200
    body = status.json()
    assert body["status"] == "OFFLINE"
    assert body["session_status"] == "OFFLINE"
    assert body["connected_clients"] is None
    assert body["data_available"] is False
    assert body["session_expires_at"] is None
    admin_expiry = datetime.fromisoformat(body["admin_session_expires_at"])
    assert admin_expiry > datetime.now(timezone.utc)
    assert admin_expiry < datetime.now(timezone.utc) + timedelta(hours=2)
    assert "No VPN session" in body["notes"]
    assert body["last_health_check"]
    codes = {error["code"] for error in body["errors"]}
    assert {"PUBLIC_ENDPOINT_MISSING", "UDP_UNREACHABLE", "NO_PRIVILEGE"} <= codes
    assert all(error["recovery_action"] for error in body["errors"])
    assert body["refresh_seconds"] == 5


def test_events_and_diagnostics_are_authenticated(client: TestClient) -> None:
    assert client.get("/api/v1/events").status_code == 401
    assert client.get("/api/v1/diagnostics").status_code == 401
    assert sign_in(client).status_code == 200
    events = client.get("/api/v1/events")
    assert events.status_code == 200
    assert any(event.get("event") == "STARTING" for event in events.json()["events"])
    diagnostics = client.get("/api/v1/diagnostics")
    assert diagnostics.status_code == 200
    assert any(check["status"] == "FAIL" for check in diagnostics.json()["checks"])


def test_events_never_contain_secrets(client: TestClient) -> None:
    assert sign_in(client).status_code == 200
    logging.getLogger("security-test").warning(
        "leak password=hunter2 private_key=%s token=Bearer %s", WG_KEY, WG_KEY
    )
    response = client.get("/api/v1/events")
    assert response.status_code == 200
    payload = response.text
    assert "hunter2" not in payload
    assert WG_KEY not in payload


def test_logout_invalidates_session(client: TestClient) -> None:
    assert sign_in(client).status_code == 200
    assert client.get("/api/v1/status").status_code == 200
    logout = client.post("/api/v1/auth/logout", json={}, headers={"X-CSRF-Token": client.cookies["rubevpn_csrf"]})
    assert logout.status_code == 200
    assert client.get("/api/v1/status").status_code == 401


def test_wireguard_provider_selection_never_invents_status(tmp_path: Path, monkeypatch) -> None:
    raw = json.loads((ROOT / "config" / "settings.example.json").read_text(encoding="utf-8"))
    raw["vpn"]["provider"] = "wireguard"
    config = tmp_path / "settings.json"
    config.write_text(json.dumps(raw), encoding="utf-8")
    monkeypatch.setenv("RUBEVPN_SETTINGS_PATH", str(config))

    with TestClient(create_app()) as test_client:
        assert sign_in(test_client).status_code == 200
        body = test_client.get("/api/v1/status").json()
        assert body["status"] == "OFFLINE"
        assert body["connected_clients"] is None
        assert body["data_available"] is False
        codes = {check["code"] for check in body["diagnostics"]}
        assert "WIREGUARD_SERVICE_FAILURE" in codes


def test_snapshot_notes_follow_real_provider_state() -> None:
    from backend.app.config import load_settings
    from backend.app.monitoring.events import EventBuffer
    from backend.app.monitoring.health import build_snapshot
    from backend.app.monitoring.models import HealthReport, StatusValue

    class FakeProvider:
        def __init__(self, value: StatusValue) -> None:
            self.value = value

        def diagnostics(self):
            return []

        def health_check(self):
            return HealthReport(status=self.value, checked_at=datetime.now(timezone.utc), details="")

        def connected_clients(self):
            return 1

        def data_available(self):
            return True

    settings = load_settings(ROOT / "config" / "settings.example.json")
    online = build_snapshot(settings, FakeProvider(StatusValue.ONLINE),
                            EventBuffer(), time.monotonic())
    assert "handshake observed" in online.notes
    degraded = build_snapshot(settings, FakeProvider(StatusValue.DEGRADED),
                              EventBuffer(), time.monotonic())
    assert "no peer completed" in degraded.notes
    offline = build_snapshot(settings, FakeProvider(StatusValue.OFFLINE),
                             EventBuffer(), time.monotonic())
    assert "No VPN session" in offline.notes


def test_error_envelope_is_consistent_and_correlated(client: TestClient) -> None:
    response = client.get("/api/v1/status", headers={"X-Request-ID": "correlation-123"})
    body = response.json()
    assert response.status_code == 401
    assert set(body) == {"code", "message", "timestamp", "context",
                         "recovery_action", "request_id"}
    assert body["code"] == "AUTH_REQUIRED"
    assert body["request_id"] == "correlation-123"
    assert response.headers["X-Request-ID"] == "correlation-123"

    client.get("/")
    csrf = client.cookies.get("rubevpn_csrf")
    failed = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "wrong"},
        headers={"X-CSRF-Token": csrf},
    )
    assert set(failed.json()) == set(body)

    assert sign_in(client).status_code == 200
    events = client.get("/api/v1/events").json()["events"]
    logged = [event for event in events if event.get("event") == "AUTH_FAILED"]
    assert logged and any(event.get("request_id") for event in logged)


def test_generated_request_id_is_returned(client: TestClient) -> None:
    response = client.get("/health")
    assert response.headers["X-Request-ID"]
    assert len(response.headers["X-Request-ID"]) >= 16


def test_dashboard_html_loads(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    html = response.text
    for fragment in ("vpn-status", "session-status", "app-version", "events", "diagnostics",
                     "connection-status", "connect-btn", "disconnect-btn", "devices",
                     "device-form"):
        assert fragment in html
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/style.css").status_code == 200
