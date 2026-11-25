"""API authentication, real status data, and dashboard tests."""
from __future__ import annotations

import json
import logging
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
    assert response.json()["detail"]["code"] == "AUTH_REQUIRED"


def test_wrong_password_is_rejected(client: TestClient) -> None:
    response = sign_in(client, password="definitely-wrong")
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "AUTH_FAILED"
    assert client.get("/api/v1/status").status_code == 401


def test_non_ascii_username_is_rejected_cleanly(client: TestClient) -> None:
    response = sign_in(client, username="ådmin")
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "AUTH_FAILED"


def test_csrf_token_is_required(client: TestClient) -> None:
    response = sign_in(client, with_csrf=False)
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "CSRF_FAILED"


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


def test_dashboard_html_loads(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    html = response.text
    for fragment in ("vpn-status", "session-status", "app-version", "events", "diagnostics"):
        assert fragment in html
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/style.css").status_code == 200
