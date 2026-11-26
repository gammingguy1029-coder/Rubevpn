"""Connection control and multi-device API tests (no real processes spawned)."""
from __future__ import annotations

import json
import time
from pathlib import Path

from fastapi.testclient import TestClient

from backend.app.main import create_app
from backend.app.services import tunnel_controller as controller


def sign_in(client: TestClient) -> None:
    client.get("/")
    csrf = client.cookies.get("rubevpn_csrf")
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "correct-horse-battery"},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 200


def csrf(client: TestClient) -> dict[str, str]:
    return {"X-CSRF-Token": client.cookies["rubevpn_csrf"]}


def test_connection_endpoints_require_auth() -> None:
    with TestClient(create_app()) as client:
        assert client.get("/api/v1/connection").status_code == 401
        assert client.post("/api/v1/connection/start").status_code == 401
        assert client.post("/api/v1/connection/stop").status_code == 401
        assert client.get("/api/v1/devices").status_code == 401
        assert client.post("/api/v1/devices", json={"name": "x"}).status_code == 401
        assert client.delete("/api/v1/devices/x").status_code == 401


def test_connection_state_and_control(monkeypatch) -> None:
    sample = {"status": "STARTING", "endpoint": "udp://1.2.3.4:51820", "devices": []}
    monkeypatch.setattr(controller, "state", lambda: sample)
    monkeypatch.setattr(controller, "start", lambda: {"status": "STARTING", "pid": 7})
    monkeypatch.setattr(controller, "stop", lambda: {"status": "OFFLINE"})
    with TestClient(create_app()) as client:
        sign_in(client)
        assert client.get("/api/v1/connection").json() == sample
        assert client.post("/api/v1/connection/start", headers=csrf(client)).json()["pid"] == 7
        assert client.post("/api/v1/connection/stop", headers=csrf(client)).json()["status"] == "OFFLINE"
        # CSRF is enforced on state-changing routes.
        assert client.post("/api/v1/connection/start").status_code == 403


def test_device_endpoints_never_expose_private_keys(monkeypatch) -> None:
    devices = [{"id": "laptop", "name": "Laptop", "ip": "10.0.0.2",
                "public_key": "B" * 44, "connected": True}]
    monkeypatch.setattr(controller, "list_devices", lambda: devices)
    monkeypatch.setattr(controller, "add_device", lambda name: {"name": name, "devices": devices})
    monkeypatch.setattr(controller, "remove_device", lambda device_id: {"id": device_id})
    with TestClient(create_app()) as client:
        sign_in(client)
        body = client.get("/api/v1/devices").json()
        assert body["devices"] == devices
        assert "private_key" not in json.dumps(body)
        created = client.post("/api/v1/devices", json={"name": "Laptop"}, headers=csrf(client))
        assert created.json()["name"] == "Laptop"
        assert client.delete("/api/v1/devices/laptop", headers=csrf(client)).json()["id"] == "laptop"


def test_device_name_validation_is_enforced(monkeypatch) -> None:
    def reject(name: str):
        raise ValueError("Device name may contain letters, digits, spaces, '-' or '_' only.")

    monkeypatch.setattr(controller, "add_device", reject)
    with TestClient(create_app()) as client:
        sign_in(client)
        response = client.post("/api/v1/devices", json={"name": "../evil"}, headers=csrf(client))
        assert response.status_code == 400
        assert response.json()["code"] == "CFG_INVALID"


def test_state_reports_relay_provider_and_expiry(tmp_path: Path, monkeypatch) -> None:
    cfg = tmp_path / "wg"
    cfg.mkdir(parents=True)
    (cfg / "state.json").write_text(json.dumps({
        "endpoint": "udp://1.2.3.4:51820",
        "provider": "pinggy",
        "static_endpoint": False,
        "updated_at": "2026-11-26T12:00:00+00:00",
        "processes": [],
    }), encoding="utf-8")
    monkeypatch.setattr(controller, "config_dir", lambda: cfg)
    state = controller.state()
    assert state["provider"] == "pinggy"
    assert state["static_endpoint"] is False
    assert state["expires_at"] == "2026-11-26T13:00:00+00:00"

    (cfg / "state.json").write_text(json.dumps({
        "provider": "playit", "static_endpoint": True, "processes": [],
    }), encoding="utf-8")
    static = controller.state()
    assert static["provider"] == "playit"
    assert static["static_endpoint"] is True
    assert static["expires_at"] is None


def test_state_uses_real_handshakes_and_hides_keys(tmp_path: Path, monkeypatch) -> None:
    cfg = tmp_path / "wg"
    (cfg / "devices").mkdir(parents=True)
    (cfg / "state.json").write_text(json.dumps({
        "endpoint": "udp://1.2.3.4:51820",
        "processes": [{"pid": 0, "name": "server.exe"}],
    }), encoding="utf-8")
    (cfg / "devices" / "laptop.json").write_text(json.dumps({
        "id": "laptop", "name": "Laptop", "ip": "10.0.0.2",
        "public_key": "B" * 44, "private_key": "SECRET" * 10,
    }), encoding="ascii")
    monkeypatch.setattr(controller, "config_dir", lambda: cfg)

    (cfg / "server-status.json").write_text(json.dumps({
        "updated_at": int(time.time()),
        "peers": [{"public_key": "B" * 44, "last_handshake_unix": int(time.time()) - 5}],
    }), encoding="utf-8")
    fresh = controller.state()
    assert fresh["status"] == "ONLINE"
    assert fresh["devices"][0]["connected"] is True
    assert "private_key" not in json.dumps(fresh)

    (cfg / "server-status.json").write_text(json.dumps({
        "peers": [{"public_key": "B" * 44, "last_handshake_unix": int(time.time()) - 500}],
    }), encoding="utf-8")
    stale = controller.state()
    assert stale["status"] == "OFFLINE"
    assert stale["devices"][0]["connected"] is False
