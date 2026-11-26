"""Control plane for the experimental userspace WireGuard stack.

All state comes from the files written by scripts/start_experimental.py and
from the status file written by the Go server. Nothing here invents a device
or a handshake.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = PROJECT_ROOT / "scripts"
HANDSHAKE_WINDOW = 180
DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,48}$")
DEVICE_NAME_RE = re.compile(r"^[A-Za-z0-9 _-]{1,64}$")


def config_dir() -> Path:
    base = os.getenv("LOCALAPPDATA") or str(Path.home() / ".rubevpn")
    return Path(os.getenv("RUBEVPN_WG_DIR", str(Path(base) / "RubeVPN" / "wg")))


def _read_json(path: Path, default: Any) -> Any:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return default
    return data if isinstance(data, dict) else default


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name != "nt":
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False
    try:
        result = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                                capture_output=True, text=True, timeout=5)
        return str(pid) in result.stdout
    except (OSError, subprocess.SubprocessError):
        return False


def list_devices() -> list[dict[str, Any]]:
    """Return device metadata only; private keys never leave the config dir."""
    directory = config_dir() / "devices"
    if not directory.is_dir():
        return []
    devices: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")):
        record = _read_json(path, {})
        if not record.get("id") or not record.get("public_key"):
            continue
        devices.append({
            "id": record["id"],
            "name": record.get("name", record["id"]),
            "ip": record.get("ip"),
            "public_key": record["public_key"],
            "created_at": record.get("created_at"),
            "config": str(directory / f"{record['id']}.conf"),
            "qr": str(directory / f"{record['id']}-qr.png"),
        })
    return devices


def state() -> dict[str, Any]:
    cfg = config_dir()
    saved = _read_json(cfg / "state.json", {})
    status = _read_json(cfg / "server-status.json", {})
    peers = {
        peer.get("public_key"): peer
        for peer in (status.get("peers") or [])
        if isinstance(peer, dict)
    }
    now = int(time.time())
    devices = list_devices()
    for device in devices:
        peer = peers.get(device["public_key"], {})
        handshake = int(peer.get("last_handshake_unix") or 0)
        device["connected"] = bool(handshake and now - handshake < HANDSHAKE_WINDOW)
        device["last_handshake_unix"] = handshake or None
        device["rx_bytes"] = peer.get("rx_bytes")
        device["tx_bytes"] = peer.get("tx_bytes")

    processes = saved.get("processes") or []
    running = False
    for entry in processes:
        if isinstance(entry, dict):
            try:
                running = running or _pid_alive(int(entry.get("pid", 0)))
            except (TypeError, ValueError):
                continue
    online = any(device["connected"] for device in devices)
    provider = str(saved.get("provider") or "pinggy")
    static_endpoint = bool(saved.get("static_endpoint", provider == "playit"))
    expires_at = None
    if not static_endpoint and saved.get("updated_at"):
        try:
            started = datetime.fromisoformat(str(saved["updated_at"]))
            expires_at = (started + timedelta(minutes=60)).isoformat()
        except (TypeError, ValueError):
            expires_at = None
    return {
        "status": "ONLINE" if online else ("STARTING" if running else "OFFLINE"),
        "endpoint": saved.get("endpoint") or None,
        "provider": provider,
        "static_endpoint": static_endpoint,
        "expires_at": expires_at,
        "running": running,
        "devices": devices,
        "status_updated_at": status.get("updated_at"),
        "server_log": str(cfg / "server.log"),
        "tunnel_log": str(cfg / "tunnel.log"),
    }


def start() -> dict[str, Any]:
    current = state()
    if current["status"] in {"ONLINE", "STARTING"}:
        return {"status": current["status"], "already_running": True}
    cfg = config_dir()
    cfg.mkdir(parents=True, exist_ok=True)
    log = (cfg / "controller.log").open("ab")
    kwargs: dict[str, Any] = {
        "cwd": str(PROJECT_ROOT), "stdout": log, "stderr": subprocess.STDOUT,
    }
    if os.name == "nt":
        flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(
            subprocess, "DETACHED_PROCESS", 0)
        kwargs["creationflags"] = flags
    process = subprocess.Popen(
        [sys.executable, str(SCRIPTS / "start_experimental.py")], **kwargs
    )
    return {"status": "STARTING", "pid": process.pid, "already_running": False}


def stop() -> dict[str, Any]:
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "start_experimental.py"), "--stop"],
        capture_output=True, text=True, timeout=30,
    )
    output = (result.stdout + result.stderr).strip()
    if result.returncode != 0:
        raise RuntimeError(output[:500] or "stop command failed")
    return {"status": "OFFLINE", "output": output[:500]}


def add_device(name: str) -> dict[str, Any]:
    if not DEVICE_NAME_RE.fullmatch(name):
        raise ValueError("Device name may contain letters, digits, spaces, '-' or '_' only.")
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "start_experimental.py"), "--add-device", name],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout).strip()[:500])
    return {"name": name, "devices": list_devices()}


def remove_device(device_id: str) -> dict[str, Any]:
    if not DEVICE_ID_RE.fullmatch(device_id):
        raise ValueError("Invalid device id.")
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "start_experimental.py"),
         "--remove-device", device_id],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout).strip()[:500])
    return {"id": device_id, "devices": list_devices()}
