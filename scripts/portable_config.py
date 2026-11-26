"""Portable, gitignored runtime state.

The GitHub RDP VM is ephemeral: %LOCALAPPDATA% disappears between sessions.
This file lives inside the repo checkout so the same WireGuard keys, device
profiles and playit credentials can be restored on a fresh runner. It is
never committed and never echoed to logs or the dashboard API.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PORTABLE_PATH = ROOT / "config" / "rubevpn.local.json"
KEY_NAMES = ("server", "client", "verify")


def load(path: Path = PORTABLE_PATH) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _restrict(path: Path) -> None:
    if os.name == "nt":
        user = f"{os.getenv('USERDOMAIN', '')}\\{os.getenv('USERNAME', '')}".strip("\\")
        if user:
            subprocess.run(
                ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
                capture_output=True,
            )
        return
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def save(data: dict[str, Any], path: Path = PORTABLE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _restrict(path)


def _write_if_absent(path: Path, content: str) -> None:
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def seed(cfg: Path, path: Path = PORTABLE_PATH) -> None:
    """Restore portable state into a fresh runner's config directory."""
    data = load(path)
    if not data:
        return
    for name in KEY_NAMES:
        content = (data.get("keys") or {}).get(name)
        if content:
            _write_if_absent(cfg / f"{name}_keys.json", content)
    playit = data.get("playit") or {}
    if playit:
        lines = [f'{key} = {json.dumps(value)}' for key, value in sorted(playit.items()) if value]
        if lines:
            _write_if_absent(cfg / "playit.toml", "\n".join(lines) + "\n")
    devices = data.get("devices") or []
    for device in devices:
        if not isinstance(device, dict) or not device.get("id"):
            continue
        device_id = device["id"]
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", str(device_id)):
            continue
        _write_if_absent(cfg / "devices" / f"{device_id}.json",
                         json.dumps(device, indent=2))
        conf = device.get("conf")
        if conf:
            _write_if_absent(cfg / "devices" / f"{device_id}.conf", str(conf))


def capture(cfg: Path, path: Path = PORTABLE_PATH) -> None:
    """Persist the current runner state back into the portable file."""
    data = load(path)
    keys = dict(data.get("keys") or {})
    for name in KEY_NAMES:
        key_path = cfg / f"{name}_keys.json"
        if key_path.is_file():
            try:
                keys[name] = key_path.read_text(encoding="ascii")
            except OSError:
                pass
    if keys:
        data["keys"] = keys

    device_dir = cfg / "devices"
    devices: list[dict[str, Any]] = []
    if device_dir.is_dir():
        for record_path in sorted(device_dir.glob("*.json")):
            try:
                record = json.loads(record_path.read_text(encoding="ascii"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(record, dict) or not record.get("id"):
                continue
            conf_path = device_dir / f"{record['id']}.conf"
            if conf_path.is_file():
                try:
                    record["conf"] = conf_path.read_text(encoding="ascii")
                except OSError:
                    pass
            devices.append(record)
    if devices:
        data["devices"] = devices

    playit = dict(data.get("playit") or {})
    playit_path = cfg / "playit.toml"
    if playit_path.is_file():
        try:
            for line in playit_path.read_text(encoding="utf-8").splitlines():
                match = re.match(r'\s*([a-z_]+)\s*=\s*"(.*)"\s*$', line)
                if match:
                    playit[match.group(1)] = match.group(2)
        except OSError:
            pass
    if playit:
        data["playit"] = playit
    save(data, path)
