#!/usr/bin/env python3
"""One-time, non-destructive setup for the playit.gg UDP relay.

Secrets are written only to the restricted RubeVPN config directory and are
never printed, logged, or sent through the dashboard API.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import portable_config

BASE = os.getenv("LOCALAPPDATA") or str(Path.home() / ".rubevpn")
CFG = Path(os.getenv("RUBEVPN_WG_DIR", str(Path(BASE) / "RubeVPN" / "wg")))
DEFAULT_CONFIG = CFG / "playit.toml"
ENDPOINT_RE = re.compile(r"^[A-Za-z0-9.\-]+:\d{1,5}$")
PLACEHOLDER_MARKERS = (
    "REAL_SECRET", "PASTE-THE-REAL", "YOUR_SECRET", "YOUR_KEY",
    "EXAMPLE", "SAMPLE", "NEWHOST", "NEWPORT", "REAL_HOST", "REAL_PORT",
    "BRAVE-FALCON",
)


def _is_placeholder(value: str) -> bool:
    upper = value.upper()
    return ("<" in value or ">" in value
            or any(marker in upper for marker in PLACEHOLDER_MARKERS))


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
        os.chmod(path.parent, 0o700)
        os.chmod(path, 0o600)
    except OSError:
        pass


def _read(path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    if not path.is_file():
        return data
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            match = re.match(r'\s*([a-z_]+)\s*=\s*"(.*)"\s*$', line)
            if match:
                data[match.group(1)] = match.group(2)
    except OSError:
        pass
    return data


def _write(path: Path, data: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(f'{key} = {json.dumps(value)}' for key, value in sorted(data.items())) + "\n",
        encoding="utf-8",
    )
    _restrict(path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Configure the playit.gg relay for RubeVPN")
    parser.add_argument("--secret", default=None,
                        help="agent secret key from playit.gg/manage/agents (never echoed)")
    parser.add_argument("--endpoint", default=None,
                        help="public host:port from your playit UDP tunnel dashboard")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--check", action="store_true",
                        help="report configuration status without printing secrets")
    args = parser.parse_args()

    secret = (args.secret or os.getenv("RUBEVPN_PLAYIT_SECRET") or "").strip()
    endpoint = (args.endpoint or "").strip()

    if secret and (secret.upper() in {"KEY", "SECRET"} or _is_placeholder(secret)):
        print("[ERROR] Replace the placeholder secret with the real agent secret "
              "from https://playit.gg/manage/agents.", file=sys.stderr)
        return 1
    if endpoint and _is_placeholder(endpoint):
        print("[ERROR] Replace the placeholder endpoint with the exact public "
              "host:port shown on your playit.gg UDP tunnel page.", file=sys.stderr)
        return 1

    data = _read(args.config)
    portable = portable_config.load()
    for key in ("secret", "endpoint"):
        if not data.get(key) and (portable.get("playit") or {}).get(key):
            data[key] = portable["playit"][key]
    if data.get("secret") and _is_placeholder(str(data["secret"])):
        print("[ERROR] The saved secret is still placeholder text. Copy the real "
              "key from https://playit.gg/manage/agents.", file=sys.stderr)
        return 1
    if data.get("endpoint") and _is_placeholder(str(data["endpoint"])):
        print("[ERROR] The saved endpoint is still a placeholder. Use the exact "
              "host:port from your playit UDP tunnel page.", file=sys.stderr)
        return 1
    if secret:
        if len(secret) < 16:
            print("[ERROR] Secret key is too short. Copy the full key from "
                  "https://playit.gg/manage/agents.", file=sys.stderr)
            return 1
        data["secret"] = secret
    if endpoint:
        if not ENDPOINT_RE.fullmatch(endpoint):
            print("[ERROR] Endpoint must be in host:port form, e.g. "
                  "name.tun.ply.gg:10906.", file=sys.stderr)
            return 1
        data["endpoint"] = endpoint

    if secret or endpoint:
        _write(args.config, data)
        portable["playit"] = {key: data[key] for key in ("secret", "endpoint") if data.get(key)}
        portable_config.save(portable)
        print(f"[OK] Saved playit configuration to {args.config}")
        print("     Also saved to config/rubevpn.local.json (gitignored, portable).")
        print("     The secret key was not printed and is stored only in these files.")

    bundled = args.config.parent / ("playitd.exe" if os.name == "nt" else "playitd")
    binary = (os.getenv("RUBEVPN_PLAYIT_BIN")
              or (str(bundled) if bundled.is_file() else None)
              or shutil.which("playitd"))
    has_secret = bool(data.get("secret"))
    has_endpoint = bool(data.get("endpoint"))
    status = "READY" if (binary and has_secret and has_endpoint) else "INCOMPLETE"
    print(f"playit setup: {status}")
    print(f"  binary:   {'found' if binary else 'missing'}")
    print(f"  secret:   {'configured' if has_secret else 'missing'}")
    print(f"  endpoint: {data.get('endpoint') or 'missing'}")
    if args.check and status != "READY":
        return 2
    return 0 if has_secret or has_endpoint or args.check else 0


if __name__ == "__main__":
    raise SystemExit(main())
