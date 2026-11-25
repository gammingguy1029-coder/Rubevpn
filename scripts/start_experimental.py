#!/usr/bin/env python3
"""Start the experimental userspace WireGuard + public UDP tunnel stack.

First run: generates keys, builds/copies binaries, starts the server and the
UDP tunnel, writes the Android profile and QR code.
Later runs: reuses existing keys (no regeneration), restarts server + tunnel,
and refreshes the endpoint in the Android profile.

This is an experimental proof of concept, not a production VPN.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools" / "userspace_wg"
BASE = os.getenv("LOCALAPPDATA") or str(Path.home() / ".rubevpn")
CFG = Path(os.getenv("RUBEVPN_WG_DIR", str(Path(BASE) / "RubeVPN" / "wg")))
STATE = CFG / "state.json"
ENDPOINT_RE = re.compile(r"udp://([A-Za-z0-9.\-]+):(\d+)")
TUNNEL_ID_RE = re.compile(r"Tunnel\s+(\d+)")
# Windows: a new process group keeps children alive after the launcher exits.
# DETACHED_PROCESS breaks npx/cmd.exe, so it is deliberately not used.
DETACHED = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)


def _run(args: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True)


def _fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def stop_existing() -> None:
    if not STATE.exists():
        return
    try:
        data = json.loads(STATE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        STATE.unlink(missing_ok=True)
        return
    # Kill only our own server. Pinggy runs a shared daemon, so killing the
    # tunnel process tree would stop every tunnel, including other sessions.
    for pid in data.get("pids", [])[:1]:
        subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True)
    tunnel_id = data.get("tunnel_id")
    if tunnel_id:
        _run(["cmd.exe", "/c", f"npx -y pinggy stop {tunnel_id}"])
    STATE.unlink(missing_ok=True)
    time.sleep(1)


def ensure_binary(name: str) -> Path:
    target = CFG / name
    if target.exists():
        return target
    source = TOOLS / name
    if source.exists():
        shutil.copy2(source, target)
        return target
    go = shutil.which("go")
    if not go:
        _fail(f"{name} is missing and Go was not found. Install Go 1.19 or copy the binary into {TOOLS}.")
    package = name[:-4] if name.endswith(".exe") else name
    result = _run([go, "build", "-o", str(target), f"./{package}"], cwd=TOOLS)
    if result.returncode != 0:
        _fail(f"could not build {name}: {result.stderr.strip()}")
    return target


def ensure_keys(keygen: Path) -> tuple[dict[str, str], dict[str, str]]:
    keys: dict[str, dict[str, str]] = {}
    for name in ("server", "client"):
        path = CFG / f"{name}_keys.json"
        if not path.exists():
            result = _run([str(keygen)])
            if result.returncode != 0:
                _fail(f"key generation failed: {result.stderr.strip()}")
            try:
                parsed = json.loads(result.stdout)
            except json.JSONDecodeError:
                _fail("key generator returned invalid JSON")
            if len(parsed.get("private_key", "")) != 44 or len(parsed.get("public_key", "")) != 44:
                _fail("key generator returned invalid key lengths")
            path.write_text(json.dumps(parsed), encoding="ascii")
        keys[name] = json.loads(path.read_text(encoding="ascii"))
    return keys["server"], keys["client"]


def write_server_env(server: dict[str, str], client: dict[str, str]) -> None:
    lines = [
        f"RUBEVPN_WG_PRIVATE_KEY={server['private_key']}",
        f"RUBEVPN_WG_PEER_PUBLIC_KEY={client['public_key']}",
        "RUBEVPN_WG_LISTEN_PORT=51820",
    ]
    (CFG / "server.env").write_text("\n".join(lines) + "\n", encoding="ascii")


def start_server(server_exe: Path) -> int:
    env = os.environ.copy()
    for line in (CFG / "server.env").read_text(encoding="ascii").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            env[key] = value
    log = (CFG / "server.log").open("ab")
    process = subprocess.Popen(
        [str(server_exe)], cwd=CFG, env=env,
        stdout=log, stderr=subprocess.STDOUT, creationflags=DETACHED,
    )
    return process.pid


def start_tunnel() -> int:
    log = (CFG / "tunnel.log").open("wb")
    command = "npx -y pinggy -p 443 -R0:localhost:51820 udp@free.pinggy.io --noTui"
    process = subprocess.Popen(
        ["cmd.exe", "/c", command], cwd=CFG,
        stdout=log, stderr=subprocess.STDOUT, creationflags=DETACHED,
    )
    return process.pid


def wait_for_endpoint(timeout: int = 120) -> str:
    deadline = time.time() + timeout
    log_path = CFG / "tunnel.log"
    while time.time() < deadline:
        if log_path.exists():
            text = log_path.read_text(encoding="utf-8", errors="ignore")
            match = ENDPOINT_RE.search(text)
            if match:
                host, port = match.group(1), match.group(2)
                try:
                    return f"{socket.gethostbyname(host)}:{port}"
                except OSError:
                    return f"{host}:{port}"
        time.sleep(1)
    _fail("no UDP endpoint was published by the tunnel (is Node.js/npm installed?)")


def write_android_profile(server: dict[str, str], client: dict[str, str], endpoint: str) -> str:
    content = "\n".join([
        "[Interface]",
        f"PrivateKey = {client['private_key']}",
        "Address = 10.0.0.2/32",
        "DNS = 10.0.0.1",
        "",
        "[Peer]",
        f"PublicKey = {server['public_key']}",
        "AllowedIPs = 0.0.0.0/0",
        f"Endpoint = {endpoint}",
        "PersistentKeepalive = 25",
        "",
    ])
    (CFG / "phone.conf").write_text(content, encoding="ascii")
    try:
        import qrcode  # type: ignore
    except ImportError:
        _run([sys.executable, "-m", "pip", "install", "qrcode", "pillow", "--quiet"])
        try:
            import qrcode  # type: ignore
        except ImportError:
            qrcode = None  # type: ignore[assignment]
    if qrcode is not None:
        try:
            qrcode.make(content).save(CFG / "phone-qr.png")
        except Exception:
            pass
    return content


def main() -> int:
    parser = argparse.ArgumentParser(description="Start RubeVPN's experimental tunnel stack")
    parser.add_argument("--stop", action="store_true", help="stop the running server and tunnel")
    args = parser.parse_args()

    CFG.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        user = f"{os.getenv('USERDOMAIN', '')}\\{os.getenv('USERNAME', '')}".strip("\\")
        if user:
            subprocess.run(
                ["icacls", str(CFG), "/inheritance:r", "/grant:r", f"{user}:F"],
                capture_output=True,
            )
    if args.stop:
        stop_existing()
        print("Stopped experimental WireGuard server and tunnel.")
        return 0

    configured = (CFG / "server_keys.json").exists() and (CFG / "client_keys.json").exists()
    print(f"Config directory: {CFG}")
    print("Already configured - reusing existing keys." if configured else "First run - generating configuration.")

    stop_existing()
    server_exe = ensure_binary("server.exe")
    keygen = ensure_binary("keygen.exe")
    server_keys, client_keys = ensure_keys(keygen)
    write_server_env(server_keys, client_keys)

    server_pid = start_server(server_exe)
    tunnel_pid = start_tunnel()
    endpoint = wait_for_endpoint()
    write_android_profile(server_keys, client_keys, endpoint)

    qr = CFG / "phone-qr.png"
    if qr.exists() and os.name == "nt" and os.getenv("RUBEVPN_NO_QR") != "1":
        try:
            os.startfile(str(qr))  # type: ignore[attr-defined]
        except OSError:
            pass

    tunnel_log = (CFG / "tunnel.log").read_text(encoding="utf-8", errors="ignore")
    tunnel_match = TUNNEL_ID_RE.search(tunnel_log)
    STATE.write_text(json.dumps({
        "pids": [server_pid, tunnel_pid],
        "tunnel_id": tunnel_match.group(1) if tunnel_match else None,
        "endpoint": endpoint,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }, indent=2), encoding="utf-8")

    print(f"Server PID: {server_pid}   Tunnel PID: {tunnel_pid}")
    print(f"Public UDP endpoint: udp://{endpoint}")
    print(f"Android profile: {CFG / 'phone.conf'}")
    qr = CFG / "phone-qr.png"
    if qr.exists():
        print(f"QR code: {qr}")
        print(f'Show it with: Start-Process "{qr}"')
    print("Import once in the official WireGuard app, then toggle it on.")
    print("Free tunnel expires in ~60 minutes and the port changes on restart.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
