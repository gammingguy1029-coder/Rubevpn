#!/usr/bin/env python3
"""Start the experimental userspace WireGuard + public UDP tunnel stack.

First run: generates keys, copies bundled binaries, starts server and tunnel,
verifies an encrypted handshake, writes the Android profile/QR, and reports a
clear ONLINE status with log locations.
Later runs: reuses existing keys and refreshes the public endpoint.

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
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools" / "userspace_wg"
BASE = os.getenv("LOCALAPPDATA") or str(Path.home() / ".rubevpn")
CFG = Path(os.getenv("RUBEVPN_WG_DIR", str(Path(BASE) / "RubeVPN" / "wg")))
STATE = CFG / "state.json"
ENDPOINT_RE = re.compile(r"udp://([A-Za-z0-9.\-]+):(\d+)")
TUNNEL_ID_RE = re.compile(r"Tunnel\s+([A-Za-z0-9]+)")
LISTEN_PORT = int(os.getenv("RUBEVPN_WG_LISTEN_PORT", "51820"))
DETACHED = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)


class StartupError(Exception):
    def __init__(self, code: str, message: str, recovery: str,
                 context: dict[str, object] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.recovery = recovery
        self.context = context or {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def format_error(error: StartupError) -> str:
    context = ", ".join(f"{key}={value}" for key, value in error.context.items()) or "none"
    return (
        f"[ERROR] {error.code}\n"
        f"  message:   {error.message}\n"
        f"  timestamp: {_now()}\n"
        f"  context:   {context}\n"
        f"  recovery:  {error.recovery}"
    )


def fail(code: str, message: str, recovery: str,
         context: dict[str, object] | None = None) -> NoReturn:
    error = StartupError(code, message, recovery, context)
    print(format_error(error), file=sys.stderr)
    for name in ("server.log", "tunnel.log"):
        tail = tail_log(CFG / name)
        if tail:
            print(f"--- {name} (last lines) ---\n{tail}", file=sys.stderr)
    raise SystemExit(1)


def tail_log(path: Path, lines: int = 12) -> str:
    if not path.exists():
        return ""
    try:
        content = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return ""
    return "\n".join(content[-lines:])


def _run(args: list[str], *, cwd: Path | None = None,
         timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout)


def process_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        result = _run(["tasklist", "/FI", f"PID eq {pid}", "/NH"])
        return str(pid) in result.stdout
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def process_name(pid: int) -> str:
    if os.name != "nt":
        return "unknown"
    result = _run(["tasklist", "/FI", f"PID eq {pid}", "/NH"])
    parts = result.stdout.strip().split()
    return parts[0] if parts else ""


def safe_stop_pid(pid: int, expected: tuple[str, ...]) -> None:
    """Only stop a PID when it still belongs to the process we started."""
    if not process_alive(pid):
        return
    actual = process_name(pid).lower()
    if expected and not any(name in actual for name in expected):
        return
    subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True)


def stop_existing() -> None:
    if not STATE.exists():
        return
    try:
        data = json.loads(STATE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        STATE.unlink(missing_ok=True)
        return
    processes = data.get("processes") or [
        {"pid": pid, "name": "server.exe" if index == 0 else "cmd.exe"}
        for index, pid in enumerate(data.get("pids", []))
    ]
    for entry in processes:
        try:
            safe_stop_pid(int(entry["pid"]), ("server.exe", "cmd.exe"))
        except (KeyError, TypeError, ValueError):
            continue
    tunnel_id = data.get("tunnel_id")
    if tunnel_id:
        _run(["cmd.exe", "/c", f"npx -y pinggy stop {tunnel_id}"])
    STATE.unlink(missing_ok=True)
    time.sleep(1)


def udp_port_available(port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def ensure_binary(name: str) -> Path:
    target = CFG / name
    if target.exists():
        return target
    source = TOOLS / name
    if source.exists():
        shutil.copy2(source, target)
        return target
    fail(
        "MISSING_DEPENDENCY",
        f"Bundled binary {name} is missing from {source}.",
        "Re-clone the repository with the bundled binaries, or place a compatible binary in that folder.",
        {"binary": name},
    )


def ensure_keys(keygen: Path) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    keys: dict[str, dict[str, str]] = {}
    for name in ("server", "client", "verify"):
        path = CFG / f"{name}_keys.json"
        if not path.exists():
            result = _run([str(keygen)])
            if result.returncode != 0:
                fail("KEY_GENERATION_FAILED", "WireGuard key generation failed.",
                     "Verify the bundled keygen.exe and retry.", {"stderr": result.stderr.strip()[:200]})
            try:
                parsed = json.loads(result.stdout)
            except json.JSONDecodeError:
                fail("KEY_GENERATION_FAILED", "Key generator returned invalid JSON.",
                     "Re-clone the repository with a valid keygen.exe.")
            if len(parsed.get("private_key", "")) != 44 or len(parsed.get("public_key", "")) != 44:
                fail("KEY_GENERATION_FAILED", "Key generator returned invalid key lengths.",
                     "Re-clone the repository with a valid keygen.exe.")
            path.write_text(json.dumps(parsed), encoding="ascii")
        try:
            keys[name] = json.loads(path.read_text(encoding="ascii"))
        except (OSError, json.JSONDecodeError):
            fail("CFG_INVALID", f"Key file {path.name} is unreadable.",
                 "Move the file aside and rerun start.bat to regenerate keys.")
    return keys["server"], keys["client"], keys["verify"]


def write_server_env(server: dict[str, str], client: dict[str, str], verify: dict[str, str]) -> None:
    lines = [
        f"RUBEVPN_WG_PRIVATE_KEY={server['private_key']}",
        f"RUBEVPN_WG_PEER_PUBLIC_KEY={client['public_key']}",
        f"RUBEVPN_WG_VERIFY_PUBLIC_KEY={verify['public_key']}",
        f"RUBEVPN_WG_LISTEN_PORT={LISTEN_PORT}",
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
    command = f"npx -y pinggy -p 443 -R0:localhost:{LISTEN_PORT} udp@free.pinggy.io --noTui"
    process = subprocess.Popen(
        ["cmd.exe", "/c", command], cwd=CFG,
        stdout=log, stderr=subprocess.STDOUT, creationflags=DETACHED,
    )
    return process.pid


def wait_for_endpoint(tunnel_pid: int, timeout: int = 75) -> str:
    deadline = time.time() + timeout
    log_path = CFG / "tunnel.log"
    while time.time() < deadline:
        if not process_alive(tunnel_pid):
            fail("TUNNEL_FAILED", "The UDP tunnel process exited before publishing an endpoint.",
                 "Check Node.js/npm installation and the tunnel log.", {"pid": tunnel_pid})
        text = log_path.read_text(encoding="utf-8", errors="ignore") if log_path.exists() else ""
        if "Tunnel stopped" in text or "Daemon process is no longer running" in text:
            fail("TUNNEL_FAILED", "The Pinggy daemon stopped the tunnel.",
                 "Retry start.bat; avoid stopping other tunnels manually.")
        match = ENDPOINT_RE.search(text)
        if match:
            host, port = match.group(1), match.group(2)
            try:
                return f"{socket.gethostbyname(host)}:{port}"
            except OSError:
                return f"{host}:{port}"
        time.sleep(0.5)
    fail("TUNNEL_TIMEOUT", "No public UDP endpoint was published in time.",
         "Check internet access and Node.js/npm, then retry.", {"timeout_seconds": timeout})


def verify_handshake(server: dict[str, str], verify: dict[str, str], endpoint: str) -> int:
    peercheck = ensure_binary("peercheck.exe")
    env = os.environ.copy()
    env.update({
        "RUBEVPN_WG_PRIVATE_KEY": verify["private_key"],
        "RUBEVPN_WG_SERVER_PUBLIC_KEY": server["public_key"],
        "RUBEVPN_WG_LOCAL_ADDRESS": "10.0.0.3",
        "RUBEVPN_TEST_ENDPOINT": endpoint,
    })
    try:
        result = subprocess.run([str(peercheck)], env=env, capture_output=True,
                                text=True, timeout=30)
    except subprocess.TimeoutExpired:
        fail("VERIFY_TIMEOUT", "Handshake verification timed out.",
             "Check UDP reachability and retry.")
    match = re.search(r"VERIFY_OK reply_bytes=(\d+)", result.stdout)
    if not match:
        fail("VERIFY_FAILED", "No encrypted handshake reply was received through the tunnel.",
             "Confirm the endpoint is current and the server is listening on UDP 51820.",
             {"endpoint": endpoint, "stdout": result.stdout.strip()[:200]})
    return int(match.group(1))


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
        except (ImportError, OSError):
            qrcode = None  # type: ignore[assignment]
    if qrcode is not None:
        try:
            qrcode.make(content).save(CFG / "phone-qr.png")
        except (OSError, ValueError):
            pass
    return content


def print_online(endpoint: str, server_pid: int, tunnel_pid: int, reply_bytes: int | None) -> None:
    state = "ONLINE" if reply_bytes is not None else "DEGRADED"
    handshake = f"verified (reply_bytes={reply_bytes})" if reply_bytes is not None else "SKIPPED"
    print("=" * 48)
    print(f" RUBEVPN SERVICE {state}")
    print("=" * 48)
    print(f" Endpoint : udp://{endpoint}")
    print(f" Server   : pid {server_pid}, UDP {LISTEN_PORT}")
    print(f" Tunnel   : pid {tunnel_pid}")
    print(f" Handshake: {handshake}")
    print(f" Profile  : {CFG / 'phone.conf'}")
    qr = CFG / "phone-qr.png"
    if qr.exists():
        opened = "not opened (RUBEVPN_NO_QR=1)" if os.getenv("RUBEVPN_NO_QR") == "1" else "opened automatically"
        print(f" QR       : {qr} ({opened})")
    print(f" Logs     : {CFG / 'server.log'}")
    print(f"            {CFG / 'tunnel.log'}")
    print(" Note     : free tunnel expires in ~60 min; import the fresh QR after each restart.")
    print("=" * 48)


def main() -> int:
    parser = argparse.ArgumentParser(description="Start RubeVPN's experimental tunnel stack")
    parser.add_argument("--stop", action="store_true", help="stop the running server and tunnel")
    args = parser.parse_args()

    CFG.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        user = f"{os.getenv('USERDOMAIN', '')}\\{os.getenv('USERNAME', '')}".strip("\\")
        if user:
            subprocess.run(["icacls", str(CFG), "/inheritance:r", "/grant:r", f"{user}:F"],
                           capture_output=True)

    if args.stop:
        stop_existing()
        print("[OK] Stopped RubeVPN server and tunnel.")
        return 0

    print("[..] Checking prerequisites")
    if not udp_port_available(LISTEN_PORT):
        fail("PORT_CONFLICT", f"UDP port {LISTEN_PORT} is already in use.",
             "Find the owning process with Get-NetUDPEndpoint before retrying.",
             {"port": LISTEN_PORT})
    if shutil.which("npm") is None:
        fail("MISSING_DEPENDENCY", "Node.js/npm was not found.",
             "Install Node.js from https://nodejs.org/ and retry.")

    configured = all((CFG / f"{name}_keys.json").exists() for name in ("server", "client", "verify"))
    print(f"[OK] Config directory: {CFG}")
    print("[OK] Reusing existing keys." if configured else "[OK] First run: generating keys.")

    stop_existing()
    server_exe = ensure_binary("server.exe")
    keygen = ensure_binary("keygen.exe")
    server_keys, client_keys, verify_keys = ensure_keys(keygen)
    write_server_env(server_keys, client_keys, verify_keys)

    server_pid = start_server(server_exe)
    time.sleep(0.7)
    if not process_alive(server_pid):
        fail("SERVER_START_FAILED", "The WireGuard server exited immediately after launch.",
             "Inspect server.log for the startup error.", {"pid": server_pid})
    print(f"[OK] WireGuard server listening on UDP {LISTEN_PORT} (pid {server_pid})")

    tunnel_pid = start_tunnel()
    endpoint = wait_for_endpoint(tunnel_pid)
    print(f"[OK] Public UDP endpoint: udp://{endpoint}")

    reply_bytes: int | None = None
    if os.getenv("RUBEVPN_SKIP_VERIFY") == "1":
        print("[WARN] Handshake verification skipped by RUBEVPN_SKIP_VERIFY=1")
    else:
        reply_bytes = verify_handshake(server_keys, verify_keys, endpoint)
        print(f"[OK] Encrypted handshake verified (reply_bytes={reply_bytes})")

    write_android_profile(server_keys, client_keys, endpoint)
    qr = CFG / "phone-qr.png"
    if qr.exists() and os.name == "nt" and os.getenv("RUBEVPN_NO_QR") != "1":
        try:
            os.startfile(str(qr))  # type: ignore[attr-defined]
        except OSError:
            pass

    tunnel_text = (CFG / "tunnel.log").read_text(encoding="utf-8", errors="ignore")
    tunnel_match = TUNNEL_ID_RE.search(tunnel_text)
    STATE.write_text(json.dumps({
        "processes": [
            {"pid": server_pid, "name": "server.exe"},
            {"pid": tunnel_pid, "name": "cmd.exe"},
        ],
        "pids": [server_pid, tunnel_pid],
        "tunnel_id": tunnel_match.group(1) if tunnel_match else None,
        "endpoint": endpoint,
        "updated_at": _now(),
    }, indent=2), encoding="utf-8")

    print_online(endpoint, server_pid, tunnel_pid, reply_bytes)
    return 0 if reply_bytes is not None else 2


if __name__ == "__main__":
    raise SystemExit(main())
