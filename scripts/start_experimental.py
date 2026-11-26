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
import hashlib
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

from portable_config import capture as capture_portable, seed as seed_portable
from portable_config import load as load_portable, save as save_portable
from tunnel_providers import TunnelError, TunnelHandle, select_provider

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools" / "userspace_wg"
BASE = os.getenv("LOCALAPPDATA") or str(Path.home() / ".rubevpn")
CFG = Path(os.getenv("RUBEVPN_WG_DIR", str(Path(BASE) / "RubeVPN" / "wg")))
STATE = CFG / "state.json"
ENDPOINT_RE = re.compile(r"udp://([A-Za-z0-9.\-]+):(\d+)")
TUNNEL_ID_RE = re.compile(r"Tunnel\s+([A-Za-z0-9]+)")
LISTEN_PORT = int(os.getenv("RUBEVPN_WG_LISTEN_PORT", "51820"))
DEFAULT_MTU = "1420"
MTU_MIN = 1200
MTU_MAX = 1500
DEVICES_DIR_NAME = "devices"
STATUS_FILE_NAME = "server-status.json"
FIRST_DEVICE_IP = 2
VERIFY_DEVICE_IP = 3
DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,48}$")
DETACHED = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

# Pin the relay client: an unpinned `npx -y` fetch is a supply-chain and
# reproducibility risk, especially on CI runners.
PINGGY_PACKAGE = os.getenv("RUBEVPN_PINGGY_PACKAGE", "pinggy@0.6.10")

_TUNNEL_PROVIDER = None


def tunnel_provider():
    """Lazily select the public relay (pinggy by default, playit opt-in)."""
    global _TUNNEL_PROVIDER
    if _TUNNEL_PROVIDER is None:
        try:
            _TUNNEL_PROVIDER = select_provider()
        except TunnelError as exc:
            fail(exc.code, exc.message, exc.recovery, exc.context)
    return _TUNNEL_PROVIDER


def provider_failure(exc: TunnelError) -> NoReturn:
    fail(exc.code, exc.message, exc.recovery, exc.context)


# Hashes of the binaries committed under tools/userspace_wg. A mismatch means
# the bundle was altered and must not be executed.
EXPECTED_BINARY_SHA256 = {
    "keygen.exe": "fdbc341194c095338299cce60d0d3f6b2910d87b22e48a151f0b5d4a25b02a50",
    "peercheck.exe": "26468610e8ac435efd216f9a80e4109a087dd7e90f3aef95048c86b62ac1bacf",
    "server.exe": "93263f941c6cd7bdcb1bb51521c6d6577c049a676cb62c0a37cffe18046b9fd2",
    "speedtest.exe": "e3bd0e69ea87efd52d5616e2f387e6336a114a5dfe647aa40ee1335d538c5572",
}


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


def _process_creation_ticks(pid: int) -> int | None:
    """Windows FILETIME creation stamp; None when identity cannot be verified."""
    if os.name != "nt" or pid <= 0:
        return None
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.GetProcessTimes.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
        ]
        kernel32.GetProcessTimes.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return None
        try:
            creation, exit_time, kernel_time, user_time = (wintypes.FILETIME() for _ in range(4))
            ok = kernel32.GetProcessTimes(
                handle, ctypes.byref(creation), ctypes.byref(exit_time),
                ctypes.byref(kernel_time), ctypes.byref(user_time),
            )
            if not ok:
                return None
            return (creation.dwHighDateTime << 32) | creation.dwLowDateTime
        finally:
            kernel32.CloseHandle(handle)
    except Exception:
        return None


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


def safe_stop_pid(pid: int, expected: tuple[str, ...],
                  created_ticks: int | None = None) -> None:
    """Only stop a PID when it still belongs to the process we started.

    A recycled PID is the dangerous case: creation time is authoritative when
    available, and an unverifiable identity means we do not kill anything.
    """
    if not process_alive(pid):
        return
    if created_ticks is not None:
        if _process_creation_ticks(pid) != created_ticks:
            return
    else:
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
    provider_name = str(data.get("provider") or "pinggy").lower()
    relay_names = ("playitd", "playit") if provider_name == "playit" else ("cmd.exe", "npx")
    for entry in processes:
        try:
            expected = ("server.exe",) if entry.get("name") == "server.exe" else relay_names
            safe_stop_pid(int(entry["pid"]), expected, entry.get("created_ticks"))
        except (KeyError, TypeError, ValueError, AttributeError):
            continue
    try:
        tunnel_handle = TunnelHandle(
            int(data.get("pids", [0, 0])[1]) if len(data.get("pids", [])) > 1 else 0,
            data.get("tunnel_id"),
        )
        tunnel_provider().stop(tunnel_handle, PINGGY_PACKAGE)
    except (TunnelError, OSError, TypeError, ValueError):
        pass
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


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ensure_binary(name: str) -> Path:
    target = CFG / name
    source = TOOLS / name
    if source.exists():
        digest = _sha256(source)
        expected = EXPECTED_BINARY_SHA256.get(name)
        if (expected and digest != expected
                and os.getenv("RUBEVPN_SKIP_BINARY_VERIFY") != "1"):
            fail(
                "BINARY_INTEGRITY_FAILED",
                f"Bundled binary {name} does not match its pinned SHA-256.",
                "Re-clone the repository. Set RUBEVPN_SKIP_BINARY_VERIFY=1 only "
                "when you intentionally supplied your own verified binary.",
                {"binary": name, "expected": expected, "actual": digest},
            )
        # A previous install may hold an older binary. Refresh it whenever the
        # bundled version changes, otherwise new peers/features are missing.
        if target.exists() and _sha256(target) == digest:
            return target
        shutil.copy2(source, target)
        return target
    if target.exists():
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


def _devices_dir() -> Path:
    return CFG / DEVICES_DIR_NAME


def list_devices() -> list[dict[str, str]]:
    """Read the device registry. Private keys stay on disk, never in the API."""
    directory = _devices_dir()
    if not directory.is_dir():
        return []
    devices: list[dict[str, str]] = []
    for path in sorted(directory.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="ascii"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict) and data.get("id") and data.get("public_key"):
            devices.append(data)
    return devices


def next_device_ip(devices: list[dict[str, str]]) -> int:
    used = {VERIFY_DEVICE_IP}
    for device in devices:
        try:
            used.add(int(str(device.get("ip", "")).split(".")[-1]))
        except (ValueError, TypeError):
            continue
    candidate = FIRST_DEVICE_IP
    while candidate in used:
        candidate += 1
    if candidate > 250:
        fail("ADDRESS_EXHAUSTED", "No free tunnel address remains for a new device.",
             "Remove an unused device and retry.")
    return candidate


def _write_device_record(record: dict[str, str]) -> None:
    directory = _devices_dir()
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{record['id']}.json").write_text(json.dumps(record, indent=2), encoding="ascii")


def ensure_default_device(client_keys: dict[str, str]) -> dict[str, str]:
    """Migrate the legacy single-client install into the device registry."""
    devices = list_devices()
    if devices:
        return devices[0]
    record = {
        "id": "phone",
        "name": "Phone",
        "private_key": client_keys["private_key"],
        "public_key": client_keys["public_key"],
        "ip": f"10.0.0.{next_device_ip(devices)}",
        "created_at": _now(),
    }
    _write_device_record(record)
    return record


def add_device(name: str) -> dict[str, str]:
    keygen = ensure_binary("keygen.exe")
    result = _run([str(keygen)])
    if result.returncode != 0:
        fail("KEY_GENERATION_FAILED", "WireGuard key generation failed.",
             "Verify the bundled keygen.exe and retry.", {"stderr": result.stderr.strip()[:200]})
    try:
        keys = json.loads(result.stdout)
    except json.JSONDecodeError:
        fail("KEY_GENERATION_FAILED", "Key generator returned invalid JSON.",
             "Re-clone the repository with a valid keygen.exe.")
    if len(keys.get("private_key", "")) != 44 or len(keys.get("public_key", "")) != 44:
        fail("KEY_GENERATION_FAILED", "Key generator returned invalid key lengths.",
             "Re-clone the repository with a valid keygen.exe.")

    devices = list_devices()
    base = re.sub(r"[^a-z0-9_-]+", "-", str(name).strip().lower()).strip("-")[:32] or "device"
    existing = {device.get("id") for device in devices}
    device_id = base
    suffix = 2
    while device_id in existing:
        device_id = f"{base}-{suffix}"
        suffix += 1
    record = {
        "id": device_id,
        "name": str(name).strip()[:64] or device_id,
        "private_key": keys["private_key"],
        "public_key": keys["public_key"],
        "ip": f"10.0.0.{next_device_ip(devices)}",
        "created_at": _now(),
    }
    _write_device_record(record)
    return record


def remove_device(device_id: str) -> bool:
    if not DEVICE_ID_RE.fullmatch(device_id):
        return False
    directory = _devices_dir()
    record_path = directory / f"{device_id}.json"
    if not record_path.is_file():
        return False
    record_path.unlink()
    for suffix in (".conf", "-qr.png"):
        (directory / f"{device_id}{suffix}").unlink(missing_ok=True)
    return True


def read_server_status() -> dict[str, object]:
    """Real per-device handshake data written by the Go server, never guessed."""
    path = CFG / STATUS_FILE_NAME
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"updated_at": None, "peers": []}
    if not isinstance(data, dict):
        return {"updated_at": None, "peers": []}
    return data


def read_mtu() -> int:
    """Read and validate the WireGuard MTU from the environment."""
    raw = os.getenv("RUBEVPN_WG_MTU", DEFAULT_MTU)
    recovery = (
        f"Set RUBEVPN_WG_MTU to an integer from {MTU_MIN} to {MTU_MAX} "
        "(default 1420; try 1400 on CGNAT/relay links) and retry."
    )
    try:
        mtu = int(raw)
    except (TypeError, ValueError):
        fail("CFG_INVALID", f"RUBEVPN_WG_MTU must be an integer (got {raw!r}).",
             recovery, {"RUBEVPN_WG_MTU": raw})
    if not MTU_MIN <= mtu <= MTU_MAX:
        fail("CFG_INVALID",
             f"RUBEVPN_WG_MTU={raw} is outside the supported range {MTU_MIN}..{MTU_MAX}.",
             recovery, {"RUBEVPN_WG_MTU": raw, "allowed_range": f"{MTU_MIN}..{MTU_MAX}"})
    return mtu


def write_server_env(server: dict[str, str], client: dict[str, str], verify: dict[str, str],
                     mtu: int | None = None,
                     devices: list[dict[str, str]] | None = None) -> None:
    resolved_mtu = read_mtu() if mtu is None else mtu
    peers = devices if devices is not None else [
        {"public_key": client["public_key"], "ip": "10.0.0.2"}
    ]
    peer_json = json.dumps(
        [{"public_key": device["public_key"], "allowed_ip": f"{device['ip']}/32"}
         for device in peers],
        separators=(",", ":"),
    )
    lines = [
        f"RUBEVPN_WG_PRIVATE_KEY={server['private_key']}",
        f"RUBEVPN_WG_PEERS_JSON={peer_json}",
        f"RUBEVPN_WG_PEER_PUBLIC_KEY={client['public_key']}",  # legacy fallback
        f"RUBEVPN_WG_VERIFY_PUBLIC_KEY={verify['public_key']}",
        f"RUBEVPN_WG_LISTEN_PORT={LISTEN_PORT}",
        f"RUBEVPN_WG_MTU={resolved_mtu}",
        f"RUBEVPN_WG_STATUS_FILE={CFG / STATUS_FILE_NAME}",
    ]
    (CFG / "server.env").write_text("\n".join(lines) + "\n", encoding="ascii")


def start_server(server_exe: Path) -> tuple[int, int | None]:
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
    return process.pid, _process_creation_ticks(process.pid)


def start_tunnel() -> tuple[int, int | None]:
    try:
        pid = tunnel_provider().start(CFG, LISTEN_PORT, PINGGY_PACKAGE)
    except TunnelError as exc:
        provider_failure(exc)
    return pid, _process_creation_ticks(pid)


def wait_for_endpoint(tunnel_pid: int, timeout: int = 75) -> str:
    try:
        return tunnel_provider().wait_for_endpoint(
            CFG, TunnelHandle(tunnel_pid), timeout, process_alive)
    except TunnelError as exc:
        provider_failure(exc)


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


def run_speedtest(server: dict[str, str], verify: dict[str, str], endpoint: str) -> str:
    """Optional bundled throughput probe; failures never gate normal startup."""
    speedtest = ensure_binary("speedtest.exe")
    env = os.environ.copy()
    env.update({
        "RUBEVPN_WG_PRIVATE_KEY": verify["private_key"],
        "RUBEVPN_WG_SERVER_PUBLIC_KEY": server["public_key"],
        "RUBEVPN_WG_LOCAL_ADDRESS": "10.0.0.3",
        "RUBEVPN_TEST_ENDPOINT": endpoint,
    })
    try:
        result = subprocess.run([str(speedtest)], env=env, capture_output=True,
                                text=True, timeout=120)
    except subprocess.TimeoutExpired:
        fail("SPEEDTEST_FAILED", "The bundled speed test timed out after 120 seconds.",
             "Retry with --speedtest, or ignore it: throughput testing is optional and not "
             "required for the VPN to start.", {"endpoint": endpoint, "timeout_seconds": 120})
    output = (result.stdout or "") + (result.stderr or "")
    if output:
        print(output, end="" if output.endswith("\n") else "\n")
    if result.returncode != 0:
        fail("SPEEDTEST_FAILED", "The bundled speed test exited with a non-zero status.",
             "Retry with --speedtest after checking the endpoint and MTU; this probe is "
             "optional and does not affect startup.",
             {"endpoint": endpoint, "exit_code": result.returncode,
              "output": output.strip()[:200]})
    return output


def _write_qr(content: str, path: Path) -> None:
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
            qrcode.make(content).save(path)
        except (OSError, ValueError):
            pass


def _profile_content(private_key: str, server_public_key: str, address: str,
                     endpoint: str, mtu: int | None) -> str:
    resolved_mtu = read_mtu() if mtu is None else mtu
    return "\n".join([
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {address}/32",
        "DNS = 10.0.0.1",
        f"MTU = {resolved_mtu}",
        "",
        "[Peer]",
        f"PublicKey = {server_public_key}",
        "AllowedIPs = 0.0.0.0/0",
        f"Endpoint = {endpoint}",
        "PersistentKeepalive = 25",
        "",
    ])


def write_android_profile(server: dict[str, str], client: dict[str, str], endpoint: str,
                          mtu: int | None = None) -> str:
    """Legacy single-phone profile, kept for existing installs."""
    content = _profile_content(client["private_key"], server["public_key"],
                              "10.0.0.2", endpoint, mtu)
    (CFG / "phone.conf").write_text(content, encoding="ascii")
    _write_qr(content, CFG / "phone-qr.png")
    return content


def write_device_profile(device: dict[str, str], server: dict[str, str], endpoint: str,
                         mtu: int | None = None) -> str:
    """Per-device profile and QR, stored beside the device record."""
    content = _profile_content(device["private_key"], server["public_key"],
                              device["ip"], endpoint, mtu)
    directory = _devices_dir()
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{device['id']}.conf").write_text(content, encoding="ascii")
    _write_qr(content, directory / f"{device['id']}-qr.png")
    return content


def write_state(server_pid: int, tunnel_pid: int, endpoint: str = "",
                tunnel_id: str | None = None, server_ticks: int | None = None,
                tunnel_ticks: int | None = None, provider: str | None = None,
                static_endpoint: bool | None = None) -> None:
    """Persist PIDs and identity so a partial stack can be cleaned up safely."""
    info = tunnel_provider().info
    STATE.write_text(json.dumps({
        "processes": [
            {"pid": server_pid, "name": "server.exe", "created_ticks": server_ticks},
            {"pid": tunnel_pid, "name": "playitd" if info.name == "playit" else "cmd.exe",
             "created_ticks": tunnel_ticks},
        ],
        "pids": [server_pid, tunnel_pid],
        "tunnel_id": tunnel_id,
        "endpoint": endpoint,
        "provider": provider or info.name,
        "static_endpoint": info.static_endpoint if static_endpoint is None else static_endpoint,
        "updated_at": _now(),
    }, indent=2), encoding="utf-8")


def _qr_opening_enabled() -> bool:
    """Never auto-open a QR image on a headless CI runner."""
    return (os.getenv("RUBEVPN_NO_QR") != "1"
            and not (os.getenv("GITHUB_ACTIONS") or os.getenv("CI")))


def show_status() -> None:
    """Report the running stack without spawning or stopping anything."""
    if not STATE.exists():
        print("[OK] No RubeVPN stack is recorded.")
        return
    try:
        data = json.loads(STATE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        print("[WARN] State file is unreadable; run start.bat to rebuild it.")
        return
    print(f" Endpoint : {data.get('endpoint') or 'unknown'}")
    print(f" Relay    : {data.get('provider') or 'pinggy'}"
          f"{' (static)' if data.get('static_endpoint') else ''}")
    for entry in data.get("processes", []):
        try:
            pid = int(entry["pid"])
        except (KeyError, TypeError, ValueError):
            continue
        alive = process_alive(pid)
        identity = ""
        ticks = entry.get("created_ticks")
        if alive and ticks is not None:
            identity = (" (identity verified)"
                        if _process_creation_ticks(pid) == ticks else " (PID RECYCLED - not ours)")
        print(f" {entry.get('name', 'process')}: pid {pid}, "
              f"{'alive' if alive else 'stopped'}{identity}")
    devices = list_devices()
    if devices:
        peers = {
            peer.get("public_key"): peer
            for peer in read_server_status().get("peers", [])
            if isinstance(peer, dict)
        }
        print(" Devices:")
        for device in devices:
            peer = peers.get(device.get("public_key"), {})
            handshake = int(peer.get("last_handshake_unix") or 0)
            state = "CONNECTED" if handshake > 0 else "no handshake yet"
            print(f"  - {device['id']} ({device.get('ip', '?')}): {state}")


def print_online(endpoint: str, server_pid: int, tunnel_pid: int, reply_bytes: int | None) -> None:
    state = "ONLINE" if reply_bytes is not None else "DEGRADED"
    handshake = f"verified (reply_bytes={reply_bytes})" if reply_bytes is not None else "SKIPPED"
    print("=" * 48)
    print(f" RUBEVPN SERVICE {state}")
    print("=" * 48)
    info = tunnel_provider().info
    print(f" Endpoint : udp://{endpoint}")
    print(f" Relay    : {info.name}{' (static endpoint)' if info.static_endpoint else ''}")
    print(f" Server   : pid {server_pid}, UDP {LISTEN_PORT}")
    print(f" Tunnel   : pid {tunnel_pid}")
    print(f" Handshake: {handshake}")
    print(f" Profile  : {CFG / 'phone.conf'}")
    qr = CFG / "phone-qr.png"
    if qr.exists():
        opened = ("opened automatically" if _qr_opening_enabled()
                  else "not opened (suppressed on CI or by RUBEVPN_NO_QR=1)")
        print(f" QR       : {qr} ({opened})")
    print(f" Logs     : {CFG / 'server.log'}")
    print(f"            {CFG / 'tunnel.log'}")
    if info.expiry_minutes:
        print(f" Note     : free tunnel expires in ~{info.expiry_minutes} min; "
              "import the fresh QR after each restart.")
    else:
        print(" Note     : static endpoint; no expiry. Restart only after device changes.")
    print("=" * 48)


def main() -> int:
    parser = argparse.ArgumentParser(description="Start RubeVPN's experimental tunnel stack")
    parser.add_argument("--stop", action="store_true", help="stop the running server and tunnel")
    parser.add_argument("--status", action="store_true", help="show the running stack without changing it")
    parser.add_argument("--add-device", metavar="NAME", default=None,
                        help="create a new device profile and keypair")
    parser.add_argument("--remove-device", metavar="ID", default=None,
                        help="revoke a device profile and keypair")
    parser.add_argument("--list-devices", action="store_true", help="list enrolled devices")
    parser.add_argument("--provider", choices=("pinggy", "playit"), default=None,
                        help="choose the public relay (remembered for future runs)")
    parser.add_argument("--speedtest", action="store_true",
                        help="run the bundled optional throughput test after verification")
    args = parser.parse_args()

    if args.provider:
        os.environ["RUBEVPN_TUNNEL_PROVIDER"] = args.provider
    seed_portable(CFG)

    if args.status:
        show_status()
        return 0
    if args.list_devices:
        for device in list_devices():
            print(f"{device['id']}\t{device.get('name', '')}\t{device.get('ip', '')}\t"
                  f"{_devices_dir() / (device['id'] + '.conf')}")
        return 0
    if args.add_device:
        record = add_device(args.add_device)
        capture_portable(CFG)
        print(f"[OK] Added device {record['id']} ({record['ip']}). "
              "Restart the service to apply it.")
        return 0
    if args.remove_device:
        if remove_device(args.remove_device):
            capture_portable(CFG)
            print(f"[OK] Removed device {args.remove_device}. "
                  "Restart the service to revoke it.")
            return 0
        print("[ERROR] Device not found or invalid id.", file=sys.stderr)
        return 1

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

    # Clean up a previous or partially started stack before checking ports.
    stop_existing()

    print("[..] Checking prerequisites")
    if not udp_port_available(LISTEN_PORT):
        fail("PORT_CONFLICT", f"UDP port {LISTEN_PORT} is already in use.",
             "Find the owning process with Get-NetUDPEndpoint before retrying.",
             {"port": LISTEN_PORT})
    relay = tunnel_provider()
    print(f"[OK] Relay provider: {relay.info.name}")
    portable = load_portable()
    portable["tunnel_provider"] = relay.info.name
    save_portable(portable)
    if relay.info.name == "pinggy" and shutil.which("npm") is None:
        fail("MISSING_DEPENDENCY", "Node.js/npm was not found.",
             "Install Node.js from https://nodejs.org/ and retry.")
    if relay.info.name == "playit":
        if not getattr(relay, "binary", None):
            fail("PLAYIT_BINARY_MISSING", "playitd was not found on PATH.",
                 "Install the playit.gg agent or set RUBEVPN_PLAYIT_BIN.")
        if not relay.secret_path.is_file():
            fail("PLAYIT_SECRET_MISSING", "playit secret file is missing.",
                 "Run `python scripts/setup_playit.py --secret <key>` first.")
        if not relay.endpoint:
            fail("PLAYIT_ENDPOINT_MISSING", "No static playit.gg endpoint is configured.",
                 "Run `python scripts/setup_playit.py --endpoint host:port`.")

    mtu = read_mtu()
    print(f"[OK] WireGuard MTU: {mtu}")
    configured = all((CFG / f"{name}_keys.json").exists() for name in ("server", "client", "verify"))
    print(f"[OK] Config directory: {CFG}")
    print("[OK] Reusing existing keys." if configured else "[OK] First run: generating keys.")

    server_exe = ensure_binary("server.exe")
    keygen = ensure_binary("keygen.exe")
    ensure_binary("speedtest.exe")  # sync the optional probe for new devices
    server_keys, client_keys, verify_keys = ensure_keys(keygen)
    ensure_default_device(client_keys)
    devices = list_devices()
    capture_portable(CFG)
    write_server_env(server_keys, client_keys, verify_keys, mtu, devices)

    server_pid, server_ticks = start_server(server_exe)
    time.sleep(0.7)
    if not process_alive(server_pid):
        fail("SERVER_START_FAILED", "The WireGuard server exited immediately after launch.",
             "Inspect server.log for the startup error.", {"pid": server_pid})
    print(f"[OK] WireGuard server listening on UDP {LISTEN_PORT} (pid {server_pid})")

    tunnel_pid: int | None = None
    tunnel_ticks: int | None = None
    try:
        tunnel_pid, tunnel_ticks = start_tunnel()
        write_state(server_pid, tunnel_pid, server_ticks=server_ticks,
                    tunnel_ticks=tunnel_ticks)
        endpoint = wait_for_endpoint(tunnel_pid)
        print(f"[OK] Public UDP endpoint: udp://{endpoint}")

        reply_bytes: int | None = None
        if os.getenv("RUBEVPN_SKIP_VERIFY") == "1":
            print("[WARN] Handshake verification skipped by RUBEVPN_SKIP_VERIFY=1")
        else:
            reply_bytes = verify_handshake(server_keys, verify_keys, endpoint)
            print(f"[OK] Encrypted handshake verified (reply_bytes={reply_bytes})")
            if args.speedtest:
                run_speedtest(server_keys, verify_keys, endpoint)

        write_android_profile(server_keys, client_keys, endpoint, mtu)
        for device in devices:
            write_device_profile(device, server_keys, endpoint, mtu)
        qr = CFG / "phone-qr.png"
        if qr.exists() and os.name == "nt" and _qr_opening_enabled():
            try:
                os.startfile(str(qr))  # type: ignore[attr-defined]
            except OSError:
                pass

        tunnel_text = (CFG / "tunnel.log").read_text(encoding="utf-8", errors="ignore")
        tunnel_match = TUNNEL_ID_RE.search(tunnel_text)
        write_state(server_pid, tunnel_pid, endpoint,
                    tunnel_match.group(1) if tunnel_match else None,
                    server_ticks, tunnel_ticks)

        print_online(endpoint, server_pid, tunnel_pid, reply_bytes)
        return 0 if reply_bytes is not None else 2
    except BaseException:
        # Anything failing after the first spawn must not leak detached
        # processes. Identity checks stop us killing a recycled PID.
        if tunnel_pid is not None:
            safe_stop_pid(tunnel_pid, ("cmd.exe",), tunnel_ticks)
        safe_stop_pid(server_pid, ("server.exe",), server_ticks)
        STATE.unlink(missing_ok=True)
        raise


if __name__ == "__main__":
    raise SystemExit(main())
