#!/usr/bin/env python3
"""Idempotent, non-destructive environment preflight for RubeVPN.

Checks OS, dependencies, configuration, installation state, port conflicts,
and network prerequisites. Never modifies configuration or credentials.
"""
from __future__ import annotations

import argparse
import getpass
import importlib.util
import json
import platform
import socket
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.app.config import ConfigError, load_settings  # noqa: E402
from backend.app.security.auth import hash_password  # noqa: E402
from backend.app.security.redaction import redact  # noqa: E402
from backend.app.services.host_capabilities import is_admin as _host_is_admin  # noqa: E402
from backend.app.services.host_capabilities import wireguard_installed  # noqa: E402
from backend.app.services.windows_wireguard import (  # noqa: E402
    SystemCommandRunner,
    ip_forwarding_enabled as _host_ip_forwarding_enabled,
)

REQUIRED_MODULES = ("fastapi", "uvicorn", "pydantic", "pytest", "httpx")


def _check(name: str, status: str, code: str, message: str, recovery: str,
           context: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "name": name,
        "status": status,
        "code": code,
        "message": redact(message),
        "recovery_action": redact(recovery),
        "context": context or {},
    }


def check_os() -> dict[str, Any]:
    system = platform.system()
    return _check("operating_system", "PASS" if system in {"Windows", "Linux"} else "FAIL",
                  "MISSING_DEPENDENCY" if system not in {"Windows", "Linux"} else "OK",
                  f"Detected {system} {platform.release()} ({platform.version()}).",
                  "Use a supported Windows or Linux host.",
                  {"system": system, "release": platform.release()})


def check_python() -> dict[str, Any]:
    ok = sys.version_info >= (3, 12)
    return _check("python_version", "PASS" if ok else "FAIL", "MISSING_DEPENDENCY",
                  f"Python {platform.python_version()} detected; 3.12+ required.",
                  "Install Python 3.12 or newer.",
                  {"version": platform.python_version()})


def check_dependencies() -> dict[str, Any]:
    missing = [name for name in REQUIRED_MODULES if importlib.util.find_spec(name) is None]
    return _check("dependencies", "FAIL" if missing else "PASS", "MISSING_DEPENDENCY",
                  "Missing packages: " + ", ".join(missing) if missing else "All required packages are importable.",
                  "Install them with `python -m pip install -r backend/requirements.txt`.",
                  {"missing": missing})


def check_config(path: Path) -> tuple[dict[str, Any], Any]:
    try:
        settings = load_settings(path)
    except ConfigError as exc:
        safe = {k: v for k, v in exc.context.items() if k in {"path", "missing", "location"}}
        return _check("configuration", "FAIL", exc.code, exc.message, exc.recovery_action, safe), None
    return _check("configuration", "PASS", "OK",
                  f"Settings validated from {path}.", "No action required.",
                  {"path": str(path), "provider": settings.vpn.provider,
                   "endpoint_port": settings.vpn.endpoint_port}), settings


def check_installation() -> dict[str, Any]:
    found = wireguard_installed()
    return _check("existing_installation", "SKIP" if not found else "PASS", "OK",
                  "WireGuard tools found on this host." if found
                  else "No WireGuard installation detected; nothing will be overwritten.",
                  "Leave existing installations untouched unless you intend to manage them.",
                  {"wireguard_tools": found})


def _port_in_use(port: int, kind: str) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if kind == "udp" else socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", port))
        return False
    except OSError:
        return True
    finally:
        sock.close()


def check_ports(settings: Any) -> dict[str, Any]:
    if settings is None:
        return _check("port_conflicts", "SKIP", "OK", "Skipped because configuration is invalid.",
                      "Fix the configuration first.")
    conflicts = []
    if _port_in_use(settings.vpn.endpoint_port, "udp"):
        conflicts.append(f"udp/{settings.vpn.endpoint_port}")
    if _port_in_use(settings.dashboard.port, "tcp"):
        conflicts.append(f"tcp/{settings.dashboard.port}")
    return _check("port_conflicts", "FAIL" if conflicts else "PASS", "PORT_CONFLICT" if conflicts else "OK",
                  "Ports already in use: " + ", ".join(conflicts) if conflicts else "Required ports are free.",
                  "Identify the owning process before starting the service; do not kill it blindly.",
                  {"conflicts": conflicts})


def _is_admin() -> bool:
    return _host_is_admin()


def _ip_forwarding_enabled() -> bool:
    return _host_ip_forwarding_enabled(SystemCommandRunner())


def check_privileges() -> dict[str, Any]:
    admin = _is_admin()
    forwarding = _ip_forwarding_enabled()
    ok = admin and forwarding
    return _check("vpn_privileges", "PASS" if ok else "FAIL", "NO_PRIVILEGE",
                  f"Elevation={'yes' if admin else 'no'}, IP forwarding={'on' if forwarding else 'off'}.",
                  "An authorized VPN host must provide elevation and enabled IP forwarding/NAT.",
                  {"elevated": admin, "ip_forwarding": forwarding})


def check_network(settings: Any, online: bool) -> dict[str, Any]:
    if settings is None:
        return _check("network_prerequisites", "SKIP", "OK", "Skipped because configuration is invalid.",
                      "Fix the configuration first.")
    endpoint = settings.vpn.endpoint_host
    checks: list[dict[str, Any]] = []

    if endpoint:
        checks.append(_check("public_endpoint", "PASS", "OK",
                             f"Public endpoint configured: {endpoint}:{settings.vpn.endpoint_port}.",
                             "Verify inbound UDP reachability from an external client.", {}))
    else:
        checks.append(_check("public_endpoint", "FAIL", "PUBLIC_ENDPOINT_MISSING",
                             "No public endpoint is configured.",
                             "Deploy on an authorized host with a static public IPv4 address.", {}))

    if online:
        try:
            with urllib.request.urlopen("https://api.ipify.org", timeout=8) as response:
                public_ip = response.read().decode("utf-8").strip()
            local_ip = socket.gethostbyname(socket.gethostname())
            is_public = public_ip == local_ip
            checks.append(_check(
                "public_address", "PASS" if is_public else "FAIL",
                "OK" if is_public else "PUBLIC_ENDPOINT_MISSING",
                f"External address {public_ip}; local primary address {local_ip} "
                f"({'publicly bound' if is_public else 'behind NAT / not bound locally'}).",
                "Use a host where the advertised endpoint is bound to a local interface.",
                {"external_prefix": public_ip.rsplit(".", 1)[0] + ".x"},
            ))
        except Exception as exc:
            checks.append(_check("public_address", "SKIP", "OK",
                                 f"Public address lookup unavailable: {type(exc).__name__}.",
                                 "Retry with network access or pass --offline.", {}))
    else:
        checks.append(_check("public_address", "SKIP", "OK", "Online checks disabled (--offline).",
                             "Run without --offline to test the public path.", {}))

    return {
        "name": "network_prerequisites",
        "status": "FAIL" if any(c["status"] == "FAIL" for c in checks) else "PASS",
        "code": "PUBLIC_ENDPOINT_MISSING" if any(c["status"] == "FAIL" for c in checks) else "OK",
        "message": "See nested network checks.",
        "recovery_action": "Use an authorized host with a public endpoint and inbound UDP.",
        "context": {"checks": checks},
    }


def run_preflight(path: Path, online: bool) -> dict[str, Any]:
    os_check = check_os()
    python_check = check_python()
    dependency_check = check_dependencies()
    config_check, settings = check_config(path)
    checks = [
        os_check,
        python_check,
        dependency_check,
        config_check,
        check_installation(),
        check_ports(settings),
        check_privileges(),
        check_network(settings, online),
    ]
    blocking = [check["name"] for check in checks if check["status"] == "FAIL"]
    return {
        "tool": "rubevpn-preflight",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(),
        "blocking": blocking,
        "ready": not blocking,
        "checks": checks,
    }


def print_human(report: dict[str, Any]) -> None:
    for check in report["checks"]:
        print(f"[{check['status']:>4}] {check['name']}: {check['message']}")
        if check["status"] == "FAIL":
            print(f"       recovery: {check['recovery_action']}")
    print(f"Ready: {'yes' if report['ready'] else 'no'} (blocking: {', '.join(report['blocking']) or 'none'})")


def main() -> int:
    parser = argparse.ArgumentParser(description="RubeVPN non-destructive environment preflight")
    parser.add_argument("--config", type=Path, default=ROOT / "config" / "settings.example.json")
    parser.add_argument("--json", action="store_true", help="emit JSON report")
    parser.add_argument("--save", action="store_true", help="write logs/preflight-results.json")
    parser.add_argument("--strict", action="store_true", help="exit 2 when blocking issues exist")
    parser.add_argument("--offline", action="store_true", help="skip public network lookups")
    parser.add_argument("--hash-password", action="store_true", help="prompt for a password and print its PBKDF2 hash")
    args = parser.parse_args()

    if args.hash_password:
        password = getpass.getpass("New admin password: ")
        confirmation = getpass.getpass("Confirm password: ")
        if not password or password != confirmation:
            print("Passwords did not match or were empty.", file=sys.stderr)
            return 1
        print(hash_password(password))
        return 0

    try:
        report = run_preflight(args.config, online=not args.offline)
    except Exception as exc:
        print(f"Preflight failed internally: {type(exc).__name__}", file=sys.stderr)
        return 1

    if args.save:
        output = ROOT / "logs" / "preflight-results.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2), encoding="utf-8")

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_human(report)
    return 2 if (args.strict and report["blocking"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
