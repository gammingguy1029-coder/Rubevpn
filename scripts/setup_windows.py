#!/usr/bin/env python3
"""Idempotent Windows WireGuard setup. Non-destructive by default.

Without --apply this only reports a plan. With --apply it creates files and
system configuration, but never overwrites existing keys or configs.
"""
from __future__ import annotations

import argparse
import ctypes
import ipaddress
import json
import os
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.app.config import load_settings  # noqa: E402
from backend.app.monitoring.models import ErrorCode  # noqa: E402
from backend.app.security.redaction import redact  # noqa: E402
from backend.app.services.windows_wireguard import (  # noqa: E402
    CommandResult,
    CommandRunner,
    SystemCommandRunner,
    WireGuardError,
    WireGuardPaths,
    derive_public_key,
    discover_paths,
    generate_private_key,
    ip_forwarding_enabled,
    is_valid_wireguard_key,
    service_name,
    service_status,
)

STATE_FILE = "setup-state.json"
SERVER_KEY_FILE = "server_private.key"
CLIENT_KEY_FILE = "client_private.key"
CLIENT_CONFIG_FILE = "phone.conf"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_admin() -> bool:
    if platform.system() != "Windows":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class FakeRunnerForTests(CommandRunner):  # pragma: no cover - documented test hook
    def __init__(self, results: dict[tuple[Any, ...], CommandResult]):
        self.results = results

    def run(self, args, *, input_text=None, timeout=10):
        return self.results.get(tuple(args), CommandResult(1, "", "unmocked command"))


def _action(name: str, status: str, detail: str, code: str = "OK",
            context: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "name": name,
        "status": status,
        "code": code,
        "detail": redact(detail),
        "context": context or {},
    }


def _read_key(path: Path) -> str:
    value = path.read_text(encoding="utf-8").strip()
    if not is_valid_wireguard_key(value):
        raise WireGuardError(
            ErrorCode.CFG_INVALID,
            f"Existing key file {path.name} is invalid.",
            "Move the invalid file aside and rerun setup to generate a new keypair.",
        )
    return value


def _render_server_config(settings: Any, private_key: str, client_public_key: str) -> str:
    network = ipaddress.ip_network(settings.vpn.subnet_cidr)
    server_ip = network.network_address + 1
    client_ip = network.network_address + 2
    dns = ", ".join(settings.vpn.dns)
    return (
        "[Interface]\n"
        f"PrivateKey = {private_key}\n"
        f"Address = {server_ip}/{network.prefixlen}\n"
        f"ListenPort = {settings.vpn.endpoint_port}\n"
        f"DNS = {dns}\n\n"
        "[Peer]\n"
        f"PublicKey = {client_public_key}\n"
        f"AllowedIPs = {client_ip}/32\n"
    )


def _render_client_config(settings: Any, private_key: str, server_public_key: str) -> str:
    network = ipaddress.ip_network(settings.vpn.subnet_cidr)
    client_ip = network.network_address + 2
    dns = ", ".join(settings.vpn.dns)
    allowed = ", ".join(settings.vpn.allowed_ipv4)
    endpoint = settings.vpn.endpoint_host
    return (
        "[Interface]\n"
        f"PrivateKey = {private_key}\n"
        f"Address = {client_ip}/32\n"
        f"DNS = {dns}\n\n"
        "[Peer]\n"
        f"PublicKey = {server_public_key}\n"
        f"AllowedIPs = {allowed}\n"
        f"Endpoint = {endpoint}:{settings.vpn.endpoint_port}\n"
        "PersistentKeepalive = 25\n"
    )


def _write_new(path: Path, content: str, created: list[str], apply: bool) -> dict[str, Any]:
    if path.exists():
        return _action(f"file:{path.name}", "SKIP", "Already exists; not overwritten.")
    if apply:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8") as handle:
            handle.write(content)
        created.append(str(path))
    return _action(f"file:{path.name}", "CREATE" if apply else "PLAN",
                   f"Would create {path.name}." if not apply else f"Created {path.name}.",
                   context={"path": str(path)})


def _restrict_acl(paths: list[str], runner: CommandRunner, apply: bool) -> list[dict[str, Any]]:
    actions = []
    for item in paths:
        if not apply:
            actions.append(_action(f"acl:{Path(item).name}", "PLAN", "Would restrict to administrators."))
            continue
        result = runner.run(["icacls", item, "/inheritance:r", "/grant:r", "*S-1-5-32-544:F"])
        if result.returncode != 0:
            actions.append(_action(f"acl:{Path(item).name}", "FAIL",
                                   "Could not restrict file ACL.", "ACL_FAILURE"))
        else:
            actions.append(_action(f"acl:{Path(item).name}", "PASS", "Restricted to administrators."))
    return actions


def _system_actions(settings: Any, paths: WireGuardPaths, runner: CommandRunner,
                    apply: bool, created: list[str]) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    if not ip_forwarding_enabled(runner):
        if apply:
            result = runner.run(["netsh", "interface", "ipv4", "set", "global", "forwarding=enabled"])
            actions.append(_action("ip_forwarding", "PASS" if result.returncode == 0 else "FAIL",
                                   "IPv4 forwarding enable command executed." if result.returncode == 0
                                   else "Failed to enable IPv4 forwarding.",
                                   "OK" if result.returncode == 0 else "NO_PRIVILEGE"))
        else:
            actions.append(_action("ip_forwarding", "PLAN", "Would enable IPv4 forwarding."))
    else:
        actions.append(_action("ip_forwarding", "SKIP", "Already enabled."))

    nat_name = f"RubeVPNNat"
    cidr = settings.vpn.subnet_cidr
    ps = (f"if (Get-NetNat -Name '{nat_name}' -ErrorAction SilentlyContinue) {{ 'EXISTS' }} "
          f"else {{ New-NetNat -Name '{nat_name}' -InternalIPInterfaceAddressPrefix '{cidr}' "
          f"| Out-Null; 'CREATED' }}")
    if apply:
        result = runner.run(["powershell", "-NoProfile", "-Command", ps])
        actions.append(_action("nat", "PASS" if result.returncode == 0 else "FAIL",
                               "NAT check/configuration executed." if result.returncode == 0
                               else "Failed to configure NAT.",
                               "OK" if result.returncode == 0 else "NO_PRIVILEGE"))
    else:
        actions.append(_action("nat", "PLAN", f"Would ensure NAT '{nat_name}' for {cidr}."))

    current = service_status(settings.vpn.interface_name, runner)
    if current == "RUNNING":
        actions.append(_action("tunnel_service", "SKIP", "Service is already running."))
    elif paths.wireguard_exe is None:
        actions.append(_action("tunnel_service", "FAIL",
                               "wireguard.exe was not found.", "WIREGUARD_SERVICE_FAILURE"))
    elif apply:
        conf = paths.config_path(settings.vpn.interface_name)
        result = runner.run([str(paths.wireguard_exe), "/installtunnelservice", str(conf)])
        if result.returncode == 0:
            created.append("SERVICE")
        actions.append(_action("tunnel_service", "PASS" if result.returncode == 0 else "FAIL",
                               "Tunnel service install command executed." if result.returncode == 0
                               else "Failed to install tunnel service.",
                               "OK" if result.returncode == 0 else "WIREGUARD_SERVICE_FAILURE"))
    else:
        actions.append(_action("tunnel_service", "PLAN",
                               f"Would install service {service_name(settings.vpn.interface_name)}."))
    return actions


def run_setup(settings: Any, paths: WireGuardPaths, runner: CommandRunner, *,
              apply: bool = False, client_public_key: str | None = None) -> dict[str, Any]:
    actions: list[dict[str, Any]] = []
    created: list[str] = []
    interface = settings.vpn.interface_name
    server_conf_path = paths.config_path(interface)

    if platform.system() != "Windows":
        actions.append(_action("operating_system", "FAIL", "Windows is required.", "MISSING_DEPENDENCY"))
    else:
        actions.append(_action("operating_system", "PASS", "Windows detected."))

    if not _is_admin():
        actions.append(_action("elevation", "FAIL", "Not elevated; --apply cannot change system state.",
                               "NO_PRIVILEGE"))
        apply = False
    else:
        actions.append(_action("elevation", "PASS", "Elevated session."))

    if paths.wg_exe is None:
        actions.append(_action("wireguard_tools", "FAIL", "wg.exe not found.",
                               "WIREGUARD_SERVICE_FAILURE"))
    else:
        actions.append(_action("wireguard_tools", "PASS", "wg.exe found."))

    if not settings.vpn.endpoint_host:
        actions.append(_action("public_endpoint", "FAIL", "vpn.endpoint_host is not configured.",
                               "PUBLIC_ENDPOINT_MISSING"))
    else:
        actions.append(_action("public_endpoint", "PASS",
                               f"Endpoint set to {redact(settings.vpn.endpoint_host)}:"
                               f"{settings.vpn.endpoint_port}."))

    server_key_path = paths.config_dir / SERVER_KEY_FILE
    client_key_path = paths.config_dir / CLIENT_KEY_FILE
    client_conf_path = paths.config_dir / CLIENT_CONFIG_FILE

    try:
        if server_key_path.exists():
            server_private = _read_key(server_key_path)
            actions.append(_action("server_key", "SKIP", "Existing server key preserved."))
        elif paths.wg_exe:
            server_private = generate_private_key(paths, runner)
            _write_new(server_key_path, server_private, created, apply)
            actions.append(_action("server_key", "CREATE" if apply else "PLAN",
                                   "Server key generated in memory."))
        else:
            server_private = ""
        server_public = derive_public_key(paths, server_private, runner) if server_private else ""

        if client_public_key:
            if not is_valid_wireguard_key(client_public_key):
                raise WireGuardError(
                    ErrorCode.CFG_INVALID,
                    "Client public key is invalid.",
                    "Provide a valid 32-byte base64 WireGuard public key.",
                )
            client_private = ""
            client_public = client_public_key
            actions.append(_action("client_key", "SKIP", "Using supplied client public key."))
        elif client_key_path.exists():
            client_private = _read_key(client_key_path)
            client_public = derive_public_key(paths, client_private, runner) if client_private else ""
            actions.append(_action("client_key", "SKIP", "Existing client key preserved."))
        elif paths.wg_exe:
            client_private = generate_private_key(paths, runner)
            _write_new(client_key_path, client_private, created, apply)
            client_public = derive_public_key(paths, client_private, runner)
            actions.append(_action("client_key", "CREATE" if apply else "PLAN",
                                   "Client key generated in memory."))
        else:
            client_private = ""
            client_public = ""

        if server_public and client_public:
            _write_new(server_conf_path, _render_server_config(settings, server_private, client_public),
                       created, apply)
            _write_new(client_conf_path, _render_client_config(settings, client_private, server_public),
                       created, apply)
        else:
            actions.append(_action("configs", "SKIP", "Keys unavailable; configs not rendered."))
    except WireGuardError as exc:
        actions.append(_action("key_management", "FAIL", exc.message, str(exc.code)))

    sensitive = [str(path) for path in (server_key_path, client_key_path, server_conf_path, client_conf_path)
                 if path.exists()]
    actions.extend(_restrict_acl(sensitive, runner, apply))
    actions.extend(_system_actions(settings, paths, runner, apply, created))

    blocking = [f"{item['name']}:{item['code']}" for item in actions if item["status"] == "FAIL"]
    report: dict[str, Any] = {
        "tool": "rubevpn-windows-setup",
        "timestamp": _now(),
        "mode": "apply" if apply else "plan",
        "interface": interface,
        "ready": not blocking,
        "blocking": blocking,
        "actions": actions,
        "created": created,
        "notes": [
            "Keys are never printed. Retrieve client profile only from an authenticated administrator session.",
            "Handshake and routing remain UNVERIFIED until tested on an eligible Windows host.",
        ],
    }
    if apply:
        state_path = paths.config_dir / STATE_FILE
        state = {
            "tool": "rubevpn-windows-setup",
            "interface": interface,
            "created": created,
            "updated_at": _now(),
        }
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
        report["state_file"] = str(state_path)
    return report


def run_cleanup(settings: Any, paths: WireGuardPaths, runner: CommandRunner) -> dict[str, Any]:
    state_path = paths.config_dir / STATE_FILE
    removed: list[str] = []
    if not state_path.exists():
        return {"tool": "rubevpn-windows-setup", "mode": "cleanup", "removed": [],
                "note": "No state file; nothing removed."}
    state = json.loads(state_path.read_text(encoding="utf-8"))
    if state.get("tool") != "rubevpn-windows-setup":
        return {"tool": "rubevpn-windows-setup", "mode": "cleanup", "removed": [],
                "note": "State file is not owned by this tool; nothing removed."}
    for item in state.get("created", []):
        if item == "SERVICE":
            if paths.wireguard_exe and service_status(settings.vpn.interface_name, runner) != "ABSENT":
                runner.run([str(paths.wireguard_exe), "/uninstalltunnelservice", settings.vpn.interface_name])
                removed.append("SERVICE")
            continue
        path = Path(item)
        if path.is_file() and path.parent == paths.config_dir:
            path.unlink()
            removed.append(path.name)
    state_path.unlink()
    return {"tool": "rubevpn-windows-setup", "timestamp": _now(), "mode": "cleanup", "removed": removed}


def main() -> int:
    parser = argparse.ArgumentParser(description="Idempotent Windows WireGuard setup for RubeVPN")
    parser.add_argument("--config", type=Path, default=ROOT / "config" / "settings.example.json")
    parser.add_argument("--apply", action="store_true", help="actually create files and system config")
    parser.add_argument("--cleanup", action="store_true", help="remove only artifacts created by this tool")
    parser.add_argument("--client-public-key", default=None,
                        help="optional phone public key (public data, safe to pass)")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    settings = load_settings(args.config)
    paths = discover_paths()
    runner: CommandRunner = SystemCommandRunner()
    if args.cleanup:
        report = run_cleanup(settings, paths, runner)
    else:
        report = run_setup(settings, paths, runner, apply=args.apply,
                           client_public_key=args.client_public_key)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"mode={report.get('mode')} ready={report.get('ready')} blocking={report.get('blocking')}")
        for item in report.get("actions", []):
            print(f"[{item['status']:>5}] {item['name']}: {item['detail']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
