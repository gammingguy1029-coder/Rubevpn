#!/usr/bin/env python3
"""Structured network diagnostics for RubeVPN.

Read-only. Reports what can actually be observed; marks unverifiable items
as UNVERIFIED instead of claiming success.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
ROOT = SCRIPTS_DIR.parent
sys.path.insert(0, str(SCRIPTS_DIR))
sys.path.insert(0, str(ROOT))

from preflight import (  # noqa: E402
    _check,
    check_config,
    check_dependencies,
    check_installation,
    check_os,
    check_privileges,
    check_python,
)


def _mask_ip(ip: str) -> str:
    parts = ip.split(".")
    return ".".join(parts[:2] + ["x", "x"]) if len(parts) == 4 else "n/a"


def dns_probe() -> dict[str, object]:
    try:
        infos = socket.getaddrinfo("example.com", 443, proto=socket.IPPROTO_TCP)
        count = len({info[4][0] for info in infos})
        return _check("dns_resolution", "PASS", "OK", f"Resolved example.com to {count} address(es).",
                      "No action required.", {"address_count": count})
    except OSError as exc:
        return _check("dns_resolution", "FAIL", "DNS_FAILURE",
                      f"DNS resolution failed: {type(exc).__name__}.",
                      "Check resolver settings and upstream connectivity.", {})


def stun_probe(port: int = 51820) -> dict[str, object]:
    """Measure the outbound UDP mapping; never infer inbound reachability from it."""
    try:
        server_ip = socket.gethostbyname("stun.l.google.com")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(6)
        bound_port = port
        try:
            sock.bind(("0.0.0.0", bound_port))
        except OSError:
            sock.bind(("0.0.0.0", 0))
            bound_port = sock.getsockname()[1]
        transaction = os.urandom(12)
        request = b"\x00\x01\x00\x00\x21\x12\xa4\x42" + transaction
        sock.sendto(request, (server_ip, 19302))
        data, _ = sock.recvfrom(2048)
        sock.close()
        marker = data.find(b"\x00\x20\x00\x08")
        if marker < 0:
            return _check("udp_mapping", "SKIP", "OK", "STUN response lacked XOR-MAPPED-ADDRESS.",
                          "Retry with a standards-compliant STUN server.", {})
        mapped_port = ((data[marker + 6] ^ 0x21) << 8) | (data[marker + 7] ^ 0x12)
        raw_ip = bytes(a ^ b for a, b in zip(data[marker + 8:marker + 12], b"\x21\x12\xa4\x42"))
        external_ip = ".".join(str(byte) for byte in raw_ip)
        preserved = mapped_port == bound_port
        return _check(
            "udp_mapping", "PASS" if preserved else "FAIL", "OK" if preserved else "UDP_UNREACHABLE",
            f"Bound UDP port {bound_port} maps to external port {mapped_port} "
            f"({'preserved' if preserved else 'NOT preserved - a public client cannot reach the configured port'}).",
            "Use a host with a public IP and inbound UDP forwarding for the WireGuard port.",
            {"bound_port": bound_port, "mapped_port": mapped_port,
             "external_address_masked": _mask_ip(external_ip), "port_preserved": preserved},
        )
    except Exception as exc:
        return _check("udp_mapping", "SKIP", "OK",
                      f"STUN probe unavailable: {type(exc).__name__}.",
                      "Retry when outbound UDP to STUN is available.", {})


def inbound_udp_probe() -> dict[str, object]:
    return _check(
        "inbound_udp", "UNVERIFIED", "UDP_UNREACHABLE",
        "Unsolicited inbound UDP cannot be verified from this host alone; an external probe is required.",
        "Run an external UDP probe against the advertised endpoint on an authorized host.", {},
    )


def run_diagnostics(config_path: Path, online: bool) -> dict[str, object]:
    config_check, settings = check_config(config_path)
    port = settings.vpn.endpoint_port if settings else 51820
    checks = [
        check_os(),
        check_python(),
        check_dependencies(),
        config_check,
        check_installation(),
        check_privileges(),
        dns_probe() if online else _check("dns_resolution", "SKIP", "OK", "Skipped (--offline).", ""),
        stun_probe(port) if online else _check("udp_mapping", "SKIP", "OK", "Skipped (--offline).", ""),
        inbound_udp_probe(),
    ]
    return {
        "tool": "rubevpn-diagnostics",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(),
        "checks": checks,
        "note": "UNVERIFIED items are not successes. No VPN handshake or client data is available on this host.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="RubeVPN structured network diagnostics")
    parser.add_argument("--config", type=Path, default=ROOT / "config" / "settings.example.json")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    report = run_diagnostics(args.config, online=not args.offline)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for check in report["checks"]:
            print(f"[{check['status']:>10}] {check['name']}: {check['message']}")
        print(report["note"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
