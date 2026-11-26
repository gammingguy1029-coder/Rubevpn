"""Pluggable public UDP relays for the experimental WireGuard stack.

Two providers are supported:
  * pinggy  - zero setup, works on this GitHub runner, endpoint expires in ~60 min
  * playit  - free, static endpoint, native UDP, good Asia routing

The WireGuard server, keys, device registry and handshake verification are
identical for both; only the public relay differs.
"""
from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol

from portable_config import load as load_portable

ENDPOINT_RE = re.compile(r"udp://([A-Za-z0-9.\-]+):(\d+)")
TUNNEL_ID_RE = re.compile(r"Tunnel\s+([A-Za-z0-9]+)")
STATIC_ENDPOINT_RE = re.compile(r"^([A-Za-z0-9.\-]+):(\d{1,5})$")


class TunnelError(Exception):
    def __init__(self, code: str, message: str, recovery: str,
                 context: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.recovery = recovery
        self.context = context or {}


@dataclass
class TunnelHandle:
    pid: int
    tunnel_id: str | None = None
    created_ticks: int | None = None


@dataclass(frozen=True)
class TunnelInfo:
    name: str
    static_endpoint: bool
    expiry_minutes: int | None


class TunnelProvider(Protocol):
    info: TunnelInfo

    def start(self, cfg: Path, listen_port: int, package: str) -> int: ...

    def wait_for_endpoint(self, cfg: Path, handle: TunnelHandle, timeout: int,
                          alive: Callable[[int], bool]) -> str: ...

    def stop(self, handle: TunnelHandle, package: str) -> None: ...


def _popen_detached(args: list[str], cwd: Path, log_path: Path) -> int:
    log = log_path.open("ab")
    kwargs: dict[str, Any] = {"cwd": str(cwd), "stdout": log, "stderr": subprocess.STDOUT}
    if os.name == "nt":
        flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(
            subprocess, "DETACHED_PROCESS", 0)
        kwargs["creationflags"] = flags
    return subprocess.Popen(args, **kwargs).pid


def _resolve_endpoint(host: str, port: str) -> str:
    try:
        return f"{socket.gethostbyname(host)}:{port}"
    except OSError:
        return f"{host}:{port}"


class PinggyProvider:
    """Existing relay. Endpoint changes on every restart; expires in ~60 min."""

    info = TunnelInfo(name="pinggy", static_endpoint=False, expiry_minutes=60)

    def __init__(self, host: str | None = None) -> None:
        self.host = host or os.getenv("RUBEVPN_TUNNEL_HOST", "free.pinggy.io")

    def _command(self, listen_port: int, package: str) -> list[str]:
        remote = f"npx -y {package} -p 443 -R0:localhost:{listen_port} udp@{self.host} --noTui"
        return ["cmd.exe", "/c", remote] if os.name == "nt" else remote.split()

    def start(self, cfg: Path, listen_port: int, package: str) -> int:
        if shutil.which("npm") is None:
            raise TunnelError(
                "MISSING_DEPENDENCY", "Node.js/npm was not found.",
                "Install Node.js from https://nodejs.org/ and retry.")
        return _popen_detached(
            self._command(listen_port, package), cfg, cfg / "tunnel.log")

    def wait_for_endpoint(self, cfg: Path, handle: TunnelHandle, timeout: int,
                          alive: Callable[[int], bool]) -> str:
        deadline = time.time() + timeout
        log_path = cfg / "tunnel.log"
        while time.time() < deadline:
            if not alive(handle.pid):
                raise TunnelError(
                    "TUNNEL_FAILED", "The UDP tunnel process exited before publishing an endpoint.",
                    "Check Node.js/npm installation and the tunnel log.", {"pid": handle.pid})
            text = log_path.read_text(encoding="utf-8", errors="ignore") if log_path.exists() else ""
            if "Tunnel stopped" in text or "Daemon process is no longer running" in text:
                raise TunnelError(
                    "TUNNEL_FAILED", "The Pinggy daemon stopped the tunnel.",
                    "Retry start.bat; avoid stopping other tunnels manually.")
            match = ENDPOINT_RE.search(text)
            if match:
                return _resolve_endpoint(match.group(1), match.group(2))
            time.sleep(0.5)
        raise TunnelError(
            "TUNNEL_TIMEOUT", "No public UDP endpoint was published in time.",
            "Check internet access and Node.js/npm, then retry.", {"timeout_seconds": timeout})

    def stop(self, handle: TunnelHandle, package: str) -> None:
        if not handle.tunnel_id:
            return
        command = ["cmd.exe", "/c", f"npx -y {package} stop {handle.tunnel_id}"] \
            if os.name == "nt" else f"npx -y {package} stop {handle.tunnel_id}".split()
        try:
            subprocess.run(command, capture_output=True, timeout=20)
        except (OSError, subprocess.SubprocessError):
            pass


class PlayitProvider:
    """Free static UDP relay with Asia datacenters. Needs a one-time agent setup."""

    info = TunnelInfo(name="playit", static_endpoint=True, expiry_minutes=None)

    def __init__(self, secret_path: Path | None = None, endpoint: str | None = None,
                 binary: str | None = None) -> None:
        self.secret_path = secret_path or _default_secret_path()
        self.endpoint = (endpoint or os.getenv("RUBEVPN_PLAYIT_ENDPOINT")
                         or _endpoint_from_file(self.secret_path)
                         or (load_portable().get("playit") or {}).get("endpoint"))
        bundled = _default_secret_path().parent / (
            "playitd.exe" if os.name == "nt" else "playitd")
        self.binary = (binary or os.getenv("RUBEVPN_PLAYIT_BIN")
                       or (str(bundled) if bundled.is_file() else None)
                       or shutil.which("playitd"))

    def start(self, cfg: Path, listen_port: int, package: str) -> int:
        if not self.binary:
            raise TunnelError(
                "PLAYIT_BINARY_MISSING", "playitd was not found on PATH.",
                "Install the playit.gg agent from https://playit.gg/download "
                "or set RUBEVPN_PLAYIT_BIN to its full path.")
        if not self.secret_path.is_file():
            raise TunnelError(
                "PLAYIT_SECRET_MISSING",
                f"playit secret file is missing: {self.secret_path}",
                "Run `python scripts/setup_playit.py --secret <key>` first.")
        if not self.endpoint:
            raise TunnelError(
                "PLAYIT_ENDPOINT_MISSING", "No static playit.gg endpoint is configured.",
                "Run `python scripts/setup_playit.py --endpoint host:port` with the "
                "public address from your playit dashboard.")
        return _popen_detached(
            [str(self.binary), "--secret-path", str(self.secret_path)],
            cfg, cfg / "tunnel.log")

    def wait_for_endpoint(self, cfg: Path, handle: TunnelHandle, timeout: int,
                          alive: Callable[[int], bool]) -> str:
        if not self.endpoint:
            raise TunnelError(
                "PLAYIT_ENDPOINT_MISSING", "No static playit.gg endpoint is configured.",
                "Run `python scripts/setup_playit.py --endpoint host:port`.")
        match = STATIC_ENDPOINT_RE.fullmatch(self.endpoint.strip())
        if not match:
            raise TunnelError(
                "PLAYIT_ENDPOINT_INVALID", f"Invalid playit endpoint: {self.endpoint!r}.",
                "Use the host:port shown in your playit.gg dashboard.")
        if not alive(handle.pid):
            raise TunnelError(
                "TUNNEL_FAILED", "The playit agent exited immediately after launch.",
                "Check tunnel.log and verify the secret key with `playit status`.",
                {"pid": handle.pid})
        return _resolve_endpoint(match.group(1), match.group(2))

    def stop(self, handle: TunnelHandle, package: str) -> None:
        # The agent is stopped by PID with identity checks in the launcher.
        return None


def _default_secret_path() -> Path:
    base = os.getenv("LOCALAPPDATA") or str(Path.home() / ".rubevpn")
    return Path(os.getenv("RUBEVPN_WG_DIR", str(Path(base) / "RubeVPN" / "wg"))) / "playit.toml"


def _endpoint_from_file(path: Path) -> str | None:
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            match = re.match(r'\s*endpoint\s*=\s*["\']?([^"\'\s]+)', line)
            if match:
                return match.group(1)
    except OSError:
        pass
    return None


def select_provider(name: str | None = None, **kwargs: Any) -> TunnelProvider:
    provider = (name or os.getenv("RUBEVPN_TUNNEL_PROVIDER")
                or load_portable().get("tunnel_provider") or "pinggy").strip().lower()
    if provider == "pinggy":
        return PinggyProvider(**kwargs)
    if provider == "playit":
        return PlayitProvider(**kwargs)
    raise TunnelError(
        "TUNNEL_PROVIDER_INVALID", f"Unknown tunnel provider: {provider!r}.",
        "Set RUBEVPN_TUNNEL_PROVIDER to 'pinggy' or 'playit'.", {"provider": provider})
