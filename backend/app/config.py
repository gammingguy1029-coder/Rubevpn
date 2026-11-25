"""Configuration loading and validation.

The settings file contains no secrets. Administrative credentials and the
session signing secret are read exclusively from environment variables.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError, field_validator

PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Keys that must never appear in a settings file.
_FORBIDDEN_KEYS = {
    "private_key",
    "privatekey",
    "password",
    "passwd",
    "secret",
    "session_secret",
    "token",
    "api_key",
    "apikey",
    "admin_password_hash",
}
_PEM_MARKER = "-----BEGIN"
_WG_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")


class ConfigError(Exception):
    """Raised when configuration is missing, invalid, or unsafe."""

    code = "CFG_INVALID"

    def __init__(self, message: str, recovery_action: str, context: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.recovery_action = recovery_action
        self.context = context or {}


def _reject_secrets(value: Any, path: str = "") -> None:
    """Recursively reject secret-looking keys and values in raw config."""
    if isinstance(value, dict):
        for key, item in value.items():
            location = f"{path}.{key}" if path else str(key)
            normalized = str(key).lower().replace("-", "_")
            if normalized in _FORBIDDEN_KEYS:
                raise ConfigError(
                    f"Secret field '{key}' is not allowed in the settings file at {location}.",
                    "Remove the secret from the file and provide it through an environment variable.",
                    {"location": location},
                )
            _reject_secrets(item, location)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_secrets(item, f"{path}[{index}]")
    elif isinstance(value, str):
        stripped = value.strip()
        if _PEM_MARKER in stripped.upper():
            raise ConfigError(
                f"Private key material was found in the settings file at {path or 'root'}.",
                "Remove the key and store it outside the repository.",
                {"location": path or "root"},
            )
        if _WG_KEY_RE.match(stripped):
            raise ConfigError(
                f"A WireGuard-style key was found in the settings file at {path or 'root'}.",
                "Remove the key; generate and store it in an authenticated, non-public location.",
                {"location": path or "root"},
            )


class VpnSettings(BaseModel):
    provider: Literal["unavailable", "wireguard"] = "unavailable"
    endpoint_host: str | None = None
    endpoint_port: int = Field(default=51820, ge=1, le=65535)
    allowed_ipv4: list[str] = Field(default_factory=lambda: ["0.0.0.0/0"])
    dns: list[str] = Field(default_factory=lambda: ["1.1.1.1"])
    session_duration_minutes: int = Field(default=60, ge=1, le=10080)
    interface_name: str = "RubeVPN"
    subnet_cidr: str = "10.7.0.0/24"

    @field_validator("interface_name")
    @classmethod
    def validate_interface_name(cls, value: str) -> str:
        import re

        if not re.fullmatch(r"[A-Za-z0-9_-]{1,15}", value):
            raise ValueError("interface_name must be 1-15 characters: letters, digits, '-' or '_'")
        return value

    @field_validator("subnet_cidr")
    @classmethod
    def validate_subnet(cls, value: str) -> str:
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise ValueError(f"Invalid IPv4 VPN subnet '{value}': {exc}") from exc
        if network.version != 4 or network.prefixlen > 30:
            raise ValueError("subnet_cidr must be an IPv4 network with at least 4 addresses")
        return str(network)

    @field_validator("allowed_ipv4")
    @classmethod
    def validate_networks(cls, values: list[str]) -> list[str]:
        result: list[str] = []
        for entry in values:
            try:
                network = ipaddress.ip_network(entry, strict=True)
            except ValueError as exc:
                raise ValueError(f"Invalid IPv4 network '{entry}': {exc}") from exc
            if network.version != 4:
                raise ValueError(f"Only IPv4 networks are supported: '{entry}'")
            result.append(str(network))
        if not result:
            raise ValueError("At least one allowed IPv4 network is required")
        return result

    @field_validator("dns")
    @classmethod
    def validate_dns(cls, values: list[str]) -> list[str]:
        result: list[str] = []
        for entry in values:
            try:
                address = ipaddress.ip_address(entry)
            except ValueError as exc:
                raise ValueError(f"Invalid DNS IP address '{entry}': {exc}") from exc
            result.append(str(address))
        if not result:
            raise ValueError("At least one explicit DNS server is required")
        return result

    @field_validator("endpoint_host")
    @classmethod
    def validate_host(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value or any(char in value for char in " \t\r\n/:"):
            raise ValueError("endpoint_host must be a hostname or IPv4 address without scheme or port")
        return value


class DashboardSettings(BaseModel):
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)
    refresh_seconds: int = Field(default=5, ge=1, le=300)

    @field_validator("host")
    @classmethod
    def validate_bind_host(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("dashboard host must not be empty")
        return value


class LoggingSettings(BaseModel):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    format: Literal["json", "text"] = "json"


class AppSettings(BaseModel):
    app_version: str = "1.0.0-m1"
    environment: str = "development"
    vpn: VpnSettings = Field(default_factory=VpnSettings)
    dashboard: DashboardSettings = Field(default_factory=DashboardSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)


def default_settings_path() -> Path:
    """Use a local settings.json when present, otherwise the committed example."""
    override = os.getenv("RUBEVPN_SETTINGS_PATH")
    if override:
        return Path(override)
    local = PROJECT_ROOT / "config" / "settings.json"
    return local if local.is_file() else PROJECT_ROOT / "config" / "settings.example.json"


def load_settings(path: str | Path | None = None) -> AppSettings:
    settings_path = Path(path) if path is not None else default_settings_path()
    if not settings_path.is_file():
        raise ConfigError(
            f"Settings file not found: {settings_path}",
            "Copy config/settings.example.json to config/settings.json and edit it.",
            {"path": str(settings_path)},
        )
    try:
        raw = json.loads(settings_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(
            f"Settings file could not be parsed: {exc}",
            "Fix the JSON syntax and ensure the file is readable.",
            {"path": str(settings_path)},
        ) from exc

    if not isinstance(raw, dict):
        raise ConfigError(
            "Settings file must contain a JSON object.",
            "Replace the file with a copy of config/settings.example.json.",
            {"path": str(settings_path)},
        )
    _reject_secrets(raw)
    try:
        return AppSettings.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(
            f"Settings validation failed: {exc}",
            "Correct the reported fields. See config/settings.example.json for valid values.",
            {"path": str(settings_path), "errors": exc.errors()},
        ) from exc


class SecuritySettings(BaseModel):
    username: str = "admin"
    password_hash: str
    session_secret: str
    cookie_secure: bool = False
    session_ttl_seconds: int = 3600

    @field_validator("session_secret")
    @classmethod
    def validate_secret(cls, value: str) -> str:
        if len(value) < 32:
            raise ValueError("RUBEVPN_SESSION_SECRET must be at least 32 characters")
        return value


def load_security_settings() -> SecuritySettings:
    """Load secrets from the environment. Missing secrets are a hard failure."""
    password_hash = os.getenv("RUBEVPN_ADMIN_PASSWORD_HASH")
    secret = os.getenv("RUBEVPN_SESSION_SECRET")
    missing = [
        name
        for name, value in (
            ("RUBEVPN_ADMIN_PASSWORD_HASH", password_hash),
            ("RUBEVPN_SESSION_SECRET", secret),
        )
        if not value
    ]
    if missing:
        raise ConfigError(
            f"Missing required security environment variables: {', '.join(missing)}",
            "Generate an admin password hash with `python scripts/preflight.py --hash-password` "
            "and a random session secret; export both before starting the service.",
            {"missing": missing},
        )
    try:
        return SecuritySettings(
            username=os.getenv("RUBEVPN_ADMIN_USER", "admin"),
            password_hash=password_hash or "",
            session_secret=secret or "",
            cookie_secure=os.getenv("RUBEVPN_COOKIE_SECURE", "false").lower() in {"1", "true", "yes"},
        )
    except ValidationError as exc:
        raise ConfigError(
            f"Security settings validation failed: {exc}",
            "Check the session secret length (minimum 32 characters) and the password hash format.",
            {"errors": exc.errors()},
        ) from exc
