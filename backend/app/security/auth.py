"""Password hashing and signed session tokens (stdlib only)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any

_ITERATIONS = 210_000
_ALGORITHM = "pbkdf2_sha256"


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def hash_password(password: str, iterations: int = _ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{_ALGORITHM}${iterations}${_b64encode(salt)}${_b64encode(digest)}"


def verify_password(stored: str, provided: str) -> bool:
    try:
        algorithm, iteration_text, salt_text, digest_text = stored.split("$", 3)
        if algorithm != _ALGORITHM:
            return False
        iterations = int(iteration_text)
        if iterations < 100_000 or iterations > 10_000_000:
            return False
        salt = _b64decode(salt_text)
        expected = _b64decode(digest_text)
        actual = hashlib.pbkdf2_hmac("sha256", provided.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(expected, actual)
    except (ValueError, TypeError):
        return False


def create_session_token(secret: str, username: str, ttl_seconds: int = 3600) -> str:
    now = int(time.time())
    payload = {"sub": username, "iat": now, "exp": now + ttl_seconds}
    payload_part = _b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = hmac.new(secret.encode("utf-8"), payload_part.encode("ascii"), hashlib.sha256).digest()
    return f"{payload_part}.{_b64encode(signature)}"


def verify_session_token(secret: str, token: str | None) -> dict[str, Any] | None:
    if not token:
        return None
    try:
        payload_part, signature_part = token.split(".", 1)
        expected = hmac.new(secret.encode("utf-8"), payload_part.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64decode(signature_part)):
            return None
        payload = json.loads(_b64decode(payload_part).decode("utf-8"))
        if not isinstance(payload, dict):
            return None
        if int(payload.get("exp", 0)) <= int(time.time()):
            return None
        if not payload.get("sub"):
            return None
        return payload
    except (ValueError, TypeError, KeyError, UnicodeDecodeError):
        return None
