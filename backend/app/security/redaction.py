"""Secret redaction applied to every log record before it is stored or emitted."""
from __future__ import annotations

import re
from typing import Any

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # PEM encoded private keys (possibly multi-line).
    (re.compile(r"-----BEGIN[^-]*-----.*?-----END[^-]*-----", re.DOTALL), "[REDACTED_PRIVATE_KEY]"),
    # key=value / "key": "value" style pairs.
    (
        re.compile(
            r"(?i)\b(private[_-]?key|password|passwd|secret|token|api[_-]?key)"
            r"(\s*[:=]\s*|\"\s*:\s*\")([^\s,;\"}]+)",
        ),
        r"\1\2[REDACTED]",
    ),
    # Bearer tokens.
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"), r"\1[REDACTED]"),
    # WireGuard base64 keys embedded in free text (43 chars plus '=').
    (re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/])"), "[REDACTED_KEY]"),
]


def redact(text: str) -> str:
    """Replace anything resembling a credential with a fixed marker."""
    result = text
    for pattern, replacement in _PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def redact_value(value: Any) -> Any:
    """Recursively redact strings inside dicts and lists."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {key: redact_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_value(item) for item in value]
    return value
