"""Structured event capture used by the dashboard's event log."""
from __future__ import annotations

import logging
from collections import deque
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any

from ..security.redaction import redact

# Correlates every log event emitted while handling one HTTP request.
REQUEST_ID: ContextVar[str | None] = ContextVar("rubevpn_request_id", default=None)

_STANDARD = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys()) | {
    "message",
    "asctime",
    "taskName",
}


def record_to_event(record: logging.LogRecord) -> dict[str, Any]:
    """Convert a log record into a redacted, JSON-serialisable event."""
    event: dict[str, Any] = {
        "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
        "level": record.levelname,
        "logger": record.name,
        "message": redact(record.getMessage()),
    }
    for key, value in record.__dict__.items():
        if key not in _STANDARD and not key.startswith("_"):
            event[key] = redact(value) if isinstance(value, str) else value
    request_id = REQUEST_ID.get()
    if request_id is not None:
        event["request_id"] = request_id
    return event


class JsonFormatter(logging.Formatter):
    """Minimal JSON formatter with no external dependency."""

    def format(self, record: logging.LogRecord) -> str:
        import json

        return json.dumps(record_to_event(record), default=str)


class TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        event = record_to_event(record)
        suffix = "".join(
            f" {key}={value}"
            for key, value in event.items()
            if key not in {"timestamp", "level", "logger", "message"}
        )
        return f"{event['timestamp']} {event['level']} {event['logger']}: {event['message']}{suffix}"


class EventBuffer:
    """Fixed-size ring buffer of recent structured events."""

    def __init__(self, capacity: int = 200) -> None:
        self._events: deque[dict[str, Any]] = deque(maxlen=capacity)

    def append(self, event: dict[str, Any]) -> None:
        self._events.append(event)

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        if limit <= 0:
            return []
        return list(self._events)[-limit:][::-1]


class EventCaptureHandler(logging.Handler):
    def __init__(self, buffer: EventBuffer) -> None:
        super().__init__(level=logging.INFO)
        self.buffer = buffer

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.buffer.append(record_to_event(record))
        except Exception:  # pragma: no cover - logging must never break the app
            self.handleError(record)


def configure_logging(level: str, fmt: str, buffer: EventBuffer) -> None:
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    handler: logging.Handler
    if fmt == "text":
        handler = logging.StreamHandler()
        handler.setFormatter(TextFormatter())
    else:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
    handler.setLevel(getattr(logging, level, logging.INFO))
    root.addHandler(handler)
    root.addHandler(EventCaptureHandler(buffer))
    root.setLevel(getattr(logging, level, logging.INFO))
