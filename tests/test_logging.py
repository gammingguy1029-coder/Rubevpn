"""Secret-redaction tests for structured logging."""
from __future__ import annotations

import logging

from backend.app.monitoring.events import EventBuffer, record_to_event
from backend.app.security.redaction import redact, redact_value

WG_KEY = "A" * 43 + "="


def test_redacts_password_pairs() -> None:
    output = redact('login password=hunter2 for user admin')
    assert "hunter2" not in output
    assert "[REDACTED]" in output


def test_redacts_json_style_secrets() -> None:
    output = redact('{"private_key": "' + WG_KEY + '"}')
    assert WG_KEY not in output


def test_redacts_pem_blocks() -> None:
    output = redact("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----")
    assert "abc" not in output
    assert "[REDACTED_PRIVATE_KEY]" in output


def test_redacts_nested_values() -> None:
    value = redact_value({"nested": [f"token=Bearer {WG_KEY}"]})
    assert WG_KEY not in str(value)


def test_log_record_event_is_redacted() -> None:
    record = logging.LogRecord(
        name="test", level=logging.WARNING, pathname="", lineno=0,
        msg="candidate key=%s", args=(WG_KEY,), exc_info=None,
    )
    record.event = "TEST"
    event = record_to_event(record)
    assert WG_KEY not in str(event)
    assert event["message"].endswith("[REDACTED_KEY]")


def test_event_buffer_keeps_most_recent_first() -> None:
    buffer = EventBuffer(capacity=2)
    buffer.append({"n": 1})
    buffer.append({"n": 2})
    buffer.append({"n": 3})
    assert [event["n"] for event in buffer.recent()] == [3, 2]
