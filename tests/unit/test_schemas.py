"""Tests for Pydantic schemas validation."""

from __future__ import annotations

import pytest

from sentinel.core.schemas import EventType, LogEvent, Severity


class TestLogEvent:
    """Test LogEvent schema validation."""

    def test_valid_event(self) -> None:
        """A valid event should be created without errors."""
        event = LogEvent(
            src_ip="192.168.1.100",
            event_type=EventType.NORMAL,
        )
        assert event.src_ip == "192.168.1.100"
        assert event.event_type == EventType.NORMAL
        assert event.event_id  # auto-generated UUID
        assert event.timestamp is not None

    def test_missing_required_field(self) -> None:
        """Missing src_ip should raise validation error."""
        with pytest.raises(ValueError, match="src_ip"):
            LogEvent(event_type=EventType.NORMAL)

    def test_port_validation(self) -> None:
        """Ports must be between 0 and 65535."""
        with pytest.raises(ValueError, match="less than or equal"):
            LogEvent(src_ip="1.2.3.4", event_type=EventType.NORMAL, src_port=70000)

    def test_response_status_validation(self) -> None:
        """HTTP status must be between 0 and 599."""
        with pytest.raises(ValueError, match="greater than or equal"):
            LogEvent(src_ip="1.2.3.4", event_type=EventType.NORMAL, response_status=-1)

    def test_payload_max_length(self) -> None:
        """Payload should enforce max length of 10000."""
        with pytest.raises(ValueError, match="at most 10000"):
            LogEvent(
                src_ip="1.2.3.4",
                event_type=EventType.NORMAL,
                payload="x" * 10001,
            )

    def test_serialization_roundtrip(self) -> None:
        """Event should survive JSON serialization and deserialization."""
        original = LogEvent(
            src_ip="10.0.0.5",
            event_type=EventType.SQLI_ATTEMPT,
            payload="' OR '1'='1' --",
        )
        json_str = original.model_dump_json()
        restored = LogEvent.model_validate_json(json_str)
        assert restored.event_id == original.event_id
        assert restored.event_type == EventType.SQLI_ATTEMPT
        assert restored.payload == "' OR '1'='1' --"


class TestEventType:
    """Test EventType enum values."""

    def test_all_event_types_exist(self) -> None:
        """All expected event types should be defined."""
        expected = {
            "ssh_brute_force", "sqli_attempt", "port_scan",
            "xss_attempt", "dns_exfiltration", "normal",
        }
        actual = {e.value for e in EventType}
        assert actual == expected


class TestSeverity:
    """Test Severity enum values."""

    def test_severity_ordering(self) -> None:
        """Severity values should match NIST standard levels."""
        expected = {"low", "medium", "high", "critical"}
        actual = {s.value for s in Severity}
        assert actual == expected
