"""Tests for the log event simulator."""

from __future__ import annotations

from sentinel.core.schemas import EventType, LogEvent
from sentinel.ingestion.simulator import generate_batch, generate_event


class TestGenerateEvent:
    """Test single event generation."""

    def test_generates_valid_log_event(self) -> None:
        """generate_event should return a valid LogEvent."""
        event = generate_event()
        assert isinstance(event, LogEvent)
        assert event.event_id  # non-empty
        assert event.src_ip  # non-empty
        assert event.timestamp is not None

    def test_generates_specific_type(self) -> None:
        """generate_event with explicit type should honor it."""
        for event_type in EventType:
            event = generate_event(event_type)
            assert event.event_type == event_type

    def test_ssh_brute_force_uses_port_22(self) -> None:
        """SSH brute force events should target port 22."""
        event = generate_event(EventType.SSH_BRUTE_FORCE)
        assert event.dst_port == 22
        assert event.response_status == 401

    def test_sqli_has_payload(self) -> None:
        """SQL injection events should have a non-empty payload."""
        event = generate_event(EventType.SQLI_ATTEMPT)
        assert len(event.payload) > 0
        assert event.event_type == EventType.SQLI_ATTEMPT

    def test_port_scan_has_common_ports(self) -> None:
        """Port scan events should target well-known ports."""
        common_ports = {21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 3389, 5432, 8080}
        event = generate_event(EventType.PORT_SCAN)
        assert event.dst_port in common_ports

    def test_xss_has_script_payload(self) -> None:
        """XSS events should contain script-like content."""
        event = generate_event(EventType.XSS_ATTEMPT)
        payload_lower = event.payload.lower()
        assert any(
            keyword in payload_lower
            for keyword in ["script", "onerror", "onload", "javascript", "iframe"]
        )

    def test_normal_traffic_is_benign(self) -> None:
        """Normal traffic should have standard HTTP status codes."""
        event = generate_event(EventType.NORMAL)
        assert event.event_type == EventType.NORMAL
        assert event.response_status in (200, 301, 304, 404)


class TestGenerateBatch:
    """Test batch event generation."""

    def test_batch_count(self) -> None:
        """Batch should produce the exact requested count."""
        events = generate_batch(count=50)
        assert len(events) == 50

    def test_batch_attack_ratio(self) -> None:
        """Attack ratio should approximately match the requested ratio."""
        events = generate_batch(count=1000, attack_ratio=0.3)
        attacks = [e for e in events if e.event_type != EventType.NORMAL]
        # Allow 5% tolerance due to integer rounding
        assert 250 <= len(attacks) <= 350

    def test_batch_all_normal(self) -> None:
        """attack_ratio=0 should produce only normal traffic."""
        events = generate_batch(count=100, attack_ratio=0.0)
        assert all(e.event_type == EventType.NORMAL for e in events)

    def test_batch_all_attacks(self) -> None:
        """attack_ratio=1 should produce only attack events."""
        events = generate_batch(count=100, attack_ratio=1.0)
        assert all(e.event_type != EventType.NORMAL for e in events)

    def test_batch_contains_diverse_types(self) -> None:
        """Large batch should contain multiple attack types."""
        events = generate_batch(count=500, attack_ratio=0.5)
        types = {e.event_type for e in events}
        # Should have at least 3 different types (normal + 2 attacks)
        assert len(types) >= 3
