"""Tests for the YAML rule engine."""

from __future__ import annotations

from pathlib import Path

from sentinel.core.schemas import EventType, LogEvent, Severity
from sentinel.detection.rule_engine import (
    DetectionRule,
    RuleCondition,
    RuleEngine,
)


class TestRuleConditionMatching:
    """Test individual rule condition operators."""

    def _make_ssh_event(self) -> LogEvent:
        """Create a sample SSH brute force event."""
        return LogEvent(
            src_ip="192.168.1.105",
            dst_port=22,
            event_type=EventType.SSH_BRUTE_FORCE,
            response_status=401,
            payload="Failed password for root",
        )

    def test_equals_operator(self) -> None:
        """equals should match exact string values."""
        engine = RuleEngine()
        engine.add_rule(DetectionRule(
            rule_id="test-eq",
            title="Test Equals",
            severity=Severity.HIGH,
            description="Test",
            mitre_attack_id="T0000",
            conditions=[
                RuleCondition(field="event_type", operator="equals", value="ssh_brute_force"),
            ],
        ))
        event = self._make_ssh_event()
        matches = engine.evaluate(event)
        assert len(matches) == 1
        assert matches[0].matched is True

    def test_contains_operator(self) -> None:
        """contains should match substrings (case-insensitive)."""
        engine = RuleEngine()
        engine.add_rule(DetectionRule(
            rule_id="test-contains",
            title="Test Contains",
            severity=Severity.MEDIUM,
            description="Test",
            mitre_attack_id="T0000",
            conditions=[
                RuleCondition(field="payload", operator="contains", value="password"),
            ],
        ))
        event = self._make_ssh_event()
        matches = engine.evaluate(event)
        assert len(matches) == 1

    def test_gt_operator(self) -> None:
        """gt should match when field > value."""
        engine = RuleEngine()
        engine.add_rule(DetectionRule(
            rule_id="test-gt",
            title="Test GT",
            severity=Severity.LOW,
            description="Test",
            mitre_attack_id="T0000",
            conditions=[
                RuleCondition(field="response_status", operator="gt", value=400),
            ],
        ))
        # 401 > 400 should match
        event = self._make_ssh_event()
        matches = engine.evaluate(event)
        assert len(matches) == 1

    def test_in_operator(self) -> None:
        """in should match when field value is contained in a list/set."""
        engine = RuleEngine()
        engine.add_rule(DetectionRule(
            rule_id="test-in",
            title="Test IN",
            severity=Severity.LOW,
            description="Test",
            mitre_attack_id="T0000",
            conditions=[
                RuleCondition(field="dst_port", operator="in", value=[21, 22, 23]),
            ],
        ))
        event = self._make_ssh_event()
        matches = engine.evaluate(event)
        assert len(matches) == 1

    def test_in_operator_non_iterable_safe(self) -> None:
        """in should safely return False if expected value is not iterable."""
        engine = RuleEngine()
        engine.add_rule(DetectionRule(
            rule_id="test-in-invalid",
            title="Test IN Invalid",
            severity=Severity.LOW,
            description="Test",
            mitre_attack_id="T0000",
            conditions=[
                RuleCondition(field="dst_port", operator="in", value=12345),
            ],
        ))
        event = self._make_ssh_event()
        matches = engine.evaluate(event)
        assert len(matches) == 0

    def test_no_match_returns_empty(self) -> None:
        """Non-matching events should produce no matches."""
        engine = RuleEngine()
        engine.add_rule(DetectionRule(
            rule_id="test-nomatch",
            title="Test No Match",
            severity=Severity.HIGH,
            description="Test",
            mitre_attack_id="T0000",
            conditions=[
                RuleCondition(field="event_type", operator="equals", value="normal"),
            ],
        ))
        # SSH brute force != normal
        event = self._make_ssh_event()
        matches = engine.evaluate(event)
        assert len(matches) == 0

    def test_and_logic_all_conditions_must_match(self) -> None:
        """All conditions must match (AND logic)."""
        engine = RuleEngine()
        engine.add_rule(DetectionRule(
            rule_id="test-and",
            title="Test AND",
            severity=Severity.HIGH,
            description="Test",
            mitre_attack_id="T0000",
            conditions=[
                RuleCondition(field="event_type", operator="equals", value="ssh_brute_force"),
                RuleCondition(field="dst_port", operator="equals", value=22),
                RuleCondition(field="response_status", operator="equals", value=401),
            ],
        ))
        event = self._make_ssh_event()
        matches = engine.evaluate(event)
        assert len(matches) == 1

    def test_and_logic_partial_match_fails(self) -> None:
        """If one condition fails, the whole rule fails."""
        engine = RuleEngine()
        engine.add_rule(DetectionRule(
            rule_id="test-and-fail",
            title="Test AND Fail",
            severity=Severity.HIGH,
            description="Test",
            mitre_attack_id="T0000",
            conditions=[
                RuleCondition(field="event_type", operator="equals", value="ssh_brute_force"),
                RuleCondition(field="dst_port", operator="equals", value=443),  # Wrong port!
            ],
        ))
        event = self._make_ssh_event()
        matches = engine.evaluate(event)
        assert len(matches) == 0


class TestRuleEngine:
    """Test the RuleEngine loading and evaluation."""

    def test_load_yaml_rules(self) -> None:
        """Should load all YAML rules from the rules directory."""
        engine = RuleEngine()
        rules_dir = Path("src/sentinel/detection/rules")
        count = engine.load_rules(rules_dir)
        assert count == 3
        assert engine.rule_count == 3

    def test_load_nonexistent_dir_returns_zero(self) -> None:
        """Loading from a nonexistent directory should return 0."""
        engine = RuleEngine()
        count = engine.load_rules(Path("/nonexistent/path"))
        assert count == 0

    def test_ssh_rule_matches_brute_force(self) -> None:
        """The SSH brute force YAML rule should match SSH attacks."""
        engine = RuleEngine()
        engine.load_rules(Path("src/sentinel/detection/rules"))

        event = LogEvent(
            src_ip="attacker",
            dst_port=22,
            event_type=EventType.SSH_BRUTE_FORCE,
            response_status=401,
        )
        matches = engine.evaluate(event)
        ssh_matches = [m for m in matches if m.rule.rule_id == "RULE-001"]
        assert len(ssh_matches) == 1
        assert ssh_matches[0].rule.severity == Severity.HIGH

    def test_sqli_rule_matches_injection(self) -> None:
        """The SQLi YAML rule should match SQL injection attempts."""
        engine = RuleEngine()
        engine.load_rules(Path("src/sentinel/detection/rules"))

        event = LogEvent(
            src_ip="attacker",
            event_type=EventType.SQLI_ATTEMPT,
            request_method="POST",
            payload="' OR '1'='1' --",
        )
        matches = engine.evaluate(event)
        sqli_matches = [m for m in matches if m.rule.rule_id == "RULE-002"]
        assert len(sqli_matches) == 1
        assert sqli_matches[0].rule.severity == Severity.CRITICAL

    def test_port_scan_rule_matches(self) -> None:
        """The port scan YAML rule should match scanning events."""
        engine = RuleEngine()
        engine.load_rules(Path("src/sentinel/detection/rules"))

        event = LogEvent(
            src_ip="scanner",
            event_type=EventType.PORT_SCAN,
            dst_port=3306,
            response_status=0,
        )
        matches = engine.evaluate(event)
        scan_matches = [m for m in matches if m.rule.rule_id == "RULE-003"]
        assert len(scan_matches) == 1

    def test_normal_traffic_no_matches(self) -> None:
        """Normal traffic should not match any attack rules."""
        engine = RuleEngine()
        engine.load_rules(Path("src/sentinel/detection/rules"))

        event = LogEvent(
            src_ip="user",
            event_type=EventType.NORMAL,
            dst_port=80,
            response_status=200,
        )
        matches = engine.evaluate(event)
        assert len(matches) == 0

    def test_rule_match_contains_details(self) -> None:
        """Rule matches should include descriptive details."""
        engine = RuleEngine()
        engine.add_rule(DetectionRule(
            rule_id="test-details",
            title="Detail Test",
            severity=Severity.HIGH,
            description="Test rule",
            mitre_attack_id="T9999",
            conditions=[
                RuleCondition(field="event_type", operator="equals", value="ssh_brute_force"),
            ],
        ))
        event = LogEvent(
            src_ip="10.0.0.1",
            event_type=EventType.SSH_BRUTE_FORCE,
        )
        matches = engine.evaluate(event)
        assert len(matches) == 1
        assert "Detail Test" in matches[0].details
