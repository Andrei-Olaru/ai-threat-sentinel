"""Sigma-style YAML rule engine for signature-based threat detection.

Why Do We Need Rules AND Machine Learning?
==========================================
Think of it like a hospital:
- ML (Isolation Forest) = general health screening that catches unusual patterns
  you didn't expect. "Your blood work looks abnormal, let's investigate."
- Rules = specific tests for known diseases. "Your blood sugar is 300 → diabetes."

Neither alone is sufficient:
- ML alone might miss known attack patterns that look "normal" statistically
- Rules alone can't detect novel (zero-day) attacks

Together = defense in depth. This is how real SIEMs work:
  Splunk, QRadar, and Elastic SIEM all combine signature rules + ML anomaly detection.

What is Sigma?
==============
Sigma is an open standard for writing detection rules (like YARA for logs).
Our rule format is inspired by Sigma but simplified for this project.
Each rule is a YAML file with conditions that match against LogEvent fields.

Rule Format:
  title: Human-readable name
  severity: low / medium / high / critical
  description: What this rule detects
  mitre_attack_id: MITRE ATT&CK technique ID (e.g., T1110.001)
  conditions: List of field-value matchers (all must match = AND logic)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from sentinel.core.logging import get_logger
from sentinel.core.schemas import LogEvent, Severity

logger = get_logger(__name__)


@dataclass(frozen=True)
class RuleCondition:
    """A single condition in a detection rule.

    Attributes:
        field: The LogEvent field to check (e.g., "event_type", "dst_port").
        operator: How to compare — "equals", "contains", "gt", "lt", "in".
        value: The value to compare against.
    """

    field: str
    operator: str
    value: Any


@dataclass(frozen=True)
class DetectionRule:
    """A complete detection rule loaded from YAML.

    Attributes:
        rule_id: Unique identifier for this rule.
        title: Human-readable name.
        severity: Alert severity if this rule matches.
        description: What this rule detects and why.
        mitre_attack_id: MITRE ATT&CK technique ID.
        conditions: All conditions that must match (AND logic).
    """

    rule_id: str
    title: str
    severity: Severity
    description: str
    mitre_attack_id: str
    conditions: list[RuleCondition] = field(default_factory=list)


@dataclass
class RuleMatch:
    """Result of a rule matching against an event."""

    rule: DetectionRule
    matched: bool
    details: str = ""


def _check_condition(event: LogEvent, condition: RuleCondition) -> bool:
    """Check if a single condition matches against an event.

    Args:
        event: The log event to check.
        condition: The condition to evaluate.

    Returns:
        True if the condition matches.
    """
    # Get the field value from the event using getattr
    event_value = getattr(event, condition.field, None)
    if event_value is None:
        # Check in metadata dict as fallback
        event_value = event.metadata.get(condition.field)
        if event_value is None:
            return False

    # Convert enum values to their string representation
    if hasattr(event_value, "value"):
        event_value = event_value.value

    op = condition.operator
    expected = condition.value

    if op == "equals":
        return str(event_value) == str(expected)
    if op == "contains":
        return str(expected).lower() in str(event_value).lower()
    if op == "gt":
        return float(event_value) > float(expected)
    if op == "lt":
        return float(event_value) < float(expected)
    if op == "gte":
        return float(event_value) >= float(expected)
    if op == "lte":
        return float(event_value) <= float(expected)
    if op == "in":
        try:
            return bool(event_value in expected)
        except TypeError:
            return False

    logger.warning("unknown_rule_operator", operator=op, rule_field=condition.field)
    return False


def _parse_rule_file(path: Path) -> DetectionRule | None:
    """Parse a single YAML rule file into a DetectionRule.

    Args:
        path: Path to the YAML rule file.

    Returns:
        A DetectionRule, or None if parsing fails.
    """
    try:
        raw: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))

        conditions = []
        for cond in raw.get("conditions", []):
            conditions.append(
                RuleCondition(
                    field=cond["field"],
                    operator=cond["operator"],
                    value=cond["value"],
                )
            )

        return DetectionRule(
            rule_id=raw.get("rule_id", path.stem),
            title=raw["title"],
            severity=Severity(raw.get("severity", "medium")),
            description=raw.get("description", ""),
            mitre_attack_id=raw.get("mitre_attack_id", ""),
            conditions=conditions,
        )
    except Exception:
        logger.exception("rule_parse_error", path=str(path))
        return None


class RuleEngine:
    """Load YAML rules and match them against log events.

    Usage:
        engine = RuleEngine()
        engine.load_rules(Path("src/sentinel/detection/rules"))
        matches = engine.evaluate(event)
    """

    def __init__(self) -> None:
        """Initialize with an empty rule set."""
        self._rules: list[DetectionRule] = []

    @property
    def rules(self) -> list[DetectionRule]:
        """Get the loaded rules."""
        return list(self._rules)

    @property
    def rule_count(self) -> int:
        """Get the number of loaded rules."""
        return len(self._rules)

    def load_rules(self, rules_dir: Path) -> int:
        """Load all YAML rules from a directory.

        Args:
            rules_dir: Path to directory containing .yml rule files.

        Returns:
            Number of rules successfully loaded.
        """
        self._rules = []

        if not rules_dir.is_dir():
            logger.warning("rules_directory_not_found", path=str(rules_dir))
            return 0

        for path in sorted(rules_dir.glob("*.yml")):
            rule = _parse_rule_file(path)
            if rule is not None:
                self._rules.append(rule)
                logger.debug("rule_loaded", rule_id=rule.rule_id, title=rule.title)

        logger.info("rules_loaded", count=len(self._rules), directory=str(rules_dir))
        return len(self._rules)

    def add_rule(self, rule: DetectionRule) -> None:
        """Add a rule programmatically (useful for testing)."""
        self._rules.append(rule)

    def evaluate(self, event: LogEvent) -> list[RuleMatch]:
        """Evaluate all rules against a log event.

        Args:
            event: The log event to check.

        Returns:
            List of RuleMatch results — one per matched rule.
            Only rules that fully match are returned.
        """
        matches: list[RuleMatch] = []

        for rule in self._rules:
            # ALL conditions must match (AND logic)
            all_matched = all(_check_condition(event, c) for c in rule.conditions)

            if all_matched and rule.conditions:
                matches.append(
                    RuleMatch(
                        rule=rule,
                        matched=True,
                        details=f"Rule '{rule.title}' matched on event {event.event_id}",
                    )
                )
                logger.debug(
                    "rule_matched",
                    rule_id=rule.rule_id,
                    event_id=event.event_id,
                    severity=rule.severity.value,
                )

        return matches
