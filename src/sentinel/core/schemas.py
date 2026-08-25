"""Shared Pydantic models (schemas) for the Sentinel platform.

These schemas serve as the contract between all components:
- API validates incoming data against LogEvent
- Queue serializes/deserializes using these models
- ML engine reads features from normalized events
- Database stores alerts using AlertRecord
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class EventType(StrEnum):
    """Types of security events the system can process."""

    SSH_BRUTE_FORCE = "ssh_brute_force"
    SQLI_ATTEMPT = "sqli_attempt"
    PORT_SCAN = "port_scan"
    XSS_ATTEMPT = "xss_attempt"
    DNS_EXFILTRATION = "dns_exfiltration"
    NORMAL = "normal"


class Severity(StrEnum):
    """Alert severity levels (aligned with NIST standards)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class LogEvent(BaseModel):
    """Incoming log event from any source.

    This is the schema for POST /api/v1/ingest.
    All fields are validated by Pydantic before the event
    touches any internal system.
    """

    event_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique event identifier",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(tz=UTC),
        description="When the event occurred",
    )
    src_ip: str = Field(
        ...,
        description="Source IP address",
        examples=["192.168.1.105"],
    )
    dst_ip: str = Field(
        default="10.0.0.1",
        description="Destination IP address",
    )
    src_port: int = Field(default=0, ge=0, le=65535)
    dst_port: int = Field(default=0, ge=0, le=65535)
    protocol: str = Field(default="TCP", description="Network protocol")
    event_type: EventType = Field(..., description="Classification of the event")
    payload: str = Field(
        default="",
        max_length=10000,
        description="Raw log content or request payload",
    )
    user_agent: str = Field(default="", max_length=500)
    request_path: str = Field(default="", max_length=2000)
    request_method: str = Field(default="GET")
    response_status: int = Field(default=200, ge=0, le=599)
    bytes_sent: int = Field(default=0, ge=0)
    metadata: dict[str, str | int | float | bool] = Field(default_factory=dict)


class IngestResponse(BaseModel):
    """Response returned after successfully ingesting a log event."""

    event_id: str
    status: str = "accepted"
    queue_position: int | None = None


class FeatureVector(BaseModel):
    """Numerical features extracted from a log event for ML scoring.

    Each feature is a measurable property that Isolation Forest
    uses to determine if the event is anomalous.
    """

    requests_per_minute: float = Field(description="Request frequency from this IP")
    unique_endpoints: int = Field(description="Distinct URLs accessed by this IP")
    error_rate: float = Field(ge=0.0, le=1.0, description="Fraction of 4xx/5xx responses")
    avg_payload_size: float = Field(description="Mean request body size in bytes")
    time_sin: float = Field(description="sin(2π * hour/24) — cyclical time encoding")
    time_cos: float = Field(description="cos(2π * hour/24) — cyclical time encoding")
    unique_user_agents: int = Field(description="Distinct user-agent strings from this IP")
    port_diversity: int = Field(description="Number of distinct destination ports targeted")


class AlertRecord(BaseModel):
    """An alert generated after ML detection + LLM enrichment."""

    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    src_ip: str
    event_type: EventType
    severity: Severity = Severity.MEDIUM
    anomaly_score: float = Field(ge=-1.0, le=1.0)
    rule_matched: str | None = None
    rca: str | None = Field(default=None, description="Root cause analysis from LLM")
    mitre_attack_id: str | None = Field(default=None, description="e.g. T1110.001")
    mitre_technique: str | None = Field(default=None, description="e.g. Brute Force")
    remediation: list[str] = Field(default_factory=list)
    is_blocked: bool = False
