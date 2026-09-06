"""Feature extraction — converts raw LogEvents into numerical FeatureVectors.

Why do we need this?
====================
Machine learning algorithms (like Isolation Forest) only understand numbers.
A LogEvent has strings (IP addresses), enums (event types), timestamps, etc.
The normalizer's job is to extract *meaningful numerical features* from each
event that capture the *behavior* behind the event.

Think of it like a translator:
  LogEvent (human-readable) → FeatureVector (machine-readable numbers)

Feature Engineering Decisions:
-----------------------------
1. requests_per_minute: High frequency from one IP = suspicious (brute force, DDoS)
2. unique_endpoints: Accessing many different URLs = possible reconnaissance
3. error_rate: High 4xx/5xx rate = failed attack attempts
4. avg_payload_size: Large payloads may indicate data exfiltration
5. time_sin/time_cos: Cyclical time encoding — attacks often peak at odd hours
6. unique_user_agents: Rotating user agents = bot behavior
7. port_diversity: Scanning many ports = port scan attack

Why sin/cos for time?
--------------------
If we used raw hour (0-23), the model would think 23:00 and 00:00 are
far apart (23 vs 0), but they're actually 1 hour apart. By encoding as
sin(2π·hour/24) and cos(2π·hour/24), we create a smooth circle where
23:00 and 00:00 are neighbors. This is called "cyclical encoding".
"""

from __future__ import annotations

import math

from sentinel.core.schemas import FeatureVector, LogEvent


def extract_features(
    event: LogEvent,
    recent_events: list[LogEvent] | None = None,
) -> FeatureVector:
    """Extract numerical features from a log event.

    Args:
        event: The current log event to analyze.
        recent_events: Optional list of recent events from the same source IP
                       (used for frequency/diversity calculations). If None,
                       features are calculated from the single event only.

    Returns:
        A FeatureVector with 8 numerical features for ML scoring.
    """
    # If we have recent context from this IP, use it; otherwise just this event
    ip_events = recent_events if recent_events else [event]

    # --- Feature 1: Request frequency ---
    # Count how many events from this IP in the time window
    requests_per_minute = float(len(ip_events))

    # --- Feature 2: Endpoint diversity ---
    # How many unique URLs/paths has this IP accessed?
    unique_endpoints = len({e.request_path for e in ip_events if e.request_path})
    # Minimum of 1 (the current event always counts)
    unique_endpoints = max(unique_endpoints, 1)

    # --- Feature 3: Error rate ---
    # What fraction of responses are errors (4xx or 5xx)?
    # High error rate = likely failed attack attempts
    status_codes = [e.response_status for e in ip_events if e.response_status > 0]
    if status_codes:
        errors = sum(1 for s in status_codes if s >= 400)
        error_rate = errors / len(status_codes)
    else:
        error_rate = 0.0

    # --- Feature 4: Average payload size ---
    # Large payloads can indicate data exfiltration or injection attempts
    payload_sizes = [len(e.payload) for e in ip_events]
    avg_payload_size = sum(payload_sizes) / len(payload_sizes) if payload_sizes else 0.0

    # --- Features 5 & 6: Cyclical time encoding ---
    # Convert hour of day to sin/cos representation
    hour = event.timestamp.hour + event.timestamp.minute / 60.0
    time_sin = math.sin(2 * math.pi * hour / 24.0)
    time_cos = math.cos(2 * math.pi * hour / 24.0)

    # --- Feature 7: User-agent diversity ---
    # Bots often rotate user-agent strings to avoid detection
    user_agents = {e.user_agent for e in ip_events if e.user_agent}
    unique_user_agents = max(len(user_agents), 1)

    # --- Feature 8: Port diversity ---
    # Port scanning targets many different ports
    ports = {e.dst_port for e in ip_events if e.dst_port > 0}
    port_diversity = max(len(ports), 1)

    return FeatureVector(
        requests_per_minute=requests_per_minute,
        unique_endpoints=unique_endpoints,
        error_rate=error_rate,
        avg_payload_size=avg_payload_size,
        time_sin=time_sin,
        time_cos=time_cos,
        unique_user_agents=unique_user_agents,
        port_diversity=port_diversity,
    )


def feature_vector_to_array(fv: FeatureVector) -> list[float]:
    """Convert a FeatureVector to a flat list of floats for scikit-learn.

    Scikit-learn expects input as numpy arrays or lists of lists.
    This function bridges our Pydantic model to sklearn's interface.
    """
    return [
        fv.requests_per_minute,
        float(fv.unique_endpoints),
        fv.error_rate,
        fv.avg_payload_size,
        fv.time_sin,
        fv.time_cos,
        float(fv.unique_user_agents),
        float(fv.port_diversity),
    ]
