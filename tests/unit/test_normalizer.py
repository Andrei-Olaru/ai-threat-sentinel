"""Tests for the feature extraction normalizer."""

from __future__ import annotations

from sentinel.core.schemas import EventType, LogEvent
from sentinel.processing.normalizer import extract_features, feature_vector_to_array


class TestExtractFeatures:
    """Test feature extraction from log events."""

    def test_single_event_produces_valid_vector(self) -> None:
        """A single event should produce a FeatureVector with all 8 features."""
        event = LogEvent(
            src_ip="192.168.1.100",
            event_type=EventType.NORMAL,
            dst_port=80,
            request_path="/api/v1/users",
            response_status=200,
            payload="hello",
            user_agent="Mozilla/5.0",
        )
        fv = extract_features(event)

        assert fv.requests_per_minute == 1.0  # single event
        assert fv.unique_endpoints == 1
        assert fv.error_rate == 0.0  # 200 is not an error
        assert fv.avg_payload_size == 5.0  # len("hello")
        assert fv.unique_user_agents == 1
        assert fv.port_diversity == 1

    def test_error_rate_calculated_correctly(self) -> None:
        """Error rate should reflect the fraction of 4xx/5xx responses."""
        normal = LogEvent(
            src_ip="10.0.0.1",
            event_type=EventType.NORMAL,
            response_status=200,
        )
        error = LogEvent(
            src_ip="10.0.0.1",
            event_type=EventType.SSH_BRUTE_FORCE,
            response_status=401,
        )
        # 1 normal + 1 error = 50% error rate
        fv = extract_features(error, recent_events=[normal, error])
        assert fv.error_rate == 0.5

    def test_port_diversity_with_multiple_ports(self) -> None:
        """Port scan events should show high port diversity."""
        events = [
            LogEvent(
                src_ip="attacker",
                event_type=EventType.PORT_SCAN,
                dst_port=port,
                response_status=0,
            )
            for port in [22, 80, 443, 3306, 5432]
        ]
        fv = extract_features(events[0], recent_events=events)
        assert fv.port_diversity == 5

    def test_cyclical_time_encoding(self) -> None:
        """Sin/cos encoding should produce values between -1 and 1."""
        event = LogEvent(
            src_ip="10.0.0.1",
            event_type=EventType.NORMAL,
        )
        fv = extract_features(event)

        assert -1.0 <= fv.time_sin <= 1.0
        assert -1.0 <= fv.time_cos <= 1.0
        # sin² + cos² should equal 1 (Pythagorean identity)
        assert abs(fv.time_sin**2 + fv.time_cos**2 - 1.0) < 0.0001

    def test_unique_user_agents(self) -> None:
        """Multiple user agents from same IP should be counted."""
        events = [
            LogEvent(
                src_ip="bot",
                event_type=EventType.NORMAL,
                user_agent=ua,
            )
            for ua in ["Mozilla/5.0", "curl/7.68", "python-requests/2.31"]
        ]
        fv = extract_features(events[0], recent_events=events)
        assert fv.unique_user_agents == 3

    def test_unique_endpoints(self) -> None:
        """Multiple paths from same IP should be counted."""
        events = [
            LogEvent(
                src_ip="scanner",
                event_type=EventType.NORMAL,
                request_path=path,
            )
            for path in ["/admin", "/wp-login.php", "/api/v1/users", "/.env"]
        ]
        fv = extract_features(events[0], recent_events=events)
        assert fv.unique_endpoints == 4


class TestFeatureVectorToArray:
    """Test conversion of FeatureVector to flat array."""

    def test_produces_8_floats(self) -> None:
        """Array should have exactly 8 float elements."""
        event = LogEvent(
            src_ip="10.0.0.1",
            event_type=EventType.NORMAL,
        )
        fv = extract_features(event)
        arr = feature_vector_to_array(fv)

        assert len(arr) == 8
        assert all(isinstance(v, float) for v in arr)

    def test_values_match_feature_vector(self) -> None:
        """Array values should match the FeatureVector fields in order."""
        event = LogEvent(
            src_ip="10.0.0.1",
            event_type=EventType.NORMAL,
            dst_port=443,
            request_path="/index",
            user_agent="test",
            payload="data",
        )
        fv = extract_features(event)
        arr = feature_vector_to_array(fv)

        assert arr[0] == fv.requests_per_minute
        assert arr[1] == float(fv.unique_endpoints)
        assert arr[2] == fv.error_rate
        assert arr[3] == fv.avg_payload_size
        assert abs(arr[4] - fv.time_sin) < 1e-10
        assert abs(arr[5] - fv.time_cos) < 1e-10
        assert arr[6] == float(fv.unique_user_agents)
        assert arr[7] == float(fv.port_diversity)
