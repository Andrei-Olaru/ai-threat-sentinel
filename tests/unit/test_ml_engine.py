"""Tests for the Isolation Forest ML engine."""

from __future__ import annotations

import pytest

from sentinel.core.schemas import EventType, LogEvent
from sentinel.detection.ml_engine import MLEngine
from sentinel.ingestion.simulator import generate_batch
from sentinel.processing.normalizer import extract_features


class TestMLEngine:
    """Test the Isolation Forest wrapper."""

    def _train_engine(self, n_samples: int = 200) -> MLEngine:
        """Helper: create and train an ML engine with synthetic data."""
        engine = MLEngine()
        # Generate mostly normal traffic for training
        events = generate_batch(count=n_samples, attack_ratio=0.1)
        features = [extract_features(e) for e in events]
        engine.train(features)
        return engine

    def test_untrained_predict_raises(self) -> None:
        """Calling predict before train should raise RuntimeError."""
        engine = MLEngine()
        event = LogEvent(src_ip="10.0.0.1", event_type=EventType.NORMAL)
        fv = extract_features(event)
        with pytest.raises(RuntimeError, match="not trained"):
            engine.predict(fv)

    def test_train_sets_is_trained(self) -> None:
        """After training, is_trained should be True."""
        engine = self._train_engine()
        assert engine.is_trained is True

    def test_untrained_is_trained_false(self) -> None:
        """Before training, is_trained should be False."""
        engine = MLEngine()
        assert engine.is_trained is False

    def test_train_requires_minimum_samples(self) -> None:
        """Training with fewer than 10 samples should raise ValueError."""
        engine = MLEngine()
        events = generate_batch(count=5, attack_ratio=0.0)
        features = [extract_features(e) for e in events]
        with pytest.raises(ValueError, match="at least 10"):
            engine.train(features)

    def test_predict_returns_float(self) -> None:
        """predict() should return a single float score."""
        engine = self._train_engine()
        event = LogEvent(src_ip="10.0.0.1", event_type=EventType.NORMAL)
        fv = extract_features(event)
        score = engine.predict(fv)
        assert isinstance(score, float)

    def test_normal_traffic_scores_higher(self) -> None:
        """Normal traffic should generally score higher than attacks.

        This is a statistical test — not every single sample will
        behave perfectly, but the averages should differ clearly.
        """
        engine = self._train_engine(n_samples=500)

        # Score normal events
        normal_events = generate_batch(count=50, attack_ratio=0.0)
        normal_scores = [
            engine.predict(extract_features(e))
            for e in normal_events
        ]

        # Score attack events
        attack_events = generate_batch(count=50, attack_ratio=1.0)
        attack_scores = [
            engine.predict(extract_features(e))
            for e in attack_events
        ]

        avg_normal = sum(normal_scores) / len(normal_scores)
        avg_attack = sum(attack_scores) / len(attack_scores)

        # Normal traffic should have higher average score (more positive)
        # than attack traffic (more negative)
        assert avg_normal > avg_attack

    def test_predict_batch_matches_individual(self) -> None:
        """Batch prediction should produce same results as individual."""
        engine = self._train_engine()
        events = generate_batch(count=10, attack_ratio=0.5)
        features = [extract_features(e) for e in events]

        # Individual predictions
        individual = [engine.predict(fv) for fv in features]
        # Batch prediction
        batch = engine.predict_batch(features)

        assert len(batch) == len(individual)
        for i_score, b_score in zip(individual, batch, strict=True):
            assert abs(i_score - b_score) < 1e-10

    def test_is_anomaly_negative_scores(self) -> None:
        """Negative scores should be classified as anomalies."""
        engine = MLEngine()
        assert engine.is_anomaly(-0.5) is True
        assert engine.is_anomaly(-0.01) is True

    def test_is_anomaly_positive_scores(self) -> None:
        """Positive scores should NOT be classified as anomalies."""
        engine = MLEngine()
        assert engine.is_anomaly(0.5) is False
        assert engine.is_anomaly(0.01) is False

    def test_is_anomaly_zero_boundary(self) -> None:
        """Zero score is on the boundary — should NOT be an anomaly."""
        engine = MLEngine()
        assert engine.is_anomaly(0.0) is False
