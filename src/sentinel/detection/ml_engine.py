"""Isolation Forest anomaly detection engine.

How Isolation Forest Works (ELI5):
==================================
Imagine you have a bag of 1000 balls. 990 are red (normal traffic),
10 are blue (attacks). If you randomly split the balls into groups,
the blue balls (anomalies) get isolated FASTER because they're different
from the majority.

Technically:
1. Build many random "trees" (decision trees with random splits)
2. For each data point, count how many splits it takes to isolate it
3. Points that are isolated quickly (short path) = anomalies
4. Points that take many splits to isolate = normal (they blend in)

Score interpretation:
  - Score close to -1.0 = ANOMALY (isolated quickly, very unusual)
  - Score close to +1.0 = NORMAL (hard to isolate, blends with majority)
  - Score around  0.0 = borderline

Why Isolation Forest for a SIEM?
================================
1. UNSUPERVISED — no labeled data needed (in real SOCs, you rarely have
   pre-labeled "this is an attack" data)
2. FAST — O(n·t·ψ) where n=samples, t=trees, ψ=subsample size
3. HANDLES HIGH DIMENSIONS — works well with our 8-feature vectors
4. LOW MEMORY — each tree only samples 256 points by default

Configuration:
  contamination=0.1 → we expect ~10% of traffic to be anomalous
  n_estimators=100  → ensemble of 100 random trees (more = more stable)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import numpy as np
from sklearn.ensemble import IsolationForest

from sentinel.core.logging import get_logger
from sentinel.processing.normalizer import feature_vector_to_array

if TYPE_CHECKING:
    from sentinel.config import Settings
    from sentinel.core.schemas import FeatureVector

logger = get_logger(__name__)


class MLEngine:
    """Wrapper around scikit-learn's Isolation Forest.

    Lifecycle:
        1. Create engine: engine = MLEngine(settings)
        2. Train on baseline: engine.train(normal_feature_vectors)
        3. Score new events: score = engine.predict(feature_vector)
    """

    def __init__(self, settings: Settings | None = None) -> None:
        """Initialize the ML engine with configuration.

        Args:
            settings: Application settings. If None, uses defaults.
        """
        contamination = 0.1
        n_estimators = 100

        if settings is not None:
            contamination = settings.ML_CONTAMINATION
            n_estimators = settings.ML_N_ESTIMATORS

        self._model: IsolationForest = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=42,  # Reproducible results
            n_jobs=-1,  # Use all CPU cores
        )
        self._is_trained: bool = False

        logger.info(
            "ml_engine_initialized",
            contamination=contamination,
            n_estimators=n_estimators,
        )

    @property
    def is_trained(self) -> bool:
        """Check if the model has been trained."""
        return self._is_trained

    def train(self, feature_vectors: list[FeatureVector]) -> None:
        """Train the Isolation Forest on a set of feature vectors.

        Call this with baseline (mostly normal) traffic data.
        The model learns what "normal" looks like, so it can
        flag anything that deviates as an anomaly.

        Args:
            feature_vectors: List of FeatureVectors to train on.
                            Should be mostly normal traffic (~90%).
        """
        if len(feature_vectors) < 10:
            msg = "Need at least 10 samples to train Isolation Forest"
            raise ValueError(msg)

        # Convert Pydantic models to numpy array
        data = np.array([feature_vector_to_array(fv) for fv in feature_vectors])

        self._model.fit(data)
        self._is_trained = True

        logger.info(
            "ml_model_trained",
            samples=len(feature_vectors),
            features=data.shape[1],
        )

    def predict(self, feature_vector: FeatureVector) -> float:
        """Score a single event for anomaly detection.

        Args:
            feature_vector: Numerical features extracted from a log event.

        Returns:
            Anomaly score between -1.0 (anomaly) and +1.0 (normal).
            The threshold is automatically set based on the contamination
            parameter during training.

        Raises:
            RuntimeError: If the model hasn't been trained yet.
        """
        if not self._is_trained:
            msg = "Model not trained. Call train() first."
            raise RuntimeError(msg)

        # sklearn expects 2D array: [[f1, f2, ...]]
        data = np.array([feature_vector_to_array(feature_vector)])

        # Negative scores indicate anomalies; positive scores indicate normal data
        scores = self._model.decision_function(data)
        return float(scores[0])

    def predict_batch(self, feature_vectors: list[FeatureVector]) -> list[float]:
        """Score multiple events at once (more efficient than one-by-one).

        Args:
            feature_vectors: List of feature vectors to score.

        Returns:
            List of anomaly scores (same order as input).
        """
        if not self._is_trained:
            msg = "Model not trained. Call train() first."
            raise RuntimeError(msg)

        data = np.array([feature_vector_to_array(fv) for fv in feature_vectors])
        scores = self._model.decision_function(data)
        return [float(s) for s in scores]

    def is_anomaly(self, score: float) -> bool:
        """Determine if a score indicates an anomaly.

        Isolation Forest convention:
          - Negative scores = anomalies
          - Positive scores = normal
          - Zero = decision boundary

        Args:
            score: The anomaly score from predict().

        Returns:
            True if the score indicates an anomaly.
        """
        return score < 0
