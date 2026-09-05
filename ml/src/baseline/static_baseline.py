"""
Static Baseline Classifier (Logistic Regression & Random Forest).
Trained on single-window snapshots without temporal sequence dynamics,
serving as the experimental baseline benchmark required by the problem statement.
"""

from typing import Dict, Any, Optional, Tuple
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import joblib

from src.features.state_window import STATE_DIM, STATE_FEATURE_NAMES


class StaticBaselineClassifier:
    """
    Evaluates individual network state snapshots in isolation without temporal history.
    """

    def __init__(self, model_type: str = "logistic_regression", random_state: int = 42):
        self.model_type = model_type
        self.random_state = random_state

        if model_type == "logistic_regression":
            clf = LogisticRegression(
                max_iter=1000,
                class_weight="balanced",
                random_state=random_state,
            )
        elif model_type == "random_forest":
            clf = RandomForestClassifier(
                n_estimators=100,
                class_weight="balanced",
                random_state=random_state,
                n_jobs=-1,
            )
        else:
            raise ValueError(f"Unknown baseline model type: {model_type}")

        self.pipeline = Pipeline([
            ("scaler", StandardScaler()),
            ("classifier", clf),
        ])

    def fit(self, X_states: np.ndarray, y_attacks: np.ndarray) -> None:
        """Fits baseline classifier on static state vectors."""
        self.pipeline.fit(X_states, y_attacks)

    def predict_proba(self, X_states: np.ndarray) -> np.ndarray:
        """Returns threat probability for each static state vector."""
        probs = self.pipeline.predict_proba(X_states)
        # Prob of class 1 (attack)
        if probs.shape[1] > 1:
            return probs[:, 1]
        return probs[:, 0]

    def predict(self, X_states: np.ndarray, threshold: float = 0.5) -> np.ndarray:
        """Returns binary predictions."""
        probs = self.predict_proba(X_states)
        return (probs >= threshold).astype(int)

    def save(self, filepath: str) -> None:
        """Saves pipeline artifact."""
        joblib.dump(self.pipeline, filepath)

    @classmethod
    def load(cls, filepath: str) -> "StaticBaselineClassifier":
        """Loads baseline pipeline."""
        instance = cls()
        instance.pipeline = joblib.load(filepath)
        return instance
