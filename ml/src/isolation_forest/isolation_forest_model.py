"""
Isolation Forest Anomaly Detection Model.
Unsupervised tree-based anomaly isolation for behavioral feature vectors.
"""

from typing import Dict, List, Optional, Tuple, Any
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler
import joblib
from pathlib import Path

from src.features.feature_extractor import get_feature_columns


class IsolationForestAnomalyDetector:
    def __init__(
        self,
        feature_cols: Optional[List[str]] = None,
        n_estimators: int = 200,
        contamination: float = 0.02,
        random_state: int = 42
    ):
        self.feature_cols = feature_cols or get_feature_columns()
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        
        self.scaler = RobustScaler()
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            max_samples="auto",
            random_state=self.random_state,
            n_jobs=-1
        )
        self.is_fitted = False
        self.score_min = -0.5
        self.score_max = 0.5

    def fit(self, df: pd.DataFrame) -> "IsolationForestAnomalyDetector":
        """
        Fits the Isolation Forest on normal/unsupervised training feature vectors.
        """
        X = df[self.feature_cols].fillna(0).values
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_fitted = True

        # Calibrate decision function bounds for scaling
        raw_scores = self.model.decision_function(X_scaled)
        self.score_min = float(np.percentile(raw_scores, 1))
        self.score_max = float(np.percentile(raw_scores, 99))
        return self

    def predict_anomaly_scores(self, df: pd.DataFrame) -> np.ndarray:
        """
        Computes calibrated anomaly scores in [0..1] range.
        Higher score = more anomalous.
        """
        if not self.is_fitted:
            raise ValueError("Model is not fitted yet.")

        X = df[self.feature_cols].fillna(0).values
        X_scaled = self.scaler.transform(X)
        
        # decision_function: higher is normal, lower is anomalous
        raw_scores = self.model.decision_function(X_scaled)
        
        # Calibrate into [0, 1] using logistic sigmoid transformation
        # Centered around 0 (the typical decision boundary)
        # raw_score < 0 is anomalous -> anomaly_score > 0.5
        k = 10.0
        anomaly_scores = 1.0 / (1.0 + np.exp(k * raw_scores))
        return np.clip(anomaly_scores, 0.0, 1.0)

    def explain_record(self, record_dict: Dict[str, float], top_k: int = 4) -> List[Dict[str, Any]]:
        """
        Identifies which features contributed most to the anomaly by measuring scaled deviation.
        """
        X_single = np.array([[record_dict.get(c, 0.0) for c in self.feature_cols]])
        X_scaled = self.scaler.transform(X_single)[0]
        
        # Top scaled values indicate rare/isolated feature values
        contributions = []
        for feat, s_val in zip(self.feature_cols, X_scaled):
            raw_val = float(record_dict.get(feat, 0.0))
            if s_val > 1.5 or (s_val > 0.5 and raw_val > 0):
                contributions.append({
                    "feature": feat,
                    "raw_value": round(raw_val, 2),
                    "scaled_deviation": round(float(s_val), 2),
                    "message": f"Unusual {feat.replace('_', ' ')}: {raw_val:.1f}"
                })
        
        contributions.sort(key=lambda x: x["scaled_deviation"], reverse=True)
        return contributions[:top_k]

    def save(self, filepath: str) -> None:
        """Saves model and scaler to disk."""
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, filepath)

    @classmethod
    def load(cls, filepath: str) -> "IsolationForestAnomalyDetector":
        """Loads model from disk."""
        return joblib.load(filepath)
