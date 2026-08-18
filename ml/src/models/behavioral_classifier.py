"""
Gradient Boosted Behavioral Classifier (LightGBM / HistGradientBoosting).
High-precision supervised detector trained on multi-stream behavioral vectors
and rolling behavioral surge indicators.
"""

from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import HistGradientBoostingClassifier
import lightgbm as lgb
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score

from src.features.feature_extractor import get_feature_columns


class GradientBoostedBehavioralClassifier:
    def __init__(
        self,
        feature_cols: Optional[List[str]] = None,
        n_estimators: int = 150,
        learning_rate: float = 0.05,
        random_state: int = 42
    ):
        self.feature_cols = feature_cols or get_feature_columns()
        self.n_estimators = n_estimators
        self.learning_rate = learning_rate
        self.random_state = random_state
        
        # LightGBM Classifier with class-imbalance weighting
        self.model = lgb.LGBMClassifier(
            n_estimators=self.n_estimators,
            learning_rate=self.learning_rate,
            class_weight="balanced",
            random_state=self.random_state,
            n_jobs=-1,
            verbose=-1
        )
        self.is_fitted = False
        self.feature_importances_: Dict[str, float] = {}

    def fit(self, df: pd.DataFrame) -> "GradientBoostedBehavioralClassifier":
        """
        Fits the Gradient Boosted Classifier on behavioral feature vectors.
        """
        X = df[self.feature_cols].fillna(0).values
        y = df["is_anomaly"].values

        self.model.fit(X, y)
        self.is_fitted = True

        # Extract normalized feature importances
        raw_importances = self.model.feature_importances_
        total_imp = np.sum(raw_importances) if np.sum(raw_importances) > 0 else 1.0
        self.feature_importances_ = {
            col: float(imp / total_imp)
            for col, imp in zip(self.feature_cols, raw_importances)
        }
        return self

    def predict_proba(self, df: pd.DataFrame) -> np.ndarray:
        """
        Returns anomaly probabilities in [0..1].
        """
        if not self.is_fitted:
            raise ValueError("Model is not fitted.")
        X = df[self.feature_cols].fillna(0).values
        probs = self.model.predict_proba(X)[:, 1]
        return probs

    def explain_record(self, record_dict: Dict[str, float], top_k: int = 4) -> List[Dict[str, Any]]:
        """
        Returns top features driving the anomaly score based on feature importance and magnitude.
        """
        explanations = []
        for feat in self.feature_cols:
            val = float(record_dict.get(feat, 0.0))
            imp = self.feature_importances_.get(feat, 0.0)
            if val > 0 and imp > 0.02:
                explanations.append({
                    "feature": feat,
                    "value": round(val, 2),
                    "importance_weight": round(imp, 3),
                    "message": f"Elevated {feat.replace('_', ' ')}: {val:.1f} (feature weight: {imp*100:.1f}%)"
                })
        explanations.sort(key=lambda x: x["importance_weight"], reverse=True)
        return explanations[:top_k]

    def save(self, filepath: str) -> None:
        """Saves model to disk."""
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, filepath)

    @classmethod
    def load(cls, filepath: str) -> "GradientBoostedBehavioralClassifier":
        """Loads model from disk."""
        return joblib.load(filepath)
