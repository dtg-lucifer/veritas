"""
Statistical Behavioral Baseline Engine.
Constructs per-user and per-role normal behavior baselines (mean, std, percentiles)
and evaluates Z-score behavioral deviations with full explainability.
"""

from typing import Dict, List, Optional, Tuple, Any
import numpy as np
import pandas as pd
import joblib
from pathlib import Path

from src.features.feature_extractor import get_feature_columns


class UserBaselineProfiler:
    def __init__(self, feature_cols: Optional[List[str]] = None, eps: float = 1e-4):
        self.feature_cols = feature_cols or get_feature_columns()
        self.eps = eps
        
        # User-level baseline profiles: {user: {feat: {'mean': float, 'std': float, 'median': float, 'p95': float}}}
        self.user_profiles: Dict[str, Dict[str, Dict[str, float]]] = {}
        
        # Global fallback profile across the whole organization
        self.global_profile: Dict[str, Dict[str, float]] = {}

    def fit(self, df: pd.DataFrame) -> "UserBaselineProfiler":
        """
        Fits baseline distributions per user using only normal activity days (is_anomaly == 0 if available).
        """
        train_df = df[df["is_anomaly"] == 0] if "is_anomaly" in df.columns else df
        
        # 1. Global enterprise profile
        self.global_profile = {}
        for feat in self.feature_cols:
            if feat in train_df.columns:
                series = train_df[feat].astype(float)
                self.global_profile[feat] = {
                    "mean": float(series.mean()),
                    "std": float(series.std() if series.std() > 0 else 1.0),
                    "median": float(series.median()),
                    "p95": float(series.quantile(0.95)),
                }

        # 2. Per-user profile
        self.user_profiles = {}
        for user, group in train_df.groupby("user"):
            if len(group) < 2:
                # Use global profile for users with very few samples
                self.user_profiles[user] = self.global_profile
                continue
            
            u_prof = {}
            for feat in self.feature_cols:
                if feat in group.columns:
                    s = group[feat].astype(float)
                    std_val = float(s.std())
                    u_prof[feat] = {
                        "mean": float(s.mean()),
                        "std": float(std_val if std_val > 0 else (self.global_profile[feat]["std"] * 0.5)),
                        "median": float(s.median()),
                        "p95": float(s.quantile(0.95)),
                    }
            self.user_profiles[user] = u_prof

        return self

    def score_record(self, user: str, feat_dict: Dict[str, float]) -> Tuple[float, List[Dict[str, Any]]]:
        """
        Scores a single behavioral vector against the user's historical baseline.
        Returns:
            (anomaly_score [0..1], list of explanation dictionaries)
        """
        profile = self.user_profiles.get(user, self.global_profile)
        if not profile:
            return 0.0, []

        z_scores = []
        explanations = []

        for feat in self.feature_cols:
            val = float(feat_dict.get(feat, 0.0))
            stat = profile.get(feat, self.global_profile.get(feat, {"mean": 0.0, "std": 1.0}))
            mean = stat["mean"]
            std = stat["std"] if stat["std"] > self.eps else 1.0

            z = (val - mean) / (std + self.eps)
            
            # Anomaly is significant positive deviation in activity/volume
            if z > 0:
                z_scores.append(z)
                if z >= 2.0:  # 2+ standard deviations above baseline
                    pct_increase = ((val - mean) / (mean + 1e-3)) * 100.0 if mean > 0 else 100.0
                    explanations.append({
                        "feature": feat,
                        "current_value": round(val, 2),
                        "baseline_mean": round(mean, 2),
                        "z_score": round(z, 2),
                        "percent_increase": round(pct_increase, 1),
                        "message": f"{feat.replace('_', ' ').title()} spiked to {val:.1f} ({z:.1f}σ above baseline)"
                    })

        if not z_scores:
            return 0.0, []

        # Aggregate Z-scores using a non-linear softplus/exponential scaling into [0, 1]
        top_k_z = sorted(z_scores, reverse=True)[:5]
        mean_top_z = float(np.mean(top_k_z))
        
        # Sigmoid-like mapping: z=0 -> 0.0, z=2 -> ~0.5, z=5 -> ~0.95
        anomaly_score = float(1.0 - np.exp(-0.35 * max(0.0, mean_top_z)))
        anomaly_score = min(1.0, max(0.0, anomaly_score))

        # Sort explanations by z_score descending
        explanations.sort(key=lambda x: x["z_score"], reverse=True)
        return anomaly_score, explanations

    def predict_scores(self, df: pd.DataFrame) -> Tuple[np.ndarray, List[List[Dict[str, Any]]]]:
        """
        Scores all rows in a DataFrame.
        """
        scores = []
        all_exps = []
        for _, row in df.iterrows():
            u = row["user"]
            row_dict = row.to_dict()
            s, exp = self.score_record(u, row_dict)
            scores.append(s)
            all_exps.append(exp)
        return np.array(scores), all_exps

    def save(self, filepath: str) -> None:
        """Saves baseline profiler to disk."""
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, filepath)

    @classmethod
    def load(cls, filepath: str) -> "UserBaselineProfiler":
        """Loads baseline profiler from disk."""
        return joblib.load(filepath)
