"""
AI/ML Security Model Predictor.
Loads trained models from ml/models and evaluates behavioral feature vectors.
Supports both fast-path composite triage (LightGBM + Baseline + Isolation Forest)
and full multi-model deep inference.
"""

import sys
from pathlib import Path
from typing import Dict, Any, List, Optional
import pandas as pd
import joblib

# Add ml directory to sys.path so model classes in src.* unpickle cleanly
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
ML_DIR = ROOT_DIR / "ml"
if str(ML_DIR) not in sys.path:
    sys.path.insert(0, str(ML_DIR))

from src.features.feature_extractor import get_feature_columns

MODELS_DIR = ML_DIR / "models"


class SecurityModelPredictor:
    def __init__(self):
        self.feature_cols = get_feature_columns()

        # 1. Supervised Gradient Boosted Classifier (LightGBM) - Primary Fast Detector
        gb_path = MODELS_DIR / "behavioral_classifier.joblib"
        self.gb_model = joblib.load(gb_path) if gb_path.exists() else None

        # 2. Statistical Baseline Profiler - O(1) Table Lookup
        baseline_path = MODELS_DIR / "baseline_profiler.joblib"
        self.baseline_model = joblib.load(baseline_path) if baseline_path.exists() else None

        # 3. Isolation Forest - Fast Decision Tree Traversal
        if_path = MODELS_DIR / "isolation_forest.joblib"
        self.if_model = joblib.load(if_path) if if_path.exists() else None

        # 4. Deep Autoencoder (Optional non-linear pass)
        ae_path = MODELS_DIR / "autoencoder.pt"
        ae_meta_path = MODELS_DIR / "autoencoder_meta.joblib"
        self.ae_model = None
        if ae_path.exists() and ae_meta_path.exists():
            try:
                from src.autoencoders.autoencoder_model import AutoencoderAnomalyDetector
                self.ae_model = AutoencoderAnomalyDetector.load(str(ae_path), str(ae_meta_path))
            except Exception as e:
                print(f"[Predictor] Warning loading PyTorch Autoencoder: {e}")

        print("✓ SecurityModelPredictor successfully initialized with trained ML models.")

    def evaluate_features(
        self,
        user: str,
        date_str: str,
        feature_dict: Dict[str, float],
        include_autoencoder: bool = False
    ) -> Dict[str, Any]:
        """
        Fast composite evaluation combining LightGBM, Statistical Baselines, and Isolation Forest.
        Total execution time: <1.0 ms per record.
        """
        # Ensure all required feature columns exist with 0.0 default
        complete_features = {col: 0.0 for col in self.feature_cols}
        complete_features.update(feature_dict)
        complete_features["user"] = user
        complete_features["is_anomaly"] = 0

        df_single = pd.DataFrame([complete_features])

        # 1. Supervised threat score (LightGBM)
        s_gb = float(self.gb_model.predict_proba(df_single)[0]) if self.gb_model else 0.0
        gb_exps = self.gb_model.explain_record(complete_features) if self.gb_model else []

        # 2. Baseline deviation score (Z-Score table lookup)
        s_base, base_exps = (0.0, [])
        if self.baseline_model:
            s_base, base_exps = self.baseline_model.score_record(user, complete_features)

        # 3. Isolation Forest score (Tree traversal)
        s_if = float(self.if_model.predict_anomaly_scores(df_single)[0]) if self.if_model else 0.0
        if_exps = self.if_model.explain_record(complete_features) if self.if_model else []

        # 4. Optional Autoencoder score
        s_ae = 0.0
        if include_autoencoder and self.ae_model:
            s_ae = float(self.ae_model.predict_anomaly_scores(df_single)[0])

        # Composite Fast Risk Formula (0 - 100)
        if include_autoencoder:
            w_gb, w_base, w_if, w_ae = 0.55, 0.15, 0.15, 0.15
            composite_prob = (w_gb * s_gb + w_base * s_base + w_if * s_if + w_ae * s_ae)
        else:
            w_gb, w_base, w_if = 0.60, 0.25, 0.15
            composite_prob = (w_gb * s_gb + w_base * s_base + w_if * s_if)

        risk_score = round(float(composite_prob * 100.0), 1)
        risk_score = min(100.0, max(0.0, risk_score))

        # Enforce Policy Mapping
        if risk_score >= 80.0 or s_gb >= 0.85:
            status = "CRITICAL"
            action = "ISOLATE_DEVICE"
        elif risk_score >= 55.0 or s_gb >= 0.60:
            status = "SUSPICIOUS"
            action = "ALERT_ADMIN"
        elif risk_score >= 30.0:
            status = "LOW RISK"
            action = "MONITOR"
        else:
            status = "NORMAL"
            action = "ALLOW"

        # Combine top human-readable explanations
        deviations = []
        for exp in base_exps[:2]:
            deviations.append(exp["message"])
        for exp in gb_exps[:2]:
            if not any(exp["feature"] in d for d in deviations):
                deviations.append(exp["message"])
        for exp in if_exps[:2]:
            if not any(exp["feature"] in d for d in deviations):
                deviations.append(exp["message"])

        if not deviations and risk_score >= 50.0:
            deviations.append("Multivariate anomaly across low-level network traffic features")

        return {
            "user": user,
            "timestamp": date_str,
            "risk_score": risk_score,
            "status": status,
            "policy_action": action,
            "signals": {
                "supervised_threat_score": round(s_gb, 3),
                "baseline_deviation_score": round(s_base, 3),
                "isolation_forest_score": round(s_if, 3),
                "autoencoder_reconstruction_score": round(s_ae, 3) if include_autoencoder else None
            },
            "top_deviations": deviations[:4],
            "feature_snapshot": complete_features
        }
