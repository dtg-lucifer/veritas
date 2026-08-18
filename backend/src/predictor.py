"""
AI/ML Security Model Predictor.
Loads trained models from ml/models and evaluates behavioral feature vectors.
"""

import sys
import importlib.util
from pathlib import Path
from typing import Dict, Any, List
import pandas as pd
import joblib

# Ensure ml package and submodules are explicitly registered in sys.modules
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
ML_DIR = ROOT_DIR / "ml"
if str(ML_DIR) not in sys.path:
    sys.path.insert(0, str(ML_DIR))

# Explicitly register ml's src modules to guarantee unpickler resolution
for mod_name in [
    "src.features.feature_extractor",
    "src.models.behavioral_classifier",
    "src.baseline.statistical_baseline",
    "src.isolation_forest.isolation_forest_model",
    "src.autoencoders.autoencoder_model"
]:
    rel_path = mod_name.replace(".", "/") + ".py"
    file_path = ML_DIR / rel_path
    if file_path.exists() and mod_name not in sys.modules:
        spec = importlib.util.spec_from_file_location(mod_name, file_path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = mod
        spec.loader.exec_module(mod)

MODELS_DIR = ML_DIR / "models"


class SecurityModelPredictor:
    def __init__(self):
        # 1. Supervised Gradient Boosted Classifier
        gb_path = MODELS_DIR / "behavioral_classifier.joblib"
        self.gb_model = joblib.load(gb_path) if gb_path.exists() else None

        # 2. Statistical Baseline Profiler
        baseline_path = MODELS_DIR / "baseline_profiler.joblib"
        self.baseline_model = joblib.load(baseline_path) if baseline_path.exists() else None

        # 3. Isolation Forest
        if_path = MODELS_DIR / "isolation_forest.joblib"
        self.if_model = joblib.load(if_path) if if_path.exists() else None

        # 4. Deep Autoencoder (Optional loading)
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

    def evaluate_features(self, user: str, date_str: str, feature_dict: Dict[str, float]) -> Dict[str, Any]:
        """
        Evaluates a 30-dimension behavioral vector against the ensemble.
        Returns a calibrated 0-100 Risk Score, Security Status, and Action.
        """
        df_single = pd.DataFrame([feature_dict])
        df_single["user"] = user
        if "is_anomaly" not in df_single.columns:
            df_single["is_anomaly"] = 0

        # 1. Supervised threat score
        s_gb = float(self.gb_model.predict_proba(df_single)[0]) if self.gb_model else 0.0
        gb_exps = self.gb_model.explain_record(feature_dict) if self.gb_model else []

        # 2. Baseline deviation score
        s_base, base_exps = (0.0, [])
        if self.baseline_model:
            s_base, base_exps = self.baseline_model.score_record(user, feature_dict)

        # 3. Isolation Forest score
        s_if = float(self.if_model.predict_anomaly_scores(df_single)[0]) if self.if_model else 0.0
        if_exps = self.if_model.explain_record(feature_dict) if self.if_model else []

        # 4. Autoencoder score
        s_ae = float(self.ae_model.predict_anomaly_scores(df_single)[0]) if self.ae_model else 0.0

        # Composite Risk Formula (0 - 100)
        w_gb, w_base, w_if, w_ae = 0.55, 0.15, 0.15, 0.15
        composite_prob = (w_gb * s_gb + w_base * s_base + w_if * s_if + w_ae * s_ae)
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
                "autoencoder_reconstruction_score": round(s_ae, 3)
            },
            "top_deviations": deviations[:4],
            "feature_snapshot": feature_dict
        }
