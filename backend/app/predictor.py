"""
AI/ML Security Model Predictor.
Loads trained models from ml/models and evaluates 5-minute behavioral feature vectors
using the 4-model ensemble (LightGBM + Statistical Baseline + Isolation Forest + PyTorch Autoencoder).
Implements the multi-model risk fusion formula and policy mappings from WORKFLOW.md.
"""

import sys
from pathlib import Path
from typing import Dict, Any, List, Optional
import pandas as pd
import joblib

# Add ml directory to sys.path so model classes in src.* unpickle cleanly
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
ML_DIR = ROOT_DIR / "ml"
ml_str = str(ML_DIR)
if ml_str in sys.path:
    sys.path.remove(ml_str)
sys.path.insert(0, ml_str)

if "src" in sys.modules:
    src_mod = sys.modules["src"]
    if hasattr(src_mod, "__file__") and src_mod.__file__ and "ml/src" not in src_mod.__file__:
        del sys.modules["src"]

from src.features.feature_extractor import get_feature_columns

MODELS_DIR = ML_DIR / "models"


class SecurityModelPredictor:
    def __init__(self):
        self.feature_cols = get_feature_columns()

        # 1. Supervised Gradient Boosted Classifier (LightGBM) - Threat Classifier (w1 = 0.40)
        gb_path = MODELS_DIR / "behavioral_classifier.joblib"
        self.gb_model = joblib.load(gb_path) if gb_path.exists() else None

        # 2. Statistical Baseline Profiler - User Baseline Z-Scores (w2 = 0.25)
        baseline_path = MODELS_DIR / "baseline_profiler.joblib"
        self.baseline_model = joblib.load(baseline_path) if baseline_path.exists() else None

        # 3. Isolation Forest - Unsupervised Decision Trees (w3 = 0.20)
        if_path = MODELS_DIR / "isolation_forest.joblib"
        self.if_model = joblib.load(if_path) if if_path.exists() else None

        # 4. Deep PyTorch Autoencoder - Reconstruction Error (w4 = 0.15)
        ae_path = MODELS_DIR / "autoencoder.pt"
        ae_meta_path = MODELS_DIR / "autoencoder_meta.joblib"
        self.ae_model = None
        if ae_path.exists() and ae_meta_path.exists():
            try:
                from src.autoencoders.autoencoder_model import AutoencoderAnomalyDetector
                self.ae_model = AutoencoderAnomalyDetector.load(str(ae_path), str(ae_meta_path))
            except Exception as e:
                print(f"[Predictor] Warning loading PyTorch Autoencoder: {e}")

        print("✓ SecurityModelPredictor successfully initialized with 4-model ML ensemble.")

    def evaluate_features(
        self,
        user: str,
        date_str: str,
        feature_dict: Dict[str, float],
        include_autoencoder: bool = True
    ) -> Dict[str, Any]:
        """
        Ensemble evaluation combining LightGBM, Statistical Baseline, Isolation Forest, and Deep Autoencoder.
        Computes the Composite Risk Score (0 - 100) and maps to automated firewall policies.
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

        # 4. Deep Autoencoder score (Reconstruction Loss)
        s_ae = 0.0
        ae_exps = []
        if include_autoencoder and self.ae_model:
            try:
                s_ae = float(self.ae_model.predict_anomaly_scores(df_single)[0])
                ae_exps = self.ae_model.explain_record(complete_features)
            except Exception:
                s_ae = 0.0

        # Multi-Model Risk Fusion Formula
        # Check for actual threat indicator signals
        has_sensitive_web = complete_features.get("sensitive_web_count", 0.0) > 0
        has_usb = complete_features.get("device_connect_count", 0.0) > 0 or complete_features.get("usb_surge_zscore", 0.0) > 1.5
        has_file_exfil = complete_features.get("file_copy_count", 0.0) > 0 or complete_features.get("file_surge_zscore", 0.0) > 1.5
        has_email_exfil = complete_features.get("email_external_count", 0.0) > 0 or complete_features.get("email_bytes_surge_zscore", 0.0) > 1.5
        has_after_hours = complete_features.get("after_hours_ratio", 0.0) > 0.4
        has_threat_signals = has_sensitive_web or has_usb or has_file_exfil or has_email_exfil or has_after_hours

        # 1. Ensemble base weighted fusion (50% Supervised GB, 20% Baseline, 15% Isolation Forest, 15% Autoencoder)
        base_ensemble = (0.50 * s_gb + 0.20 * s_base + 0.15 * s_if + 0.15 * s_ae)

        # 2. Threat signal & supervised probability integration
        if s_gb >= 0.70:
            # High-confidence supervised insider attack
            composite_prob = max(s_gb, base_ensemble)
        elif s_gb >= 0.35 or has_threat_signals:
            # Threat signals present (USB connect, file copy, sensitive URL, external email exfil, after-hours surge)
            unsupervised_threat_consensus = (0.40 * s_base + 0.35 * s_ae + 0.25 * s_if)
            composite_prob = max(s_gb, 0.40 * s_gb + 0.60 * unsupervised_threat_consensus)
        else:
            # Completely benign activity (0 USB, 0 file exfil, 0 sensitive web, 0 external emails, normal working hours)
            # Volume variation during benign web browsing is capped in the safe ALLOW / NORMAL zone (< 35)
            composite_prob = min(0.30, base_ensemble)

        risk_score = round(float(composite_prob * 100.0), 1)
        risk_score = min(100.0, max(0.0, risk_score))

        # Enforce Policy Mapping according to WORKFLOW.md Matrix
        # Level 3: CRITICAL (Risk >= 65 or severe high-confidence model triggers with actual threats)
        if risk_score >= 65.0 or s_gb >= 0.75 or (has_threat_signals and s_base >= 0.85 and s_if >= 0.50):
            status = "CRITICAL"
            action = "ISOLATE_DEVICE"
        # Level 2: SUSPICIOUS (35 <= Risk < 65 or elevated supervised probability)
        elif risk_score >= 35.0 or s_gb >= 0.35 or (has_threat_signals and s_base >= 0.65):
            status = "SUSPICIOUS"
            action = "ALERT_ADMIN"
        # Level 1: NORMAL (Risk < 35)
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
        for exp in ae_exps[:2]:
            if not any(exp["feature"] in d for d in deviations):
                deviations.append(exp["message"])

        if not deviations and risk_score >= 40.0:
            deviations.append("Multivariate anomaly across low-level 5-minute network traffic features")

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
                "autoencoder_reconstruction_score": round(s_ae, 3) if include_autoencoder and self.ae_model else None
            },
            "top_deviations": deviations[:4],
            "feature_snapshot": complete_features
        }
