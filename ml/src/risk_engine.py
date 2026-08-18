"""
Composite Risk Engine & Incident Assessment.
Fuses Supervised Gradient Boosting, Statistical Baselines, Isolation Forest,
and Deep Autoencoder signals into a calibrated 0-100 Risk Score with policy recommendations.
"""

from typing import Dict, List, Optional, Tuple, Any
import numpy as np
import pandas as pd
from dataclasses import dataclass, asdict

from src.baseline.statistical_baseline import UserBaselineProfiler
from src.isolation_forest.isolation_forest_model import IsolationForestAnomalyDetector
from src.autoencoders.autoencoder_model import AutoencoderAnomalyDetector
from src.models.behavioral_classifier import GradientBoostedBehavioralClassifier


@dataclass
class RiskAssessment:
    user: str
    date: str
    risk_score: float                # 0 - 100
    status: str                      # NORMAL, LOW RISK, SUSPICIOUS, CRITICAL
    action: str                      # ALLOW, MONITOR, ALERT_ADMIN, ISOLATE_DEVICE
    supervised_score: float          # 0 - 1
    baseline_score: float            # 0 - 1
    isolation_forest_score: float    # 0 - 1
    autoencoder_score: float         # 0 - 1
    top_deviations: List[str]        # Human-readable explanation tags
    details: Dict[str, Any]          # Detailed sub-scores and feature values


class CompositeRiskEngine:
    def __init__(
        self,
        baseline_model: UserBaselineProfiler,
        if_model: IsolationForestAnomalyDetector,
        ae_model: AutoencoderAnomalyDetector,
        gb_model: Optional[GradientBoostedBehavioralClassifier] = None,
        w_gb: float = 0.50,
        w_baseline: float = 0.20,
        w_if: float = 0.15,
        w_ae: float = 0.15
    ):
        self.baseline_model = baseline_model
        self.if_model = if_model
        self.ae_model = ae_model
        self.gb_model = gb_model
        
        # Normalize weights
        total_w = (w_gb if gb_model else 0.0) + w_baseline + w_if + w_ae
        self.w_gb = (w_gb / total_w) if gb_model else 0.0
        self.w_baseline = w_baseline / total_w
        self.w_if = w_if / total_w
        self.w_ae = w_ae / total_w

    def evaluate_record(self, user: str, date_str: str, record_dict: Dict[str, float]) -> RiskAssessment:
        """
        Evaluates a single behavioral record and outputs a structured RiskAssessment.
        """
        df_single = pd.DataFrame([record_dict])
        df_single["user"] = user
        if "is_anomaly" not in df_single.columns:
            df_single["is_anomaly"] = 0

        # 1. Supervised GB score
        s_gb = float(self.gb_model.predict_proba(df_single)[0]) if self.gb_model else 0.0
        gb_exps = self.gb_model.explain_record(record_dict) if self.gb_model else []

        # 2. Baseline deviation score & explanations
        s_base, base_exps = self.baseline_model.score_record(user, record_dict)

        # 3. Isolation Forest score & explanations
        s_if = float(self.if_model.predict_anomaly_scores(df_single)[0])
        if_exps = self.if_model.explain_record(record_dict)

        # 4. Autoencoder reconstruction score & explanations
        s_ae = float(self.ae_model.predict_anomaly_scores(df_single)[0])
        ae_exps = self.ae_model.explain_record(record_dict)

        # Composite Risk Calculation (0..100)
        composite_anomaly = (
            self.w_gb * s_gb +
            self.w_baseline * s_base +
            self.w_if * s_if +
            self.w_ae * s_ae
        )
        risk_score = round(float(composite_anomaly * 100.0), 1)
        risk_score = min(100.0, max(0.0, risk_score))

        # Determine Security Status & Policy Action
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

        # Combine top explanation points
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
            deviations.append("Multivariate anomaly across low-level network activity distributions")

        return RiskAssessment(
            user=user,
            date=date_str,
            risk_score=risk_score,
            status=status,
            action=action,
            supervised_score=round(s_gb, 3),
            baseline_score=round(s_base, 3),
            isolation_forest_score=round(s_if, 3),
            autoencoder_score=round(s_ae, 3),
            top_deviations=deviations[:4],
            details={
                "features": record_dict,
                "supervised_explanations": gb_exps,
                "baseline_explanations": base_exps,
                "isolation_explanations": if_exps,
                "autoencoder_explanations": ae_exps,
            }
        )

    def evaluate_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Evaluates an entire DataFrame and appends risk assessment columns.
        """
        s_gb = self.gb_model.predict_proba(df) if self.gb_model else np.zeros(len(df))
        base_scores, _ = self.baseline_model.predict_scores(df)
        if_scores = self.if_model.predict_anomaly_scores(df)
        ae_scores = self.ae_model.predict_anomaly_scores(df)

        composite = (
            self.w_gb * s_gb +
            self.w_baseline * base_scores +
            self.w_if * if_scores +
            self.w_ae * ae_scores
        )

        res_df = df.copy()
        res_df["supervised_score"] = s_gb
        res_df["baseline_score"] = base_scores
        res_df["isolation_forest_score"] = if_scores
        res_df["autoencoder_score"] = ae_scores
        res_df["risk_score"] = np.clip(np.round(composite * 100.0, 1), 0.0, 100.0)

        # Assign status and action
        conditions = [
            (res_df["risk_score"] >= 80.0) | (res_df["supervised_score"] >= 0.85),
            (res_df["risk_score"] >= 55.0) | (res_df["supervised_score"] >= 0.60),
            (res_df["risk_score"] >= 30.0)
        ]
        statuses = ["CRITICAL", "SUSPICIOUS", "LOW RISK"]
        actions = ["ISOLATE_DEVICE", "ALERT_ADMIN", "MONITOR"]

        res_df["status"] = np.select(conditions, statuses, default="NORMAL")
        res_df["action"] = np.select(conditions, actions, default="ALLOW")
        return res_df
