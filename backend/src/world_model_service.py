"""
World Model Inference & Real-Time Flow State Aggregation Service.
Bridges live or replayed network flows from Kafka to the trained
Autoregressive World Model (StateWindowAggregator -> ForwardSimulator -> ThreatExplainer).
Includes enterprise client scaling, WebRTC/Google Meet conferencing normalization,
and decoupled structured window evaluation results.
"""

import os
import sys
import time
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import numpy as np
import pandas as pd
from rich.console import Console

# Resolve imports to ML package
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
ML_DIR = ROOT_DIR / "ml"
if str(ML_DIR) not in sys.path:
    sys.path.insert(0, str(ML_DIR))

from src.features.state_window import StateWindowAggregator, STATE_FEATURE_NAMES, STATE_DIM
from src.world_model.network_world_model import WorldModelWrapper
from src.world_model.forward_simulator import ForwardSimulator, ForwardSimulationReport
from src.world_model.explainability import ThreatExplainer
from src.config import get_config

console = Console()


@dataclass
class EvaluationResult:
    """Explicit structured result of a window evaluation."""
    evaluated: bool = False
    is_threat: bool = False
    risk_pct: float = 0.0
    stage: str = "Benign"
    policy: str = "ALLOW"
    severity: str = "NORMAL"  # NORMAL, SUSPICIOUS, CRITICAL, CONFERENCING
    is_conferencing: bool = False
    flow_count: int = 0
    report: Optional[Dict[str, Any]] = None
    alert_payload: Optional[Dict[str, Any]] = None


class WorldModelService:
    """
    Manages stateful stream aggregation of Kafka network flows,
    temporal sequence buffering, K-step forward simulation, and autonomous policy trigger.
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        window_size_seconds: Optional[int] = None,
        seq_len: int = 8,
        rollout_steps: int = 5,
        alert_threshold: Optional[float] = None,
    ):
        self.config = get_config()
        self.window_size_seconds = window_size_seconds or self.config.thresholds.window_size_seconds
        self.seq_len = seq_len
        self.rollout_steps = rollout_steps
        self.alert_threshold = alert_threshold if alert_threshold is not None else self.config.thresholds.alert_threshold
        if self.alert_threshold > 1.0:
            self.alert_threshold /= 100.0

        # Model checkpoint path
        default_model = ML_DIR / "models" / "world_model.pt"
        self.model_path = Path(model_path or os.getenv("WORLD_MODEL_PATH", str(default_model)))

        self.wrapper: Optional[WorldModelWrapper] = None
        self.simulator: Optional[ForwardSimulator] = None
        self.explainer: Optional[ThreatExplainer] = None
        self.aggregator = StateWindowAggregator(window_size_seconds=self.window_size_seconds)

        # Buffers
        self.flow_buffer: List[Dict[str, Any]] = []
        self.state_history: List[np.ndarray] = []  # List of (32,) float32 vectors
        self.state_timestamps: List[str] = []
        self.max_history_len = 32

        # Telemetry & Status
        self.metrics = {
            "flows_ingested": 0,
            "windows_evaluated": 0,
            "simulations_completed": 0,
            "alerts_generated": 0,
            "last_simulation_time": None,
            "peak_risk_observed": 0.0,
        }
        self.latest_report: Optional[Dict[str, Any]] = None
        self.latest_alert: Optional[Dict[str, Any]] = None

        self._initialize_model()

    def _initialize_model(self):
        """Loads World Model checkpoint and initialises simulator and explainer."""
        if not self.model_path.exists():
            console.print(f"[bold red]❌ World Model checkpoint not found at: {self.model_path}[/bold red]")
            return

        try:
            self.wrapper = WorldModelWrapper.load(str(self.model_path))
            self.simulator = ForwardSimulator(self.wrapper)
            self.explainer = ThreatExplainer(self.wrapper)
            console.print(f"[bold green]✓ Loaded AI World Model checkpoint from: {self.model_path}[/bold green]")
        except Exception as e:
            console.print(f"[bold red]❌ Failed to load World Model checkpoint: {e}[/bold red]")

    def ingest_flow(self, flow: Dict[str, Any]):
        """Buffers a single incoming Kafka flow record."""
        self.flow_buffer.append(flow)
        self.metrics["flows_ingested"] += 1

    def ingest_batch(self, flows: List[Dict[str, Any]]) -> EvaluationResult:
        """
        Buffers a batch of incoming flows and runs evaluation when window boundaries complete.
        Returns an EvaluationResult dataclass indicating whether evaluation occurred and alert status.
        """
        for f in flows:
            self.ingest_flow(f)

        # Evaluate when flows cross window boundaries or buffer exceeds 25 flows
        if len(self.flow_buffer) >= 25:
            return self.process_pending_flows(flush_all=False)
        return EvaluationResult(evaluated=False)

    def process_pending_flows(self, flush_all: bool = False) -> EvaluationResult:
        """
        Aggregates pending flows into 32-dim State Vectors, updates history,
        and performs K-step autoregressive forward simulation.
        If flush_all is False, retains the latest active window until flows cross to a new window.
        """
        if not self.flow_buffer or self.simulator is None:
            return EvaluationResult(evaluated=False)

        cfg = get_config()
        self.alert_threshold = cfg.thresholds.alert_threshold

        df_flows = pd.DataFrame(self.flow_buffer)
        if df_flows.empty:
            return EvaluationResult(evaluated=False)

        # Ensure all numeric column types are coerced and NaN filled
        for col in df_flows.columns:
            if col not in ["timestamp", "label"]:
                df_flows[col] = pd.to_numeric(df_flows[col], errors="coerce").fillna(0.0)

        # Parse window timestamp
        if "timestamp" in df_flows.columns:
            df_flows["window_timestamp"] = pd.to_datetime(
                df_flows["timestamp"], format="mixed", dayfirst=True, errors="coerce"
            ).dt.floor(f"{self.window_size_seconds}s")
        else:
            df_flows["window_timestamp"] = pd.Timestamp.now(timezone.utc).floor(f"{self.window_size_seconds}s")

        unique_windows = df_flows["window_timestamp"].dropna().sort_values().unique()

        # If not flushing all and we haven't crossed to a subsequent window yet, hold until window boundary is reached
        if not flush_all and len(unique_windows) <= 1:
            return EvaluationResult(evaluated=False)

        if flush_all or len(unique_windows) <= 1:
            flows_df = df_flows
            self.flow_buffer.clear()
        else:
            active_window = unique_windows[-1]
            active_mask = (df_flows["window_timestamp"] == active_window)
            self.flow_buffer = [f for f, m in zip(self.flow_buffer, active_mask) if m]
            flows_df = df_flows[~active_mask]

        if flows_df.empty:
            return EvaluationResult(evaluated=False)

        # Check for WebRTC Conferencing traffic (e.g. Google Meet, STUN/TURN port 3478, 19302-19309)
        conferencing_ports = set(cfg.traffic_policy.conferencing_ports)
        is_webrtc_flow = (
            (flows_df["protocol"].astype(float) == 17) &
            (flows_df["dst_port"].isin(conferencing_ports) | flows_df["src_port"].isin(conferencing_ports))
        )
        webrtc_ratio = float(is_webrtc_flow.mean()) if len(flows_df) > 0 else 0.0
        is_conferencing_window = (
            cfg.traffic_policy.allow_webrtc_conferencing
            and webrtc_ratio >= 0.35
            and (flows_df.get("syn_flag_cnt", pd.Series(0, index=flows_df.index)).sum() == 0)
            and (flows_df.get("rst_flag_cnt", pd.Series(0, index=flows_df.index)).sum() == 0)
        )

        # Aggregate flows into temporal windows
        df_states = self.aggregator.aggregate_flows_to_states(flows_df)
        if df_states.empty:
            return EvaluationResult(evaluated=False)

        # Filter out isolated micro-fragments (< 3 flows) when more substantial windows exist in batch
        if len(df_states) > 1 and (df_states["flow_count"] >= 3).any():
            df_states = df_states[df_states["flow_count"] >= 3].reset_index(drop=True)

        self.metrics["windows_evaluated"] += len(df_states)

        # Client Scaling Factor (Normalizes multi-client enterprise networks to single-host baseline)
        client_scale = 1.0
        if cfg.network.auto_scale_volumetric_thresholds and cfg.network.connected_clients_count > 1:
            client_scale = max(1.0, float(cfg.network.connected_clients_count) / float(cfg.network.baseline_clients_capacity))

        volumetric_features = [
            "flow_count", "tot_fwd_pkts", "tot_bwd_pkts",
            "tot_fwd_bytes", "tot_bwd_bytes", "flow_bytes_rate", "flow_pkts_rate"
        ]

        # Append new state vectors into history
        for _, row in df_states.iterrows():
            row_dict = row[STATE_FEATURE_NAMES].to_dict()

            # 1. Scale volumetric features for connected client capacity
            if client_scale > 1.0:
                for vf in volumetric_features:
                    if vf in row_dict:
                        row_dict[vf] = row_dict[vf] / client_scale

            # 2. Dampen WebRTC conferencing volumetric features if active video call
            if is_conferencing_window:
                dampen_factor = 0.10  # legitimate audio/video RTP normalized
                for vf in volumetric_features:
                    if vf in row_dict:
                        row_dict[vf] = row_dict[vf] * dampen_factor
                # Conferencing STUN/TURN is recognized, not rogue ephemeral
                row_dict["ephemeral_port_ratio"] = 0.0

            state_vec = np.array([row_dict[f] for f in STATE_FEATURE_NAMES], dtype=np.float32)
            state_vec = np.nan_to_num(state_vec, nan=0.0, posinf=0.0, neginf=0.0)
            self.state_history.append(state_vec)
            self.state_timestamps.append(str(row.get("window_timestamp", datetime.now(timezone.utc).isoformat())))

            if len(self.state_history) > self.max_history_len:
                self.state_history.pop(0)
                self.state_timestamps.pop(0)

        # Prepare context sequence for Forward Simulation
        if len(self.state_history) < self.seq_len:
            pad_count = self.seq_len - len(self.state_history)
            pad_states = [self.state_history[0]] * pad_count
            context_seq = np.array(pad_states + self.state_history, dtype=np.float32)
        else:
            context_seq = np.array(self.state_history[-self.seq_len:], dtype=np.float32)

        # 3. Perform K-Step Autoregressive Forward Simulation
        report: ForwardSimulationReport = self.simulator.simulate(context_seq, k_steps=self.rollout_steps)
        explanation = self.explainer.explain_sequence(context_seq) if self.explainer else {}

        self.metrics["simulations_completed"] += 1
        now_str = datetime.now(timezone.utc).isoformat()
        self.metrics["last_simulation_time"] = now_str

        max_risk = float(report.max_infiltration_prob)
        peak_stage = report.peak_stage_name

        # Policy & Threat Evaluation
        if is_conferencing_window:
            # Verified Google Meet / WebRTC traffic: suppress false Command & Control / DoS alarm
            max_risk = min(max_risk, 0.12)
            peak_stage = "Benign (WebRTC/Conferencing)"
            recommended_policy = "ALLOW"
            soc_note = "Legitimate WebRTC media stream detected (Google Meet / STUN/TURN). Traffic normalized."
        else:
            if max_risk >= cfg.thresholds.critical_threshold:
                recommended_policy = "ISOLATE_DEVICE"
            elif max_risk >= self.alert_threshold:
                recommended_policy = "ALERT_ADMIN"
            else:
                recommended_policy = "ALLOW"
            soc_note = explanation.get("soc_explanation", "") if explanation else ""

        if max_risk > self.metrics["peak_risk_observed"]:
            self.metrics["peak_risk_observed"] = max_risk

        # Build clean JSON serializable rollout report
        rollout_summary = []
        for s in report.rollout_steps:
            step_prob = min(float(s.infiltration_prob), 0.12) if is_conferencing_window else float(s.infiltration_prob)
            step_stage = "Benign (WebRTC)" if is_conferencing_window else s.mitre_stage_name
            step_policy = "ALLOW" if is_conferencing_window else s.policy_action
            rollout_summary.append({
                "step": s.step,
                "relative_seconds": s.step * self.window_size_seconds,
                "infiltration_prob": round(step_prob, 4),
                "mitre_stage": step_stage,
                "status": "NORMAL" if is_conferencing_window else s.status,
                "policy_action": step_policy,
                "predicted_flow_count": int(s.predicted_state_denorm.get("flow_count", 0)),
                "predicted_syn_ratio": round(float(s.predicted_state_denorm.get("syn_ratio", 0.0)), 4),
            })

        latest_rep = {
            "timestamp": now_str,
            "window_size_seconds": self.window_size_seconds,
            "rollout_steps": rollout_summary,
            "max_infiltration_prob": round(max_risk, 4),
            "peak_stage": peak_stage,
            "recommended_policy": recommended_policy,
            "top_attributions": explanation.get("top_driving_features", [])[:4] if explanation else [],
            "soc_guidance": soc_note,
            "is_conferencing": is_conferencing_window,
            "network_scale": {
                "connected_clients_count": cfg.network.connected_clients_count,
                "client_scale_applied": client_scale,
            }
        }
        self.latest_report = latest_rep

        # 4. Check Threat Threshold & Trigger Alert
        min_warmup_states = min(cfg.thresholds.min_warmup_windows, self.seq_len)
        is_threat = (
            not is_conferencing_window
            and len(self.state_history) >= min_warmup_states
            and (
                max_risk >= self.alert_threshold
                or recommended_policy in ["ALERT_ADMIN", "ISOLATE_DEVICE"]
            )
        )

        alert_payload = None
        if is_threat:
            self.metrics["alerts_generated"] += 1
            severity = "CRITICAL" if max_risk >= cfg.thresholds.critical_threshold else "SUSPICIOUS"

            alert_payload = {
                "type": "WORLD_MODEL_PREDICTION_ALERT",
                "severity": severity,
                "timestamp": now_str,
                "max_infiltration_prob": latest_rep["max_infiltration_prob"],
                "mitre_stage": latest_rep["peak_stage"],
                "policy_action": recommended_policy,
                "report": latest_rep,
            }
            self.latest_alert = alert_payload
        else:
            self.latest_alert = None
            if is_conferencing_window:
                severity = "CONFERENCING"
            elif max_risk >= cfg.thresholds.critical_threshold:
                severity = "CRITICAL"
            elif max_risk >= self.alert_threshold:
                severity = "SUSPICIOUS"
            else:
                severity = "NORMAL"

        return EvaluationResult(
            evaluated=True,
            is_threat=is_threat,
            risk_pct=round(max_risk * 100.0, 2),
            stage=peak_stage,
            policy=recommended_policy,
            severity=severity,
            is_conferencing=is_conferencing_window,
            flow_count=len(flows_df),
            report=latest_rep,
            alert_payload=alert_payload,
        )

    def reset(self):
        """Clears state history and flow buffers for clean demo benchmarking."""
        self.flow_buffer.clear()
        self.state_history.clear()
        self.state_timestamps.clear()
        self.latest_report = None
        self.latest_alert = None
        self.metrics["flows_ingested"] = 0
        self.metrics["windows_evaluated"] = 0
        self.metrics["simulations_completed"] = 0
        self.metrics["alerts_generated"] = 0
        self.metrics["peak_risk_observed"] = 0.0
        console.print("[bold cyan]🔄 World Model state history and flow buffers reset to clean state.[/bold cyan]")

    def get_status(self) -> Dict[str, Any]:
        """Returns service status and metrics for health checks and APIs."""
        cfg = get_config()
        return {
            "model_loaded": self.simulator is not None,
            "model_path": str(self.model_path),
            "window_size_seconds": self.window_size_seconds,
            "seq_len": self.seq_len,
            "rollout_steps": self.rollout_steps,
            "alert_threshold": self.alert_threshold,
            "connected_clients_count": cfg.network.connected_clients_count,
            "allow_webrtc_conferencing": cfg.traffic_policy.allow_webrtc_conferencing,
            "active_history_states": len(self.state_history),
            "pending_buffer_flows": len(self.flow_buffer),
            "metrics": self.metrics,
            "latest_report": self.latest_report,
        }
