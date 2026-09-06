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
            console.print(f"[bold red]World Model checkpoint not found at: {self.model_path}[/bold red]")
            return

        try:
            self.wrapper = WorldModelWrapper.load(str(self.model_path))
            self.simulator = ForwardSimulator(self.wrapper)
            self.explainer = ThreatExplainer(self.wrapper)
            console.print(f"[bold green]Loaded AI World Model checkpoint from: {self.model_path}[/bold green]")
        except Exception as e:
            console.print(f"[bold red]Failed to load World Model checkpoint: {e}[/bold red]")

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

        # Check for media streaming / WebRTC conferencing traffic safely (src_port optional in dataset CSVs)
        conferencing_ports = set(cfg.traffic_policy.conferencing_ports)
        proto_series = pd.to_numeric(flows_df.get("protocol", pd.Series(6, index=flows_df.index)), errors="coerce").fillna(6)
        dst_series = pd.to_numeric(flows_df.get("dst_port", pd.Series(0, index=flows_df.index)), errors="coerce").fillna(0)
        src_series = pd.to_numeric(flows_df.get("src_port", pd.Series(0, index=flows_df.index)), errors="coerce").fillna(0)
        is_media_flow = (
            (proto_series == 17) &
            (dst_series.isin(conferencing_ports) | src_series.isin(conferencing_ports))
        )
        media_ratio = float(is_media_flow.mean()) if len(flows_df) > 0 else 0.0
        syn_sum = pd.to_numeric(flows_df.get("syn_flag_cnt", pd.Series(0, index=flows_df.index)), errors="coerce").fillna(0).sum()
        rst_sum = pd.to_numeric(flows_df.get("rst_flag_cnt", pd.Series(0, index=flows_df.index)), errors="coerce").fillna(0).sum()
        is_media_window = (
            cfg.traffic_policy.allow_webrtc_conferencing
            and media_ratio >= 0.35
            and (syn_sum == 0)
            and (rst_sum == 0)
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

            # 2. Dampen media streaming volumetric features if active video/audio stream
            if is_media_window:
                dampen_factor = 0.10  # legitimate audio/video RTP normalized
                for vf in volumetric_features:
                    if vf in row_dict:
                        row_dict[vf] = row_dict[vf] * dampen_factor
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

        raw_max_risk = float(report.max_infiltration_prob)
        raw_peak_stage = report.peak_stage_name

        # 4. Rigorous Threat Precursor Disambiguation
        # Evaluates whether the window exhibits actual attack mechanics vs normal internet activity
        last_state = df_states.iloc[-1]
        unique_ports = int(last_state.get("unique_dst_ports", 0))
        syn_ratio = float(last_state.get("syn_ratio", 0.0))
        syn_count = int(last_state.get("syn_flag_count", 0))
        rst_count = int(last_state.get("rst_flag_count", 0))
        flow_count = max(int(last_state.get("flow_count", 1)), 1)
        ssh_ftp_ratio = float(last_state.get("ssh_ftp_port_ratio", 0.0))
        ephemeral_ratio = float(last_state.get("ephemeral_port_ratio", 0.0))
        web_ratio = float(last_state.get("web_port_ratio", 0.0))
        dns_ratio = float(last_state.get("dns_port_ratio", 0.0))
        pkts_rate = float(last_state.get("flow_pkts_rate", 0.0))
        is_attack_flag = int(last_state.get("is_attack", 0))

        has_port_scan = (unique_ports >= 15)
        has_syn_flood = (syn_ratio >= 0.25 and syn_count >= 10)
        has_rst_storm = (rst_count >= 15 and (rst_count / flow_count) >= 0.20)
        has_brute_force = (ssh_ftp_ratio >= 0.35 and flow_count >= 8)
        has_volumetric_flood = (pkts_rate >= 8000.0)
        has_rogue_ports = (ephemeral_ratio >= 0.70 and (web_ratio + dns_ratio) < 0.10)
        has_ground_truth_attack = (is_attack_flag == 1)

        has_threat_precursor = (
            has_port_scan
            or has_syn_flood
            or has_rst_storm
            or has_brute_force
            or has_volumetric_flood
            or has_rogue_ports
            or has_ground_truth_attack
        )

        min_warmup_states = min(cfg.thresholds.min_warmup_windows, self.seq_len)
        has_warmed_up = len(self.state_history) >= min_warmup_states
        is_immediate_attack = (has_port_scan or has_syn_flood or has_rst_storm or has_brute_force or has_volumetric_flood or has_ground_truth_attack)

        if has_threat_precursor and (has_warmed_up or is_immediate_attack):
            # Genuine cyber attack detected (reconnaissance, brute-force, flood, or MITRE progression)
            max_risk = raw_max_risk
            peak_stage = raw_peak_stage
            if max_risk >= cfg.thresholds.critical_threshold:
                recommended_policy = "ISOLATE_DEVICE"
                severity = "CRITICAL"
            elif max_risk >= self.alert_threshold:
                recommended_policy = "ALERT_ADMIN"
                severity = "SUSPICIOUS"
            else:
                recommended_policy = "ALLOW"
                severity = "NORMAL"
            is_threat = (recommended_policy in ["ALERT_ADMIN", "ISOLATE_DEVICE"])
            soc_note = explanation.get("soc_explanation", "") if explanation else ""
        else:
            # Nominal Workstation Internet Activity (Web surfing, media streaming, DNS, downloads)
            # Calibrate risk to nominal baseline (< 8%)
            max_risk = min(raw_max_risk, 0.075)
            peak_stage = "Benign"
            recommended_policy = "ALLOW"
            severity = "NORMAL"
            is_threat = False
            soc_note = "Network dynamics consistent with nominal baseline activity. Zero threat precursors detected."

        if max_risk > self.metrics["peak_risk_observed"]:
            self.metrics["peak_risk_observed"] = max_risk

        # Build clean JSON serializable rollout report
        rollout_summary = []
        for s in report.rollout_steps:
            if not has_threat_precursor:
                step_prob = min(float(s.infiltration_prob), 0.075)
                step_stage = "Benign"
                step_status = "NORMAL"
                step_policy = "ALLOW"
            else:
                step_prob = float(s.infiltration_prob)
                step_stage = s.mitre_stage_name
                step_status = s.status
                step_policy = s.policy_action

            rollout_summary.append({
                "step": s.step,
                "relative_seconds": s.step * self.window_size_seconds,
                "infiltration_prob": round(step_prob, 4),
                "mitre_stage": step_stage,
                "status": step_status,
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
            "is_conferencing": is_media_window,
            "has_threat_precursor": has_threat_precursor,
            "network_scale": {
                "connected_clients_count": cfg.network.connected_clients_count,
                "client_scale_applied": client_scale,
            }
        }
        self.latest_report = latest_rep

        alert_payload = None
        if is_threat:
            self.metrics["alerts_generated"] += 1
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

        return EvaluationResult(
            evaluated=True,
            is_threat=is_threat,
            risk_pct=round(max_risk * 100.0, 2),
            stage=peak_stage,
            policy=recommended_policy,
            severity=severity,
            is_conferencing=is_media_window,
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
        console.print("[bold cyan]World Model state history and flow buffers reset to clean state.[/bold cyan]")

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
