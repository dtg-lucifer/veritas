"""
World Model Inference & Real-Time Flow State Aggregation Service.
Bridges live or replayed network flows from Kafka to the trained
Autoregressive World Model (StateWindowAggregator -> ForwardSimulator -> ThreatExplainer).
"""

import os
import sys
import time
from pathlib import Path
from datetime import datetime, timezone
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

console = Console()


class WorldModelService:
    """
    Manages stateful stream aggregation of Kafka network flows,
    temporal sequence buffering, K-step forward simulation, and autonomous policy trigger.
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        window_size_seconds: int = 15,
        seq_len: int = 8,
        rollout_steps: int = 5,
        alert_threshold: float = 0.40,
    ):
        self.window_size_seconds = int(os.getenv("WINDOW_SECONDS", str(window_size_seconds)))
        self.seq_len = seq_len
        self.rollout_steps = rollout_steps
        self.alert_threshold = float(os.getenv("ALERT_THRESHOLD", str(alert_threshold)))
        if self.alert_threshold > 1.0:
            # Handle percentage notation (e.g. 40.0 -> 0.40)
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

    def ingest_batch(self, flows: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Buffers a batch of incoming flows and runs evaluation if window threshold is reached.
        Returns an alert payload dictionary if threat threshold is breached.
        """
        for f in flows:
            self.ingest_flow(f)

        # Evaluate if we have collected enough flows or crossed a time boundary
        if len(self.flow_buffer) >= 20:
            return self.process_pending_flows()
        return None

    def process_pending_flows(self) -> Optional[Dict[str, Any]]:
        """
        Aggregates pending flows into 32-dim State Vectors, updates history,
        and performs K-step autoregressive forward simulation.
        """
        if not self.flow_buffer:
            return None

        if self.simulator is None:
            return None

        flows_to_process = list(self.flow_buffer)
        self.flow_buffer.clear()

        df_flows = pd.DataFrame(flows_to_process)
        if df_flows.empty:
            return None

        # Standardize and coerce all numeric column types
        for col in df_flows.columns:
            if col not in ["timestamp", "label"]:
                df_flows[col] = pd.to_numeric(df_flows[col], errors="coerce").fillna(0.0)

        # Aggregate flows into temporal windows
        df_states = self.aggregator.aggregate_flows_to_states(df_flows)
        if df_states.empty:
            return None

        self.metrics["windows_evaluated"] += len(df_states)

        # Append new state vectors into history
        for _, row in df_states.iterrows():
            state_vec = row[STATE_FEATURE_NAMES].values.astype(np.float32)
            # Replace NaNs with 0
            state_vec = np.nan_to_num(state_vec, nan=0.0, posinf=0.0, neginf=0.0)
            self.state_history.append(state_vec)
            self.state_timestamps.append(str(row.get("window_timestamp", datetime.now(timezone.utc).isoformat())))

            if len(self.state_history) > self.max_history_len:
                self.state_history.pop(0)
                self.state_timestamps.pop(0)

        # Prepare context sequence for Forward Simulation
        if len(self.state_history) < self.seq_len:
            # Pad by repeating earliest available state
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
        if max_risk > self.metrics["peak_risk_observed"]:
            self.metrics["peak_risk_observed"] = max_risk

        # Determine overall recommended policy action based on peak risk across the rollout horizon
        if max_risk >= 0.70:
            recommended_policy = "ISOLATE_DEVICE"
        elif max_risk >= self.alert_threshold:
            recommended_policy = "ALERT_ADMIN"
        else:
            recommended_policy = "ALLOW"

        # Build clean JSON serializable rollout report
        rollout_summary = []
        for s in report.rollout_steps:
            rollout_summary.append({
                "step": s.step,
                "relative_seconds": s.step * self.window_size_seconds,
                "infiltration_prob": round(float(s.infiltration_prob), 4),
                "mitre_stage": s.mitre_stage_name,
                "status": s.status,
                "policy_action": s.policy_action,
                "predicted_flow_count": int(s.predicted_state_denorm.get("flow_count", 0)),
                "predicted_syn_ratio": round(float(s.predicted_state_denorm.get("syn_ratio", 0.0)), 4),
            })

        latest_rep = {
            "timestamp": now_str,
            "window_size_seconds": self.window_size_seconds,
            "rollout_steps": rollout_summary,
            "max_infiltration_prob": round(max_risk, 4),
            "peak_stage": report.peak_stage_name,
            "recommended_policy": recommended_policy,
            "top_attributions": explanation.get("top_driving_features", [])[:4] if explanation else [],
            "soc_guidance": explanation.get("soc_explanation", "") if explanation else "",
        }
        self.latest_report = latest_rep

        # 4. Check Threat Threshold & Trigger Alert
        is_threat = (
            max_risk >= self.alert_threshold
            or recommended_policy in ["ALERT_ADMIN", "ISOLATE_DEVICE"]
        )

        if is_threat:
            self.metrics["alerts_generated"] += 1
            severity = "CRITICAL" if max_risk >= 0.70 else "SUSPICIOUS"

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
            return alert_payload

        return None

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
        return {
            "model_loaded": self.simulator is not None,
            "model_path": str(self.model_path),
            "window_size_seconds": self.window_size_seconds,
            "seq_len": self.seq_len,
            "rollout_steps": self.rollout_steps,
            "alert_threshold": self.alert_threshold,
            "active_history_states": len(self.state_history),
            "pending_buffer_flows": len(self.flow_buffer),
            "metrics": self.metrics,
            "latest_report": self.latest_report,
        }
