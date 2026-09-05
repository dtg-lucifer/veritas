"""
Autoregressive Forward Simulation Engine for World Model.
Performs K-step forward rollout given an observed network traffic history,
forecasting the infiltration probability timeline, projected network states,
and MITRE ATT&CK tactical attack progression.
"""

from typing import List, Dict, Any, Optional, Tuple
import numpy as np
import torch

from src.mitre_mapping import STAGE_NAMES, STAGE_DESCRIPTIONS
from src.features.state_window import STATE_FEATURE_NAMES, STATE_DIM
from src.world_model.network_world_model import WorldModelWrapper


class RolloutStepResult:
    """Encapsulates the prediction for a single future step ahead."""

    def __init__(
        self,
        step: int,
        infiltration_prob: float,
        mitre_stage_id: int,
        mitre_stage_name: str,
        stage_probabilities: Dict[str, float],
        predicted_state_denorm: Dict[str, float],
        status: str,
        policy_action: str,
    ):
        self.step = step
        self.infiltration_prob = infiltration_prob
        self.mitre_stage_id = mitre_stage_id
        self.mitre_stage_name = mitre_stage_name
        self.stage_probabilities = stage_probabilities
        self.predicted_state_denorm = predicted_state_denorm
        self.status = status
        self.policy_action = policy_action

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step,
            "infiltration_probability": round(float(self.infiltration_prob), 4),
            "mitre_stage_id": self.mitre_stage_id,
            "mitre_stage_name": self.mitre_stage_name,
            "stage_probabilities": {k: round(v, 4) for k, v in self.stage_probabilities.items()},
            "status": self.status,
            "policy_action": self.policy_action,
            "predicted_state": {k: round(v, 2) for k, v in self.predicted_state_denorm.items()},
        }


class ForwardSimulationReport:
    """Summary of a K-step rollout simulation."""

    def __init__(
        self,
        rollout_steps: List[RolloutStepResult],
        max_infiltration_prob: float,
        peak_stage_name: str,
        convergence_step: Optional[int],
        driving_features: List[Tuple[str, float]],
        attention_history: List[float],
    ):
        self.rollout_steps = rollout_steps
        self.max_infiltration_prob = max_infiltration_prob
        self.peak_stage_name = peak_stage_name
        self.convergence_step = convergence_step
        self.driving_features = driving_features
        self.attention_history = attention_history

    def to_dict(self) -> Dict[str, Any]:
        return {
            "max_infiltration_prob": round(float(self.max_infiltration_prob), 4),
            "peak_stage_name": self.peak_stage_name,
            "convergence_step": self.convergence_step,
            "probability_timeline": [s.infiltration_prob for s in self.rollout_steps],
            "stage_timeline": [s.mitre_stage_name for s in self.rollout_steps],
            "driving_features": [
                {"feature": feat, "attribution_score": round(score, 4)}
                for feat, score in self.driving_features
            ],
            "attention_history": [round(w, 4) for w in self.attention_history],
            "rollout_steps": [s.to_dict() for s in self.rollout_steps],
        }


class ForwardSimulator:
    """
    Executes autoregressive forward simulation over a trained WorldModelWrapper.
    """

    def __init__(
        self,
        world_model: WorldModelWrapper,
        threshold_suspicious: float = 0.40,
        threshold_critical: float = 0.70,
    ):
        self.wm = world_model
        self.model = world_model.model
        self.scaler = world_model.scaler
        self.device = world_model.device
        self.threshold_suspicious = threshold_suspicious
        self.threshold_critical = threshold_critical

    def simulate(
        self,
        history_states: np.ndarray,
        k_steps: int = 5,
    ) -> ForwardSimulationReport:
        """
        Rolls out K steps ahead starting from the observed history sequence.
        
        Args:
            history_states: (W, STATE_DIM) unnormalized raw state vectors
            k_steps: number of future time steps to simulate (K)
            
        Returns:
            ForwardSimulationReport containing forecast trajectory
        """
        self.model.eval()

        if len(history_states.shape) != 2 or history_states.shape[1] != STATE_DIM:
            raise ValueError(f"Expected history_states shape (W, {STATE_DIM}), got {history_states.shape}")

        # Normalize history states
        history_norm = self.scaler.transform(history_states)  # (W, D)
        curr_seq = history_norm.copy()  # (W, D)

        rollout_results: List[RolloutStepResult] = []
        max_prob = 0.0
        peak_stage = "Benign"
        convergence_step: Optional[int] = None
        first_step_attn: List[float] = []

        for step in range(1, k_steps + 1):
            # Format tensor (1, W, D)
            seq_tensor = torch.tensor(curr_seq, dtype=torch.float32, device=self.device).unsqueeze(0)
            
            with torch.no_grad():
                pred_next_norm, inf_logits, stage_logits, attn_weights = self.model(seq_tensor)

            if step == 1:
                first_step_attn = attn_weights.squeeze(0).cpu().numpy().tolist()

            inf_prob = float(torch.sigmoid(inf_logits).item())
            stage_probs = torch.softmax(stage_logits, dim=-1).squeeze(0).cpu().numpy()
            pred_stage_id = int(np.argmax(stage_probs))
            pred_stage_name = STAGE_NAMES.get(pred_stage_id, "Unknown")

            if inf_prob > max_prob:
                max_prob = inf_prob
                peak_stage = pred_stage_name

            # Determine Policy Action & Status
            if inf_prob >= self.threshold_critical:
                status = "CRITICAL"
                action = "ISOLATE_DEVICE"
                if convergence_step is None:
                    convergence_step = step
            elif inf_prob >= self.threshold_suspicious:
                status = "SUSPICIOUS"
                action = "ALERT_ADMIN"
            else:
                status = "NORMAL"
                action = "ALLOW"

            # Denormalize predicted state vector
            pred_next_np = pred_next_norm.squeeze(0).cpu().numpy()
            pred_state_denorm = self.scaler.inverse_transform(pred_next_np.reshape(1, -1)).squeeze(0)
            # Clip non-negative features like counts and rates to >= 0
            pred_state_denorm = np.maximum(pred_state_denorm, 0.0)
            pred_dict = {STATE_FEATURE_NAMES[i]: float(pred_state_denorm[i]) for i in range(STATE_DIM)}

            stage_prob_dict = {STAGE_NAMES.get(i, f"Stage {i}"): float(stage_probs[i]) for i in range(len(stage_probs))}

            step_res = RolloutStepResult(
                step=step,
                infiltration_prob=inf_prob,
                mitre_stage_id=pred_stage_id,
                mitre_stage_name=pred_stage_name,
                stage_probabilities=stage_prob_dict,
                predicted_state_denorm=pred_dict,
                status=status,
                policy_action=action,
            )
            rollout_results.append(step_res)

            # Autoregressive sequence update: append predicted next state, slide window
            next_step_norm = pred_next_np.reshape(1, STATE_DIM)
            curr_seq = np.vstack([curr_seq[1:], next_step_norm])

        # Compute explainability driving features for step 1 using input gradients
        driving_features = self._compute_driving_features(history_norm)

        return ForwardSimulationReport(
            rollout_steps=rollout_results,
            max_infiltration_prob=max_prob,
            peak_stage_name=peak_stage,
            convergence_step=convergence_step,
            driving_features=driving_features,
            attention_history=first_step_attn,
        )

    def _compute_driving_features(
        self,
        history_norm: np.ndarray,
        top_n: int = 5,
    ) -> List[Tuple[str, float]]:
        """
        Computes gradient-based feature attribution: |S_t * d(inf_prob)/d(S_t)|
        """
        seq_tensor = torch.tensor(history_norm, dtype=torch.float32, device=self.device).unsqueeze(0)
        seq_tensor.requires_grad_(True)

        _, inf_logits, _, _ = self.model(seq_tensor)
        inf_prob = torch.sigmoid(inf_logits)
        inf_prob.backward()

        # Attribute specifically to the latest state vector S_t in the history
        grads = seq_tensor.grad.squeeze(0).cpu().numpy()[-1]  # (STATE_DIM,)
        vals = history_norm[-1]  # (STATE_DIM,)
        attribution = np.abs(grads * vals)

        total_attr = np.sum(attribution)
        if total_attr > 1e-8:
            attribution = attribution / total_attr

        top_indices = np.argsort(attribution)[::-1][:top_n]
        return [(STATE_FEATURE_NAMES[idx], float(attribution[idx])) for idx in top_indices]
