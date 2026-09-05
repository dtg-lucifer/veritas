"""
Explainability & Attribution Engine for Network World Model.
Provides:
1. Temporal Attention Interpretation (historical window attribution).
2. Gradient x Input / Saliency feature attribution.
3. Natural Language Root-Cause Synthesizer for SOC Analysts.
"""

from typing import List, Dict, Any, Tuple
import numpy as np
import torch

from src.features.state_window import STATE_FEATURE_NAMES, STATE_DIM
from src.world_model.network_world_model import WorldModelWrapper


class ThreatExplainer:
    """
    Computes explainability matrices and plain-English threat rationale for SOC analysts.
    """

    def __init__(self, world_model: WorldModelWrapper):
        self.wm = world_model
        self.model = world_model.model
        self.scaler = world_model.scaler
        self.device = world_model.device

    def explain_sequence(
        self,
        history_states: np.ndarray,
        top_k_features: int = 5,
    ) -> Dict[str, Any]:
        """
        Extracts temporal attention weights and feature attributions for an input sequence.
        
        Args:
            history_states: (W, STATE_DIM) raw observation sequence
            top_k_features: number of top features to highlight
        """
        self.model.eval()
        history_norm = self.scaler.transform(history_states)
        seq_tensor = torch.tensor(history_norm, dtype=torch.float32, device=self.device).unsqueeze(0)
        seq_tensor.requires_grad_(True)

        _, inf_logits, stage_logits, attn_weights = self.model(seq_tensor)
        inf_prob = torch.sigmoid(inf_logits)
        inf_prob.backward()

        # Attention distribution across past W time steps
        attn = attn_weights.squeeze(0).detach().cpu().numpy().tolist()

        # Feature saliency on the most recent state S_t
        grads = seq_tensor.grad.squeeze(0).cpu().numpy()[-1]
        vals = history_norm[-1]
        attr = np.abs(grads * vals)
        
        sum_attr = np.sum(attr)
        norm_attr = attr / sum_attr if sum_attr > 1e-8 else attr

        sorted_indices = np.argsort(norm_attr)[::-1][:top_k_features]
        top_attributions = [
            {
                "feature": STATE_FEATURE_NAMES[idx],
                "score": float(norm_attr[idx]),
                "raw_value": float(history_states[-1, idx]),
            }
            for idx in sorted_indices
        ]

        # Synthesize plain English summary
        summary = self._synthesize_explanation(top_attributions, float(inf_prob.item()))

        return {
            "infiltration_probability": float(inf_prob.item()),
            "attention_weights": [round(float(w), 4) for w in attn],
            "top_driving_features": top_attributions,
            "soc_explanation": summary,
        }

    def _synthesize_explanation(
        self,
        top_features: List[Dict[str, Any]],
        inf_prob: float,
    ) -> str:
        """
        Translates raw feature attributions into readable root-cause descriptions.
        """
        if inf_prob < 0.40:
            return "Traffic behavior aligns with baseline nominal distributions. No threat precursors detected."

        signals = []
        for item in top_features[:3]:
            feat = item["feature"]
            val = item["raw_value"]
            score_pct = int(item["score"] * 100)

            if "syn" in feat:
                signals.append(f"abnormal SYN packet concentration ({score_pct}% attribution)")
            elif "unique_dst_ports" in feat or "ephemeral" in feat:
                signals.append(f"rapid multi-port scanning activity ({int(val)} distinct ports)")
            elif "bytes_rate" in feat or "pkts_rate" in feat:
                signals.append(f"sudden volumetric traffic surge ({score_pct}% attribution)")
            elif "iat" in feat:
                signals.append(f"anomalous inter-arrival timing patterns ({score_pct}% attribution)")
            elif "pkt_len" in feat:
                signals.append(f"irregular payload size variance ({score_pct}% attribution)")
            else:
                signals.append(f"{feat.replace('_', ' ')}: {val:.2f}")

        joined_signals = "; ".join(signals)
        urgency = "HIGH RISK" if inf_prob >= 0.70 else "SUSPICIOUS"
        return f"[{urgency}] Forward dynamics forecast threat escalation driven primarily by: {joined_signals}."
