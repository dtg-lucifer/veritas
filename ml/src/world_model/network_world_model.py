"""
PyTorch Attention-Augmented Recurrent Latent World Model.
Learns network state transition dynamics P(S_{t+1} | S_{<=t}),
predicts next-state evolution, infiltration probability, and MITRE ATT&CK attack stage.
"""

from typing import Tuple, Dict, Any, Optional
import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from sklearn.preprocessing import RobustScaler
import joblib

from src.mitre_mapping import NUM_STAGES
from src.features.state_window import STATE_DIM


class TemporalMultiHeadAttention(nn.Module):
    """
    Computes self-attention over the temporal history sequence [t-W+1, ..., t].
    Returns context-weighted pooled hidden state and attention weights for explainability.
    """

    def __init__(self, hidden_dim: int, num_heads: int = 4, dropout: float = 0.1):
        super().__init__()
        self.num_heads = num_heads
        self.hidden_dim = hidden_dim
        self.head_dim = hidden_dim // num_heads
        assert hidden_dim % num_heads == 0, "hidden_dim must be divisible by num_heads"

        self.q_linear = nn.Linear(hidden_dim, hidden_dim)
        self.k_linear = nn.Linear(hidden_dim, hidden_dim)
        self.v_linear = nn.Linear(hidden_dim, hidden_dim)
        self.out_proj = nn.Linear(hidden_dim, hidden_dim)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        # x: (batch_size, seq_len, hidden_dim)
        B, T, D = x.shape
        H = self.num_heads
        d_k = self.head_dim

        q = self.q_linear(x).view(B, T, H, d_k).transpose(1, 2)  # (B, H, T, d_k)
        k = self.k_linear(x).view(B, T, H, d_k).transpose(1, 2)  # (B, H, T, d_k)
        v = self.v_linear(x).view(B, T, H, d_k).transpose(1, 2)  # (B, H, T, d_k)

        scores = torch.matmul(q, k.transpose(-2, -1)) / (d_k ** 0.5)  # (B, H, T, T)
        attn_probs = F.softmax(scores, dim=-1)
        attn_probs = self.dropout(attn_probs)

        context = torch.matmul(attn_probs, v)  # (B, H, T, d_k)
        context = context.transpose(1, 2).contiguous().view(B, T, D)
        out = self.out_proj(context)  # (B, T, D)

        # Average attention weights across heads for step t (query = last step T-1)
        # attn_weights: (B, T)
        last_step_attn = attn_probs[:, :, -1, :].mean(dim=1)

        # Summary representation for the sequence
        pooled = out[:, -1, :]  # Take the attended representation at current step

        return pooled, last_step_attn


class NetworkWorldModel(nn.Module):
    """
    World Model for Network Dynamics Simulation & Threat Anticipation.
    P(S_{t+1} | S_{<=t}) + Multi-Task Threat Classification.
    """

    def __init__(
        self,
        state_dim: int = STATE_DIM,
        hidden_dim: int = 64,
        num_layers: int = 2,
        num_heads: int = 4,
        num_stages: int = NUM_STAGES,
        dropout: float = 0.15,
    ):
        super().__init__()
        self.state_dim = state_dim
        self.hidden_dim = hidden_dim
        self.num_stages = num_stages

        # 1. State Latent Encoder: maps raw observation S_t to latent z_t
        self.encoder = nn.Sequential(
            nn.Linear(state_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.LeakyReLU(0.1),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.LeakyReLU(0.1),
        )

        # 2. Recurrent Causal Dynamics Core (LSTM)
        self.recurrent_core = nn.LSTM(
            input_size=hidden_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0,
        )

        # 3. Temporal Self-Attention
        self.attention = TemporalMultiHeadAttention(hidden_dim, num_heads=num_heads, dropout=dropout)

        # 4. Dynamics Transition Head: simulates next network state \hat{S}_{t+1}
        self.dynamics_head = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.LeakyReLU(0.1),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, state_dim),
        )

        # 5. Infiltration Probability Head (Binary: Infiltration / Threat)
        self.infiltration_head = nn.Sequential(
            nn.Linear(hidden_dim, 32),
            nn.LeakyReLU(0.1),
            nn.Dropout(dropout),
            nn.Linear(32, 1),
        )

        # 6. MITRE ATT&CK Tactical Stage Head (Multi-class: 0..NUM_STAGES-1)
        self.stage_head = nn.Sequential(
            nn.Linear(hidden_dim, 32),
            nn.LeakyReLU(0.1),
            nn.Dropout(dropout),
            nn.Linear(32, num_stages),
        )

    def forward(
        self, x_seq: torch.Tensor
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        r"""
        Forward pass over sequence of past network states.
        
        Args:
            x_seq: (batch_size, seq_len, state_dim)
            
        Returns:
            predicted_next_state: (batch_size, state_dim) -> \hat{S}_{t+1}
            infiltration_logits: (batch_size, 1)
            stage_logits: (batch_size, num_stages)
            attention_weights: (batch_size, seq_len)
        """
        B, T, D = x_seq.shape

        # Step 1: Encode state features into latent space
        # x_seq: (B*T, D) -> (B*T, H) -> (B, T, H)
        z_seq = self.encoder(x_seq.view(B * T, D)).view(B, T, self.hidden_dim)

        # Step 2: Causal temporal evolution via LSTM
        lstm_out, _ = self.recurrent_core(z_seq)  # (B, T, H)

        # Step 3: Temporal Multi-Head Attention pooling
        pooled_h, attn_weights = self.attention(lstm_out)  # (B, H), (B, T)

        # Step 4: Dynamics Transition Prediction \hat{S}_{t+1}
        predicted_next_state = self.dynamics_head(pooled_h)  # (B, D)

        # Step 5: Threat & Stage predictions
        inf_logits = self.infiltration_head(pooled_h)  # (B, 1)
        stage_logits = self.stage_head(pooled_h)  # (B, num_stages)

        return predicted_next_state, inf_logits, stage_logits, attn_weights


class WorldModelWrapper:
    """
    Production wrapper handling normalization scalers, checkpointing, and inference.
    """

    def __init__(
        self,
        model: Optional[NetworkWorldModel] = None,
        scaler: Optional[RobustScaler] = None,
        device: Optional[torch.device] = None,
    ):
        self.device = device or torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = model or NetworkWorldModel()
        self.model.to(self.device)
        self.scaler = scaler or RobustScaler()

    def fit_scaler(self, x_states: np.ndarray) -> None:
        """Fits normalization scaler on baseline state vectors."""
        self.scaler.fit(x_states)

    def transform_states(self, x_states: np.ndarray) -> np.ndarray:
        """Normalizes state vectors."""
        return self.scaler.transform(x_states)

    def inverse_transform_states(self, x_norm: np.ndarray) -> np.ndarray:
        """Denormalizes state vectors back to physical traffic units."""
        return self.scaler.inverse_transform(x_norm)

    def save(self, filepath: str) -> None:
        """Saves weights and normalization scaler to disk."""
        checkpoint = {
            "model_state_dict": self.model.state_dict(),
            "scaler": self.scaler,
            "state_dim": self.model.state_dim,
            "hidden_dim": self.model.hidden_dim,
            "num_stages": self.model.num_stages,
        }
        torch.save(checkpoint, filepath)

    @classmethod
    def load(cls, filepath: str, device: Optional[torch.device] = None) -> "WorldModelWrapper":
        """Loads weights and scaler from disk."""
        dev = device or torch.device("cuda" if torch.cuda.is_available() else "cpu")
        checkpoint = torch.load(filepath, map_location=dev, weights_only=False)
        model = NetworkWorldModel(
            state_dim=checkpoint.get("state_dim", STATE_DIM),
            hidden_dim=checkpoint.get("hidden_dim", 64),
            num_stages=checkpoint.get("num_stages", NUM_STAGES),
        )
        model.load_state_dict(checkpoint["model_state_dict"])
        scaler = checkpoint["scaler"]
        wrapper = cls(model=model, scaler=scaler, device=dev)
        wrapper.model.eval()
        return wrapper
