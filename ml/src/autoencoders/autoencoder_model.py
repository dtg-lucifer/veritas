"""
PyTorch Deep Autoencoder for Behavioral Anomaly Detection.
Learns a compact latent representation of normal employee network activity
and detects anomalies via high reconstruction error ||X - X_hat||^2.
"""

from typing import Dict, List, Optional, Tuple, Any
import numpy as np
import pandas as pd
from pathlib import Path
import joblib

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import StandardScaler

from src.features.feature_extractor import get_feature_columns


class BehavioralAutoencoderNet(nn.Module):
    def __init__(self, input_dim: int, latent_dim: int = 16):
        super().__init__()
        # Encoder
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.BatchNorm1d(64),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.1),
            nn.Linear(64, 32),
            nn.BatchNorm1d(32),
            nn.LeakyReLU(0.2),
            nn.Linear(32, latent_dim),
        )
        # Decoder
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 32),
            nn.BatchNorm1d(32),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.1),
            nn.Linear(32, 64),
            nn.BatchNorm1d(64),
            nn.LeakyReLU(0.2),
            nn.Linear(64, input_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        latent = self.encoder(x)
        reconstruction = self.decoder(latent)
        return reconstruction


class AutoencoderAnomalyDetector:
    def __init__(
        self,
        feature_cols: Optional[List[str]] = None,
        latent_dim: int = 16,
        batch_size: int = 64,
        lr: float = 1e-3,
        epochs: int = 40,
        device: Optional[str] = None
    ):
        self.feature_cols = feature_cols or get_feature_columns()
        self.latent_dim = latent_dim
        self.batch_size = batch_size
        self.lr = lr
        self.epochs = epochs
        self.device = torch.device(device or ("cuda" if torch.cuda.is_available() else "cpu"))
        
        self.scaler = StandardScaler()
        self.model: Optional[BehavioralAutoencoderNet] = None
        self.is_fitted = False
        
        # Calibration bounds for reconstruction error
        self.recon_p50 = 0.1
        self.recon_p99 = 2.0

    def fit(self, df: pd.DataFrame, val_split: float = 0.15) -> "AutoencoderAnomalyDetector":
        """
        Trains the Autoencoder on normal activity feature vectors.
        """
        train_df = df[df["is_anomaly"] == 0] if "is_anomaly" in df.columns else df
        X = train_df[self.feature_cols].fillna(0).values.astype(np.float32)
        X_scaled = self.scaler.fit_transform(X)

        input_dim = len(self.feature_cols)
        self.model = BehavioralAutoencoderNet(input_dim=input_dim, latent_dim=self.latent_dim).to(self.device)

        # Validation split
        n_val = int(len(X_scaled) * val_split)
        indices = np.random.permutation(len(X_scaled))
        train_idx, val_idx = indices[n_val:], indices[:n_val]
        
        train_loader = DataLoader(
            TensorDataset(torch.tensor(X_scaled[train_idx], dtype=torch.float32)),
            batch_size=self.batch_size,
            shuffle=True,
            drop_last=(len(train_idx) > self.batch_size)
        )

        val_tensor = torch.tensor(X_scaled[val_idx], dtype=torch.float32).to(self.device) if n_val > 0 else None

        criterion = nn.MSELoss()
        optimizer = optim.AdamW(self.model.parameters(), lr=self.lr, weight_decay=1e-4)
        scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=self.epochs)

        self.model.train()
        for epoch in range(self.epochs):
            total_loss = 0.0
            for (batch_x,) in train_loader:
                batch_x = batch_x.to(self.device)
                optimizer.zero_grad()
                recon = self.model(batch_x)
                loss = criterion(recon, batch_x)
                loss.backward()
                optimizer.step()
                total_loss += loss.item() * len(batch_x)
            
            scheduler.step()

        # Compute calibration statistics on training set
        self.model.eval()
        with torch.no_grad():
            X_tensor = torch.tensor(X_scaled, dtype=torch.float32).to(self.device)
            recon = self.model(X_tensor)
            recon_errors = torch.mean((X_tensor - recon) ** 2, dim=1).cpu().numpy()
            self.recon_p50 = float(np.percentile(recon_errors, 50))
            self.recon_p99 = float(np.percentile(recon_errors, 98))
            if self.recon_p99 <= self.recon_p50:
                self.recon_p99 = self.recon_p50 + 1.0

        self.is_fitted = True
        return self

    def predict_anomaly_scores(self, df: pd.DataFrame) -> np.ndarray:
        """
        Computes normalized reconstruction error anomaly scores in [0..1].
        """
        if not self.is_fitted or self.model is None:
            raise ValueError("Autoencoder is not fitted.")

        X = df[self.feature_cols].fillna(0).values.astype(np.float32)
        X_scaled = self.scaler.transform(X)

        self.model.eval()
        with torch.no_grad():
            X_tensor = torch.tensor(X_scaled, dtype=torch.float32).to(self.device)
            recon = self.model(X_tensor)
            mse = torch.mean((X_tensor - recon) ** 2, dim=1).cpu().numpy()

        # Scale into [0, 1] relative to normal distribution percentiles
        scaled_scores = (mse - self.recon_p50) / (self.recon_p99 - self.recon_p50 + 1e-4)
        return np.clip(scaled_scores, 0.0, 1.0)

    def explain_record(self, record_dict: Dict[str, float], top_k: int = 4) -> List[Dict[str, Any]]:
        """
        Identifies features with highest reconstruction error.
        """
        if not self.is_fitted or self.model is None:
            return []

        X_single = np.array([[record_dict.get(c, 0.0) for c in self.feature_cols]], dtype=np.float32)
        X_scaled = self.scaler.transform(X_single)

        self.model.eval()
        with torch.no_grad():
            X_t = torch.tensor(X_scaled, dtype=torch.float32).to(self.device)
            recon_t = self.model(X_t)
            errs = ((X_t - recon_t) ** 2).cpu().numpy()[0]

        exps = []
        for feat, err in zip(self.feature_cols, errs):
            raw_val = float(record_dict.get(feat, 0.0))
            if err > 1.0 or (err > 0.5 and raw_val > 0):
                exps.append({
                    "feature": feat,
                    "raw_value": round(raw_val, 2),
                    "reconstruction_error": round(float(err), 2),
                    "message": f"High reconstruction deviation on {feat.replace('_', ' ')} (error: {err:.2f})"
                })
        
        exps.sort(key=lambda x: x["reconstruction_error"], reverse=True)
        return exps[:top_k]

    def save(self, model_path: str, meta_path: str) -> None:
        """Saves model weights and scaler/calibration metadata."""
        Path(model_path).parent.mkdir(parents=True, exist_ok=True)
        torch.save(self.model.state_dict(), model_path)
        metadata = {
            "feature_cols": self.feature_cols,
            "latent_dim": self.latent_dim,
            "recon_p50": self.recon_p50,
            "recon_p99": self.recon_p99,
            "scaler": self.scaler,
            "is_fitted": self.is_fitted
        }
        joblib.dump(metadata, meta_path)

    @classmethod
    def load(cls, model_path: str, meta_path: str, device: Optional[str] = None) -> "AutoencoderAnomalyDetector":
        """Loads trained autoencoder from checkpoint and metadata."""
        metadata = joblib.load(meta_path)
        detector = cls(
            feature_cols=metadata["feature_cols"],
            latent_dim=metadata["latent_dim"],
            device=device
        )
        detector.scaler = metadata["scaler"]
        detector.recon_p50 = metadata["recon_p50"]
        detector.recon_p99 = metadata["recon_p99"]
        detector.is_fitted = metadata["is_fitted"]

        input_dim = len(detector.feature_cols)
        detector.model = BehavioralAutoencoderNet(input_dim=input_dim, latent_dim=detector.latent_dim).to(detector.device)
        detector.model.load_state_dict(torch.load(model_path, map_location=detector.device))
        detector.model.eval()
        return detector
