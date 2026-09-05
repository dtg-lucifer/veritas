"""
Temporal Network State Aggregator & Sequence Windowing.
Aggregates raw flow/packet records into consecutive uniform time windows (e.g. 10s, 30s),
computes 32-dimensional Network State Vectors S_t, and structures them into temporal
trajectories for World Model sequence learning and forward simulation.
"""

from typing import List, Tuple, Dict, Any, Optional
import numpy as np
import pandas as pd
from rich.console import Console

from src.mitre_mapping import map_label_to_mitre, STAGE_BENIGN

console = Console()

# Exact 32 Feature Dimension Names for the Network State Vector S_t
STATE_FEATURE_NAMES = [
    "flow_count",
    "tot_fwd_pkts",
    "tot_bwd_pkts",
    "tot_fwd_bytes",
    "tot_bwd_bytes",
    "flow_bytes_rate",
    "flow_pkts_rate",
    "flow_duration_mean",
    "syn_flag_count",
    "syn_ratio",
    "ack_flag_count",
    "ack_ratio",
    "rst_flag_count",
    "fin_flag_count",
    "psh_flag_count",
    "urg_flag_count",
    "unique_dst_ports",
    "ephemeral_port_ratio",
    "web_port_ratio",
    "dns_port_ratio",
    "ssh_ftp_port_ratio",
    "tcp_protocol_ratio",
    "udp_protocol_ratio",
    "pkt_len_mean",
    "pkt_len_std",
    "flow_iat_mean",
    "flow_iat_std",
    "flow_iat_max",
    "down_up_ratio_mean",
    "init_fwd_win_mean",
    "active_duration_mean",
    "idle_duration_mean",
]

STATE_DIM = len(STATE_FEATURE_NAMES)  # 32


class StateWindowAggregator:
    """
    Transforms stream of flow records into time-windowed network state vectors S_t.
    """

    def __init__(self, window_size_seconds: int = 15):
        self.window_size_seconds = window_size_seconds

    def aggregate_flows_to_states(self, df_flows: pd.DataFrame) -> pd.DataFrame:
        """
        Groups flows into uniform time windows of `window_size_seconds` and computes S_t
        using fast vectorized aggregations.
        """
        if df_flows.empty:
            return pd.DataFrame()

        df = df_flows.copy()
        if "timestamp" not in df.columns or not pd.api.types.is_datetime64_any_dtype(df["timestamp"]):
            df["timestamp"] = pd.to_datetime(df["timestamp"], format="mixed", dayfirst=True, errors="coerce")

        df = df.dropna(subset=["timestamp"])
        df = df.sort_values(by="timestamp").reset_index(drop=True)

        # Floor timestamp to window interval
        df["window_timestamp"] = df["timestamp"].dt.floor(f"{self.window_size_seconds}s")

        # Ensure all numeric columns are coerced and valid
        num_cols = [
            "dst_port", "protocol", "tot_fwd_pkts", "tot_bwd_pkts", "tot_fwd_bytes", "tot_bwd_bytes",
            "flow_bytes_per_sec", "flow_pkts_per_sec", "flow_duration", "syn_flag_cnt", "ack_flag_cnt",
            "rst_flag_cnt", "fin_flag_cnt", "psh_flag_cnt", "urg_flag_cnt", "pkt_len_mean", "pkt_len_std",
            "flow_iat_mean", "flow_iat_std", "flow_iat_max", "down_up_ratio", "init_fwd_win_bytes",
            "active_mean", "idle_mean"
        ]
        for col in num_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce").replace([np.inf, -np.inf], 0.0).fillna(0.0)

        # Precompute port and protocol masks for vectorized aggregation
        df["is_ephemeral"] = (df["dst_port"] >= 1024).astype(float)
        df["is_web"] = df["dst_port"].isin([80, 443, 8080]).astype(float)
        df["is_dns"] = (df["dst_port"].astype(float) == 53).astype(float)
        df["is_ssh_ftp"] = df["dst_port"].astype(float).isin([21, 22]).astype(float)
        df["is_tcp"] = (df["protocol"].astype(float) == 6).astype(float)
        df["is_udp"] = (df["protocol"].astype(float) == 17).astype(float)
        df["is_attack_flag"] = (df["label"].astype(str).str.strip().str.lower() != "benign").astype(int)

        # Fast Groupby Aggregation
        agg_rules = {
            "dst_port": ["count", "nunique"],
            "tot_fwd_pkts": "sum",
            "tot_bwd_pkts": "sum",
            "tot_fwd_bytes": "sum",
            "tot_bwd_bytes": "sum",
            "flow_bytes_per_sec": "mean",
            "flow_pkts_per_sec": "mean",
            "flow_duration": "mean",
            "syn_flag_cnt": "sum",
            "ack_flag_cnt": "sum",
            "rst_flag_cnt": "sum",
            "fin_flag_cnt": "sum",
            "psh_flag_cnt": "sum",
            "urg_flag_cnt": "sum",
            "is_ephemeral": "mean",
            "is_web": "mean",
            "is_dns": "mean",
            "is_ssh_ftp": "mean",
            "is_tcp": "mean",
            "is_udp": "mean",
            "pkt_len_mean": "mean",
            "pkt_len_std": "mean",
            "flow_iat_mean": "mean",
            "flow_iat_std": "mean",
            "flow_iat_max": "max",
            "down_up_ratio": "mean",
            "init_fwd_win_bytes": "mean",
            "active_mean": "mean",
            "idle_mean": "mean",
            "is_attack_flag": "max",
        }

        grouped = df.groupby("window_timestamp").agg(agg_rules)
        grouped.columns = [
            "flow_count", "unique_dst_ports", "tot_fwd_pkts", "tot_bwd_pkts",
            "tot_fwd_bytes", "tot_bwd_bytes", "flow_bytes_rate", "flow_pkts_rate",
            "flow_duration_mean", "syn_flag_count", "ack_flag_count", "rst_flag_count",
            "fin_flag_count", "psh_flag_count", "urg_flag_count", "ephemeral_port_ratio",
            "web_port_ratio", "dns_port_ratio", "ssh_ftp_port_ratio", "tcp_protocol_ratio",
            "udp_protocol_ratio", "pkt_len_mean", "pkt_len_std", "flow_iat_mean",
            "flow_iat_std", "flow_iat_max", "down_up_ratio_mean", "init_fwd_win_mean",
            "active_duration_mean", "idle_duration_mean", "is_attack"
        ]
        grouped = grouped.reset_index()

        total_pkts = np.maximum(grouped["tot_fwd_pkts"] + grouped["tot_bwd_pkts"], 1.0)
        grouped["syn_ratio"] = grouped["syn_flag_count"] / total_pkts
        grouped["ack_ratio"] = grouped["ack_flag_count"] / total_pkts

        # Find dominant label per window
        label_df = df[df["is_attack_flag"] == 1]
        if not label_df.empty:
            dominant_attacks = label_df.groupby("window_timestamp")["label"].agg(
                lambda s: s.mode().iloc[0] if not s.empty else "Benign"
            ).to_dict()
        else:
            dominant_attacks = {}

        grouped["dominant_label"] = grouped["window_timestamp"].map(
            lambda t: dominant_attacks.get(t, "Benign")
        )

        mitre_info = grouped["dominant_label"].apply(map_label_to_mitre)
        grouped["is_attack"] = [int(m[0]) for m in mitre_info]
        grouped["mitre_stage"] = [int(m[1]) for m in mitre_info]
        grouped["stage_name"] = [str(m[2]) for m in mitre_info]

        return grouped


def build_temporal_sequences(
    df_states: pd.DataFrame,
    seq_len: int = 8,
    forecast_horizon: int = 1,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """
    Constructs sliding sequence windows for World Model training.
    
    Args:
        df_states: DataFrame of aggregated states containing STATE_FEATURE_NAMES
        seq_len: History context window size W (number of historical state vectors)
        forecast_horizon: Step ahead to predict (k=1 predicts S_{t+1})

    Returns:
        X_seq: (N, seq_len, STATE_DIM) array of historical state trajectories
        Y_next_state: (N, STATE_DIM) target network state S_{t+forecast_horizon}
        Y_infiltration: (N,) binary indicator if target step is an attack
        Y_mitre_stage: (N,) target MITRE stage class ID [0..5]
    """
    if len(df_states) < (seq_len + forecast_horizon):
        raise ValueError(f"Need at least {seq_len + forecast_horizon} states, but got {len(df_states)}.")

    features = df_states[STATE_FEATURE_NAMES].values.astype(np.float32)
    is_attacks = df_states["is_attack"].values.astype(np.float32)
    stages = df_states["mitre_stage"].values.astype(np.int64)

    X_list, Y_state_list, Y_inf_list, Y_stage_list = [], [], [], []

    for i in range(len(df_states) - seq_len - forecast_horizon + 1):
        target_idx = i + seq_len + forecast_horizon - 1
        X_list.append(features[i : i + seq_len])
        Y_state_list.append(features[target_idx])
        Y_inf_list.append(is_attacks[target_idx])
        Y_stage_list.append(stages[target_idx])

    X_seq = np.array(X_list, dtype=np.float32)
    Y_next_state = np.array(Y_state_list, dtype=np.float32)
    Y_infiltration = np.array(Y_inf_list, dtype=np.float32)
    Y_mitre_stage = np.array(Y_stage_list, dtype=np.int64)

    return X_seq, Y_next_state, Y_infiltration, Y_mitre_stage
