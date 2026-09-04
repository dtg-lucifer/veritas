"""
Traffic Feature Extractor for Network Telemetry & World Model Ingestion.
Supports:
1. Open-source flow CSV datasets (CIC-IDS-2018, CIC-IoT-2023).
2. Raw PCAP packet captures via Scapy/PyShark.
Standardizes raw network traffic into uniform flow-level and packet-level records.
"""

from pathlib import Path
from typing import Optional, List, Dict, Any, Union
import numpy as np
import pandas as pd
from rich.console import Console

console = Console()

# Standardized Flow Record Feature Schema
STANDARD_COLUMNS = [
    "timestamp",
    "dst_port",
    "protocol",
    "flow_duration",
    "tot_fwd_pkts",
    "tot_bwd_pkts",
    "tot_fwd_bytes",
    "tot_bwd_bytes",
    "flow_bytes_per_sec",
    "flow_pkts_per_sec",
    "flow_iat_mean",
    "flow_iat_std",
    "flow_iat_max",
    "fwd_iat_mean",
    "bwd_iat_mean",
    "syn_flag_cnt",
    "ack_flag_cnt",
    "rst_flag_cnt",
    "fin_flag_cnt",
    "psh_flag_cnt",
    "urg_flag_cnt",
    "ece_flag_cnt",
    "pkt_len_mean",
    "pkt_len_std",
    "down_up_ratio",
    "init_fwd_win_bytes",
    "init_bwd_win_bytes",
    "active_mean",
    "idle_mean",
    "label",
]

# Column mapping from raw CIC-IDS-2018 CSV header names to standard names
CIC_IDS_2018_MAPPING = {
    "Timestamp": "timestamp",
    "Dst Port": "dst_port",
    "Protocol": "protocol",
    "Flow Duration": "flow_duration",
    "Tot Fwd Pkts": "tot_fwd_pkts",
    "Tot Bwd Pkts": "tot_bwd_pkts",
    "TotLen Fwd Pkts": "tot_fwd_bytes",
    "TotLen Bwd Pkts": "tot_bwd_bytes",
    "Flow Byts/s": "flow_bytes_per_sec",
    "Flow Pkts/s": "flow_pkts_per_sec",
    "Flow IAT Mean": "flow_iat_mean",
    "Flow IAT Std": "flow_iat_std",
    "Flow IAT Max": "flow_iat_max",
    "Fwd IAT Mean": "fwd_iat_mean",
    "Bwd IAT Mean": "bwd_iat_mean",
    "SYN Flag Cnt": "syn_flag_cnt",
    "ACK Flag Cnt": "ack_flag_cnt",
    "RST Flag Cnt": "rst_flag_cnt",
    "FIN Flag Cnt": "fin_flag_cnt",
    "PSH Flag Cnt": "psh_flag_cnt",
    "URG Flag Cnt": "urg_flag_cnt",
    "ECE Flag Cnt": "ece_flag_cnt",
    "Pkt Len Mean": "pkt_len_mean",
    "Pkt Len Std": "pkt_len_std",
    "Down/Up Ratio": "down_up_ratio",
    "Init Fwd Win Byts": "init_fwd_win_bytes",
    "Init Bwd Win Byts": "init_bwd_win_bytes",
    "Active Mean": "active_mean",
    "Idle Mean": "idle_mean",
    "Label": "label",
}


class TrafficExtractor:
    """
    Unified Ingestion & Standardization for CSV Flow Telemetry and PCAP Traces.
    """

    def __init__(self):
        pass

    def load_cic_ids_2018_csv(
        self,
        filepath: Union[str, Path],
        max_rows: Optional[int] = None,
        sample_frac: Optional[float] = None,
        random_state: int = 42,
    ) -> pd.DataFrame:
        """
        Loads and standardizes a CSE-CIC-IDS-2018 CSV flow file.
        Removes repeated header rows and coerces numeric features.
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        # Columns to read
        available_cols = list(CIC_IDS_2018_MAPPING.keys())
        
        try:
            file_size_mb = path.stat().st_size / (1024 * 1024)
            if max_rows is not None and file_size_mb <= 500:
                # Read in chunks to avoid only capturing early-morning benign traffic if attacks occur later
                chunk_iter = pd.read_csv(
                    path,
                    usecols=lambda c: c in available_cols,
                    chunksize=max_rows,
                    low_memory=False,
                )
                first_chunk = next(chunk_iter, None)
                if first_chunk is None:
                    df = pd.DataFrame()
                else:
                    first_labels = first_chunk["Label"] if "Label" in first_chunk.columns else pd.Series()
                    first_has_attacks = (first_labels.str.lower() != "benign") & (first_labels != "Label")
                    if first_has_attacks.any():
                        df = first_chunk
                    else:
                        # First chunk was pure benign; search subsequent chunks for attack activity
                        chunks = [first_chunk.iloc[: max_rows // 2]]
                        remaining = max_rows - len(chunks[0])
                        for next_chunk in chunk_iter:
                            n_labels = next_chunk["Label"] if "Label" in next_chunk.columns else pd.Series()
                            is_att = (n_labels.str.lower() != "benign") & (n_labels != "Label")
                            if is_att.any():
                                chunks.append(next_chunk[is_att].iloc[:remaining])
                                remaining -= len(chunks[-1])
                                if remaining <= 0:
                                    break
                        df = pd.concat(chunks, ignore_index=True)
            else:
                effective_rows = max_rows
                if effective_rows is None and file_size_mb > 500:
                    effective_rows = 250000
                df = pd.read_csv(
                    path,
                    usecols=lambda c: c in available_cols,
                    nrows=effective_rows,
                    low_memory=False,
                )
        except Exception as e:
            console.print(f"[red]Error reading CSV {path.name}: {e}[/red]")
            raise

        # Rename columns to standard names
        df = df.rename(columns=CIC_IDS_2018_MAPPING)

        # Filter out corrupt/repeated header rows where label or dst_port matches header string
        if "label" in df.columns:
            df = df[df["label"] != "Label"]
            df = df[df["label"].notna()]
        if "dst_port" in df.columns:
            df = df[df["dst_port"] != "Dst Port"]

        # Parse timestamp
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(
                df["timestamp"],
                format="mixed",
                errors="coerce",
            )
            # Drop rows with invalid timestamps
            df = df[df["timestamp"].notna()]
            df = df.sort_values(by="timestamp").reset_index(drop=True)

        # Numeric conversions
        numeric_cols = [c for c in STANDARD_COLUMNS if c not in ["timestamp", "label"]]
        for col in numeric_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)
            else:
                df[col] = 0.0

        # Replace infinite values with 0
        df = df.replace([np.inf, -np.inf], 0.0)

        # Optional random subsample while maintaining temporal integrity if not stratified
        if sample_frac is not None and 0.0 < sample_frac < 1.0:
            df = df.sample(frac=sample_frac, random_state=random_state)
            df = df.sort_values(by="timestamp").reset_index(drop=True)

        return df

    def parse_pcap(
        self,
        pcap_path: Union[str, Path],
        max_packets: int = 10000,
    ) -> pd.DataFrame:
        """
        Parses raw .pcap captures into standard flow-level state features using Scapy.
        Groups individual packets into (src_ip, dst_ip, src_port, dst_port, proto) sessions.
        """
        path = Path(pcap_path)
        if not path.exists():
            raise FileNotFoundError(f"PCAP file not found: {path}")

        try:
            from scapy.all import rdpcap, IP, TCP, UDP
        except ImportError:
            raise ImportError("scapy is required for PCAP parsing. Run `uv add scapy`.")

        packets = rdpcap(str(path), count=max_packets)
        flows: Dict[tuple, List[Any]] = {}

        for pkt in packets:
            if not pkt.haslayer(IP):
                continue
            ip = pkt[IP]
            proto = ip.proto
            sport = pkt.sport if (pkt.haslayer(TCP) or pkt.haslayer(UDP)) else 0
            dport = pkt.dport if (pkt.haslayer(TCP) or pkt.haslayer(UDP)) else 0
            key = (ip.src, ip.dst, sport, dport, proto)
            
            if key not in flows:
                flows[key] = []
            flows[key].append(pkt)

        records = []
        for (src, dst, sport, dport, proto), pkts in flows.items():
            times = [float(p.time) for p in pkts]
            lengths = [len(p) for p in pkts]
            dur = max(times) - min(times) if len(times) > 1 else 0.001
            dur_us = dur * 1e6
            
            iats = np.diff(sorted(times)) if len(times) > 1 else [0.0]
            
            syns = sum(1 for p in pkts if p.haslayer(TCP) and p[TCP].flags.S)
            acks = sum(1 for p in pkts if p.haslayer(TCP) and p[TCP].flags.A)
            fins = sum(1 for p in pkts if p.haslayer(TCP) and p[TCP].flags.F)
            rsts = sum(1 for p in pkts if p.haslayer(TCP) and p[TCP].flags.R)
            pshs = sum(1 for p in pkts if p.haslayer(TCP) and p[TCP].flags.P)
            urgs = sum(1 for p in pkts if p.haslayer(TCP) and p[TCP].flags.U)

            rec = {
                "timestamp": pd.to_datetime(min(times), unit="s"),
                "dst_port": float(dport),
                "protocol": float(proto),
                "flow_duration": float(dur_us),
                "tot_fwd_pkts": float(len(pkts)),
                "tot_bwd_pkts": 0.0,
                "tot_fwd_bytes": float(sum(lengths)),
                "tot_bwd_bytes": 0.0,
                "flow_bytes_per_sec": float(sum(lengths) / max(dur, 1e-4)),
                "flow_pkts_per_sec": float(len(pkts) / max(dur, 1e-4)),
                "flow_iat_mean": float(np.mean(iats) * 1e6),
                "flow_iat_std": float(np.std(iats) * 1e6),
                "flow_iat_max": float(np.max(iats) * 1e6),
                "fwd_iat_mean": float(np.mean(iats) * 1e6),
                "bwd_iat_mean": 0.0,
                "syn_flag_cnt": float(syns),
                "ack_flag_cnt": float(acks),
                "rst_flag_cnt": float(rsts),
                "fin_flag_cnt": float(fins),
                "psh_flag_cnt": float(pshs),
                "urg_flag_cnt": float(urgs),
                "ece_flag_cnt": 0.0,
                "pkt_len_mean": float(np.mean(lengths)),
                "pkt_len_std": float(np.std(lengths)),
                "down_up_ratio": 0.0,
                "init_fwd_win_bytes": 8192.0,
                "init_bwd_win_bytes": 0.0,
                "active_mean": 0.0,
                "idle_mean": 0.0,
                "label": "Benign",
            }
            records.append(rec)

        df = pd.DataFrame(records)
        return df
