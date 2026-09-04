"""
Day-Based Network Telemetry Replayer & Kafka Producer.
Streams labeled or unlabelled CSE-CIC-IDS2018 flow records into Apache Kafka.
Allows selecting specific days (Monday nominal baseline, Thursday infiltration,
Wednesday brute-force, Friday botnet) for automated streaming ingestion.
"""

import os
import sys
import time
import json
from pathlib import Path
from typing import Optional, Dict, Any, Generator
import pandas as pd
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from kafka import KafkaProducer

console = Console()

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
DATASET_DIR = ROOT_DIR / "ml" / "data" / "external-network" / "cic-ids-2018"

# Map friendly day names and attack types to dataset files
DAY_FILE_MAPPING = {
    # 1. Benign Baseline Traffic (Stage 0)
    "monday": "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv",
    "benign": "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv",
    "baseline": "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv",
    "normal": "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv",
    
    # 2. Command & Control / Botnet (Stage 4)
    "friday": "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",
    "friday-02": "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",
    "botnet": "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",
    "c2": "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",
    "bot": "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",
    
    # 3. Initial Access / Brute Force / Web Exploits (Stage 2)
    "wednesday": "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
    "wednesday-14": "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
    "bruteforce": "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
    "ssh": "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
    "ftp": "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
    "web": "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv",
    "xss": "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv",
    "sqli": "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv",
    "injection": "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv",
    "friday-23": "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv",
    "thursday-22": "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv",
    
    # 4. Infiltration / Lateral Movement (Stage 3)
    "thursday": "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv",
    "thursday-01": "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv",
    "infiltration": "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv",
    "lateral": "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv",
    
    # 5. Exfiltration / Impact / DoS & DDoS (Stage 5)
    "dos": "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv",
    "slowhttp": "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv",
    "hulk": "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv",
    "friday-16": "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv",
    "goldeneye": "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",
    "slowloris": "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",
    "thursday-15": "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",
    "ddos": "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv",
    "hoic": "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv",
    "wednesday-21": "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv",
    "loic": "Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv",
    "tuesday": "Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv",
    "tuesday-20": "Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv",
}


# Column rename mapping from CIC-IDS-2018 headers to standard flow schema
HEADER_RENAME = {
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


class DayTelemetryReplayer:
    """Streams CIC-IDS-2018 traffic logs to Kafka with configurable day selection & flow rate."""

    def __init__(
        self,
        kafka_bootstrap_servers: str = "localhost:9092",
        topic: str = "network_flows",
    ):
        self.bootstrap_servers = kafka_bootstrap_servers
        self.topic = topic
        self._producer: Optional[KafkaProducer] = None

    def get_producer(self) -> KafkaProducer:
        if self._producer is None:
            self._producer = KafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                acks=1,
                linger_ms=10,
            )
        return self._producer

    def resolve_dataset_file(self, day: str) -> Path:
        day_key = day.strip().lower()
        if day_key not in DAY_FILE_MAPPING:
            valid_days = ", ".join(sorted(DAY_FILE_MAPPING.keys()))
            raise ValueError(f"Unknown day '{day}'. Valid options: {valid_days}")

        filename = DAY_FILE_MAPPING[day_key]
        filepath = DATASET_DIR / filename
        if not filepath.exists():
            raise FileNotFoundError(f"Dataset file not found at: {filepath}")
        return filepath

    def stream_day(
        self,
        day: str,
        max_flows: Optional[int] = None,
        rate: float = 100.0,
        chunk_size: int = 5000,
        scenario: str = "auto",
    ) -> int:
        """
        Replays telemetry for the given day into Kafka.
        - day: day name (monday, tuesday, wednesday, thursday, friday)
        - max_flows: maximum number of records to emit (None for entire file)
        - rate: flow records emitted per second (0.0 for unthrottled maximum speed)
        - scenario: 'auto', 'attack', or 'benign'
        """
        filepath = self.resolve_dataset_file(day)
        day_key = day.strip().lower()
        producer = self.get_producer()

        console.print(f"[bold cyan]📂 Selected Day:[/bold cyan] [bold green]{day.upper()}[/bold green] ({filepath.name})")
        console.print(f"[bold cyan]🎯 Target Kafka Topic:[/bold cyan] [yellow]{self.topic}[/yellow] at [yellow]{self.bootstrap_servers}[/yellow]")
        console.print(f"[bold cyan]⚡ Streaming Rate:[/bold cyan] {rate if rate > 0 else 'Unthrottled (Max)'} flows/sec")
        if scenario != "auto":
            console.print(f"[bold cyan]🎯 Scenario Filter:[/bold cyan] [bold magenta]{scenario.upper()}[/bold magenta]")

        sent_count = 0
        sleep_interval = (1.0 / rate) if rate > 0 else 0.0

        # Read CSV in chunks
        chunk_iter = pd.read_csv(
            filepath,
            usecols=lambda c: c in HEADER_RENAME,
            chunksize=chunk_size,
            low_memory=False,
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(f"Streaming {day.upper()} telemetry...", total=max_flows)

            for chunk in chunk_iter:
                # Clean headers and filter corrupt header rows
                chunk = chunk.rename(columns=HEADER_RENAME)
                if "label" in chunk.columns:
                    chunk = chunk[chunk["label"] != "Label"]
                    chunk = chunk[chunk["label"].notna()]
                if "dst_port" in chunk.columns:
                    chunk = chunk[chunk["dst_port"] != "Dst Port"]

                # If monday, default to pure benign baseline
                if day_key == "monday" and "label" in chunk.columns:
                    chunk = chunk[chunk["label"].str.lower() == "benign"]

                # Apply scenario filter if specified
                if scenario == "attack" and "label" in chunk.columns:
                    chunk = chunk[chunk["label"].str.lower() != "benign"]
                elif scenario == "benign" and "label" in chunk.columns:
                    chunk = chunk[chunk["label"].str.lower() == "benign"]

                if chunk.empty:
                    continue

                for _, row in chunk.iterrows():
                    record = row.to_dict()
                    # Coerce string numbers to float/int
                    for k, v in record.items():
                        if pd.isna(v):
                            record[k] = 0.0
                        elif k not in ["timestamp", "label"]:
                            try:
                                record[k] = float(v)
                            except (ValueError, TypeError):
                                pass

                    producer.send(self.topic, value=record)
                    sent_count += 1
                    progress.update(task, advance=1)

                    if sleep_interval > 0:
                        time.sleep(sleep_interval)

                    if max_flows is not None and sent_count >= max_flows:
                        break

                if max_flows is not None and sent_count >= max_flows:
                    break

        producer.flush()
        console.print(f"[bold green]✓ Successfully published {sent_count:,} flow events to Kafka topic '{self.topic}'.[/bold green]")
        return sent_count
