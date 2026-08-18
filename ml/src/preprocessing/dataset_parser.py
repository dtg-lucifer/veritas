"""
CERT r4.2 Dataset Parser & Streaming Loader.
Handles memory-efficient streaming of CERT activity logs (device, file, email, http, LDAP)
and precise scenario ground-truth answer alignment.
"""

import os
import glob
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Generator, Set
import pandas as pd
from rich.console import Console

console = Console()


class CERTDataParser:
    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir)
        self.r42_dir = self.data_dir / "r4.2"
        self.answers_dir = self.data_dir / "answers"
        
        if not self.r42_dir.exists():
            raise FileNotFoundError(f"CERT r4.2 directory not found at {self.r42_dir}")

    def load_ldap_metadata(self) -> pd.DataFrame:
        """
        Loads LDAP user information and roles from the most recent LDAP snapshot.
        """
        ldap_files = sorted(glob.glob(str(self.r42_dir / "LDAP" / "*.csv")))
        if not ldap_files:
            return pd.DataFrame(columns=["user", "employee_name", "email", "role", "department", "functional_unit"])
        
        latest_ldap = ldap_files[-1]
        df = pd.read_csv(latest_ldap)
        df = df.rename(columns={"user_id": "user"})
        return df[["user", "employee_name", "email", "role", "department", "functional_unit"]]

    def load_exact_ground_truth(self) -> Dict[Tuple[str, str], int]:
        """
        Parses all 70 ground-truth attack scenario CSVs in answers/r4.2-1, r4.2-2, r4.2-3.
        Returns a mapping of (user, 'YYYY-MM-DD') -> scenario_id (1, 2, or 3).
        """
        exact_labels: Dict[Tuple[str, str], int] = {}
        
        for scen_folder, scen_id in [("r4.2-1", 1), ("r4.2-2", 2), ("r4.2-3", 3)]:
            scen_path = self.answers_dir / scen_folder
            if not scen_path.exists():
                continue
            
            for csv_file in glob.glob(str(scen_path / "*.csv")):
                with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        parts = line.strip().split(",")
                        if len(parts) >= 4:
                            date_raw = parts[2]
                            user = parts[3].strip()
                            try:
                                dt = pd.to_datetime(date_raw, format="mixed")
                                date_str = dt.strftime("%Y-%m-%d")
                                exact_labels[(user, date_str)] = scen_id
                            except Exception:
                                pass
                                
        console.print(f"[green]✓ Loaded {len(exact_labels)} exact malicious user-day attack events from answer CSVs.[/green]")
        return exact_labels

    def stream_device_events(self, chunksize: int = 200_000) -> Generator[pd.DataFrame, None, None]:
        """Streams device.csv in chunks."""
        device_path = self.r42_dir / "device.csv"
        if not device_path.exists() or device_path.stat().st_size == 0:
            return
        
        for chunk in pd.read_csv(device_path, chunksize=chunksize):
            chunk["date"] = pd.to_datetime(chunk["date"], format="mixed")
            yield chunk

    def stream_file_events(self, chunksize: int = 200_000) -> Generator[pd.DataFrame, None, None]:
        """Streams file.csv in chunks."""
        file_path = self.r42_dir / "file.csv"
        if not file_path.exists() or file_path.stat().st_size == 0:
            return
        
        cols = ["id", "date", "user", "pc", "filename"]
        for chunk in pd.read_csv(file_path, chunksize=chunksize, usecols=cols):
            chunk["date"] = pd.to_datetime(chunk["date"], format="mixed")
            yield chunk

    def stream_email_events(self, chunksize: int = 200_000) -> Generator[pd.DataFrame, None, None]:
        """Streams email.csv in chunks."""
        email_path = self.r42_dir / "email.csv"
        if not email_path.exists() or email_path.stat().st_size == 0:
            return
        
        cols = ["id", "date", "user", "pc", "to", "cc", "bcc", "from", "size", "attachments"]
        for chunk in pd.read_csv(email_path, chunksize=chunksize, usecols=cols):
            chunk["date"] = pd.to_datetime(chunk["date"], format="mixed")
            yield chunk

    def stream_http_events(self, chunksize: int = 400_000, max_chunks: Optional[int] = 60) -> Generator[pd.DataFrame, None, None]:
        """Streams http.csv in chunks."""
        http_path = self.r42_dir / "http.csv"
        if not http_path.exists() or http_path.stat().st_size == 0:
            return
        
        cols = ["id", "date", "user", "pc", "url"]
        chunk_count = 0
        for chunk in pd.read_csv(http_path, chunksize=chunksize, usecols=cols):
            chunk["date"] = pd.to_datetime(chunk["date"], format="mixed")
            yield chunk
            chunk_count += 1
            if max_chunks and chunk_count >= max_chunks:
                break
