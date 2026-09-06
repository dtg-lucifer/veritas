"""
Vectorized Behavioral Feature Extraction Engine for Insider Threat Detection.
High-speed chunked aggregation of multi-stream logs (USB, files, email, HTTP)
with rolling behavioral baselines and exact ground-truth scenario alignment.
"""

import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
import numpy as np
import pandas as pd
from rich.console import Console

from src.preprocessing.dataset_parser import CERTDataParser

console = Console()


class BehavioralFeatureExtractor:
    def __init__(self, data_dir: str):
        self.parser = CERTDataParser(data_dir)
        self.data_dir = Path(data_dir)
        self.cache_dir = self.data_dir / "cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def is_after_hours(dt_series: pd.Series) -> pd.Series:
        """Determines if a timestamp is outside normal working hours (07:30 - 18:30) or on weekend."""
        hour = dt_series.dt.hour + dt_series.dt.minute / 60.0
        dayofweek = dt_series.dt.dayofweek
        return (dayofweek >= 5) | (hour < 7.5) | (hour > 18.5)

    def extract_features(
        self,
        max_http_chunks: Optional[int] = 60,
        use_cache: bool = True
    ) -> pd.DataFrame:
        """
        Fast vectorized extraction of user-day behavioral vectors.
        """
        cache_path = self.cache_dir / "behavioral_features_v2.parquet"
        if use_cache and cache_path.exists():
            console.print(f"[green]Loading cached behavioral features from {cache_path}[/green]")
            return pd.read_parquet(cache_path)

        console.print("[cyan]Running high-speed vectorized feature extraction...[/cyan]")

        # 1. Load LDAP metadata & Exact Answers
        ldap_df = self.parser.load_ldap_metadata()
        user_roles = dict(zip(ldap_df["user"], ldap_df["role"].fillna("General"))) if not ldap_df.empty else {}
        user_depts = dict(zip(ldap_df["user"], ldap_df["department"].fillna("General"))) if not ldap_df.empty else {}
        exact_threat_labels = self.parser.load_exact_ground_truth()

        # --- A. Process Device Logs (Vectorized) ---
        console.print("[bold blue]1/4. Processing Device (USB) logs...[/bold blue]")
        device_agg_list = []
        for chunk in self.parser.stream_device_events(chunksize=200_000):
            chunk["date_str"] = chunk["date"].dt.strftime("%Y-%m-%d")
            after_h = self.is_after_hours(chunk["date"])
            act_lower = chunk["activity"].astype(str).str.lower()
            
            chunk["device_connect_count"] = (act_lower.str.contains("connect") & ~act_lower.str.contains("disconnect")).astype(int)
            chunk["device_disconnect_count"] = act_lower.str.contains("disconnect").astype(int)
            chunk["device_after_hours"] = (after_h & (chunk["device_connect_count"] > 0)).astype(int)
            
            agg = chunk.groupby(["user", "date_str"])[
                ["device_connect_count", "device_disconnect_count", "device_after_hours"]
            ].sum().reset_index()
            device_agg_list.append(agg)
        
        df_device = pd.concat(device_agg_list, ignore_index=True).groupby(["user", "date_str"]).sum().reset_index() if device_agg_list else pd.DataFrame(columns=["user", "date_str"])

        # --- B. Process File Logs (Vectorized) ---
        console.print("[bold blue]2/4. Processing File copy logs...[/bold blue]")
        file_agg_list = []
        for chunk in self.parser.stream_file_events(chunksize=200_000):
            chunk["date_str"] = chunk["date"].dt.strftime("%Y-%m-%d")
            after_h = self.is_after_hours(chunk["date"])
            fn_lower = chunk["filename"].astype(str).str.lower()
            
            chunk["file_copy_count"] = 1
            chunk["file_doc_pdf_count"] = fn_lower.str.endswith((".doc", ".docx", ".pdf", ".txt", ".xls", ".xlsx", ".csv", ".ppt")).astype(int)
            chunk["file_zip_exe_count"] = fn_lower.str.endswith((".zip", ".rar", ".7z", ".tar", ".gz", ".exe", ".bin", ".py")).astype(int)
            chunk["file_after_hours"] = after_h.astype(int)
            
            agg = chunk.groupby(["user", "date_str"])[
                ["file_copy_count", "file_doc_pdf_count", "file_zip_exe_count", "file_after_hours"]
            ].sum().reset_index()
            file_agg_list.append(agg)
        
        df_file = pd.concat(file_agg_list, ignore_index=True).groupby(["user", "date_str"]).sum().reset_index() if file_agg_list else pd.DataFrame(columns=["user", "date_str"])

        # --- C. Process Email Logs (Vectorized) ---
        console.print("[bold blue]3/4. Processing Email logs...[/bold blue]")
        email_agg_list = []
        for chunk in self.parser.stream_email_events(chunksize=200_000):
            chunk["date_str"] = chunk["date"].dt.strftime("%Y-%m-%d")
            after_h = self.is_after_hours(chunk["date"])
            to_str = chunk["to"].astype(str).fillna("")
            bcc_str = chunk["bcc"].astype(str).fillna("")
            size_num = pd.to_numeric(chunk["size"], errors="coerce").fillna(0)
            
            chunk["email_sent_count"] = 1
            chunk["email_total_bytes"] = size_num
            chunk["email_external_count"] = (~to_str.str.contains("@dtaa.com", regex=False) & to_str.str.contains("@", regex=False)).astype(int)
            chunk["email_bcc_count"] = ((bcc_str.str.strip() != "") & (bcc_str != "nan")).astype(int)
            chunk["email_after_hours"] = after_h.astype(int)
            
            agg = chunk.groupby(["user", "date_str"]).agg(
                email_sent_count=("email_sent_count", "sum"),
                email_total_bytes=("email_total_bytes", "sum"),
                email_external_count=("email_external_count", "sum"),
                email_bcc_count=("email_bcc_count", "sum"),
                email_after_hours=("email_after_hours", "sum"),
                email_max_bytes=("email_total_bytes", "max")
            ).reset_index()
            email_agg_list.append(agg)
            
        df_email = pd.concat(email_agg_list, ignore_index=True).groupby(["user", "date_str"]).agg(
            email_sent_count=("email_sent_count", "sum"),
            email_total_bytes=("email_total_bytes", "sum"),
            email_external_count=("email_external_count", "sum"),
            email_bcc_count=("email_bcc_count", "sum"),
            email_after_hours=("email_after_hours", "sum"),
            email_max_bytes=("email_max_bytes", "max")
        ).reset_index() if email_agg_list else pd.DataFrame(columns=["user", "date_str"])

        # --- D. Process HTTP Logs (Vectorized) ---
        console.print("[bold blue]4/4. Processing HTTP (Web) logs...[/bold blue]")
        http_agg_list = []
        for chunk in self.parser.stream_http_events(chunksize=400_000, max_chunks=max_http_chunks):
            chunk["date_str"] = chunk["date"].dt.strftime("%Y-%m-%d")
            after_h = self.is_after_hours(chunk["date"])
            url_str = chunk["url"].astype(str).str.lower()
            
            chunk["http_request_count"] = 1
            chunk["http_wikileaks_count"] = url_str.str.contains("wikileaks", regex=False).astype(int)
            chunk["http_job_search_count"] = url_str.str.contains("monster.com|careerbuilder.com|indeed.com|dice.com|simplyhired.com|jobhunt|linkedin|raytheon.com|lockheedmartin.com|boeing.com|northropgrumman.com", regex=True).astype(int)
            chunk["http_cloud_storage_count"] = url_str.str.contains("dropbox.com|drive.google.com|box.com|mediafire.com|mega.nz|rapidshare.com|sendspace.com", regex=True).astype(int)
            chunk["http_hacking_count"] = url_str.str.contains("keylogger|exploit|spectorsoft|dailykeylogger|rootkit|payload|wellresearchedreviews", regex=True).astype(int)
            chunk["http_after_hours"] = after_h.astype(int)
            
            agg = chunk.groupby(["user", "date_str"])[
                ["http_request_count", "http_wikileaks_count", "http_job_search_count", "http_cloud_storage_count", "http_hacking_count", "http_after_hours"]
            ].sum().reset_index()
            http_agg_list.append(agg)
            
        df_http = pd.concat(http_agg_list, ignore_index=True).groupby(["user", "date_str"]).sum().reset_index() if http_agg_list else pd.DataFrame(columns=["user", "date_str"])

        # --- E. Merge Streams ---
        console.print("[cyan]Merging all activity streams into unified matrix...[/cyan]")
        df = df_device.merge(df_file, on=["user", "date_str"], how="outer")
        df = df.merge(df_email, on=["user", "date_str"], how="outer")
        df = df.merge(df_http, on=["user", "date_str"], how="outer")
        df = df.fillna(0)
        df = df.rename(columns={"date_str": "date"})

        df["date_dt"] = pd.to_datetime(df["date"])
        df["dayofweek"] = df["date_dt"].dt.dayofweek
        df["is_weekend"] = (df["dayofweek"] >= 5).astype(int)

        # Derived Ratios
        df["email_avg_bytes"] = np.where(df["email_sent_count"] > 0, df["email_total_bytes"] / df["email_sent_count"], 0.0)
        df["total_activity_count"] = (
            df["device_connect_count"] + df["device_disconnect_count"] +
            df["file_copy_count"] + df["email_sent_count"] + df["http_request_count"]
        )
        df["total_after_hours_count"] = (
            df["device_after_hours"] + df["file_after_hours"] +
            df["email_after_hours"] + df["http_after_hours"]
        )
        df["after_hours_ratio"] = np.where(df["total_activity_count"] > 0, df["total_after_hours_count"] / df["total_activity_count"], 0.0)
        df["sensitive_web_count"] = df["http_wikileaks_count"] + df["http_job_search_count"] + df["http_cloud_storage_count"] + df["http_hacking_count"]
        df["sensitive_web_ratio"] = np.where(df["http_request_count"] > 0, df["sensitive_web_count"] / df["http_request_count"], 0.0)
        df["external_email_ratio"] = np.where(df["email_sent_count"] > 0, df["email_external_count"] / df["email_sent_count"], 0.0)

        # --- F. Compute Rolling Behavioral Deviation Z-Scores per User ---
        console.print("[cyan]Computing rolling user behavioral baselines and surge indicators...[/cyan]")
        df = df.sort_values(["user", "date_dt"]).reset_index(drop=True)
        
        # Fast rolling averages (7-day window)
        u_group = df.groupby("user")
        rolling_usb_mean = u_group["device_connect_count"].transform(lambda s: s.shift(1).rolling(14, min_periods=2).mean()).fillna(0)
        rolling_usb_std = u_group["device_connect_count"].transform(lambda s: s.shift(1).rolling(14, min_periods=2).std()).fillna(1.0)
        df["usb_surge_zscore"] = np.clip((df["device_connect_count"] - rolling_usb_mean) / (rolling_usb_std + 1e-3), -3.0, 20.0)

        rolling_file_mean = u_group["file_copy_count"].transform(lambda s: s.shift(1).rolling(14, min_periods=2).mean()).fillna(0)
        rolling_file_std = u_group["file_copy_count"].transform(lambda s: s.shift(1).rolling(14, min_periods=2).std()).fillna(1.0)
        df["file_surge_zscore"] = np.clip((df["file_copy_count"] - rolling_file_mean) / (rolling_file_std + 1e-3), -3.0, 20.0)

        rolling_bytes_mean = u_group["email_total_bytes"].transform(lambda s: s.shift(1).rolling(14, min_periods=2).mean()).fillna(0)
        rolling_bytes_std = u_group["email_total_bytes"].transform(lambda s: s.shift(1).rolling(14, min_periods=2).std()).fillna(1e4)
        df["email_bytes_surge_zscore"] = np.clip((df["email_total_bytes"] - rolling_bytes_mean) / (rolling_bytes_std + 1e-3), -3.0, 20.0)

        # Enrich Role & Dept
        df["role"] = df["user"].map(user_roles).fillna("General")
        df["department"] = df["user"].map(user_depts).fillna("General")

        # --- G. Precise Ground Truth Labeling ---
        console.print("[cyan]Aligning with exact malicious ground truth records...[/cyan]")
        df["is_anomaly"] = 0
        df["scenario"] = 0

        # Vectorized lookup of exact user-dates from answers/
        user_date_pairs = list(zip(df["user"], df["date"]))
        is_anom_list = []
        scen_list = []
        for u, d in user_date_pairs:
            if (u, d) in exact_threat_labels:
                is_anom_list.append(1)
                scen_list.append(exact_threat_labels[(u, d)])
            else:
                is_anom_list.append(0)
                scen_list.append(0)

        df["is_anomaly"] = is_anom_list
        df["scenario"] = scen_list

        # Save to parquet cache
        df.to_parquet(cache_path, index=False)
        total_anom = df["is_anomaly"].sum()
        console.print(f"[bold green]Vectorized extraction complete: {len(df)} records ({total_anom} exact attack events). Saved to {cache_path}[/bold green]")
        return df


def get_feature_columns() -> List[str]:
    """Returns the ordered list of numeric feature columns for ML modeling."""
    return [
        "device_connect_count",
        "device_disconnect_count",
        "device_after_hours",
        "file_copy_count",
        "file_doc_pdf_count",
        "file_zip_exe_count",
        "file_after_hours",
        "email_sent_count",
        "email_total_bytes",
        "email_avg_bytes",
        "email_max_bytes",
        "email_external_count",
        "email_bcc_count",
        "email_after_hours",
        "http_request_count",
        "http_wikileaks_count",
        "http_job_search_count",
        "http_cloud_storage_count",
        "http_hacking_count",
        "http_after_hours",
        "is_weekend",
        "total_activity_count",
        "total_after_hours_count",
        "after_hours_ratio",
        "sensitive_web_count",
        "sensitive_web_ratio",
        "external_email_ratio",
        "usb_surge_zscore",
        "file_surge_zscore",
        "email_bytes_surge_zscore",
    ]
