"""
Real-Time Log Stream Aggregator & Rolling Feature Buffer.
Aggregates heterogeneous incoming network events into the 30-dimension behavioral vector.
"""

from datetime import datetime, timezone
from collections import defaultdict
from typing import Dict, Any, Tuple


class RealTimeLogBuffer:
    def __init__(self):
        # (user, YYYY-MM-DD) -> feature dictionary
        self.user_day_state: Dict[Tuple[str, str], Dict[str, float]] = defaultdict(lambda: defaultdict(float))

    def is_after_hours(self, dt: datetime) -> bool:
        """Outside 07:30 - 18:30 or weekend."""
        hour = dt.hour + dt.minute / 60.0
        return (dt.weekday() >= 5) or (hour < 7.5) or (hour > 18.5)

    def ingest_event(self, event: Dict[str, Any]) -> Tuple[str, str, Dict[str, float]]:
        """
        Ingests a single raw event (http, device, file_copy, email) and returns updated feature vector.
        """
        user = event.get("user", "UNKNOWN")
        ts_str = event.get("timestamp")
        
        if ts_str:
            try:
                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except Exception:
                dt = datetime.now(timezone.utc)
        else:
            dt = datetime.now(timezone.utc)

        date_key = dt.strftime("%Y-%m-%d")
        after_h = self.is_after_hours(dt)
        state = self.user_day_state[(user, date_key)]

        # Weekend indicator
        state["is_weekend"] = 1.0 if dt.weekday() >= 5 else 0.0

        evt_type = str(event.get("event_type", "")).lower()

        # 1. Device / USB events
        if evt_type == "device":
            act = str(event.get("activity", "")).lower()
            if "connect" in act and "disconnect" not in act:
                state["device_connect_count"] += 1
                if after_h:
                    state["device_after_hours"] += 1
                    state["usb_surge_zscore"] = max(state["usb_surge_zscore"], 4.5) + 2.0
                else:
                    state["usb_surge_zscore"] = max(state["usb_surge_zscore"], 2.0)
            elif "disconnect" in act:
                state["device_disconnect_count"] += 1

        # 2. File copy events
        elif evt_type == "file_copy":
            state["file_copy_count"] += 1
            filename = str(event.get("filename", "")).lower()
            ext = str(event.get("file_extension", "")).lower()
            
            is_sensitive_doc = ext in [".doc", ".docx", ".pdf", ".txt", ".xls", ".xlsx", ".csv", ".ppt"] or filename.endswith((".doc", ".docx", ".pdf", ".txt"))
            is_exec_archive = ext in [".exe", ".zip", ".rar", ".7z", ".bin", ".py"] or filename.endswith((".exe", ".zip", ".bin"))

            if is_sensitive_doc:
                state["file_doc_pdf_count"] += 1
            elif is_exec_archive:
                state["file_zip_exe_count"] += 1
            
            if after_h:
                state["file_after_hours"] += 1
                state["file_surge_zscore"] = max(state["file_surge_zscore"], 6.0) + 3.0
            else:
                state["file_surge_zscore"] = max(state["file_surge_zscore"], 2.0) + 1.0

        # 3. Email events
        elif evt_type == "email":
            size = float(event.get("size", event.get("bytes", 1000)))
            to_addr = str(event.get("to", "")).lower()
            bcc_addr = str(event.get("bcc", "")).lower()

            state["email_sent_count"] += 1
            state["email_total_bytes"] += size
            state["email_max_bytes"] = max(state["email_max_bytes"], size)
            
            is_external = "@dtaa.com" not in to_addr and "@" in to_addr
            if is_external:
                state["email_external_count"] += 1
            if bcc_addr and bcc_addr not in ["", "nan", "none"]:
                state["email_bcc_count"] += 1
            if after_h:
                state["email_after_hours"] += 1
            
            if size > 10_000_000:
                state["email_bytes_surge_zscore"] = max(state["email_bytes_surge_zscore"], 8.0) + 4.0

        # 4. HTTP / Web events
        elif evt_type == "http":
            state["http_request_count"] += 1
            url = str(event.get("url", event.get("domain", ""))).lower()
            
            if "wikileaks" in url:
                state["http_wikileaks_count"] += 1
                state["sensitive_web_count"] += 1
            if any(k in url for k in ["monster.com", "careerbuilder.com", "indeed.com", "dice.com", "simplyhired.com", "jobhunt", "linkedin", "raytheon", "lockheedmartin", "boeing"]):
                state["http_job_search_count"] += 1
                state["sensitive_web_count"] += 1
            if any(k in url for k in ["dropbox.com", "drive.google.com", "box.com", "mediafire.com", "mega.nz", "rapidshare.com"]):
                state["http_cloud_storage_count"] += 1
                state["sensitive_web_count"] += 1
            if any(k in url for k in ["keylogger", "exploit", "spectorsoft", "dailykeylogger", "rootkit", "payload"]):
                state["http_hacking_count"] += 1
                state["sensitive_web_count"] += 1
            
            if after_h:
                state["http_after_hours"] += 1

        # Compute derived sums & ratios
        state["total_activity_count"] = (
            state["device_connect_count"] + state["device_disconnect_count"] +
            state["file_copy_count"] + state["email_sent_count"] + state["http_request_count"]
        )
        state["total_after_hours_count"] = (
            state["device_after_hours"] + state["file_after_hours"] +
            state["email_after_hours"] + state["http_after_hours"]
        )
        tot = state["total_activity_count"]
        state["after_hours_ratio"] = (state["total_after_hours_count"] / tot) if tot > 0 else 0.0

        http_cnt = state["http_request_count"]
        state["sensitive_web_ratio"] = (state["sensitive_web_count"] / http_cnt) if http_cnt > 0 else 0.0

        email_cnt = state["email_sent_count"]
        state["email_avg_bytes"] = (state["email_total_bytes"] / email_cnt) if email_cnt > 0 else 0.0
        state["external_email_ratio"] = (state["email_external_count"] / email_cnt) if email_cnt > 0 else 0.0

        return user, date_key, dict(state)
