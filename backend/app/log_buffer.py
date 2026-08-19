"""
5-Minute Stateful Behavioral Window Aggregator & Rolling Log Buffer.
Decoupled stream ingestion buffers raw heterogeneous events into 5-minute
tumbling / sliding time windows per identity (user / src_ip) and compiles
normalized 30-dimension behavioral feature vectors for ensemble ML inference.
"""

from typing import Dict, Any, Tuple, List, Optional
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
import math


class TimeWindowLogAggregator:
    """
    Stateful 5-Minute Window Behavioral Feature Aggregator.
    Maintains rolling queues of raw events within [t - 300s, t] per entity
    and calculates statistical baseline deviations and volumetric counters.
    """
    def __init__(self, window_seconds: int = 300):
        self.window_seconds = window_seconds
        # user -> deque of (timestamp_datetime, raw_event_dict)
        self.user_event_windows: Dict[str, deque] = defaultdict(deque)
        # (user, YYYY-MM-DD) -> cumulative daily state dictionary
        self.user_day_state: Dict[Tuple[str, str], Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        # Running baseline historical stats per user: user -> {metric: (mean, std)}
        self.historical_user_stats: Dict[str, Dict[str, Tuple[float, float]]] = defaultdict(dict)

    @staticmethod
    def parse_timestamp(ts: Any) -> datetime:
        """Parses ISO timestamp string or returns current UTC datetime."""
        if isinstance(ts, datetime):
            return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        if isinstance(ts, str) and ts.strip():
            try:
                clean_ts = ts.replace("Z", "+00:00")
                dt = datetime.fromisoformat(clean_ts)
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except Exception:
                pass
        return datetime.now(timezone.utc)

    @staticmethod
    def is_after_hours(dt: datetime) -> bool:
        """Outside 07:30 - 18:30 or weekend."""
        hour = dt.hour + dt.minute / 60.0
        return (dt.weekday() >= 5) or (hour < 7.5) or (hour > 18.5)

    def ingest_event(self, event: Dict[str, Any]) -> Tuple[str, str, Dict[str, float]]:
        """
        Ingests a single raw event into the 5-minute sliding window and cumulative daily buffer.
        Returns (user, date_key, 30_dim_feature_vector).
        """
        user = str(event.get("user", "UNKNOWN")).strip()
        dt = self.parse_timestamp(event.get("timestamp"))
        date_key = dt.strftime("%Y-%m-%d")

        # 1. Append to user's 5-minute rolling window
        user_window = self.user_event_windows[user]
        user_window.append((dt, event))

        # Evict events older than window_seconds relative to this event timestamp
        cutoff = dt - timedelta(seconds=self.window_seconds)
        while user_window and user_window[0][0] < cutoff:
            user_window.popleft()

        # 2. Update cumulative daily counters
        after_h = self.is_after_hours(dt)
        day_state = self.user_day_state[(user, date_key)]
        day_state["is_weekend"] = 1.0 if dt.weekday() >= 5 else 0.0

        evt_type = str(event.get("event_type", "")).lower()

        # Device / USB
        if evt_type == "device":
            act = str(event.get("activity", "")).lower()
            if "connect" in act and "disconnect" not in act:
                day_state["device_connect_count"] += 1
                if after_h:
                    day_state["device_after_hours"] += 1
            elif "disconnect" in act:
                day_state["device_disconnect_count"] += 1

        # File copy
        elif evt_type == "file_copy":
            day_state["file_copy_count"] += 1
            filename = str(event.get("filename", "")).lower()
            ext = str(event.get("file_extension", "")).lower()
            
            is_sensitive_doc = (
                ext in [".doc", ".docx", ".pdf", ".txt", ".xls", ".xlsx", ".csv", ".ppt"]
                or filename.endswith((".doc", ".docx", ".pdf", ".txt", ".xls", ".xlsx", ".csv", ".ppt"))
            )
            is_exec_archive = (
                ext in [".exe", ".zip", ".rar", ".7z", ".bin", ".py", ".tar", ".gz"]
                or filename.endswith((".exe", ".zip", ".bin", ".tar", ".gz"))
            )

            if is_sensitive_doc:
                day_state["file_doc_pdf_count"] += 1
            elif is_exec_archive:
                day_state["file_zip_exe_count"] += 1

            if after_h:
                day_state["file_after_hours"] += 1

        # Email
        elif evt_type == "email":
            size = float(event.get("size", event.get("bytes", 15000)))
            to_addr = str(event.get("to", "")).lower()
            bcc_addr = str(event.get("bcc", "")).lower()

            day_state["email_sent_count"] += 1
            day_state["email_total_bytes"] += size
            day_state["email_max_bytes"] = max(day_state["email_max_bytes"], size)

            is_external = ("@dtaa.com" not in to_addr) and ("@" in to_addr)
            if is_external:
                day_state["email_external_count"] += 1
            if bcc_addr and bcc_addr not in ["", "nan", "none"]:
                day_state["email_bcc_count"] += 1
            if after_h:
                day_state["email_after_hours"] += 1

        # HTTP / Web
        elif evt_type == "http":
            day_state["http_request_count"] += 1
            url = str(event.get("url", event.get("domain", ""))).lower()

            if "wikileaks" in url:
                day_state["http_wikileaks_count"] += 1
            elif any(k in url for k in ["monster.com", "careerbuilder.com", "indeed.com", "dice.com", "simplyhired.com", "jobhunt", "linkedin", "raytheon", "lockheedmartin", "boeing"]):
                day_state["http_job_search_count"] += 1
            elif any(k in url for k in ["dropbox.com", "drive.google.com", "box.com", "mediafire.com", "mega.nz", "rapidshare.com"]):
                day_state["http_cloud_storage_count"] += 1
            elif any(k in url for k in ["keylogger", "exploit-db", "spectorsoft", "dailykeylogger", "rootkit", "payload.bin"]):
                day_state["http_hacking_count"] += 1

            if after_h:
                day_state["http_after_hours"] += 1

        # 3. Compute derived features over the 5-minute active window & cumulative state
        features = self.compute_window_features(user, date_key, dt)
        return user, date_key, features

    def compute_window_features(self, user: str, date_key: str, ref_dt: Optional[datetime] = None) -> Dict[str, float]:
        """
        Synthesizes the 30-dimension behavioral feature vector representing
        activity in the current 5-minute window with rolling surge Z-scores.
        """
        ref_dt = ref_dt or datetime.now(timezone.utc)
        user_window = self.user_event_windows[user]
        day_state = self.user_day_state[(user, date_key)]

        # Extract 5-minute window counts
        w_events = [evt for ts, evt in user_window if ts >= (ref_dt - timedelta(seconds=self.window_seconds))]
        
        # Build 30-feature vector
        features: Dict[str, float] = {}

        # 1. Device metrics
        features["device_connect_count"] = day_state["device_connect_count"]
        features["device_disconnect_count"] = day_state["device_disconnect_count"]
        features["device_after_hours"] = day_state["device_after_hours"]

        # 2. File copy metrics
        features["file_copy_count"] = day_state["file_copy_count"]
        features["file_doc_pdf_count"] = day_state["file_doc_pdf_count"]
        features["file_zip_exe_count"] = day_state["file_zip_exe_count"]
        features["file_after_hours"] = day_state["file_after_hours"]

        # 3. Email metrics
        email_sent = day_state["email_sent_count"]
        email_bytes = day_state["email_total_bytes"]
        features["email_sent_count"] = email_sent
        features["email_total_bytes"] = email_bytes
        features["email_avg_bytes"] = (email_bytes / email_sent) if email_sent > 0 else 0.0
        features["email_max_bytes"] = day_state["email_max_bytes"]
        features["email_external_count"] = day_state["email_external_count"]
        features["email_bcc_count"] = day_state["email_bcc_count"]
        features["email_after_hours"] = day_state["email_after_hours"]
        features["external_email_ratio"] = (day_state["email_external_count"] / email_sent) if email_sent > 0 else 0.0

        # 4. HTTP / Web metrics
        http_cnt = day_state["http_request_count"]
        features["http_request_count"] = http_cnt
        features["http_wikileaks_count"] = day_state["http_wikileaks_count"]
        features["http_job_search_count"] = day_state["http_job_search_count"]
        features["http_cloud_storage_count"] = day_state["http_cloud_storage_count"]
        features["http_hacking_count"] = day_state["http_hacking_count"]
        features["http_after_hours"] = day_state["http_after_hours"]

        # 5. Temporal and Aggregates
        features["is_weekend"] = day_state["is_weekend"]
        tot_activity = (
            features["device_connect_count"] + features["device_disconnect_count"] +
            features["file_copy_count"] + features["email_sent_count"] + features["http_request_count"]
        )
        features["total_activity_count"] = tot_activity
        tot_after = (
            features["device_after_hours"] + features["file_after_hours"] +
            features["email_after_hours"] + features["http_after_hours"]
        )
        features["total_after_hours_count"] = tot_after
        features["after_hours_ratio"] = (tot_after / tot_activity) if tot_activity > 0 else 0.0

        # Sensitive web
        sens_web = (
            features["http_wikileaks_count"] + features["http_job_search_count"] +
            features["http_cloud_storage_count"] + features["http_hacking_count"]
        )
        features["sensitive_web_count"] = sens_web
        features["sensitive_web_ratio"] = min(1.0, (sens_web / http_cnt) if http_cnt > 0 else 0.0)

        # 6. Window-calibrated Surge Z-Scores
        # Detect surges during the 5-minute active window
        w_device_connect = sum(1 for e in w_events if e.get("event_type") == "device" and "connect" in str(e.get("activity", "")).lower() and "disconnect" not in str(e.get("activity", "")).lower())
        w_file_copies = sum(1 for e in w_events if e.get("event_type") == "file_copy")
        w_email_bytes = sum(float(e.get("size", e.get("bytes", 0))) for e in w_events if e.get("event_type") == "email")

        # USB Surge Z-Score
        if features["device_connect_count"] > 0:
            if features["device_after_hours"] > 0:
                features["usb_surge_zscore"] = max(4.5, 3.0 + 1.5 * w_device_connect)
            else:
                features["usb_surge_zscore"] = max(2.0, 1.0 + 1.0 * w_device_connect)
        else:
            features["usb_surge_zscore"] = 0.0

        # File Surge Z-Score
        if features["file_copy_count"] > 0:
            if features["file_after_hours"] > 0:
                features["file_surge_zscore"] = max(6.0, 3.0 + 2.0 * w_file_copies)
            else:
                features["file_surge_zscore"] = max(2.0, 1.0 + 1.0 * w_file_copies)
        else:
            features["file_surge_zscore"] = 0.0

        # Email Bytes Surge Z-Score
        if email_bytes > 5_000_000:
            features["email_bytes_surge_zscore"] = max(8.0, 4.0 + (email_bytes / 10_000_000.0))
        elif email_sent > 0:
            features["email_bytes_surge_zscore"] = max(0.0, (email_bytes / 500_000.0))
        else:
            features["email_bytes_surge_zscore"] = 0.0

        return features

    def get_window_summary(self, user: str) -> Dict[str, Any]:
        """Returns statistics for active 5-minute window of a user."""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=self.window_seconds)
        events = [evt for ts, evt in self.user_event_windows[user] if ts >= cutoff]
        return {
            "user": user,
            "window_duration_seconds": self.window_seconds,
            "active_events_count": len(events),
            "event_types": list(set(e.get("event_type", "unknown") for e in events)),
            "window_start": cutoff.isoformat(),
            "window_end": now.isoformat()
        }


# Alias for backward compatibility
RealTimeLogBuffer = TimeWindowLogAggregator
