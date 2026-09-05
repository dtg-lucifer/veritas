"""
5-Minute Stateful Behavioral Window Aggregator.

Buffers raw network events into per-user sliding windows and computes
30-dimension behavioral feature vectors ON DEMAND (every 5-minute cycle).

Key design principle:
  - ingest() is SILENT — no prediction, no logging, just accumulation.
  - aggregate_window() is called by the timer thread every 5 minutes.
  - Surge Z-scores are calibrated to CERT r4.2 normal daily baselines:
      * Normal browsing (connection events only) → all z-scores = 0
      * USB + file exfil + suspicious URLs → elevated z-scores → high risk
"""

from typing import Dict, Any, Tuple, List, Optional
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
import threading


class TimeWindowLogAggregator:
    """
    Stateful 5-Minute Window Behavioral Feature Aggregator.

    Ingests raw events into per-user sliding windows and computes
    30-dimension feature vectors on demand (every 5-minute timer cycle).
    """

    def __init__(self, window_seconds: int = 300):
        self.window_seconds = window_seconds
        # user → deque of (datetime, event_dict)
        self._user_events: Dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    # ─── Timestamp Helpers ────────────────────────────────────────

    @staticmethod
    def _parse_ts(ts: Any) -> datetime:
        if isinstance(ts, datetime):
            return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        if isinstance(ts, str) and ts.strip():
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except Exception:
                pass
        return datetime.now(timezone.utc)

    @staticmethod
    def _is_after_hours(dt: datetime) -> bool:
        """Outside 07:30–18:30 or weekend."""
        h = dt.hour + dt.minute / 60.0
        return dt.weekday() >= 5 or h < 7.5 or h > 18.5

    # ─── Ingest (Silent) ──────────────────────────────────────────

    def ingest(self, event: Dict[str, Any]):
        """
        Silently buffers a raw event into the user's sliding window.
        NO prediction, NO console output — just accumulation.
        """
        user = str(event.get("user", "UNKNOWN")).strip()
        dt = self._parse_ts(event.get("timestamp"))
        with self._lock:
            self._user_events[user].append((dt, event))

    # ─── Window Queries ───────────────────────────────────────────

    def get_active_users(self) -> List[str]:
        """Returns users who have events in the current window."""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=self.window_seconds)
        active = []
        with self._lock:
            for user, q in list(self._user_events.items()):
                # Evict stale events
                while q and q[0][0] < cutoff:
                    q.popleft()
                if q:
                    active.append(user)
                else:
                    self._user_events.pop(user, None)
        return active

    def get_user_event_count(self, user: str) -> int:
        with self._lock:
            return len(self._user_events.get(user, deque()))

    # ─── 5-Minute Aggregation ─────────────────────────────────────

    def aggregate_window(self, user: str) -> Tuple[str, Dict[str, float], int]:
        """
        Aggregates ALL events in the user's current window into the
        30-dimension feature vector that the ML models expect, and drains them.

        Returns: (date_key, features_dict, event_count)
        """
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=self.window_seconds)
        date_key = now.strftime("%Y-%m-%d")

        # Snapshot and drain current window events under lock
        with self._lock:
            q = self._user_events.get(user, deque())
            while q and q[0][0] < cutoff:
                q.popleft()
            window = []
            while q:
                window.append(q.popleft())
            # Clean up empty user entry
            self._user_events.pop(user, None)

        event_count = len(window)

        # ── Raw counters ──────────────────────────────────────────
        device_connect = 0
        device_disconnect = 0
        device_after_hours = 0
        file_copy = 0
        file_doc_pdf = 0
        file_zip_exe = 0
        file_after_hours = 0
        email_sent = 0
        email_total_bytes = 0.0
        email_max_bytes = 0.0
        email_external = 0
        email_bcc = 0
        email_after_hours = 0
        http_requests = 0
        http_wikileaks = 0
        http_job_search = 0
        http_cloud_storage = 0
        http_hacking = 0
        http_after_hours = 0
        is_weekend = 0

        for ts, evt in window:
            # Check explicit event flag if provided, otherwise compute from timestamp
            after_h = bool(evt.get("is_after_hours")) if "is_after_hours" in evt else self._is_after_hours(ts)
            if ts.weekday() >= 5 or bool(evt.get("is_weekend")):
                is_weekend = 1

            evt_type = str(evt.get("event_type", "")).lower()

            # ── USB / Removable Device ────────────────────────────
            if evt_type == "device":
                act = str(evt.get("activity", "")).lower()
                if "connect" in act and "disconnect" not in act:
                    device_connect += 1
                    if after_h:
                        device_after_hours += 1
                elif "disconnect" in act:
                    device_disconnect += 1

            # ── File Copy ─────────────────────────────────────────
            elif evt_type == "file_copy":
                file_copy += 1
                ext = str(evt.get("file_extension", "")).lower()
                fname = str(evt.get("filename", "")).lower()
                doc_exts = (".doc", ".docx", ".pdf", ".txt", ".xls", ".xlsx", ".csv", ".ppt")
                exe_exts = (".exe", ".zip", ".rar", ".7z", ".bin", ".py", ".tar", ".gz")
                if ext in doc_exts or any(fname.endswith(e) for e in doc_exts):
                    file_doc_pdf += 1
                elif ext in exe_exts or any(fname.endswith(e) for e in exe_exts):
                    file_zip_exe += 1
                if after_h:
                    file_after_hours += 1

            # ── Email ─────────────────────────────────────────────
            elif evt_type == "email":
                email_sent += 1
                sz = float(evt.get("size", evt.get("bytes", 15000)))
                email_total_bytes += sz
                email_max_bytes = max(email_max_bytes, sz)
                to_addr = str(evt.get("to", "")).lower()
                if "@" in to_addr and "@dtaa.com" not in to_addr:
                    email_external += 1
                bcc_val = str(evt.get("bcc", "")).lower()
                if bcc_val and bcc_val not in ("", "nan", "none"):
                    email_bcc += 1
                if after_h:
                    email_after_hours += 1

            # ── HTTP / Connection ─────────────────────────────────
            elif evt_type == "http" or (evt_type in ("connection", "conn") and evt.get("url")):
                http_requests += 1
                url = str(evt.get("url", evt.get("domain", ""))).lower()
                if "wikileaks" in url:
                    http_wikileaks += 1
                elif any(k in url for k in (
                    "monster.com", "careerbuilder", "indeed.com", "dice.com",
                    "simplyhired", "jobhunt", "linkedin", "raytheon",
                    "lockheedmartin", "boeing",
                )):
                    http_job_search += 1
                elif any(k in url for k in (
                    "dropbox.com", "drive.google.com", "box.com",
                    "mediafire.com", "mega.nz", "rapidshare.com",
                )):
                    http_cloud_storage += 1
                elif any(k in url for k in (
                    "keylogger", "exploit-db", "spectorsoft",
                    "dailykeylogger", "rootkit", "payload.bin",
                )):
                    http_hacking += 1
                if after_h:
                    http_after_hours += 1
            elif evt_type in ("connection", "conn"):
                # Background transport packet without HTTP URL
                if after_h:
                    http_after_hours += 1

        # ── Derived metrics ───────────────────────────────────────
        email_avg = (email_total_bytes / email_sent) if email_sent > 0 else 0.0
        total_activity = device_connect + device_disconnect + file_copy + email_sent + http_requests
        total_after = device_after_hours + file_after_hours + email_after_hours + http_after_hours
        after_ratio = (total_after / total_activity) if total_activity > 0 else 0.0
        sens_web = http_wikileaks + http_job_search + http_cloud_storage + http_hacking
        sens_ratio = min(1.0, (sens_web / http_requests) if http_requests > 0 else 0.0)
        ext_email_ratio = (email_external / email_sent) if email_sent > 0 else 0.0

        # ── Surge Z-Scores (calibrated to CERT r4.2 normal baselines) ──
        usb_zscore = 0.0
        if device_connect > 0:
            usb_zscore = (device_connect - 0.3) / 0.8
            if device_after_hours > 0:
                usb_zscore += 3.0  # After-hours USB is a strong signal

        file_zscore = 0.0
        if file_copy > 0:
            file_zscore = (file_copy - 0.5) / 1.2
            if file_after_hours > 0:
                file_zscore += 2.0
            if file_zip_exe > 0:
                file_zscore += 1.5  # Archive/exe copies are suspicious

        email_zscore = 0.0
        if email_sent > 0:
            mb = email_total_bytes / 1_000_000.0
            email_zscore = max(0.0, (mb - 0.2) / 0.3)
            if email_zscore > 15.0:
                email_zscore = 15.0

        # ── Build the 30-dimension feature vector ─────────────────
        features = {
            "device_connect_count": float(device_connect),
            "device_disconnect_count": float(device_disconnect),
            "device_after_hours": float(device_after_hours),
            "file_copy_count": float(file_copy),
            "file_doc_pdf_count": float(file_doc_pdf),
            "file_zip_exe_count": float(file_zip_exe),
            "file_after_hours": float(file_after_hours),
            "email_sent_count": float(email_sent),
            "email_total_bytes": email_total_bytes,
            "email_avg_bytes": email_avg,
            "email_max_bytes": email_max_bytes,
            "email_external_count": float(email_external),
            "email_bcc_count": float(email_bcc),
            "email_after_hours": float(email_after_hours),
            "http_request_count": float(http_requests),
            "http_wikileaks_count": float(http_wikileaks),
            "http_job_search_count": float(http_job_search),
            "http_cloud_storage_count": float(http_cloud_storage),
            "http_hacking_count": float(http_hacking),
            "http_after_hours": float(http_after_hours),
            "is_weekend": float(is_weekend),
            "total_activity_count": float(total_activity),
            "total_after_hours_count": float(total_after),
            "after_hours_ratio": after_ratio,
            "sensitive_web_count": float(sens_web),
            "sensitive_web_ratio": sens_ratio,
            "external_email_ratio": ext_email_ratio,
            "usb_surge_zscore": usb_zscore,
            "file_surge_zscore": file_zscore,
            "email_bytes_surge_zscore": email_zscore,
        }

        return date_key, features, event_count


# Backward compatibility alias
RealTimeLogBuffer = TimeWindowLogAggregator
