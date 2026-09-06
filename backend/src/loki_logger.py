"""
Loki Logging Integration for Veritas Backend.
Provides non-blocking structured log forwarding to Grafana Loki.
If Loki is reachable (e.g. at http://localhost:3100 or http://loki:3100),
structured logs, policy decisions, and forward simulation events are shipped
with queryable labels for live Grafana log exploration.
"""

import os
import logging
import threading
import queue
import requests
import json
import time
from typing import Dict, Any, Optional

logger = logging.getLogger("firewall.loki")

LOKI_URL = os.getenv("LOKI_URL", "http://localhost:3100")
LOKI_ENABLED = os.getenv("LOKI_ENABLED", "true").lower() in ("true", "1", "yes")

_log_queue: queue.Queue = queue.Queue(maxsize=10000)
_worker_thread: Optional[threading.Thread] = None
_stop_event = threading.Event()


def _loki_worker():
    """Background worker sending batches of logs to Loki push API /loki/api/v1/push."""
    push_url = f"{LOKI_URL.rstrip('/')}/loki/api/v1/push"
    session = requests.Session()

    while not _stop_event.is_set():
        batch = []
        try:
            # Wait for at least one item
            item = _log_queue.get(timeout=1.0)
            batch.append(item)
            # Drain whatever else is ready up to 100 items
            while len(batch) < 100:
                try:
                    batch.append(_log_queue.get_nowait())
                except queue.Empty:
                    break
        except queue.Empty:
            continue

        if not batch:
            continue

        # Group by labels
        streams_map: Dict[str, list] = {}
        for entry in batch:
            labels_dict = entry.get("labels", {})
            labels_key = json.dumps(labels_dict, sort_keys=True)
            if labels_key not in streams_map:
                streams_map[labels_key] = {
                    "stream": labels_dict,
                    "values": []
                }
            # Loki expects nanosecond timestamp string: [str(ns), line_string]
            ts_ns = str(int(entry.get("timestamp_ns", time.time() * 1e9)))
            line = entry.get("line", "")
            streams_map[labels_key]["values"].append([ts_ns, line])

        payload = {
            "streams": list(streams_map.values())
        }

        try:
            resp = session.post(
                push_url,
                headers={"Content-Type": "application/json"},
                json=payload,
                timeout=2.5,
            )
            # Status 204 or 200 means success
        except Exception:
            # Silent fallback if Loki is currently unreachable or down
            pass


def init_loki_logging():
    """Initializes the background worker for shipping logs to Loki."""
    global _worker_thread
    if not LOKI_ENABLED:
        return

    if _worker_thread is None or not _worker_thread.is_alive():
        _worker_thread = threading.Thread(target=_loki_worker, daemon=True, name="LokiLogForwarder")
        _worker_thread.start()


def log_to_loki(
    message: str,
    level: str = "info",
    event_type: str = "operational",
    extra_labels: Optional[Dict[str, str]] = None,
    details: Optional[Dict[str, Any]] = None,
):
    """
    Ships a structured log entry to Grafana Loki asynchronously without blocking.
    
    Args:
        message: Human-readable log line
        level: 'info', 'warn', 'error', 'critical', 'debug'
        event_type: 'threat_alert', 'policy_enforce', 'window_eval', 'normal_traffic', 'media_stream'
        extra_labels: Additional Loki indexing labels (e.g. {'policy': 'ISOLATE_DEVICE', 'target': '10.0.4.21'})
        details: Dict with structured payload appended to the log line JSON
    """
    if not LOKI_ENABLED:
        return

    init_loki_logging()

    labels = {
        "job": "firewall_backend",
        "service": "ai_world_model",
        "level": level.lower(),
        "event_type": event_type,
    }
    if extra_labels:
        for k, v in extra_labels.items():
            labels[k] = str(v)

    log_entry = {
        "message": message,
        "level": level.upper(),
        "event_type": event_type,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if details:
        log_entry["details"] = details

    try:
        _log_queue.put_nowait({
            "labels": labels,
            "line": json.dumps(log_entry),
            "timestamp_ns": int(time.time() * 1e9),
        })
    except queue.Full:
        pass


class LokiLoggingHandler(logging.Handler):
    """Standard python logging handler that forwards log records to Loki."""

    def emit(self, record: logging.LogRecord):
        try:
            msg = self.format(record)
            log_to_loki(
                message=msg,
                level=record.levelname.lower(),
                event_type="python_log",
                extra_labels={"logger": record.name},
            )
        except Exception:
            self.handleError(record)
