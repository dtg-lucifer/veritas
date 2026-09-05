"""
Distributed Telemetry & Ingestion Metrics Service with Redis Persistence.
Tracks ingestion counters (logs_processed, logs_ignored, logs_malformed_schema),
active distributed loggers, and recent malformed packet samples for SOC dashboard visualization.
Built with resilient fail-open error handling to prevent server lockup if Redis is unavailable.
"""

import json
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
import redis.asyncio as aioredis
from rich.console import Console

from src.config import get_config

console = Console()


class RedisMetricsManager:
    """
    Asynchronous metrics tracker storing ingestion and evaluation telemetry in Redis.
    Falls back gracefully to in-memory counters if Redis is unreachable.
    """

    def __init__(self, redis_url: Optional[str] = None):
        self.config = get_config()
        self.redis_url = redis_url or self.config.redis.url
        self.prefix = self.config.redis.key_prefix
        self.enabled = self.config.redis.enabled
        self.client: Optional[aioredis.Redis] = None
        self._connected = False
        self._warned_connection_failure = False

        # In-memory fallbacks
        self._memory_counters: Dict[str, int] = {
            "logs_processed": 0,
            "logs_ignored": 0,
            "logs_malformed_schema": 0,
            "logs_webrtc_conferencing": 0,
            "windows_evaluated": 0,
            "alerts_normal": 0,
            "alerts_suspicious": 0,
            "alerts_critical": 0,
        }
        self._memory_active_loggers: set = set()
        self._memory_malformed_samples: List[Dict[str, Any]] = []
        self._memory_recent_evaluations: List[Dict[str, Any]] = []
        self._last_log_timestamp: Optional[str] = None
        self._last_eval_timestamp: Optional[str] = None

    async def connect(self):
        """Initializes Redis connection."""
        if not self.enabled:
            return

        try:
            self.client = aioredis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_connect_timeout=2.0,
                socket_timeout=2.0,
            )
            await self.client.ping()
            self._connected = True
            console.print(f"[bold green]✓ Connected to Redis Telemetry Broker at {self.redis_url}[/bold green]")
        except Exception as e:
            self._connected = False
            if not self._warned_connection_failure:
                console.print(f"[bold yellow]⚠️ Redis Telemetry unavailable ({e}). Using in-memory metrics fallback.[/bold yellow]")
                self._warned_connection_failure = True

    async def close(self):
        """Closes Redis client."""
        if self.client:
            try:
                await self.client.aclose()
            except Exception:
                pass
            self._connected = False

    async def _ensure_connection(self) -> bool:
        """Verifies or attempts to restore connection."""
        if not self.enabled:
            return False
        if not self._connected or self.client is None:
            await self.connect()
        return self._connected

    # --- INGESTION TELEMETRY COUNTERS ---

    async def record_log_processed(self, count: int = 1, logger_id: Optional[str] = None, is_webrtc: bool = False):
        """Increments successfully processed flow records counter."""
        self._memory_counters["logs_processed"] += count
        if is_webrtc:
            self._memory_counters["logs_webrtc_conferencing"] += count
        now_iso = datetime.now(timezone.utc).isoformat()
        self._last_log_timestamp = now_iso

        if logger_id:
            self._memory_active_loggers.add(logger_id)

        if await self._ensure_connection():
            try:
                pipe = self.client.pipeline()
                metrics_key = f"{self.prefix}metrics"
                pipe.hincrby(metrics_key, "logs_processed", count)
                if is_webrtc:
                    pipe.hincrby(metrics_key, "logs_webrtc_conferencing", count)
                pipe.hset(metrics_key, "last_log_timestamp", now_iso)
                if logger_id:
                    pipe.sadd(f"{self.prefix}active_loggers", logger_id)
                    pipe.hset(f"{self.prefix}logger_last_seen", logger_id, now_iso)
                await pipe.execute()
            except Exception:
                self._connected = False

    async def record_log_ignored(self, reason: str, raw_payload: Any = None, logger_id: Optional[str] = None):
        """
        Records an ignored or malformed log record without crashing the server.
        Increments logs_ignored and logs_malformed_schema, and saves a sample for inspection.
        """
        self._memory_counters["logs_ignored"] += 1
        self._memory_counters["logs_malformed_schema"] += 1
        now_iso = datetime.now(timezone.utc).isoformat()

        # Sanitize payload for sample storage
        raw_str = str(raw_payload)
        if len(raw_str) > 500:
            raw_str = raw_str[:500] + "... [truncated]"

        sample = {
            "timestamp": now_iso,
            "reason": reason,
            "logger_id": logger_id or "unknown",
            "sample": raw_str,
        }
        self._memory_malformed_samples.append(sample)
        if len(self._memory_malformed_samples) > 50:
            self._memory_malformed_samples.pop(0)

        if await self._ensure_connection():
            try:
                metrics_key = f"{self.prefix}metrics"
                samples_key = f"{self.prefix}recent_malformed_samples"
                pipe = self.client.pipeline()
                pipe.hincrby(metrics_key, "logs_ignored", 1)
                pipe.hincrby(metrics_key, "logs_malformed_schema", 1)
                pipe.hset(metrics_key, "last_malformed_timestamp", now_iso)
                pipe.lpush(samples_key, json.dumps(sample))
                pipe.ltrim(samples_key, 0, 49)  # Keep latest 50 samples
                await pipe.execute()
            except Exception:
                self._connected = False

    # --- EVALUATION TELEMETRY ---

    async def record_evaluation(self, risk_pct: float, stage: str, policy: str, flow_count: int):
        """Records a completed temporal window evaluation and updates risk counters."""
        self._memory_counters["windows_evaluated"] += 1
        if risk_pct >= 70.0 or policy == "ISOLATE_DEVICE":
            self._memory_counters["alerts_critical"] += 1
            severity = "CRITICAL"
        elif risk_pct >= (self.config.thresholds.alert_threshold * 100) or policy == "ALERT_ADMIN":
            self._memory_counters["alerts_suspicious"] += 1
            severity = "SUSPICIOUS"
        else:
            self._memory_counters["alerts_normal"] += 1
            severity = "NORMAL"

        now_iso = datetime.now(timezone.utc).isoformat()
        self._last_eval_timestamp = now_iso

        eval_summary = {
            "timestamp": now_iso,
            "risk_pct": round(risk_pct, 2),
            "stage": stage,
            "policy": policy,
            "severity": severity,
            "flow_count": flow_count,
        }
        self._memory_recent_evaluations.append(eval_summary)
        if len(self._memory_recent_evaluations) > 50:
            self._memory_recent_evaluations.pop(0)

        if await self._ensure_connection():
            try:
                metrics_key = f"{self.prefix}metrics"
                history_key = f"{self.prefix}recent_evaluations"
                pipe = self.client.pipeline()
                pipe.hincrby(metrics_key, "windows_evaluated", 1)
                if severity == "CRITICAL":
                    pipe.hincrby(metrics_key, "alerts_critical", 1)
                elif severity == "SUSPICIOUS":
                    pipe.hincrby(metrics_key, "alerts_suspicious", 1)
                else:
                    pipe.hincrby(metrics_key, "alerts_normal", 1)

                pipe.hset(metrics_key, "last_evaluation_timestamp", now_iso)
                pipe.hset(metrics_key, "last_risk_pct", str(round(risk_pct, 2)))
                pipe.lpush(history_key, json.dumps(eval_summary))
                pipe.ltrim(history_key, 0, 49)
                await pipe.execute()
            except Exception:
                self._connected = False

    # --- RETRIEVAL FOR SOC DASHBOARD ---

    async def get_all_metrics(self) -> Dict[str, Any]:
        """
        Gathers complete telemetry metrics from Redis (or in-memory cache if disconnected)
        formatted for immediate SOC dashboard visualization.
        """
        metrics = dict(self._memory_counters)
        active_loggers = list(self._memory_active_loggers)
        malformed_samples = list(self._memory_malformed_samples)
        recent_evaluations = list(self._memory_recent_evaluations)
        last_log = self._last_log_timestamp
        last_eval = self._last_eval_timestamp
        connected_to_redis = self._connected

        if await self._ensure_connection():
            try:
                metrics_key = f"{self.prefix}metrics"
                raw_hash = await self.client.hgetall(metrics_key)
                if raw_hash:
                    for k in metrics.keys():
                        if k in raw_hash:
                            try:
                                metrics[k] = int(raw_hash[k])
                            except ValueError:
                                pass
                    last_log = raw_hash.get("last_log_timestamp", last_log)
                    last_eval = raw_hash.get("last_evaluation_timestamp", last_eval)

                # Active loggers
                loggers_set = await self.client.smembers(f"{self.prefix}active_loggers")
                if loggers_set:
                    active_loggers = list(loggers_set)

                # Recent malformed samples
                samples_raw = await self.client.lrange(f"{self.prefix}recent_malformed_samples", 0, 19)
                if samples_raw:
                    malformed_samples = [json.loads(s) for s in samples_raw if s]

                # Recent evaluations
                evals_raw = await self.client.lrange(f"{self.prefix}recent_evaluations", 0, 29)
                if evals_raw:
                    recent_evaluations = [json.loads(s) for s in evals_raw if s]

                connected_to_redis = True
            except Exception:
                connected_to_redis = False

        cfg = get_config()
        return {
            "status": "online",
            "redis_connected": connected_to_redis,
            "redis_url": self.redis_url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "counters": {
                "logs_processed": metrics["logs_processed"],
                "logs_ignored": metrics["logs_ignored"],
                "logs_malformed_schema": metrics["logs_malformed_schema"],
                "logs_webrtc_conferencing": metrics["logs_webrtc_conferencing"],
                "windows_evaluated": metrics["windows_evaluated"],
                "alerts_normal": metrics["alerts_normal"],
                "alerts_suspicious": metrics["alerts_suspicious"],
                "alerts_critical": metrics["alerts_critical"],
            },
            "network_context": {
                "connected_clients_count": cfg.network.connected_clients_count,
                "allow_webrtc_conferencing": cfg.traffic_policy.allow_webrtc_conferencing,
                "alert_threshold": cfg.thresholds.alert_threshold,
                "critical_threshold": cfg.thresholds.critical_threshold,
            },
            "timestamps": {
                "last_log_timestamp": last_log,
                "last_evaluation_timestamp": last_eval,
            },
            "active_loggers": active_loggers,
            "recent_malformed_samples": malformed_samples,
            "recent_evaluations": recent_evaluations,
        }


# Global singleton instance
redis_metrics = RedisMetricsManager()
