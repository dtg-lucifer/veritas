"""
Multithreaded Redis Queue Worker with 5-Minute Window Prediction Cycles.

Architecture (2 dedicated OS threads):
  Thread 1 – Consumer:  BRPOP from Redis → silent ingest into TimeWindowLogAggregator
  Thread 2 – Timer:     Every WINDOW_SECONDS → aggregate per-user → 4-model ML predict → WebSocket alert

Key design:
  - Individual events are NEVER scored. Only 5-minute aggregated windows are evaluated.
  - Console only logs at window boundaries, not per-event.
  - WebSocket alerts are only pushed when risk_score >= ALERT_THRESHOLD (default 65).
"""

import os
import json
import time
import threading
import asyncio
from typing import Optional, Dict, Any, Callable, List
from datetime import datetime, timezone
import redis
from rich.console import Console
from dotenv import load_dotenv

load_dotenv()

console = Console()

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REDIS_QUEUE_KEY = os.getenv("REDIS_QUEUE_KEY", "network_logs_queue")
ALERT_THRESHOLD = float(os.getenv("ALERT_THRESHOLD", "35.0"))
WINDOW_SECONDS = int(os.getenv("WINDOW_SECONDS", "300"))


class MultithreadedRedisLogWorker:
    """
    Two-thread worker:
      1. Consumer thread — BRPOP events from Redis, silently buffer in aggregator
      2. Timer thread    — every N seconds, aggregate + predict + alert
    """

    def __init__(
        self,
        log_buffer,
        predictor,
        broadcast_callback: Optional[Callable] = None,
        alerts_list: Optional[list] = None,
        redis_url: str = REDIS_URL,
        queue_key: str = REDIS_QUEUE_KEY,
        alert_threshold: float = ALERT_THRESHOLD,
        window_seconds: int = WINDOW_SECONDS,
    ):
        self.log_buffer = log_buffer
        self.predictor = predictor
        self.broadcast_callback = broadcast_callback
        self.alerts_list = alerts_list if alerts_list is not None else []
        self.redis_url = redis_url
        self.queue_key = queue_key
        self.alert_threshold = alert_threshold
        self.window_seconds = window_seconds

        self.is_running = False
        self._consumer_thread: Optional[threading.Thread] = None
        self._timer_thread: Optional[threading.Thread] = None
        self.event_loop: Optional[asyncio.AbstractEventLoop] = None
        self._redis: Optional[redis.Redis] = None

        # Metrics
        self.ingested_count = 0
        self.windows_evaluated = 0
        self.alerts_generated = 0
        self.processed_count = 0  # backward compat alias
        self._lock = threading.Lock()

    # ─── Lifecycle ────────────────────────────────────────────────

    def start(self, loop: Optional[asyncio.AbstractEventLoop] = None):
        if self.is_running:
            return
        self.is_running = True
        self.event_loop = loop

        self._consumer_thread = threading.Thread(
            target=self._consumer_loop,
            name="RedisConsumerThread",
            daemon=True,
        )
        self._timer_thread = threading.Thread(
            target=self._timer_loop,
            name="WindowTimerThread",
            daemon=True,
        )
        self._consumer_thread.start()
        self._timer_thread.start()

        console.print(
            f"[bold green]✓ Redis Worker started[/bold green]\n"
            f"  Queue          : {self.queue_key}\n"
            f"  Window         : {self.window_seconds}s\n"
            f"  Alert Threshold: {self.alert_threshold}\n"
            f"  Threads        : {self._consumer_thread.name}, {self._timer_thread.name}"
        )

    def stop(self, timeout: float = 3.0):
        self.is_running = False
        for t in (self._consumer_thread, self._timer_thread):
            if t and t.is_alive():
                t.join(timeout=timeout)
        if self._redis:
            try:
                self._redis.close()
            except Exception:
                pass
        console.print("[yellow]Redis Worker stopped.[/yellow]")

    # Keep backward compat property
    @property
    def worker_thread(self):
        return self._consumer_thread

    # ─── Consumer Thread ──────────────────────────────────────────

    def _connect(self) -> bool:
        try:
            self._redis = redis.Redis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_timeout=5.0,
                socket_connect_timeout=5.0,
            )
            self._redis.ping()
            console.print(f"[green]✓ Redis connected: {self.redis_url}[/green]")
            return True
        except Exception as e:
            console.print(f"[yellow]⚠ Redis connect failed ({e}), retrying in 5s…[/yellow]")
            self._redis = None
            return False

    def _consumer_loop(self):
        """Continuously BRPOP events from Redis and silently buffer them."""
        while self.is_running:
            if self._redis is None:
                if not self._connect():
                    time.sleep(5.0)
                    continue
            try:
                item = self._redis.brpop(self.queue_key, timeout=1)
                if item is None:
                    continue
                _, raw = item
                event = json.loads(raw)
                # Silent ingest — NO prediction, NO console output
                self.log_buffer.ingest(event)
                with self._lock:
                    self.ingested_count += 1
                    self.processed_count += 1
            except json.JSONDecodeError:
                continue
            except Exception as e:
                if self.is_running:
                    console.print(f"[red]Consumer error: {e}[/red]")
                    self._redis = None
                    time.sleep(2.0)

    # ─── Timer Thread ─────────────────────────────────────────────

    def _timer_loop(self):
        """Every WINDOW_SECONDS, aggregate each user's window and run ML prediction."""
        # Wait one full window before first evaluation
        self._interruptible_sleep(self.window_seconds)

        while self.is_running:
            try:
                self._evaluate_all_windows()
            except Exception as e:
                console.print(f"[red]Timer evaluation error: {e}[/red]")

            # Sleep until next window
            self._interruptible_sleep(self.window_seconds)

    def _interruptible_sleep(self, seconds: int):
        """Sleep that can be interrupted by shutdown."""
        elapsed = 0
        while self.is_running and elapsed < seconds:
            time.sleep(1.0)
            elapsed += 1

    def _evaluate_all_windows(self):
        """Aggregate all active user windows → run 4-model ensemble → alert."""
        active_users = self.log_buffer.get_active_users()
        ts_str = datetime.now().strftime("%H:%M:%S")

        if not active_users:
            console.print(
                f"[dim]── Window @ {ts_str} | No active users | "
                f"ingested={self.ingested_count} ──[/dim]"
            )
            return

        console.print(
            f"\n[bold cyan]{'━' * 60}[/bold cyan]\n"
            f"[bold cyan]  5-Min Window Evaluation @ {ts_str}[/bold cyan]\n"
            f"[bold cyan]  Active Users: {len(active_users)} | "
            f"Total Ingested: {self.ingested_count}[/bold cyan]\n"
            f"[bold cyan]{'━' * 60}[/bold cyan]"
        )

        for user in active_users:
            date_key, features, evt_count = self.log_buffer.aggregate_window(user)

            with self._lock:
                self.windows_evaluated += 1

            # Run the 4-model ensemble prediction
            assessment = self.predictor.evaluate_features(
                user=user,
                date_str=date_key,
                feature_dict=features,
                include_autoencoder=True,
            )
            assessment["window_event_count"] = evt_count
            assessment["ingest_source"] = "redis_worker"

            risk = assessment["risk_score"]
            status = assessment["status"]
            action = assessment["policy_action"]

            # Console output for every window evaluation
            if status == "CRITICAL":
                icon, color = "🚨", "bold red"
            elif status == "SUSPICIOUS":
                icon, color = "⚠️ ", "bold yellow"
            else:
                icon, color = "✅", "green"

            console.print(
                f"  [{color}]{icon} User={user} | events={evt_count} | "
                f"risk={risk}/100 | status={status} | action={action}[/{color}]"
            )

            # Print key signals
            signals = assessment.get("signals", {})
            console.print(
                f"     [dim]gb={signals.get('supervised_threat_score', 0):.3f}  "
                f"base={signals.get('baseline_deviation_score', 0):.3f}  "
                f"if={signals.get('isolation_forest_score', 0):.3f}  "
                f"ae={signals.get('autoencoder_reconstruction_score', 'N/A')}[/dim]"
            )

            # Push to WebSocket ONLY if above threshold
            if risk >= self.alert_threshold:
                alert_payload = {
                    "type": "SECURITY_INCIDENT_ALERT",
                    "alert": assessment,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }

                with self._lock:
                    self.alerts_generated += 1
                    self.alerts_list.insert(0, alert_payload)
                    if len(self.alerts_list) > 100:
                        self.alerts_list.pop()

                # Thread-safe dispatch to FastAPI event loop
                if self.broadcast_callback and self.event_loop:
                    try:
                        if self.event_loop.is_running():
                            asyncio.run_coroutine_threadsafe(
                                self.broadcast_callback(alert_payload),
                                self.event_loop,
                            )
                    except Exception as e:
                        console.print(f"[red]WebSocket broadcast error: {e}[/red]")

                # Publish to Redis pub/sub for external listeners
                if self._redis:
                    try:
                        self._redis.publish("security_alerts", json.dumps(alert_payload))
                    except Exception:
                        pass

                console.print(
                    f"     [bold red]└─ 🔔 ALERT pushed to WebSocket (risk={risk} >= {self.alert_threshold})[/bold red]"
                )

        console.print(
            f"[bold cyan]{'━' * 60}[/bold cyan]\n"
            f"[bold cyan]  Windows evaluated: {self.windows_evaluated} | "
            f"Total alerts: {self.alerts_generated}[/bold cyan]\n"
            f"[bold cyan]{'━' * 60}[/bold cyan]\n"
        )


# Backward compatibility alias
RedisLogQueueWorker = MultithreadedRedisLogWorker
