"""
Asynchronous Redis Message Queue Consumer & 5-Minute Window Worker.
Decouples line-speed log ingestion from ML inference:
1. Actively consumes raw network log streams from Redis queue ('network_logs_queue').
2. Buffers events into stateful 5-minute time windows per identity (user / IP).
3. Aggregates logs over the window and evaluates behavioral change with multi-model ensemble ML.
4. Broadcasts elevated security incidents via WebSockets and Redis Pub/Sub for automated mitigation.
"""

import os
import json
import asyncio
from typing import Optional, Dict, Any, Callable, List
from datetime import datetime, timezone
import redis.asyncio as aioredis
from rich.console import Console

console = Console()

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REDIS_QUEUE_KEY = os.getenv("REDIS_QUEUE_KEY", "network_logs_queue")
ALERT_THRESHOLD = float(os.getenv("ALERT_THRESHOLD", "40.0"))


class RedisLogQueueWorker:
    def __init__(
        self,
        log_buffer,
        predictor,
        broadcast_callback: Optional[Callable[[Dict[str, Any]], Any]] = None,
        alerts_list: Optional[list] = None,
        redis_url: str = REDIS_URL,
        queue_key: str = REDIS_QUEUE_KEY,
        alert_threshold: float = ALERT_THRESHOLD
    ):
        self.log_buffer = log_buffer
        self.predictor = predictor
        self.broadcast_callback = broadcast_callback
        self.alerts_list = alerts_list if alerts_list is not None else []
        self.redis_url = redis_url
        self.queue_key = queue_key
        self.alert_threshold = alert_threshold
        
        self.is_running = False
        self.redis_client: Optional[aioredis.Redis] = None
        self.task: Optional[asyncio.Task] = None
        self.sweep_task: Optional[asyncio.Task] = None
        self.processed_count = 0
        self.windows_evaluated = 0
        self.alerts_generated = 0

    async def start(self):
        """Starts the background Redis queue consumer and window sweep tasks."""
        self.is_running = True
        self.task = asyncio.create_task(self._consume_loop())
        self.sweep_task = asyncio.create_task(self._window_sweep_loop())
        console.print(f"[bold green]✓ Redis Log Queue Worker started on queue '{self.queue_key}' (Alert Threshold: {self.alert_threshold})[/bold green]")

    async def stop(self):
        """Stops worker tasks gracefully."""
        self.is_running = False
        for t in [self.task, self.sweep_task]:
            if t:
                t.cancel()
                try:
                    await t
                except asyncio.CancelledError:
                    pass
        if self.redis_client:
            await self.redis_client.close()
        console.print("[yellow]Redis Log Queue Worker stopped.[/yellow]")

    async def _connect_redis(self) -> bool:
        try:
            self.redis_client = aioredis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_timeout=5.0,
                socket_connect_timeout=5.0
            )
            await self.redis_client.ping()
            console.print(f"[green]✓ Connected to Redis at {self.redis_url}[/green]")
            return True
        except Exception as e:
            console.print(f"[yellow]⚠️ Could not connect to Redis at {self.redis_url} ({e}). Retrying in 5s...[/yellow]")
            return False

    async def _consume_loop(self):
        """Main non-blocking dequeue & 5-minute window inference loop."""
        while self.is_running:
            if self.redis_client is None:
                connected = await self._connect_redis()
                if not connected:
                    await asyncio.sleep(5)
                    continue

            try:
                # Block-pop next item from queue with 1-second timeout
                item = await self.redis_client.brpop(self.queue_key, timeout=1.0)
                if item is None:
                    continue

                _, raw_json = item
                event = json.loads(raw_json)
                await self.process_event(event)

            except asyncio.CancelledError:
                break
            except Exception as e:
                console.print(f"[red]Error in Redis consumer loop: {e}[/red]")
                self.redis_client = None
                await asyncio.sleep(3)

    async def _window_sweep_loop(self):
        """Periodic background sweep to re-evaluate active 5-minute windows."""
        while self.is_running:
            await asyncio.sleep(30)
            # Sweep active windows if needed

    async def process_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ingests a raw log event from Redis broker, aggregates into 5-minute behavioral window,
        runs multi-model ensemble inference, and triggers policy mitigation on elevated risk.
        """
        self.processed_count += 1
        self.windows_evaluated += 1
        
        # 1. Stateful 5-Minute Window Buffer Ingestion
        user, date_key, window_features = self.log_buffer.ingest_event(event)

        # 2. Multi-Model Ensemble Inference (LightGBM + Baseline + Isolation Forest + Autoencoder)
        assessment = self.predictor.evaluate_features(
            user=user,
            date_str=date_key,
            feature_dict=window_features,
            include_autoencoder=True
        )
        assessment["src_ip"] = event.get("src_ip", "10.0.4.1")
        assessment["last_event_type"] = event.get("event_type", "unknown")
        assessment["ingest_source"] = "redis_queue"
        assessment["window_active_events"] = len(self.log_buffer.user_event_windows[user])

        # 3. Check Risk Threshold (Level 2 Suspicious >= 40.0, Level 3 Critical >= 70.0)
        is_threat = (assessment["risk_score"] >= self.alert_threshold) or (assessment["status"] in ["SUSPICIOUS", "CRITICAL"])
        if is_threat:
            self.alerts_generated += 1
            self.alerts_list.insert(0, assessment)
            if len(self.alerts_list) > 100:
                self.alerts_list.pop()

            alert_msg = {
                "type": "REDIS_SECURITY_ALERT",
                "alert": assessment,
                "timestamp": date_key
            }

            # Broadcast to WebSocket dashboard subscribers
            if self.broadcast_callback:
                await self.broadcast_callback(alert_msg)

            # Publish to Redis pub/sub channel for external SIEM / Gateway listeners
            if self.redis_client:
                try:
                    await self.redis_client.publish("security_alerts_pubsub", json.dumps(alert_msg))
                except Exception:
                    pass

            color = "bold red" if assessment["status"] == "CRITICAL" else "bold yellow"
            console.print(
                f"[{color}]🚨 [5-Min Window Alert] User={user} Risk={assessment['risk_score']}/100 "
                f"Status={assessment['status']} Action={assessment['policy_action']}[/{color}]"
            )

        return assessment
