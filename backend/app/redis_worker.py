"""
Asynchronous Redis Message Queue Worker.
Consumes raw network log streams from Redis queue ('network_logs_queue'),
aggregates behavioral states, executes fast composite ML inference (LightGBM + Baseline + IF),
and broadcasts real-time security alerts via WebSockets.
"""

import os
import json
import asyncio
from typing import Optional, Dict, Any, Callable
import redis.asyncio as aioredis
from rich.console import Console

console = Console()

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REDIS_QUEUE_KEY = os.getenv("REDIS_QUEUE_KEY", "network_logs_queue")
ALERT_THRESHOLD = float(os.getenv("ALERT_THRESHOLD", "55.0"))


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
        self.processed_count = 0
        self.alerts_generated = 0

    async def start(self):
        """Starts the background worker task."""
        self.is_running = True
        self.task = asyncio.create_task(self._consume_loop())
        console.print(f"[bold green]✓ Redis Log Queue Worker started on queue '{self.queue_key}'[/bold green]")

    async def stop(self):
        """Stops the worker gracefully."""
        self.is_running = False
        if self.task:
            self.task.cancel()
            try:
                await self.task
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
        """Main non-blocking dequeue & inference loop."""
        while self.is_running:
            # 1. Ensure Redis connection
            if self.redis_client is None:
                connected = await self._connect_redis()
                if not connected:
                    await asyncio.sleep(5)
                    continue

            # 2. Block-pop next item from queue with 1-second timeout
            try:
                item = await self.redis_client.brpop(self.queue_key, timeout=1.0)
                if item is None:
                    continue  # Timeout reached with no item, continue loop

                _, raw_json = item
                event = json.loads(raw_json)
                await self.process_event(event)

            except asyncio.CancelledError:
                break
            except Exception as e:
                console.print(f"[red]Error in Redis consumer loop: {e}[/red]")
                self.redis_client = None
                await asyncio.sleep(3)

    async def process_event(self, event: Dict[str, Any]):
        """
        Ingests a single raw event from Redis, runs fast composite inference,
        and broadcasts any elevated risk incidents.
        """
        self.processed_count += 1
        
        # 1. Buffer and aggregate into running behavioral state
        user, date_key, updated_features = self.log_buffer.ingest_event(event)

        # 2. Ultra-fast composite ML prediction (LightGBM + Baseline + Isolation Forest: < 1ms)
        assessment = self.predictor.evaluate_features(
            user=user,
            date_str=date_key,
            feature_dict=updated_features,
            include_autoencoder=False
        )
        assessment["src_ip"] = event.get("src_ip", "10.0.0.1")
        assessment["last_event_type"] = event.get("event_type", "unknown")
        assessment["ingest_source"] = "redis_queue"

        # 3. Check Alert Threshold
        if assessment["risk_score"] >= self.alert_threshold or assessment["status"] in ["SUSPICIOUS", "CRITICAL"]:
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

            # Publish to Redis pub/sub channel for external SIEMs
            if self.redis_client:
                try:
                    await self.redis_client.publish("security_alerts_pubsub", json.dumps(alert_msg))
                except Exception:
                    pass

            console.print(
                f"[bold red]🚨 [Redis Queue Alert] User={user} Risk={assessment['risk_score']}/100 "
                f"Status={assessment['status']} Action={assessment['policy_action']}[/bold red]"
            )
