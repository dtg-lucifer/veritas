"""
Redis Message Queue Producer for Network Packet Logs.
Publishes normalized packet log events directly into the backend ingestion queue ('network_logs_queue').
"""

import json
import time
from typing import Dict, Any, Optional, List
import redis
from rich.console import Console

console = Console()


class RedisLogPublisher:
    """
    Thread-safe synchronous Redis publisher with auto-reconnection and metrics.
    """
    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        queue_key: str = "network_logs_queue"
    ):
        self.redis_url = redis_url
        self.queue_key = queue_key
        self.client: Optional[redis.Redis] = None
        self.published_count = 0
        self.failed_count = 0

    def connect(self) -> bool:
        """Establishes connection to the Redis message broker."""
        try:
            self.client = redis.Redis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_timeout=5.0,
                socket_connect_timeout=5.0
            )
            self.client.ping()
            console.print(f"[green]Connected to Redis at {self.redis_url} (Target Queue: '{self.queue_key}')[/green]")
            return True
        except Exception as e:
            console.print(f"[yellow]Could not connect to Redis at {self.redis_url} ({e}).[/yellow]")
            self.client = None
            return False

    def publish_event(self, event: Dict[str, Any]) -> bool:
        """
        Pushes a single normalized event dictionary to Redis MQ via LPUSH.
        """
        if self.client is None:
            if not self.connect():
                self.failed_count += 1
                return False

        try:
            payload_str = json.dumps(event)
            self.client.lpush(self.queue_key, payload_str)
            self.published_count += 1
            return True
        except Exception as e:
            console.print(f"[red]Error publishing packet to Redis: {e}[/red]")
            self.client = None
            self.failed_count += 1
            return False

    def publish_batch(self, events: List[Dict[str, Any]]) -> int:
        """
        Pushes a batch of events inside a single Redis pipeline for maximum throughput.
        """
        if not events:
            return 0

        if self.client is None:
            if not self.connect():
                self.failed_count += len(events)
                return 0

        try:
            pipe = self.client.pipeline()
            for event in events:
                pipe.lpush(self.queue_key, json.dumps(event))
            pipe.execute()
            self.published_count += len(events)
            return len(events)
        except Exception as e:
            console.print(f"[red]Error in Redis pipeline push: {e}[/red]")
            self.client = None
            self.failed_count += len(events)
            return 0

    def close(self):
        """Closes Redis connection cleanly."""
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
            self.client = None
