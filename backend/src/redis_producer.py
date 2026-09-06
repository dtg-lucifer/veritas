"""
Redis Network Log Producer CLI & Attack Simulator.
Pushes synthetic or CERT r4.2 network log streams directly into Redis queue ('network_logs_queue')
to demonstrate live stream ingestion, fast composite ML triage, and WebSocket alerts.
"""

import os
import sys
import json
import time
import asyncio
from datetime import datetime, timezone
import redis.asyncio as aioredis
from rich.console import Console
from rich.panel import Panel

console = Console()

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REDIS_QUEUE_KEY = os.getenv("REDIS_QUEUE_KEY", "network_logs_queue")


async def push_log_event(redis_client, event: dict, queue_key: str = REDIS_QUEUE_KEY):
    """Pushes a single log event to the Redis queue."""
    raw = json.dumps(event)
    await redis_client.lpush(queue_key, raw)


async def simulate_attack_stream(redis_url: str = REDIS_URL, queue_key: str = REDIS_QUEUE_KEY):
    """
    Simulates a 4-stage live insider attack vector:
    1. Normal day browsing
    2. Late night after-hours login & USB drive connect
    3. Large archive file copy to USB
    4. HTTP Wikileaks & Cloud Storage upload
    """
    console.print(Panel.fit(
        f"[bold red]Starting Live Attack Stream Simulation -> Redis [{queue_key}][/bold red]\n"
        f"[cyan]Target Identity: AAM0658 | Gateway Subnet: 10.0.4.0/24[/cyan]",
        border_style="red"
    ))

    try:
        r = aioredis.from_url(redis_url, decode_responses=True)
        await r.ping()
    except Exception as e:
        console.print(f"[bold red]Failed to connect to Redis at {redis_url}: {e}[/bold red]")
        sys.exit(1)

    events = [
        # Stage 1: Standard daytime HTTP activity
        {
            "event_id": "sim-evt-001",
            "timestamp": "2026-08-19T10:15:00Z",
            "user": "AAM0658",
            "src_ip": "10.0.4.21",
            "event_type": "http",
            "url": "https://stackoverflow.com/questions/internal-api"
        },
        # Stage 2: Late night after-hours USB connect
        {
            "event_id": "sim-evt-002",
            "timestamp": "2026-08-19T23:45:00Z",
            "user": "AAM0658",
            "src_ip": "10.0.4.21",
            "event_type": "device",
            "activity": "Connect",
            "device_name": "SanDisk Extreme 128GB"
        },
        # Stage 3: Large sensitive document & zip archive copies to USB
        {
            "event_id": "sim-evt-003",
            "timestamp": "2026-08-19T23:48:10Z",
            "user": "AAM0658",
            "src_ip": "10.0.4.21",
            "event_type": "file_copy",
            "filename": "Classified_Defense_Architecture_v2.pdf",
            "file_extension": ".pdf",
            "size": 15000000
        },
        {
            "event_id": "sim-evt-004",
            "timestamp": "2026-08-19T23:50:20Z",
            "user": "AAM0658",
            "src_ip": "10.0.4.21",
            "event_type": "file_copy",
            "filename": "Master_Credentials_Vault.zip",
            "file_extension": ".zip",
            "size": 48000000
        },
        # Stage 4: Wikileaks and cloud exfiltration attempt
        {
            "event_id": "sim-evt-005",
            "timestamp": "2026-08-19T23:54:00Z",
            "user": "AAM0658",
            "src_ip": "10.0.4.21",
            "event_type": "http",
            "url": "https://wikileaks.org/leak/upload"
        },
        {
            "event_id": "sim-evt-006",
            "timestamp": "2026-08-19T23:56:00Z",
            "user": "AAM0658",
            "src_ip": "10.0.4.21",
            "event_type": "http",
            "url": "https://mega.nz/file/exfil_vault"
        }
    ]

    for idx, evt in enumerate(events, 1):
        console.print(f"[yellow]Sending event {idx}/{len(events)}: [{evt['event_type']}] {evt.get('filename') or evt.get('url') or evt.get('activity')}...[/yellow]")
        await push_log_event(r, evt, queue_key)
        await asyncio.sleep(1.0)

    console.print(f"[bold green]Successfully dumped {len(events)} attack stream events into Redis queue '{queue_key}'![/bold green]")
    await r.close()


if __name__ == "__main__":
    asyncio.run(simulate_attack_stream())
