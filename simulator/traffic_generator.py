"""
Traffic Dispatcher & Stream Injector.
Transmits simulated network log events to either Redis Message Queue ('network_logs_queue')
or directly to the FastAPI Ingest REST endpoint with live security assessment feedback.
"""

import json
import asyncio
from typing import List, Dict, Any, Optional
import httpx
import redis.asyncio as aioredis
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


class TrafficDispatcher:
    def __init__(
        self,
        target_mode: str = "redis",
        redis_url: str = "redis://localhost:6379/0",
        redis_queue: str = "network_logs_queue",
        api_base_url: str = "http://localhost:8000"
    ):
        self.target_mode = target_mode.lower()
        self.redis_url = redis_url
        self.redis_queue = redis_queue
        self.api_base_url = api_base_url
        self.redis_client: Optional[aioredis.Redis] = None
        self.http_client: Optional[httpx.AsyncClient] = None
        self.pubsub_task: Optional[asyncio.Task] = None
        self.received_alerts: List[Dict[str, Any]] = []

    async def connect(self):
        if self.target_mode == "redis":
            self.redis_client = aioredis.from_url(self.redis_url, decode_responses=True)
            await self.redis_client.ping()
            console.print(f"[green]✓ Connected to Redis Broker at {self.redis_url} (Queue: '{self.redis_queue}')[/green]")
            # Start background pubsub listener for live alert notifications
            self.pubsub_task = asyncio.create_task(self._listen_redis_alerts())
        else:
            self.http_client = httpx.AsyncClient(base_url=self.api_base_url, timeout=10.0)
            res = await self.http_client.get("/health")
            if res.status_code == 200:
                console.print(f"[green]✓ Connected to FastAPI Gateway at {self.api_base_url}[/green]")
            else:
                console.print(f"[yellow]⚠️ Gateway returned status {res.status_code}[/yellow]")

    async def _listen_redis_alerts(self):
        """Listens for real-time security alerts on Redis Pub/Sub."""
        try:
            pubsub = self.redis_client.pubsub()
            await pubsub.subscribe("security_alerts_pubsub")
            while True:
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if message and message.get("data"):
                    try:
                        data = json.loads(message["data"])
                        self.received_alerts.append(data)
                        ass = data.get("alert", {})
                        color = "bold red" if ass.get("status") == "CRITICAL" else "bold yellow"
                        console.print(
                            f"[{color}]⚡ [Redis Alert Received] User={ass.get('user')} Risk={ass.get('risk_score')}/100 "
                            f"Status={ass.get('status')} Action={ass.get('policy_action')}[/{color}]"
                        )
                    except Exception:
                        pass
                await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    async def close(self):
        if self.pubsub_task:
            self.pubsub_task.cancel()
            try:
                await self.pubsub_task
            except asyncio.CancelledError:
                pass
        if self.redis_client:
            await self.redis_client.close()
        if self.http_client:
            await self.http_client.aclose()

    async def dispatch_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Dispatches a single event to target destination (Redis queue or HTTP).
        """
        if self.target_mode == "redis":
            raw = json.dumps(event)
            await self.redis_client.lpush(self.redis_queue, raw)
            return {"mode": "redis", "status": "QUEUED", "queue": self.redis_queue}
        else:
            res = await self.http_client.post("/api/v1/logs/ingest", json=event)
            if res.status_code == 200:
                return res.json()
            else:
                return {"mode": "http", "status": f"ERROR_{res.status_code}", "text": res.text}

    async def run_scenario(
        self,
        scenario_name: str,
        events: List[Dict[str, Any]],
        delay_seconds: float = 0.5
    ):
        """
        Executes a sequence of scenario events and renders a real-time terminal monitor.
        """
        console.print(Panel.fit(
            f"[bold cyan]🚀 Injecting Scenario: {scenario_name}[/bold cyan]\n"
            f"[yellow]Target: {self.target_mode.upper()} | Total Events: {len(events)} | Interval: {delay_seconds}s[/yellow]",
            border_style="cyan"
        ))

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("#", justify="right", style="dim")
        table.add_column("Type", style="cyan")
        table.add_column("User", style="yellow")
        table.add_column("Payload Details", style="white")
        table.add_column("Gateway Assessment", justify="right")
        table.add_column("Policy Action", justify="right")

        last_assessment = None
        for idx, evt in enumerate(events, 1):
            detail = evt.get("filename") or evt.get("url") or evt.get("activity") or str(evt.get("size"))
            if len(str(detail)) > 38:
                detail = str(detail)[:35] + "..."

            response = await self.dispatch_event(evt)
            
            # Format assessment column
            if self.target_mode == "http" and response and "assessment" in response:
                ass = response["assessment"]
                last_assessment = ass
                score = ass.get("risk_score", 0.0)
                status = ass.get("status", "NORMAL")
                action = ass.get("policy_action", "ALLOW")

                color = "green" if status == "NORMAL" else ("yellow" if status == "SUSPICIOUS" else "bold red")
                action_color = "green" if action == "ALLOW" else ("yellow" if action == "ALERT_ADMIN" else "bold red")

                table.add_row(
                    str(idx),
                    evt.get("event_type", ""),
                    evt.get("user", ""),
                    str(detail),
                    f"[{color}]{status} ({score}/100)[/{color}]",
                    f"[{action_color}]{action}[/{action_color}]"
                )
            else:
                table.add_row(
                    str(idx),
                    evt.get("event_type", ""),
                    evt.get("user", ""),
                    str(detail),
                    "[green]Pushed to Broker[/green]",
                    "[dim]5-Min Window[/dim]"
                )

            await asyncio.sleep(delay_seconds)

        console.print(table)
        
        # Display top deviations if available
        if last_assessment and last_assessment.get("top_deviations"):
            console.print("[bold yellow]🔍 Top ML Baseline Deviations:[/bold yellow]")
            for dev in last_assessment["top_deviations"]:
                console.print(f"  • {dev}")

        console.print(f"[bold green]✓ Scenario '{scenario_name}' completed successfully![/bold green]\n")
