"""
Multi-Target Traffic Dispatcher & Threat Stream Injector.
Transmits simulated network traffic to:
1. Redis Message Queue ('network_logs_queue')
2. FastAPI Gateway REST Ingestion ('/api/v1/logs/ingest')
3. Real Local Network Requests (for PyShark Sniffer validation)
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
    """
    Asynchronous traffic dispatcher supporting Redis MQ, HTTP Gateway, and live network calls.
    """
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
        """Connects to chosen backend or broker."""
        if self.target_mode == "redis":
            self.redis_client = aioredis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_timeout=5.0
            )
            await self.redis_client.ping()
            console.print(f"[green]✓ Connected to Redis Broker at {self.redis_url} (Queue: '{self.redis_queue}')[/green]")
            # Start background pubsub subscriber for live alert notifications
            self.pubsub_task = asyncio.create_task(self._listen_redis_alerts())
        else:
            self.http_client = httpx.AsyncClient(base_url=self.api_base_url, timeout=10.0)
            try:
                res = await self.http_client.get("/health")
                if res.status_code == 200:
                    console.print(f"[green]✓ Connected to FastAPI Gateway at {self.api_base_url}[/green]")
                else:
                    console.print(f"[yellow]⚠️ Gateway returned status {res.status_code}[/yellow]")
            except Exception as e:
                console.print(f"[yellow]⚠️ Could not reach FastAPI Gateway at {self.api_base_url}: {e}[/yellow]")

    async def _listen_redis_alerts(self):
        """Listens for real-time security incident alerts published by the backend."""
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
                            f"[{color}]🚨 [Real-Time Alert] User={ass.get('user')} "
                            f"Risk={ass.get('risk_score')}/100 Status={ass.get('status')} "
                            f"Policy={ass.get('policy_action')}[/{color}]"
                        )
                    except Exception:
                        pass
                await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    async def close(self):
        """Gracefully closes all connections."""
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
        Dispatches a single event to the configured target destination.
        """
        if self.target_mode == "redis":
            if self.redis_client is None:
                await self.connect()
            raw_str = json.dumps(event)
            await self.redis_client.lpush(self.redis_queue, raw_str)
            return {"mode": "redis", "status": "QUEUED", "queue": self.redis_queue}

        elif self.target_mode == "http":
            if self.http_client is None:
                await self.connect()
            res = await self.http_client.post("/api/v1/logs/ingest", json=event)
            if res.status_code == 200:
                return res.json()
            else:
                return {"mode": "http", "status": f"ERROR_{res.status_code}", "text": res.text}

        elif self.target_mode == "network":
            # Live local network HTTP call to test live PyShark sniffing
            if self.http_client is None:
                await self.connect()
            headers = {"X-User-Id": event.get("user", "AAM0658")}
            url = event.get("url") or f"/health?sim={event.get('event_id')}"
            try:
                await self.http_client.get(f"/health?user={event.get('user')}&sim={event.get('event_id')}", headers=headers)
            except Exception:
                pass
            return {"mode": "network", "status": "PACKET_TRANSMITTED"}

        return None

    async def run_scenario(
        self,
        scenario_name: str,
        events: List[Dict[str, Any]],
        delay_seconds: float = 0.05
    ):
        """
        Transmits a full sequence of scenario events and renders a real-time terminal monitor.
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
        table.add_column("Payload / URL", style="white")
        table.add_column("Size", justify="right", style="green")
        table.add_column("Gateway Assessment", justify="right")
        table.add_column("Policy Action", justify="right")

        last_assessment = None
        for idx, evt in enumerate(events, 1):
            detail = evt.get("url") or evt.get("filename") or evt.get("activity") or "payload"
            if len(str(detail)) > 42:
                detail = str(detail)[:39] + "..."

            size_str = f"{evt.get('size', 0):,.0f} B"

            response = await self.dispatch_event(evt)

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
                    size_str,
                    f"[{color}]{status} ({score}/100)[/{color}]",
                    f"[{action_color}]{action}[/{action_color}]"
                )
            else:
                table.add_row(
                    str(idx),
                    evt.get("event_type", ""),
                    evt.get("user", ""),
                    str(detail),
                    size_str,
                    "[cyan]QUEUED (MQ)[/cyan]",
                    "[dim]PENDING_ASYNC[/dim]"
                )

            # Throttle delay
            if delay_seconds > 0:
                await asyncio.sleep(delay_seconds)

        console.print(table)

        if last_assessment:
            score = last_assessment.get("risk_score", 0.0)
            status = last_assessment.get("status", "NORMAL")
            action = last_assessment.get("policy_action", "ALLOW")
            color = "bold green" if status == "NORMAL" else ("bold yellow" if status == "SUSPICIOUS" else "bold red")
            console.print(Panel(
                f"[bold]Final Window Security Status:[/bold] [{color}]{status}[/{color}]\n"
                f"[bold]Composite Risk Score:[/bold] [{color}]{score} / 100[/{color}]\n"
                f"[bold]Firewall Policy Decision:[/bold] [{color}]{action}[/{color}]\n"
                f"[bold]Top Behavioral Deviations:[/bold]\n" +
                "\n".join(f"  • {d}" for d in last_assessment.get("top_deviations", [])),
                title="🛡️ 5-Minute Window ML Assessment Result",
                border_style="red" if status == "CRITICAL" else "green"
            ))
