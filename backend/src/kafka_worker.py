"""
Kafka Consumer Worker for Network Flow Ingestion & World Model Evaluation.
Consumes continuous network flow records from Apache Kafka topic 'network_flows',
aggregates them into 15-second state vectors, triggers the AI World Model
autoregressive forward simulation, and streams real-time threat alerts to the SOC WebSocket feed.
"""

import os
import json
import asyncio
import logging
from typing import List, Dict, Any, Optional, Callable
from rich.console import Console
from aiokafka import AIOKafkaConsumer

from src.world_model_service import WorldModelService

console = Console()
logger = logging.getLogger("kafka_worker")

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "network_flows")
KAFKA_GROUP_ID = os.getenv("KAFKA_GROUP_ID", "firewall_world_model_group")
FLUSH_INTERVAL_SECONDS = float(os.getenv("FLUSH_INTERVAL_SECONDS", "3.0"))


class KafkaFlowConsumerWorker:
    """
    Asynchronous Kafka worker consuming network flow telemetry.
    Orchestrates continuous flow aggregation, forward simulation, and WebSocket incident broadcasting.
    """

    def __init__(
        self,
        world_model_service: WorldModelService,
        broadcast_callback: Optional[Callable[[Dict[str, Any]], Any]] = None,
        alerts_list: Optional[List[Dict[str, Any]]] = None,
        bootstrap_servers: str = KAFKA_BOOTSTRAP_SERVERS,
        topic: str = KAFKA_TOPIC,
        group_id: str = KAFKA_GROUP_ID,
    ):
        self.world_model_service = world_model_service
        self.broadcast_callback = broadcast_callback
        self.alerts_list = alerts_list if alerts_list is not None else []
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.group_id = group_id

        self.consumer: Optional[AIOKafkaConsumer] = None
        self._consumer_task: Optional[asyncio.Task] = None
        self._timer_task: Optional[asyncio.Task] = None
        self.is_running = False

    async def start(self):
        """Initializes Kafka consumer connection and starts consumer and periodic flush tasks."""
        if self.is_running:
            return

        console.print(f"[bold cyan]🚀 Starting Kafka Consumer Worker on topic '{self.topic}' @ {self.bootstrap_servers}...[/bold cyan]")
        try:
            self.consumer = AIOKafkaConsumer(
                self.topic,
                bootstrap_servers=self.bootstrap_servers,
                group_id=self.group_id,
                value_deserializer=lambda m: json.loads(m.decode("utf-8")),
                auto_offset_reset="latest",
                enable_auto_commit=True,
            )
            await self.consumer.start()
            self.is_running = True
            console.print(f"[bold green]✓ Kafka Consumer connected successfully to {self.bootstrap_servers} (topic: {self.topic})[/bold green]")

            self._consumer_task = asyncio.create_task(self._consume_loop())
            self._timer_task = asyncio.create_task(self._periodic_flush_loop())

        except Exception as e:
            console.print(f"[bold red]❌ Failed to connect to Kafka at {self.bootstrap_servers}: {e}[/bold red]")
            self.is_running = False

    async def stop(self):
        """Stops tasks and closes Kafka connection gracefully."""
        self.is_running = False
        if self._consumer_task and not self._consumer_task.done():
            self._consumer_task.cancel()
        if self._timer_task and not self._timer_task.done():
            self._timer_task.cancel()

        if self.consumer:
            try:
                await self.consumer.stop()
                console.print("[yellow]Kafka consumer stopped gracefully.[/yellow]")
            except Exception as e:
                console.print(f"[red]Error stopping Kafka consumer: {e}[/red]")

    async def _consume_loop(self):
        """Main loop fetching flow events from Kafka and routing to World Model service."""
        batch: List[Dict[str, Any]] = []
        batch_size = 25

        try:
            async for msg in self.consumer:
                if not self.is_running:
                    break

                flow_record = msg.value
                batch.append(flow_record)

                if len(batch) >= batch_size:
                    alert = self.world_model_service.ingest_batch(batch)
                    batch.clear()
                    await self._handle_evaluation(alert)

        except asyncio.CancelledError:
            pass
        except Exception as e:
            console.print(f"[bold red]❌ Exception in Kafka consume loop: {e}[/bold red]")
        finally:
            # Flush remaining batch on exit
            if batch:
                alert = self.world_model_service.ingest_batch(batch)
                await self._handle_evaluation(alert)

    async def _periodic_flush_loop(self):
        """Timer task ensuring buffered flows are evaluated even during slow arrival rates."""
        while self.is_running:
            try:
                await asyncio.sleep(FLUSH_INTERVAL_SECONDS)
                if self.world_model_service.flow_buffer:
                    alert = self.world_model_service.process_pending_flows(flush_all=True)
                    await self._handle_evaluation(alert)
            except asyncio.CancelledError:
                break
            except Exception as e:
                console.print(f"[yellow]Warning in periodic flush loop: {e}[/yellow]")

    async def _handle_evaluation(self, alert: Optional[Dict[str, Any]]):
        """Dispatches an alert if threat detected, or prints normal evaluation status."""
        if alert:
            await self._dispatch_alert(alert)
        else:
            latest = self.world_model_service.latest_report
            if latest:
                risk = latest.get("max_infiltration_prob", 0.0) * 100
                stage = latest.get("peak_stage", "Benign")
                policy = latest.get("recommended_policy", "ALLOW")
                history_len = len(self.world_model_service.state_history)
                min_warmup = min(4, self.world_model_service.seq_len)
                if history_len < min_warmup:
                    console.print(
                        f"[bold cyan]⏳ [WARM-UP {history_len}/{min_warmup}][/bold cyan] Buffering Temporal Sequence | "
                        f"Risk: [cyan]{risk:.1f}%[/cyan] | Stage: [cyan]{stage}[/cyan] | Policy: [bold green]ALLOW[/bold green]"
                    )
                else:
                    console.print(
                        f"[bold green]🟢 [NORMAL TRAFFIC][/bold green] Evaluated Window | Risk: [bold green]{risk:.1f}%[/bold green] "
                        f"| Stage: [cyan]{stage}[/cyan] | Policy: [bold green]{policy}[/bold green]"
                    )

    async def _dispatch_alert(self, alert: Dict[str, Any]):
        """Dispatches an alert to WebSocket clients and internal alert log."""
        self.alerts_list.append(alert)
        if len(self.alerts_list) > 100:
            self.alerts_list.pop(0)

        console.print(
            f"[bold red]🚨 [WORLD MODEL ALERT][/bold red] Risk: [bold]{alert.get('max_infiltration_prob', 0)*100:.1f}%[/bold] "
            f"| Stage: [magenta]{alert.get('mitre_stage')}[/magenta] "
            f"| Policy: [bold yellow]{alert.get('policy_action')}[/bold yellow]"
        )

        if self.broadcast_callback:
            try:
                await self.broadcast_callback(alert)
            except Exception as e:
                console.print(f"[red]Error broadcasting alert to WebSockets: {e}[/red]")
