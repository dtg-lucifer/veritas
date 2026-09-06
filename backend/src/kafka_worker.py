"""
Kafka Consumer Worker for Network Flow Ingestion & World Model Evaluation.
Consumes continuous network flow records from Apache Kafka topic 'network_flows',
validates schemas with Redis telemetry, aggregates them into 15-second state vectors,
triggers the AI World Model forward simulation, and streams real-time threat alerts to the SOC feed.
Handles malformed inputs gracefully without server panic or freeze.
"""

import os
import json
import asyncio
import logging
from typing import List, Dict, Any, Optional, Callable
from rich.console import Console
from aiokafka import AIOKafkaConsumer

from src.world_model_service import WorldModelService, EvaluationResult
from src.redis_metrics import redis_metrics
from src.config import get_config
from src.loki_logger import log_to_loki

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

        # Ensure Redis telemetry connection is initialized
        await redis_metrics.connect()

        console.print(f"[bold cyan]Starting Kafka Consumer Worker on topic '{self.topic}' @ {self.bootstrap_servers}...[/bold cyan]")
        try:
            self.consumer = AIOKafkaConsumer(
                self.topic,
                bootstrap_servers=self.bootstrap_servers,
                group_id=self.group_id,
                value_deserializer=self._safe_deserialize,
                auto_offset_reset="latest",
                enable_auto_commit=True,
            )
            await self.consumer.start()
            self.is_running = True
            console.print(f"[bold green]Kafka Consumer connected successfully to {self.bootstrap_servers} (topic: {self.topic})[/bold green]")

            self._consumer_task = asyncio.create_task(self._consume_loop())
            self._timer_task = asyncio.create_task(self._periodic_flush_loop())

        except Exception as e:
            console.print(f"[bold red]Failed to connect to Kafka at {self.bootstrap_servers}: {e}[/bold red]")
            self.is_running = False

    @staticmethod
    def _safe_deserialize(raw_bytes: bytes) -> Any:
        """Safely deserializes JSON messages without throwing unhandled exceptions."""
        try:
            return json.loads(raw_bytes.decode("utf-8"))
        except Exception as e:
            return {"_deserialization_error": str(e), "_raw_snippet": str(raw_bytes[:200])}

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

        await redis_metrics.close()

    async def _consume_loop(self):
        """Main loop fetching flow events from Kafka and routing to World Model service."""
        batch: List[Dict[str, Any]] = []
        batch_size = 25
        cfg = get_config()

        try:
            async for msg in self.consumer:
                if not self.is_running:
                    break

                flow_record = msg.value

                # 1. Validation & Schema Check
                if not isinstance(flow_record, dict) or "_deserialization_error" in flow_record:
                    err = flow_record.get("_deserialization_error", "Message is not a JSON object") if isinstance(flow_record, dict) else "Non-dict message"
                    await redis_metrics.record_log_ignored(
                        reason=err,
                        raw_payload=flow_record,
                        logger_id="malformed_producer"
                    )
                    continue

                # Ensure minimum required fields exist
                if not any(k in flow_record for k in ["dst_port", "protocol", "timestamp", "event_id"]):
                    await redis_metrics.record_log_ignored(
                        reason="Missing fundamental flow keys (dst_port/protocol/timestamp)",
                        raw_payload=flow_record,
                        logger_id=flow_record.get("logger_id", "unknown_logger")
                    )
                    continue

                # Check logger identity & WebRTC status
                logger_id = flow_record.get("logger_id") or flow_record.get("user") or flow_record.get("src_ip") or "default_logger"
                dst_port = flow_record.get("dst_port", 0)
                protocol = flow_record.get("protocol", 0)
                is_webrtc = (protocol == 17 and dst_port in cfg.traffic_policy.conferencing_ports)

                # Record processed log in Redis
                await redis_metrics.record_log_processed(count=1, logger_id=str(logger_id), is_webrtc=is_webrtc)

                batch.append(flow_record)

                if len(batch) >= batch_size:
                    eval_res = self.world_model_service.ingest_batch(batch)
                    batch.clear()
                    await self._handle_evaluation(eval_res)

        except asyncio.CancelledError:
            pass
        except Exception as e:
            console.print(f"[bold red]Exception in Kafka consume loop: {e}[/bold red]")
        finally:
            # Flush remaining batch on exit
            if batch:
                eval_res = self.world_model_service.ingest_batch(batch)
                await self._handle_evaluation(eval_res)

    async def _periodic_flush_loop(self):
        """Timer task ensuring buffered flows are evaluated even during slow arrival rates."""
        while self.is_running:
            try:
                await asyncio.sleep(FLUSH_INTERVAL_SECONDS)
                if self.world_model_service.flow_buffer:
                    eval_res = self.world_model_service.process_pending_flows(flush_all=True)
                    await self._handle_evaluation(eval_res)
            except asyncio.CancelledError:
                break
            except Exception as e:
                console.print(f"[yellow]Warning in periodic flush loop: {e}[/yellow]")

    async def _handle_evaluation(self, eval_res: EvaluationResult):
        """Dispatches an alert if threat detected, or logs clean evaluation status."""
        if not eval_res.evaluated:
            # Active window is still accumulating flows; no new evaluation occurred
            return

        # Record evaluation metrics in Redis
        await redis_metrics.record_evaluation(
            risk_pct=eval_res.risk_pct,
            stage=eval_res.stage,
            policy=eval_res.policy,
            flow_count=eval_res.flow_count,
        )

        if eval_res.is_threat and eval_res.alert_payload:
            await self._dispatch_alert(eval_res.alert_payload)
        else:
            if eval_res.is_conferencing:
                console.print(
                    f"[bold cyan][MEDIA STREAMING / RTP][/bold cyan] Evaluated Window | "
                    f"Risk: [bold green]{eval_res.risk_pct:.1f}%[/bold green] | "
                    f"Stage: [cyan]{eval_res.stage}[/cyan] | "
                    f"Policy: [bold green]ALLOW[/bold green] (Real-Time Media Baseline)"
                )
                log_to_loki(
                    message=f"[MEDIA STREAMING / RTP] Evaluated Window | Risk: {eval_res.risk_pct:.1f}% | Stage: {eval_res.stage} | Policy: ALLOW",
                    level="info",
                    event_type="media_stream",
                    extra_labels={"policy": "ALLOW", "stage": eval_res.stage, "severity": "NORMAL"},
                    details={"risk_pct": eval_res.risk_pct, "stage": eval_res.stage, "flow_count": eval_res.flow_count}
                )
            else:
                history_len = len(self.world_model_service.state_history)
                cfg = get_config()
                min_warmup = min(cfg.thresholds.min_warmup_windows, self.world_model_service.seq_len)
                if history_len < min_warmup:
                    console.print(
                        f"[bold cyan][WARM-UP {history_len}/{min_warmup}][/bold cyan] Buffering Temporal Sequence | "
                        f"Risk: [cyan]{eval_res.risk_pct:.1f}%[/cyan] | Stage: [cyan]{eval_res.stage}[/cyan] | Policy: [bold green]ALLOW[/bold green]"
                    )
                else:
                    console.print(
                        f"[bold green][NORMAL TRAFFIC][/bold green] Evaluated Window | "
                        f"Risk: [bold green]{eval_res.risk_pct:.1f}%[/bold green] | "
                        f"Stage: [cyan]{eval_res.stage}[/cyan] | "
                        f"Policy: [bold green]{eval_res.policy}[/bold green]"
                    )
                    log_to_loki(
                        message=f"[NORMAL TRAFFIC] Evaluated Window | Risk: {eval_res.risk_pct:.1f}% | Stage: {eval_res.stage} | Policy: {eval_res.policy}",
                        level="info",
                        event_type="normal_traffic",
                        extra_labels={"policy": eval_res.policy, "stage": eval_res.stage, "severity": eval_res.severity},
                        details={"risk_pct": eval_res.risk_pct, "stage": eval_res.stage, "flow_count": eval_res.flow_count}
                    )

    async def _dispatch_alert(self, alert: Dict[str, Any]):
        """Dispatches an alert to WebSocket clients, internal alert log, and Grafana Loki."""
        self.alerts_list.append(alert)
        if len(self.alerts_list) > 100:
            self.alerts_list.pop(0)

        risk_pct = alert.get("max_infiltration_prob", 0) * 100
        stage = alert.get("mitre_stage", "Unknown")
        policy = alert.get("policy_action", "ALERT_ADMIN")
        target = alert.get("target", "10.0.4.21")
        sev = alert.get("severity", "CRITICAL" if risk_pct >= 70 else "SUSPICIOUS")

        console.print(
            f"[bold red][WORLD MODEL ALERT][/bold red] Risk: [bold]{risk_pct:.1f}%[/bold] "
            f"| Stage: [magenta]{stage}[/magenta] "
            f"| Policy: [bold yellow]{policy}[/bold yellow]"
        )

        # Ship alert event to Grafana Loki
        log_to_loki(
            message=f"[WORLD MODEL ALERT] Target: {target} | Risk: {risk_pct:.1f}% | Stage: {stage} | Policy: {policy}",
            level="critical" if sev == "CRITICAL" else "warn",
            event_type="threat_alert",
            extra_labels={
                "severity": sev,
                "policy": policy,
                "stage": stage,
                "target": target,
            },
            details=alert,
        )

        if self.broadcast_callback:
            try:
                await self.broadcast_callback(alert)
            except Exception as e:
                console.print(f"[red]Error broadcasting alert to WebSockets: {e}[/red]")
