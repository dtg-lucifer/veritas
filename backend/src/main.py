"""
Internal Firewall - FastAPI Gateway Backend with Kafka Ingestion & AI World Model Forward Simulation.
Consumes real-time/replayed flow telemetry from Apache Kafka, aggregates 15-second state vectors,
performs K-step autoregressive forward simulation, enforces policy actions,
and streams live security incidents via WebSockets to SOC dashboards.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from contextlib import asynccontextmanager
import asyncio
import json
import os
import time
import resource
from dotenv import load_dotenv

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from rich.console import Console

from src.world_model_service import WorldModelService
from src.kafka_worker import KafkaFlowConsumerWorker, KAFKA_BOOTSTRAP_SERVERS, KAFKA_TOPIC
from src.config import get_config, save_config, FirewallConfig
from src.redis_metrics import redis_metrics

SERVER_START_TIME = time.time()

load_dotenv()

console = Console()

# Global in-memory components
recent_alerts: List[Dict[str, Any]] = []
blocked_users_and_ips: Dict[str, Dict[str, Any]] = {}

# Initialize AI World Model Service
world_model_service = WorldModelService(
    window_size_seconds=int(os.getenv("WINDOW_SECONDS", "15")),
    rollout_steps=int(os.getenv("ROLLOUT_STEPS", "5")),
    alert_threshold=float(os.getenv("ALERT_THRESHOLD", "40.0")),
)


# --- WEBSOCKET CONNECTION MANAGER ---

class WebSocketHub:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        console.print(f"[bold green]Dashboard / Postman WebSocket client connected. Active connections: {len(self.active_connections)}[/bold green]")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            console.print(f"[yellow]Dashboard client disconnected. Active connections: {len(self.active_connections)}[/yellow]")

    async def broadcast(self, payload: dict):
        if not self.active_connections:
            return
        for connection in list(self.active_connections):
            try:
                await connection.send_json(payload)
            except Exception:
                self.disconnect(connection)


ws_hub = WebSocketHub()

# --- KAFKA CONSUMER WORKER SETUP ---

kafka_worker = KafkaFlowConsumerWorker(
    world_model_service=world_model_service,
    broadcast_callback=ws_hub.broadcast,
    alerts_list=recent_alerts,
    bootstrap_servers=os.getenv("KAFKA_BOOTSTRAP_SERVERS", KAFKA_BOOTSTRAP_SERVERS),
    topic=os.getenv("KAFKA_TOPIC", KAFKA_TOPIC),
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Start Redis telemetry & Kafka Consumer Worker asynchronously
    await redis_metrics.connect()
    await kafka_worker.start()
    yield
    # Shutdown: Stop Kafka Consumer Worker and close Redis gracefully
    await kafka_worker.stop()
    await redis_metrics.close()


app = FastAPI(
    title="Internal Firewall - AI World Model Gateway & SOC Stream",
    description="SIH 2026: Apache Kafka Stream Ingestion, 15s Network State Aggregation, Autoregressive Forward Simulation & Threat Alerts.",
    version="2.0.0",
    lifespan=lifespan,
)

# CORS middleware for Next.js / React SOC Dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- PYDANTIC SCHEMAS ---

class NetworkFlowRecord(BaseModel):
    timestamp: Optional[str] = Field(None, example="2026-09-04 10:15:00")
    dst_port: Optional[int] = Field(443, example=443)
    protocol: Optional[int] = Field(6, example=6)
    flow_duration: Optional[float] = Field(120000.0, example=120000.0)
    tot_fwd_pkts: Optional[int] = Field(10, example=10)
    tot_bwd_pkts: Optional[int] = Field(8, example=8)
    tot_fwd_bytes: Optional[int] = Field(4500, example=4500)
    tot_bwd_bytes: Optional[int] = Field(8200, example=8200)
    flow_bytes_per_sec: Optional[float] = Field(1058.0, example=1058.0)
    flow_pkts_per_sec: Optional[float] = Field(15.0, example=15.0)
    syn_flag_cnt: Optional[int] = Field(1, example=1)
    ack_flag_cnt: Optional[int] = Field(1, example=1)
    rst_flag_cnt: Optional[int] = Field(0, example=0)
    fin_flag_cnt: Optional[int] = Field(0, example=0)
    psh_flag_cnt: Optional[int] = Field(1, example=1)
    urg_flag_cnt: Optional[int] = Field(0, example=0)
    label: Optional[str] = Field("Benign", example="Benign")


class PolicyEnforceRequest(BaseModel):
    target_ip: str = Field("10.0.4.21", example="10.0.4.21")
    action: str = Field("ISOLATE_DEVICE", example="ISOLATE_DEVICE")
    reason: Optional[str] = "Critical forward infiltration risk detected by AI World Model"


# --- API ROUTES ---

@app.get("/health")
def health_check():
    """Health check endpoint confirming World Model status, Kafka consumer, and WebSocket connections."""
    wm_status = world_model_service.get_status()
    cfg = get_config()
    return {
        "status": "healthy",
        "service": "Internal Firewall AI World Model Backend",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model_ready": wm_status["model_loaded"],
        "active_ws_subscribers": len(ws_hub.active_connections),
        "kafka_worker": {
            "topic": kafka_worker.topic,
            "bootstrap_servers": kafka_worker.bootstrap_servers,
            "is_running": kafka_worker.is_running,
        },
        "network_config": {
            "connected_clients_count": cfg.network.connected_clients_count,
            "allow_webrtc_conferencing": cfg.traffic_policy.allow_webrtc_conferencing,
            "alert_threshold": cfg.thresholds.alert_threshold,
            "critical_threshold": cfg.thresholds.critical_threshold,
        },
        "world_model": {
            "window_size_seconds": wm_status["window_size_seconds"],
            "rollout_steps": wm_status["rollout_steps"],
            "alert_threshold": wm_status["alert_threshold"],
            "flows_ingested": wm_status["metrics"]["flows_ingested"],
            "windows_evaluated": wm_status["metrics"]["windows_evaluated"],
            "simulations_completed": wm_status["metrics"]["simulations_completed"],
            "alerts_generated": wm_status["metrics"]["alerts_generated"],
            "peak_risk_observed": wm_status["metrics"]["peak_risk_observed"],
        },
    }


@app.get("/api/v1/kafka/status")
def get_kafka_status():
    """Returns Kafka consumer connectivity and flow ingestion telemetry."""
    return {
        "topic": kafka_worker.topic,
        "bootstrap_servers": kafka_worker.bootstrap_servers,
        "is_running": kafka_worker.is_running,
        "flows_ingested": world_model_service.metrics["flows_ingested"],
        "pending_flows": len(world_model_service.flow_buffer),
        "windows_evaluated": world_model_service.metrics["windows_evaluated"],
    }


@app.get("/api/v1/simulation/latest")
def get_latest_simulation():
    """Returns the most recent K-step forward simulation rollout report."""
    if not world_model_service.latest_report:
        return {
            "status": "WAITING_FOR_DATA",
            "message": "Awaiting network flow ingestion to compile initial temporal window.",
        }
    return {
        "status": "OK",
        "simulation": world_model_service.latest_report,
    }


@app.get("/api/v1/simulation/status")
def get_simulation_status():
    """Returns complete stateful metrics and active state vector count."""
    return world_model_service.get_status()


@app.post("/api/v1/simulation/reset")
def reset_simulation():
    """Resets flow buffer and historical state window context for clean baseline tests."""
    world_model_service.reset()
    recent_alerts.clear()
    return {
        "status": "RESET_SUCCESSFUL",
        "message": "World Model state history and alerts cleared.",
    }


# --- CONFIGURATION ENDPOINTS ---

@app.get("/api/v1/config")
def get_firewall_configuration():
    """Returns active firewall configuration including client scaling, traffic policy, and thresholds."""
    cfg = get_config()
    return {
        "status": "OK",
        "config": cfg.model_dump(),
    }


@app.post("/api/v1/config")
def update_firewall_configuration(new_config: FirewallConfig):
    """
    Dynamically updates network client capacity, WebRTC policies, or detection thresholds
    and persists them to firewall_config.yaml without restarting the server.
    """
    success = save_config(new_config)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to save configuration to disk")

    # Update world model service runtime parameters
    world_model_service.alert_threshold = new_config.thresholds.alert_threshold
    world_model_service.window_size_seconds = new_config.thresholds.window_size_seconds

    return {
        "status": "CONFIG_UPDATED",
        "message": "Firewall configuration successfully updated and persisted.",
        "config": new_config.model_dump(),
    }


# --- PROMETHEUS METRICS SCRAPING ENDPOINT ---

@app.get("/metrics", response_class=PlainTextResponse)
async def get_prometheus_metrics():
    """
    Exposes real-time firewall, AI World Model, and system metrics in Prometheus exposition format.
    Scraped automatically by Prometheus on port 9090.
    """
    now = time.time()
    uptime = now - SERVER_START_TIME

    # Process memory (resident set size in bytes)
    rusage = resource.getrusage(resource.RUSAGE_SELF)
    mem_bytes = rusage.ru_maxrss * 1024  # Linux ru_maxrss is in KiB
    cpu_user = rusage.ru_utime
    cpu_sys = rusage.ru_stime

    # Telemetry and World Model metrics
    wm_metrics = world_model_service.get_status()
    flows_ingested = wm_metrics.get("flows_ingested", 0)
    windows_evaluated = wm_metrics.get("windows_evaluated", 0)
    alerts_generated = wm_metrics.get("alerts_generated", 0)

    cfg = get_config()
    connected_clients = cfg.network.connected_clients_count
    alert_thresh = cfg.thresholds.alert_threshold
    crit_thresh = cfg.thresholds.critical_threshold

    # Redis counters if available
    try:
        redis_data = await redis_metrics.get_all_metrics()
        counters = redis_data.get("counters", {})
        logs_proc = counters.get("logs_processed", 0)
        logs_ign = counters.get("logs_ignored", 0)
        logs_conf = counters.get("logs_webrtc_conferencing", 0)
        logs_mal = counters.get("logs_malformed_schema", 0)
        active_loggers_count = len(redis_data.get("active_loggers", []))
    except Exception:
        logs_proc, logs_ign, logs_conf, logs_mal, active_loggers_count = 0, 0, 0, 0, 0

    ws_subs = len(ws_hub.active_connections)

    metrics = [
        "# HELP firewall_uptime_seconds Total runtime of the firewall backend in seconds.",
        "# TYPE firewall_uptime_seconds counter",
        f"firewall_uptime_seconds {uptime:.2f}",
        "",
        "# HELP firewall_process_memory_bytes Resident memory size of the firewall backend.",
        "# TYPE firewall_process_memory_bytes gauge",
        f"firewall_process_memory_bytes {mem_bytes}",
        "",
        "# HELP firewall_process_cpu_seconds_total Total user and system CPU time.",
        "# TYPE firewall_process_cpu_seconds_total counter",
        f'firewall_process_cpu_seconds_total{{mode="user"}} {cpu_user:.2f}',
        f'firewall_process_cpu_seconds_total{{mode="system"}} {cpu_sys:.2f}',
        "",
        "# HELP firewall_flows_ingested_total Total raw network flows ingested into World Model buffer.",
        "# TYPE firewall_flows_ingested_total counter",
        f"firewall_flows_ingested_total {flows_ingested}",
        "",
        "# HELP firewall_windows_evaluated_total Total 15-second state windows evaluated.",
        "# TYPE firewall_windows_evaluated_total counter",
        f"firewall_windows_evaluated_total {windows_evaluated}",
        "",
        "# HELP firewall_alerts_generated_total Total security incident alerts triggered by forward rollout.",
        "# TYPE firewall_alerts_generated_total counter",
        f"firewall_alerts_generated_total {alerts_generated}",
        "",
        "# HELP firewall_active_ws_subscribers Number of connected real-time SOC dashboard WebSocket clients.",
        "# TYPE firewall_active_ws_subscribers gauge",
        f"firewall_active_ws_subscribers {ws_subs}",
        "",
        "# HELP firewall_active_loggers_count Number of active distributed network loggers streaming telemetry.",
        "# TYPE firewall_active_loggers_count gauge",
        f"firewall_active_loggers_count {active_loggers_count}",
        "",
        "# HELP firewall_logs_processed_total Total flow records processed across Kafka/Redis.",
        "# TYPE firewall_logs_processed_total counter",
        f"firewall_logs_processed_total {logs_proc}",
        "",
        "# HELP firewall_logs_ignored_total Total flow records ignored or rejected.",
        "# TYPE firewall_logs_ignored_total counter",
        f"firewall_logs_ignored_total {logs_ign}",
        "",
        "# HELP firewall_logs_webrtc_conferencing_total Total media/conferencing packets normalized.",
        "# TYPE firewall_logs_webrtc_conferencing_total counter",
        f"firewall_logs_webrtc_conferencing_total {logs_conf}",
        "",
        "# HELP firewall_logs_malformed_total Total malformed schema logs encountered.",
        "# TYPE firewall_logs_malformed_total counter",
        f"firewall_logs_malformed_total {logs_mal}",
        "",
        "# HELP firewall_connected_clients_capacity Configured connected client workstations capacity.",
        "# TYPE firewall_connected_clients_capacity gauge",
        f"firewall_connected_clients_capacity {connected_clients}",
        "",
        "# HELP firewall_threshold_alert Alert threshold ratio for forward infiltration risk.",
        "# TYPE firewall_threshold_alert gauge",
        f"firewall_threshold_alert {alert_thresh:.4f}",
        "",
        "# HELP firewall_threshold_critical Critical isolation threshold ratio for forward infiltration risk.",
        "# TYPE firewall_threshold_critical gauge",
        f"firewall_threshold_critical {crit_thresh:.4f}",
        "",
    ]
    return "\n".join(metrics) + "\n"


# --- REDIS TELEMETRY METRICS ENDPOINT ---

@app.get("/api/v1/metrics/redis")
async def get_redis_telemetry_metrics():
    """
    Retrieves distributed ingestion telemetry, error counters (logs_processed, logs_ignored),
    active loggers, and recent malformed packet samples from Redis for SOC dashboard visualization.
    """
    return await redis_metrics.get_all_metrics()


@app.post("/api/v1/logs/ingest")
async def ingest_network_flow(flow: NetworkFlowRecord):
    """
    Direct HTTP flow ingestion endpoint.
    Allows pushing flow records directly to the backend flow buffer without going through Kafka.
    """
    flow_dict = flow.model_dump()
    world_model_service.ingest_flow(flow_dict)
    return {
        "status": "INGESTED",
        "buffered_flows": len(world_model_service.flow_buffer),
    }


@app.get("/api/v1/alerts")
def get_recent_alerts():
    """Returns recent forward threat alerts generated by the World Model."""
    return {
        "total_alerts": len(recent_alerts),
        "alerts": recent_alerts,
    }


@app.post("/api/v1/policy/enforce")
async def enforce_policy(req: PolicyEnforceRequest):
    """Triggers or simulates host/subnet isolation based on forward simulation alerts."""
    blocked_users_and_ips[req.target_ip] = {
        "ip": req.target_ip,
        "action": req.action,
        "reason": req.reason,
        "isolated_at": datetime.now(timezone.utc).isoformat(),
    }

    # Broadcast firewall policy action
    await ws_hub.broadcast({
        "type": "FIREWALL_POLICY_ENFORCED",
        "data": {
            "ip": req.target_ip,
            "action": req.action,
            "reason": req.reason,
        },
    })

    return {
        "status": "POLICY_APPLIED",
        "action": req.action,
        "target": req.target_ip,
        "message": f"Target {req.target_ip} successfully blocked/isolated by firewall policy.",
    }


# --- WEBSOCKET ENDPOINTS ---

@app.websocket("/ws")
@app.websocket("/ws/alerts")
@app.websocket("/api/v1/ws/alerts")
async def websocket_alerts_feed(websocket: WebSocket):
    """
    Live WebSocket endpoint streaming real-time forward simulation threat alerts
    to SOC dashboards and Postman.
    """
    await ws_hub.connect(websocket)
    try:
        # Welcome message acknowledging connection
        await websocket.send_json({
            "type": "CONNECTION_ESTABLISHED",
            "message": "Connected to AI World Model Threat Telemetry Stream",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "window_size_seconds": world_model_service.window_size_seconds,
            "rollout_steps": world_model_service.rollout_steps,
        })
        while True:
            # Keep-alive loop
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        ws_hub.disconnect(websocket)