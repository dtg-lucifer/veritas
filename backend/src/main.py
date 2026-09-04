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
from dotenv import load_dotenv

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from rich.console import Console

from src.world_model_service import WorldModelService
from src.kafka_worker import KafkaFlowConsumerWorker, KAFKA_BOOTSTRAP_SERVERS, KAFKA_TOPIC

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
        console.print(f"[bold green]✓ Dashboard / Postman WebSocket client connected. Active connections: {len(self.active_connections)}[/bold green]")

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
    # Startup: Start Kafka Consumer Worker asynchronously
    await kafka_worker.start()
    yield
    # Shutdown: Stop Kafka Consumer Worker gracefully
    await kafka_worker.stop()


app = FastAPI(
    title="🛡️ Internal Firewall - AI World Model Gateway & SOC Stream",
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