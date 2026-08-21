"""
Internal Firewall - FastAPI Gateway Backend with Multithreaded 5-Minute Window Redis Queue Worker.
Provides REST routes, 5-minute stateful window log aggregation, policy enforcement,
multithreaded Redis message broker consumer, and live WebSocket incident feeds for the SOC security dashboard.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from contextlib import asynccontextmanager
import asyncio
import json
import os

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from rich.console import Console

from app.predictor import SecurityModelPredictor
from app.log_buffer import TimeWindowLogAggregator
from app.redis_worker import MultithreadedRedisLogWorker, REDIS_URL, REDIS_QUEUE_KEY, ALERT_THRESHOLD, WINDOW_SECONDS

console = Console()

# Global in-memory components
predictor = SecurityModelPredictor()
log_buffer = TimeWindowLogAggregator(window_seconds=WINDOW_SECONDS)
recent_alerts: List[Dict[str, Any]] = []
blocked_users_and_ips: Dict[str, Dict[str, Any]] = {}


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


# --- MULTITHREADED REDIS QUEUE WORKER SETUP ---

redis_worker = MultithreadedRedisLogWorker(
    log_buffer=log_buffer,
    predictor=predictor,
    broadcast_callback=ws_hub.broadcast,
    alerts_list=recent_alerts,
    redis_url=REDIS_URL,
    queue_key=REDIS_QUEUE_KEY,
    alert_threshold=ALERT_THRESHOLD,
    window_seconds=WINDOW_SECONDS
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Launch Redis Queue Consumer & 5-minute Timer in dedicated background OS threads
    running_loop = asyncio.get_running_loop()
    redis_worker.start(loop=running_loop)
    yield
    # Shutdown: Stop Worker Threads Gracefully
    redis_worker.stop()


app = FastAPI(
    title="🛡️ Internal Firewall - Security Gateway & Anomaly Backend",
    description="SIH 2026: Multithreaded 5-Minute Behavioral Window Aggregation & Ensemble ML Anomaly Detection Gateway with Redis MQ.",
    version="1.0.0",
    lifespan=lifespan
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

class PredictRequest(BaseModel):
    user: str = Field(..., example="AAM0658")
    timestamp: Optional[str] = Field(None, example="2026-08-21")
    features: Dict[str, float] = Field(..., description="30-dimension behavioral feature dictionary")

class NetworkLogEvent(BaseModel):
    event_id: Optional[str] = Field(None, example="evt-1001")
    timestamp: Optional[str] = Field(None, example="2026-08-21T10:15:00Z")
    user: str = Field(..., example="AAM0658")
    src_ip: Optional[str] = Field("10.0.4.21", example="10.0.4.21")
    dst_ip: Optional[str] = Field("142.250.190.46", example="142.250.190.46")
    src_port: Optional[int] = Field(52341, example=52341)
    dst_port: Optional[int] = Field(443, example=443)
    protocol: Optional[str] = Field("TCP", example="TCP")
    event_type: str = Field(..., example="http", description="http, device, file_copy, email, connection")
    activity: Optional[str] = Field(None, example="Connect")
    url: Optional[str] = Field(None, example="https://wikileaks.org/upload")
    filename: Optional[str] = Field(None, example="classified_database_dump.zip")
    file_extension: Optional[str] = Field(None, example=".zip")
    size: Optional[float] = Field(None, example=45000000)
    download_bytes: Optional[float] = Field(None, example=45000000)
    upload_bytes: Optional[float] = Field(None, example=1024)
    to: Optional[str] = Field(None, example="external@competitor.com")
    bcc: Optional[str] = Field(None, example="home@gmail.com")

class PolicyEnforceRequest(BaseModel):
    user: str
    target_ip: Optional[str] = "10.0.4.21"
    action: str = Field("ISOLATE_DEVICE", example="ISOLATE_DEVICE")
    reason: Optional[str] = "Critical behavioral anomaly detected"


# --- API ROUTES ---

@app.get("/health")
def health_check():
    """Health check endpoint confirming model status & multithreaded Redis worker metrics."""
    return {
        "status": "healthy",
        "service": "Internal Firewall AI/ML Backend",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "models_ready": True,
        "active_ws_subscribers": len(ws_hub.active_connections),
        "window_seconds": redis_worker.window_seconds,
        "alert_threshold": redis_worker.alert_threshold,
        "redis_worker": {
            "queue": REDIS_QUEUE_KEY,
            "consumer_thread": redis_worker._consumer_thread.name if redis_worker._consumer_thread else None,
            "timer_thread": redis_worker._timer_thread.name if redis_worker._timer_thread else None,
            "is_alive": redis_worker.is_running,
            "ingested_count": redis_worker.ingested_count,
            "windows_evaluated": redis_worker.windows_evaluated,
            "alerts_generated": redis_worker.alerts_generated,
        }
    }


@app.get("/api/v1/redis/status")
def get_redis_worker_status():
    """Returns real-time queue processing and worker thread statistics."""
    return {
        "redis_url": REDIS_URL,
        "queue_key": REDIS_QUEUE_KEY,
        "is_running": redis_worker.is_running,
        "window_seconds": redis_worker.window_seconds,
        "alert_threshold": redis_worker.alert_threshold,
        "ingested_count": redis_worker.ingested_count,
        "windows_evaluated": redis_worker.windows_evaluated,
        "alerts_generated": redis_worker.alerts_generated
    }


@app.post("/api/v1/predict")
def predict_direct(payload: PredictRequest):
    """
    Direct model evaluation endpoint for a pre-computed 30-dimension behavioral feature vector.
    Uses full 4-model ensemble (LightGBM + Baseline + Isolation Forest + Autoencoder).
    """
    ts = payload.timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    result = predictor.evaluate_features(payload.user, ts, payload.features, include_autoencoder=True)
    return result


@app.post("/api/v1/logs/ingest")
async def ingest_network_log(event: NetworkLogEvent):
    """
    Direct HTTP Ingestion endpoint (Silent Ingest).
    Buffers event into the user's 5-minute sliding window without immediate prediction.
    Prediction occurs at the 5-minute timer cycle.
    """
    evt_dict = event.model_dump()
    log_buffer.ingest(evt_dict)
    
    return {
        "status": "QUEUED_IN_WINDOW",
        "user": event.user,
        "window_events_count": log_buffer.get_user_event_count(event.user)
    }


@app.get("/api/v1/alerts")
def get_recent_alerts():
    """Returns recent high-risk security incidents for the Dashboard."""
    return {
        "total_alerts": len(recent_alerts),
        "alerts": recent_alerts
    }


@app.get("/api/v1/users/{user}/window")
def get_user_window(user: str):
    """Returns active 5-minute time window state & manual evaluation on-demand."""
    date_key, features, event_count = log_buffer.aggregate_window(user)
    assessment = predictor.evaluate_features(user, date_key, features, include_autoencoder=True)
    return {
        "user": user,
        "event_count": event_count,
        "date_key": date_key,
        "features": features,
        "assessment": assessment
    }


@app.post("/api/v1/policy/enforce")
async def enforce_policy(req: PolicyEnforceRequest):
    """
    Simulates / triggers firewall isolation (e.g. iptables / nftables rule generation).
    """
    blocked_users_and_ips[req.user] = {
        "ip": req.target_ip,
        "action": req.action,
        "reason": req.reason,
        "isolated_at": datetime.now(timezone.utc).isoformat()
    }
    
    # Broadcast firewall policy action
    await ws_hub.broadcast({
        "type": "FIREWALL_POLICY_ENFORCED",
        "data": {
            "user": req.user,
            "ip": req.target_ip,
            "action": req.action,
            "reason": req.reason
        }
    })
    
    return {
        "status": "POLICY_APPLIED",
        "action": req.action,
        "target": f"{req.user} ({req.target_ip})",
        "message": f"Device {req.target_ip} successfully isolated from internal subnet."
    }


# WebSocket endpoints
@app.websocket("/ws")
@app.websocket("/ws/alerts")
@app.websocket("/api/v1/ws/alerts")
async def websocket_alerts_feed(websocket: WebSocket):
    """
    Live WebSocket endpoint streaming real-time security alerts to Postman and SOC dashboards.
    Alerts are pushed automatically when a 5-minute window evaluation exceeds the risk threshold (>= 65).
    """
    await ws_hub.connect(websocket)
    try:
        # Send an immediate connection welcome message so Postman confirms the channel is live
        await websocket.send_json({
            "type": "CONNECTION_ESTABLISHED",
            "message": "Connected to Internal Firewall Security Incident Stream",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "window_seconds": redis_worker.window_seconds,
            "alert_threshold": redis_worker.alert_threshold
        })
        while True:
            # Keep-alive loop
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        ws_hub.disconnect(websocket)
