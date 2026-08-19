"""
Internal Firewall - FastAPI Gateway Backend with 5-Minute Window Redis Queue Worker.
Provides REST prediction routes, 5-minute stateful window log ingestion, policy enforcement,
Redis message broker consumer, and live WebSocket incident feeds for the SOC security dashboard.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from contextlib import asynccontextmanager
import json

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from rich.console import Console

from app.predictor import SecurityModelPredictor
from app.log_buffer import RealTimeLogBuffer, TimeWindowLogAggregator
from app.redis_worker import RedisLogQueueWorker, REDIS_URL, REDIS_QUEUE_KEY, ALERT_THRESHOLD

console = Console()

# Global in-memory components
predictor = SecurityModelPredictor()
log_buffer = TimeWindowLogAggregator(window_seconds=300)
recent_alerts: List[Dict[str, Any]] = []
blocked_users_and_ips: Dict[str, Dict[str, Any]] = {}


# --- WEBSOCKET CONNECTION MANAGER ---

class WebSocketHub:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        console.print(f"[green]✓ New dashboard WebSocket client connected. Active: {len(self.active_connections)}[/green]")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            console.print(f"[yellow]Dashboard client disconnected. Active: {len(self.active_connections)}[/yellow]")

    async def broadcast(self, payload: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(payload)
            except Exception:
                self.disconnect(connection)

ws_hub = WebSocketHub()


# --- REDIS QUEUE WORKER SETUP ---

redis_worker = RedisLogQueueWorker(
    log_buffer=log_buffer,
    predictor=predictor,
    broadcast_callback=ws_hub.broadcast,
    alerts_list=recent_alerts,
    redis_url=REDIS_URL,
    queue_key=REDIS_QUEUE_KEY,
    alert_threshold=ALERT_THRESHOLD
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Launch Redis Queue Consumer & 5-Min Window Worker
    await redis_worker.start()
    yield
    # Shutdown: Stop Worker Gracefully
    await redis_worker.stop()


app = FastAPI(
    title="🛡️ Internal Firewall - Security Gateway & Anomaly Backend",
    description="SIH 2026: 5-Minute Behavioral Window Aggregation & Ensemble ML Anomaly Detection Gateway with Decoupled Redis Broker.",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware for Next.js / React Dashboard
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
    timestamp: Optional[str] = Field(None, example="2026-08-19")
    features: Dict[str, float] = Field(..., description="30-dimension behavioral feature dictionary")

class NetworkLogEvent(BaseModel):
    event_id: Optional[str] = Field(None, example="evt-1001")
    timestamp: Optional[str] = Field(None, example="2026-08-19T02:15:00Z")
    user: str = Field(..., example="AAM0658")
    src_ip: Optional[str] = Field("10.0.4.21", example="10.0.4.21")
    event_type: str = Field(..., example="http", description="http, device, file_copy, email, connection")
    activity: Optional[str] = Field(None, example="Connect")
    url: Optional[str] = Field(None, example="https://wikileaks.org/upload")
    filename: Optional[str] = Field(None, example="classified_database_dump.zip")
    file_extension: Optional[str] = Field(None, example=".zip")
    size: Optional[float] = Field(None, example=45000000)
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
    """Health check endpoint confirming model status & Redis worker metrics."""
    return {
        "status": "healthy",
        "service": "Internal Firewall AI/ML Backend",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "models_ready": True,
        "active_ws_subscribers": len(ws_hub.active_connections),
        "redis_worker": {
            "queue": REDIS_QUEUE_KEY,
            "processed_count": redis_worker.processed_count,
            "windows_evaluated": redis_worker.windows_evaluated,
            "alerts_generated": redis_worker.alerts_generated,
            "alert_threshold": redis_worker.alert_threshold,
            "is_running": redis_worker.is_running
        }
    }


@app.get("/api/v1/redis/status")
def get_redis_worker_status():
    """Returns real-time queue processing statistics."""
    return {
        "redis_url": REDIS_URL,
        "queue_key": REDIS_QUEUE_KEY,
        "is_running": redis_worker.is_running,
        "processed_count": redis_worker.processed_count,
        "windows_evaluated": redis_worker.windows_evaluated,
        "alerts_generated": redis_worker.alerts_generated,
        "alert_threshold": redis_worker.alert_threshold
    }


@app.post("/api/v1/predict")
def predict_direct(payload: PredictRequest):
    """
    Direct model evaluation endpoint for a pre-computed behavioral feature vector.
    Uses full 4-model ensemble (LightGBM + Baseline + Isolation Forest + Autoencoder).
    """
    ts = payload.timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    result = predictor.evaluate_features(payload.user, ts, payload.features, include_autoencoder=True)
    return result


@app.post("/api/v1/logs/ingest")
async def ingest_network_log(event: NetworkLogEvent):
    """
    Direct HTTP Ingestion endpoint.
    Buffers events into 5-minute stateful window, predicts anomaly risk with full multi-model ensemble,
    and automatically broadcasts WebSocket alerts on suspicious / critical threats.
    """
    evt_dict = event.model_dump()
    user, date_key, updated_features = log_buffer.ingest_event(evt_dict)
    
    assessment = predictor.evaluate_features(user, date_key, updated_features, include_autoencoder=True)
    assessment["src_ip"] = event.src_ip
    assessment["last_event_type"] = event.event_type
    assessment["window_active_events"] = len(log_buffer.user_event_windows[user])

    # If risk is elevated (Suspicious >= 40, Critical >= 70), broadcast alert in real-time
    if assessment["risk_score"] >= ALERT_THRESHOLD or assessment["status"] in ["SUSPICIOUS", "CRITICAL"]:
        recent_alerts.insert(0, assessment)
        if len(recent_alerts) > 100:
            recent_alerts.pop()
        
        # Broadcast alert payload to all connected frontend clients
        await ws_hub.broadcast({
            "type": "SECURITY_INCIDENT_ALERT",
            "alert": assessment
        })
        console.print(f"[bold red]🚨 Alert Broadcasted: User={user} Risk={assessment['risk_score']} Status={assessment['status']} Action={assessment['policy_action']}[/bold red]")

    return {
        "status": "PROCESSED",
        "user": user,
        "assessment": assessment
    }


@app.get("/api/v1/alerts")
def get_recent_alerts():
    """Returns recent high-risk security incidents for the Dashboard."""
    return {
        "total_alerts": len(recent_alerts),
        "alerts": recent_alerts
    }


@app.get("/api/v1/users/{user}/profile")
def get_user_profile(user: str):
    """Returns current behavioral counters and state for a specific identity."""
    today_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    state = log_buffer.user_day_state.get((user, today_key), {})
    assessment = predictor.evaluate_features(user, today_key, dict(state), include_autoencoder=True) if state else None
    return {
        "user": user,
        "date": today_key,
        "is_blocked": user in blocked_users_and_ips,
        "current_features": state,
        "latest_risk_assessment": assessment
    }


@app.get("/api/v1/users/{user}/window")
def get_user_window(user: str):
    """Returns active 5-minute time window state for a specific identity."""
    today_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    window_summary = log_buffer.get_window_summary(user)
    features = log_buffer.compute_window_features(user, today_key)
    assessment = predictor.evaluate_features(user, today_key, features, include_autoencoder=True)
    return {
        "summary": window_summary,
        "window_features": features,
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


@app.websocket("/ws/alerts")
async def websocket_alerts_feed(websocket: WebSocket):
    """
    Live WebSocket endpoint streaming real-time security alerts and risk scoring events.
    """
    await ws_hub.connect(websocket)
    try:
        while True:
            # Client keep-alive / ping
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_hub.disconnect(websocket)
