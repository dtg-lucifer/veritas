"""
Internal Firewall - FastAPI Gateway Backend.
Provides REST prediction routes, real-time log ingestion, policy enforcement,
and live WebSocket incident feeds for the security dashboard.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import json

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from rich.console import Console

from .predictor import SecurityModelPredictor
from .log_buffer import RealTimeLogBuffer

console = Console()

app = FastAPI(
    title="🛡️ Internal Firewall - Security Gateway & Anomaly Backend",
    description="SIH 2026 MVP: Adaptive behavioral baseline & real-time internal network anomaly detection API.",
    version="1.0.0"
)

# CORS middleware for Next.js / React Dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global in-memory components
predictor = SecurityModelPredictor()
log_buffer = RealTimeLogBuffer()
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
    """Health check endpoint confirming model status."""
    return {
        "status": "healthy",
        "service": "Internal Firewall AI/ML Backend",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "models_ready": True,
        "active_ws_subscribers": len(ws_hub.active_connections)
    }


@app.post("/api/v1/predict")
def predict_direct(payload: PredictRequest):
    """
    Direct model evaluation endpoint for a pre-computed behavioral feature vector.
    """
    ts = payload.timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    result = predictor.evaluate_features(payload.user, ts, payload.features)
    return result


@app.post("/api/v1/logs/ingest")
async def ingest_network_log(event: NetworkLogEvent):
    """
    Ingests live network activity stream events from Gateway / VPN / Endpoint agents.
    Buffers events into rolling behavioral vector, predicts anomaly risk,
    and automatically broadcasts WebSocket alerts on suspicious / critical threats.
    """
    evt_dict = event.model_dump()
    user, date_key, updated_features = log_buffer.ingest_event(evt_dict)
    
    assessment = predictor.evaluate_features(user, date_key, updated_features)
    assessment["src_ip"] = event.src_ip
    assessment["last_event_type"] = event.event_type

    # If risk is elevated, broadcast alert in real-time
    if assessment["status"] in ["SUSPICIOUS", "CRITICAL"]:
        recent_alerts.insert(0, assessment)
        if len(recent_alerts) > 100:
            recent_alerts.pop()
        
        # Broadcast alert payload to all connected frontend clients
        await ws_hub.broadcast({
            "type": "SECURITY_INCIDENT_ALERT",
            "alert": assessment
        })
        console.print(f"[bold red]🚨 Alert Broadcasted: User={user} Risk={assessment['risk_score']} Status={assessment['status']}[/bold red]")

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
    assessment = predictor.evaluate_features(user, today_key, dict(state)) if state else None
    return {
        "user": user,
        "date": today_key,
        "is_blocked": user in blocked_users_and_ips,
        "current_features": state,
        "latest_risk_assessment": assessment
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
