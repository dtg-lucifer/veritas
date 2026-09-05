# 🛡️ Internal Firewall - Backend Streaming Gateway & Forward Simulation Hub

Real-time streaming ingestion via **Apache Kafka**, state window aggregation, live WebSocket incident broadcasting, and forward simulation interface powered by **FastAPI** and the trained **Network World Model** from `../ml/models/world_model.pt`.

---

## 🏗️ Architecture: Forward Simulation Stream Triage

To handle continuous high-throughput flow telemetry and proactively forecast infiltration timelines, the backend utilizes the **World Model Forward Simulation Pipeline**:

```
[ Gateway / NetFlow / PyShark / Day Replayers ]
                       │
                       ▼ (Kafka Producer / JSON)
        [ Apache Kafka Topic: network_flows ]
                       │
                       ▼ (AIOKafkaConsumer Async Worker)
     [ 15-Second Stateful State Window Aggregator ]
                       │
                       ▼ (32-D State Vector S_t)
    [ Sliding History Buffer: S_{t-W+1} ... S_t (W=8) ]
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│ 🔮 AI Network World Model Forward Simulation                │
│   • Simulates Next State: \hat{S}_{t+1} = P(S_{t+1} | S_<=t)│
│   • Autoregressively rolls forward K steps ahead (e.g. 5)   │
│   • Projects Infiltration Risk Timeline: [P_1, ..., P_K]    │
│   • Anticipates MITRE ATT&CK Phase Progression              │
│   • Attributes Top Contributing Features via Attention & XAI│
└─────────────────────────────────────────────────────────────┘
                       │
                       ├────────────────────────────────────────┐
                       ▼ (If Max Risk >= 40% / ALERT_ADMIN)     ▼ (If Normal)
          ┌────────────────────────────────┐         [ Retain State ]
          │ 🚨 Broadcast Real-Time Alerts: │
          │   • WebSocket: /ws/alerts      │
          │   • Pre-Emptive Device Drop    │
          │   • Incident History: /alerts  │
          └────────────────────────────────┘
```

---

## ⚡ Quickstart

### 1. Start Apache Kafka (Zero Password, KRaft Mode)
```bash
docker compose up -d kafka kafka-ui
```
- Kafka Broker: `localhost:9092`
- Kafka Web UI: `http://localhost:8081`

### 2. Run the Backend Server
```bash
cd backend
WINDOW_SECONDS=15 uv run uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload
```
Interactive Swagger API documentation: **`http://localhost:8000/docs`**

### 3. Stream Telemetry into Kafka
```bash
cd logger
# Replay Thursday infiltration flows
uv run logger --day=thursday --scenario=attack --max-flows=200 --rate=100
```

---

## ⚙️ Configuration (Environment Variables)

| Variable | Default | Description |
| :--- | :--- | :--- |
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092` | Connection string for Apache Kafka broker |
| `KAFKA_TOPIC` | `network_flows` | Target Kafka topic for raw network flows |
| `KAFKA_GROUP_ID` | `firewall_world_model_group` | Consumer group ID for the backend worker |
| `WINDOW_SECONDS` | `15` | State window aggregation duration in seconds |
| `ROLLOUT_STEPS` | `5` | Forward simulation forecast horizon ($K$) |
| `ALERT_THRESHOLD` | `40.0` | Infiltration probability percentage required to trigger alert |
| `WORLD_MODEL_PATH` | `../ml/models/world_model.pt` | Path to trained PyTorch world model checkpoint |

---

## 📡 API Endpoints

| Method | Route | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Service health, model status, Kafka worker, and active WebSockets |
| `GET` | `/api/v1/kafka/status` | Real-time Kafka consumer connectivity and flow ingestion telemetry |
| `GET` | `/api/v1/simulation/latest` | Latest K-step forward simulation rollout report with MITRE stage & policy |
| `GET` | `/api/v1/simulation/status` | World Model state metrics (windows evaluated, peak risk observed) |
| `POST` | `/api/v1/simulation/reset` | Resets flow buffer and historical state context for clean benchmark runs |
| `POST` | `/api/v1/logs/ingest` | Direct HTTP flow log ingestion (bypassing Kafka if desired) |
| `GET` | `/api/v1/alerts` | Historical list of forecasted security incidents |
| `POST` | `/api/v1/policy/enforce` | Triggers firewall isolation (`ISOLATE_DEVICE`) |
| `WS` | `/ws/alerts` | Real-time WebSocket connection streaming security incident alerts |
