# 🛡️ Internal Firewall - Backend API, Streaming Gateway & Redis Queue Worker

Real-time anomaly detection backend, Redis log stream consumer, and WebSocket incident hub powered by **FastAPI** and the trained multi-model ensemble from `../ml/models`.

---

## 🏗️ Architecture: Fast Tiered ML Stream Triage

To handle thousands of incoming network events per second without latency spikes, the backend employs a **tiered composite ML pipeline**:

```
[ Gateway / SIEM / Endpoint Logs ]
                │
                ▼ (LPUSH / JSON)
       [ Redis Queue: network_logs_queue ]
                │
                ▼ (BRPOP Non-Blocking Consumer)
     [ RealTimeLogBuffer (Sliding-Window State) ]
                │
                ▼ (Sub-millisecond Triage < 1.0 ms)
┌─────────────────────────────────────────────────────────┐
│ ⚡ Fast Composite Predictor:                            │
│   • LightGBM Behavioral Classifier: s_gb (weight: 0.60) │
│   • Statistical Baseline Profiler: s_base (weight: 0.25)│
│   • Isolation Forest Tree: s_if (weight: 0.15)          │
│                                                         │
│ Risk Score = (0.60 * s_gb + 0.25 * s_base + 0.15 * s_if)│
└─────────────────────────────────────────────────────────┘
                │
                ├────────────────────────────────────────┐
                ▼ (If Risk >= 55 / SUSPICIOUS / CRITICAL)▼ (If Normal)
   ┌────────────────────────────────┐         [ Retain State ]
   │ 🚨 Broadcast Real-Time Alerts: │
   │   • WebSocket: /ws/alerts      │
   │   • Redis PubSub: alerts_pubsub│
   │   • Incident History: /alerts  │
   └────────────────────────────────┘
```

---

## ⚡ Quickstart

### 1. Run the Backend Server
```bash
cd backend
uv run uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
Interactive Swagger API documentation: **`http://localhost:8000/docs`**

### 2. Simulate Live Attack Stream via Redis Producer
In a separate terminal:
```bash
cd backend
uv run python -m app.redis_producer
```

### 3. Run Automated Integration Tests
```bash
cd backend
uv run python -m app.test_client
```

---

## ⚙️ Configuration (Environment Variables)

| Variable | Default | Description |
| :--- | :--- | :--- |
| `REDIS_URL` | `redis://localhost:6379/0` | Connection string for Redis broker |
| `REDIS_QUEUE_KEY` | `network_logs_queue` | Key of the Redis message queue |
| `ALERT_THRESHOLD` | `55.0` | Minimum composite risk score required to trigger broadcast alerts |

---

## 📡 API Endpoints

| Method | Route | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Service health, models status, and Redis worker metrics |
| `GET` | `/api/v1/redis/status` | Real-time queue consumption and alert generation stats |
| `POST` | `/api/v1/predict` | Fast composite prediction on a 30-dimension feature vector |
| `POST` | `/api/v1/logs/ingest` | Direct HTTP log ingestion |
| `GET` | `/api/v1/alerts` | Historical list of high-risk security incidents |
| `GET` | `/api/v1/users/{user}/profile` | User behavioral profile, daily counters, and isolation status |
| `POST` | `/api/v1/policy/enforce` | Triggers firewall isolation (`ISOLATE_DEVICE`) |
| `WS` | `/ws/alerts` | Real-time WebSocket connection streaming security incident alerts |

---

## 📥 How Logging Systems Dump Logs into Redis

External firewalls, proxy loggers, or endpoint agents simply dump JSON strings into Redis using `LPUSH`:

```python
import redis
import json

r = redis.Redis(host='localhost', port=6379, db=0)

log_event = {
  "event_id": "evt-live-5001",
  "timestamp": "2026-08-19T02:15:00Z",
  "user": "AAM0658",
  "src_ip": "10.0.4.21",
  "event_type": "file_copy",
  "filename": "database_master_export.zip",
  "file_extension": ".zip"
}

r.lpush("network_logs_queue", json.dumps(log_event))
```
The backend worker will immediately pop the log, calculate rolling baseline surges, run the fast composite LightGBM model, and push an instant alert to the frontend dashboard!
