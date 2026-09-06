# SOC Dashboard Integration Guide & API Reference

This document details all available backend APIs, WebSocket streams, telemetry data structures, and recommended UI components for building the Security Operations Center (SOC) dashboard.

---

## Architecture & Real-Time Data Flow

```
                                    ┌────────────────────────┐
                                    │ Distributed Loggers    │
                                    │ (Sniffers, Replayers)  │
                                    └───────────┬────────────┘
                                                │ (Kafka topic: 'network_flows')
                                                ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│ FastAPI Backend Service (http://localhost:8000)                               │
│                                                                               │
│  ┌───────────────────────────┐         ┌───────────────────────────────────┐  │
│  │ Kafka Flow Consumer       │ ──────> │ Redis 7 Telemetry Store           │  │
│  │ • Schema Validation       │         │ • logs_processed / logs_ignored   │  │
│  │ • Fail-Open Error Trap    │         │ • active_loggers set              │  │
│  └─────────────┬─────────────┘         │ • recent_malformed_samples list   │  │
│                │                       └───────────────────────────────────┘  │
│                ▼                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐  │
│  │ World Model Service                                                     │  │
│  │ • Network Scale Normalization (connected_clients_count)                 │  │
│  │ • WebRTC / Google Meet Media Filter (Port 3478 STUN/TURN)               │  │
│  │ • 15s State Aggregator (32-dim vector S_t)                              │  │
│  │ • Autoregressive Forward Simulator (K-step horizon)                     │  │
│  │ • ThreatExplainer (Feature attribution & SOC guidance)                  │  │
│  └─────────────┬───────────────────────────────────────────────────────────┘  │
│                │                                                              │
│                ▼                                                              │
│  ┌───────────────────────────┐         ┌───────────────────────────────────┐  │
│  │ WebSocket Incident Hub    │         │ REST Configuration & Status API   │  │
│  │ (/ws/alerts)              │         │ (/api/v1/config, /metrics/redis)  │  │
│  └───────────────────────────┘         └───────────────────────────────────┘  │
└───────────────────────┬───────────────────────────────────┬───────────────────┘
                        │                                   │
                        ▼ (Live WebSocket Push)             ▼ (REST Polling & Actions)
┌───────────────────────────────────────────────────────────────────────────────┐
│ Next.js SOC Security Dashboard (http://localhost:3000)                        │
│ • Ingestion Telemetry & Rogue Logger Error Log                                │
│ • Network Scale & WebRTC Policy Tuning Panel                                  │
│ • Forward Simulation Rollout Horizon & XAI Explainer                          │
│ • Live Threat Alerts & Host Isolation Action                                  │
└───────────────────────────────────────────────────────────────────────────────┘
```

---

## 1. REST API Endpoints Reference

Base URL: `http://localhost:8000`

### 1.1 Distributed Telemetry & Ingestion Metrics (Redis)
- **Endpoint**: `GET /api/v1/metrics/redis`
- **Purpose**: Provides real-time ingestion counters, error rates from rogue loggers, active distributed sensor identities, and recent evaluation history.
- **Polling Interval Recommendation**: 2 to 3 seconds.
- **Example Response**:
```json
{
  "status": "online",
  "redis_connected": true,
  "redis_url": "redis://localhost:6379/0",
  "timestamp": "2026-09-05T12:15:30.123456Z",
  "counters": {
    "logs_processed": 14250,
    "logs_ignored": 12,
    "logs_malformed_schema": 12,
    "logs_webrtc_conferencing": 8640,
    "windows_evaluated": 28,
    "alerts_normal": 26,
    "alerts_suspicious": 1,
    "alerts_critical": 1
  },
  "network_context": {
    "connected_clients_count": 1,
    "allow_webrtc_conferencing": true,
    "alert_threshold": 0.40,
    "critical_threshold": 0.70
  },
  "timestamps": {
    "last_log_timestamp": "2026-09-05T12:15:29.891234Z",
    "last_evaluation_timestamp": "2026-09-05T12:15:15.000000Z"
  },
  "active_loggers": [
    "sniff-wlan0-workstation-01",
    "replayer-node-02"
  ],
  "recent_malformed_samples": [
    {
      "timestamp": "2026-09-05T12:14:02.123456Z",
      "reason": "Missing fundamental flow keys (dst_port/protocol/timestamp)",
      "logger_id": "rogue-agent-x",
      "sample": "{'corrupted_field': 999, 'bad_str': 'xyz'}"
    }
  ],
  "recent_evaluations": [
    {
      "timestamp": "2026-09-05T12:15:15.000000Z",
      "risk_pct": 12.0,
      "stage": "Benign (WebRTC/Conferencing)",
      "policy": "ALLOW",
      "severity": "CONFERENCING",
      "flow_count": 1820
    }
  ]
}
```

---

### 1.2 Firewall & Network Scaling Configuration
- **Endpoint**: `GET /api/v1/config` (Inspect active settings)
- **Endpoint**: `POST /api/v1/config` (Live update without restarting backend)
- **Purpose**: Dynamically adjusts network client scaling, WebRTC policies, and alert thresholds.
- **Request Body for `POST /api/v1/config`**:
```json
{
  "network": {
    "connected_clients_count": 50,
    "baseline_clients_capacity": 1,
    "auto_scale_volumetric_thresholds": true
  },
  "traffic_policy": {
    "allow_webrtc_conferencing": true,
    "conferencing_ports": [3478, 19302, 19303, 19304, 19305, 19306, 19307, 19308, 19309],
    "whitelisted_ports": [53, 80, 443, 3478, 8080, 8443],
    "whitelisted_ips": []
  },
  "thresholds": {
    "alert_threshold": 0.40,
    "critical_threshold": 0.70,
    "window_size_seconds": 15,
    "min_warmup_windows": 4
  },
  "redis": {
    "url": "redis://localhost:6379/0",
    "key_prefix": "firewall:",
    "enabled": true,
    "metrics_ttl_seconds": 86400
  }
}
```

---

### 1.3 Latest Forward Simulation Rollout & XAI Report
- **Endpoint**: `GET /api/v1/simulation/latest`
- **Purpose**: Provides the latest autoregressive forward rollout trajectory ($K$-steps ahead) with root-cause feature attributions.
- **Example Response**:
```json
{
  "status": "OK",
  "simulation": {
    "timestamp": "2026-09-05T12:15:15.000000Z",
    "window_size_seconds": 15,
    "max_infiltration_prob": 0.8954,
    "peak_stage": "Command & Control",
    "recommended_policy": "ISOLATE_DEVICE",
    "is_conferencing": false,
    "network_scale": {
      "connected_clients_count": 1,
      "client_scale_applied": 1.0
    },
    "rollout_steps": [
      {
        "step": 1,
        "relative_seconds": 15,
        "infiltration_prob": 0.4215,
        "mitre_stage": "Discovery",
        "status": "SUSPICIOUS",
        "policy_action": "ALERT_ADMIN",
        "predicted_flow_count": 120,
        "predicted_syn_ratio": 0.05
      },
      {
        "step": 2,
        "relative_seconds": 30,
        "infiltration_prob": 0.6540,
        "mitre_stage": "Lateral Movement",
        "status": "SUSPICIOUS",
        "policy_action": "ALERT_ADMIN",
        "predicted_flow_count": 280,
        "predicted_syn_ratio": 0.12
      },
      {
        "step": 3,
        "relative_seconds": 45,
        "infiltration_prob": 0.8954,
        "mitre_stage": "Command & Control",
        "status": "CRITICAL",
        "policy_action": "ISOLATE_DEVICE",
        "predicted_flow_count": 890,
        "predicted_syn_ratio": 0.45
      }
    ],
    "top_attributions": [
      {
        "feature": "syn_ratio",
        "score": 0.3842,
        "raw_value": 0.45
      },
      {
        "feature": "tot_fwd_pkts",
        "score": 0.2815,
        "raw_value": 14500.0
      },
      {
        "feature": "ephemeral_port_ratio",
        "score": 0.1850,
        "raw_value": 0.82
      }
    ],
    "soc_guidance": "[HIGH RISK] Forward dynamics forecast threat escalation driven primarily by: syn ratio: 0.45; tot fwd pkts: 14500.00."
  }
}
```

---

### 1.4 Policy Action & Host Isolation
- **Endpoint**: `POST /api/v1/policy/enforce`
- **Purpose**: Triggers quarantine/isolation of a compromised IP or workstation. Also broadcasts a `FIREWALL_POLICY_ENFORCED` event to all open WebSockets.
- **Request Body**:
```json
{
  "target_ip": "10.0.4.21",
  "action": "ISOLATE_DEVICE",
  "reason": "Autonomous trigger: Autoregressive World Model predicted 89.5% C2 escalation"
}
```
- **Response**:
```json
{
  "status": "POLICY_APPLIED",
  "action": "ISOLATE_DEVICE",
  "target": "10.0.4.21",
  "message": "Target 10.0.4.21 successfully blocked/isolated by firewall policy."
}
```

---

### 1.5 System Reset & Health Checks
- **`POST /api/v1/simulation/reset`**: Flushes state history, flow buffers, and alert log (ideal for demo reset button).
- **`GET /health`**: Returns system health, model readiness, active subscribers, and network configuration.
- **`GET /api/v1/kafka/status`**: Ingestion telemetry (`flows_ingested`, `pending_flows`, `windows_evaluated`).
- **`GET /api/v1/alerts`**: Returns recent threat alerts generated during the current session.

---

## 2. WebSocket Real-Time Stream

- **WebSocket URL**: `ws://localhost:8000/ws/alerts` (or `ws://localhost:8000/api/v1/ws/alerts`)
- **Protocol**: JSON payloads over standard WebSocket.

### 2.1 Connection Established (Initial Handshake)
Pushed immediately upon successful WebSocket connection:
```json
{
  "type": "CONNECTION_ESTABLISHED",
  "message": "Connected to AI World Model Threat Telemetry Stream",
  "timestamp": "2026-09-05T12:00:00Z",
  "window_size_seconds": 15,
  "rollout_steps": 5
}
```

### 2.2 Threat Alert Event (`WORLD_MODEL_PREDICTION_ALERT`)
Pushed in real-time when an evaluated window breaches `alert_threshold`:
```json
{
  "type": "WORLD_MODEL_PREDICTION_ALERT",
  "severity": "CRITICAL",
  "timestamp": "2026-09-05T12:15:30Z",
  "max_infiltration_prob": 0.8954,
  "mitre_stage": "Command & Control",
  "policy_action": "ISOLATE_DEVICE",
  "report": {
    "timestamp": "2026-09-05T12:15:30Z",
    "window_size_seconds": 15,
    "max_infiltration_prob": 0.8954,
    "peak_stage": "Command & Control",
    "recommended_policy": "ISOLATE_DEVICE",
    "rollout_steps": [ ... ],
    "top_attributions": [ ... ],
    "soc_guidance": "..."
  }
}
```

### 2.3 Policy Enforced Event (`FIREWALL_POLICY_ENFORCED`)
Pushed when an administrator or automated policy executes host isolation:
```json
{
  "type": "FIREWALL_POLICY_ENFORCED",
  "data": {
    "ip": "10.0.4.21",
    "action": "ISOLATE_DEVICE",
    "reason": "Autonomous trigger: Forward simulation risk exceeded threshold"
  }
}
```

---

## 3. Dashboard Implementation Blueprint (UI Ideas & Widgets)

Here is a recommended feature breakdown for the Next.js frontend:

### Widget 1: Ingestion & Distributed Sensor Health Card
- **Source**: `GET /api/v1/metrics/redis`
- **Elements**:
  - **Processed vs. Ignored Gauge**: Donut chart showing `logs_processed` vs `logs_ignored`.
  - **Conferencing Counter**: Badge displaying `logs_webrtc_conferencing` (`Video Call Normalization Active`).
  - **Active Sensor Badges**: Pill badges showing active logger IDs from `active_loggers`.
  - **Rogue Logger / Malformed Log Drawer**: Expandable table of `recent_malformed_samples` showing the timestamp, logger ID, error reason, and payload snippet.

### Widget 2: Network Scaling & Policy Control Panel
- **Source**: `GET /api/v1/config` & `POST /api/v1/config`
- **Elements**:
  - **Connected Clients Slider**: Number input or slider from 1 to 500 workstations (`connected_clients_count`). Updates volumetric baseline normalization in real-time.
  - **WebRTC Conferencing Switch**: Toggle for `allow_webrtc_conferencing` (enables/disables Google Meet STUN/TURN port 3478 dampening).
  - **Risk Threshold Sliders**: Adjust `alert_threshold` (e.g. 40%) and `critical_threshold` (e.g. 70%).
  - **Save & Apply Button**: Sends `POST /api/v1/config` with toast notification (`Configuration persisted`).

### Widget 3: Forward Simulation Rollout Horizon (Line Chart)
- **Source**: `GET /api/v1/simulation/latest` (field `rollout_steps`)
- **Elements**:
  - **X-Axis**: Relative seconds into the future (`+15s`, `+30s`, `+45s`, `+60s`, `+75s`).
  - **Y-Axis**: Predicted Infiltration Probability (`0%` to `100%`).
  - **Threshold Lines**: Reference lines at 40% (Warning) and 70% (Critical).
  - **Step Tooltips**: Display predicted MITRE stage and recommended policy action for each future step.

### Widget 4: Explainable AI (XAI) Root Cause Bar Chart
- **Source**: `GET /api/v1/simulation/latest` (field `top_attributions`)
- **Elements**:
  - Horizontal bar chart of the top driving features (e.g. `syn_ratio`, `tot_fwd_pkts`, `flow_bytes_rate`).
  - Plain-English guidance callout box showing `soc_guidance`.

### Widget 5: Incident Feed & Host Isolation
- **Source**: WebSocket `/ws/alerts`
- **Elements**:
  - Scrolling feed of real-time threat alerts with color-coded severity badges (`NORMAL`, `SUSPICIOUS`, `CRITICAL`, `CONFERENCING`).
  - **Isolate Host Button**: Triggers `POST /api/v1/policy/enforce` with target IP.
  - **Demo Reset Button**: Triggers `POST /api/v1/simulation/reset` to clear historical buffers for clean presentation tests.
