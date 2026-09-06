# Veritas & AI World Model — Judge Presentation & Operational Playbook

> **SIH 2026 Problem Statement**: Autonomous Veritas with AI World Model Predictive Defense.  
> **Core Innovation**: Moving beyond reactive, single-packet classifiers to an **Attention-Augmented Recurrent World Model** that learns network transition dynamics $P(S_{t+1} \mid S_{\le t})$ across 15-second macro-states ($S_t \in \mathbb{R}^{32}$), forecasting the MITRE ATT&CK kill chain **$K$-steps into the future** before exfiltration or device takeover occurs.

---

## Table of Contents
1. [5-Minute Live Judge Pitch Script (Recommended Presentation Flow)](#1-5-minute-live-judge-pitch-script-recommended-presentation-flow)
2. [Recommended 4-Terminal Presentation Layout](#2-recommended-4-terminal-presentation-layout)
3. [Act 1: Infrastructure & Gateway Bring-Up](#3-act-1-infrastructure--gateway-bring-up)
4. [Act 2: Zero False-Positive Demonstration (Normal Browsing & WebRTC)](#4-act-2-zero-false-positive-demonstration-normal-browsing--webrtc)
5. [Act 3: Attack Telemetry & Predictive Forward Simulation](#5-act-3-attack-telemetry--predictive-forward-simulation)
6. [Act 4: Enterprise Dynamic Scaling & Policy Adaptation](#6-act-4-enterprise-dynamic-scaling--policy-adaptation)
7. [Act 5: Distributed Telemetry & Fault-Tolerance (Redis & Kafka)](#7-act-5-distributed-telemetry--fault-tolerance-redis--kafka)
8. [Act 6: Standalone ML Terminal Walkthrough & Reports (`demo.py`)](#8-act-6-standalone-ml-terminal-walkthrough--reports-demopy)
9. [Complete Dataset Attack Replay Reference](#9--complete-dataset-attack-replay-reference)
10. [REST API & SOC Management Cheat Sheet](#10--rest-api--soc-management-cheat-sheet)
11. [Judge Q&A Defense Sheet (Winning Explanations)](#11--judge-qa-defense-sheet-winning-explanations)

---

## 1. 5-Minute Live Judge Pitch Script (Recommended Presentation Flow)

When presenting before the jury, follow this battle-tested, chronological script:

| Time | Presentation Act | What to Run | What Judges See / Your Pitch |
| :--- | :--- | :--- | :--- |
| **0:00 - 0:45** | **Act 1: System Bring-Up** | Docker + Backend + Dashboard | Full microservices stack up in seconds: Apache Kafka broker, Redis metrics, FastAPI Gateway, and Next.js radar dashboard. |
| **0:45 - 1:45** | **Act 2: The False-Positive Proof** | Live laptop sniff / Monday baseline | Normal web browsing and video streaming (Meet/WebRTC) evaluated at **Risk $\le 0.8\%$ (ALLOW)**. Explain how standard IDS models fail by flagging normal traffic, whereas our World Model prevents SOC alert fatigue. |
| **1:45 - 3:15** | **Act 3: Live Attack Ingestion** | Friday Botnet C2 or Thursday Infiltration | The killer feature: The model doesn't just flag the current packet—it forecasts $K$-steps ahead ($t+15s \to t+75s$), plotting the MITRE kill chain before damage occurs and autonomously triggering `ISOLATE_DEVICE`. |
| **3:15 - 4:00** | **Act 4: Enterprise Scale** | REST config update to 100 clients | Dynamic volumetric normalization: enterprise network scaled via REST without server reboot. |
| **4:00 - 5:00** | **Act 5: Explainability & Metrics** | Redis telemetry & XAI attributions | Root-cause feature attributions (`top_attributions`) show why the AI made the decision, coupled with distributed Redis throughput metrics. |

---

## 2. Recommended 4-Terminal Presentation Layout

To deliver a flawless, high-impact demonstration, open **4 terminal split-panes** (or tabs):

```
┌──────────────────────────────────────┬──────────────────────────────────────┐
│  TERMINAL 1: FastAPI Gateway Core    │  TERMINAL 2: Next.js SOC Dashboard   │
│  (Live evaluations, policy actions)  │  (Radar display, WebSocket incidents)│
├──────────────────────────────────────┼──────────────────────────────────────┤
│  TERMINAL 3: Telemetry Replayer/Sniff│  TERMINAL 4: Admin CLI & Quick Curl  │
│  (Attack injector, live sniffer)     │  (State resets, config changes, XAI) │
└──────────────────────────────────────┴──────────────────────────────────────┘
```

---

## 3. Act 1: Infrastructure & Gateway Bring-Up

### Step 1.1: Start Core Infrastructure (Kafka, Kafka-UI, Redis, Prometheus, Loki, Grafana)
```bash
# In project root:
docker compose up -d kafka kafka-ui redis prometheus loki grafana
```
- **Apache Kafka Broker**: `localhost:9092` (Distributed flow event bus)
- **Kafka Web Console**: `http://localhost:8081` (Inspect live topics & consumer lags)
- **Redis Telemetry Store**: `localhost:6379` (Real-time ingestion metrics & counters)
- **Grafana Loki Log Store**: `http://localhost:3100` (Centralized log aggregation)
- **Prometheus Metrics Engine**: `http://localhost:9090` (Scrapes `/metrics` from backend)
- **Grafana SOC Dashboard**: `http://localhost:3001` (Unified visual metrics & Loki log explorer)

### Step 1.2: Launch the FastAPI AI World Model Gateway (Terminal 1)
```bash
cd backend
WINDOW_SECONDS=15 uv run uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload
```
- **Interactive Swagger Docs**: `http://localhost:8000/docs`
- **Health Verification**: `http://localhost:8000/health`
- **WebSocket Alert Feed**: `ws://localhost:8000/ws/alerts`

### Step 1.3: Launch the Next.js SOC Radar Dashboard (Terminal 2)
```bash
cd dashboard
pnpm dev
# or: npm run dev
```
- **Live SOC Dashboard**: Open `http://localhost:3000` in your browser.

---

## 4. Act 2: Zero False-Positive Demonstration (Normal Browsing & WebRTC)

> **Judge Pitch**: *"Most ML-based intrusion detection systems fail in enterprise deployments because normal HTTPS browsing and video calls trigger false volumetric alarms. Our system uses threat precursor verification and media stream normalization to maintain nominal baseline confidence."*

### Option A: Live Laptop Network Sniffing (Shows Real Hardware Capture)
Discover your active network interface and capture real laptop browsing packets:

```bash
# Terminal 4: Detect active network interface (e.g. wlan0 or eth0)
ACTIVE_IFACE=$(ip route get 8.8.8.8 | awk '{print $5; exit}')
echo "Active interface is: $ACTIVE_IFACE"

# Terminal 3: Sniff live interface and stream into Kafka
cd logger
sudo uv run logger sniff --interface $ACTIVE_IFACE
```
- Now open your browser and surf normal sites (Wikipedia, Google, GitHub, YouTube).
- **Backend Terminal Output**:
  ```text
  [NORMAL TRAFFIC] Evaluated Window | Risk: 0.8% | Stage: Benign | Policy: ALLOW
  ```

### Option B: Real-Time Media Streaming / Video Call (WebRTC UDP 3478)
If you join a video meeting (Google Meet / Zoom / Teams), the backend automatically normalizes the high-frequency UDP RTP traffic:
```text
[MEDIA STREAMING / RTP] Evaluated Window | Risk: 7.5% | Stage: Benign | Policy: ALLOW (Real-Time Media Baseline)
```

### Option C: Benchmark Nominal Baseline Replay (Deterministic Demo)
If live Wi-Fi is unstable during the presentation, stream Monday's benign benchmark dataset:
```bash
# Terminal 3: Replay 200 benign flows at 100 flows/sec
cd logger
uv run logger --day=monday --rate=100 --max-flows=200
```
- **Expected Result**: Infiltration Probability $\le 0.5\%$, Stage `Benign`, Policy `ALLOW`.

---

## 5. Act 3: Attack Telemetry & Predictive Forward Simulation

> **Judge Pitch**: *"Now watch what happens when an adversary executes an attack. Our AI World Model doesn't just detect the attack—it executes a 5-step autoregressive rollout into the future ($t+15s \to t+75s$), anticipating the full kill-chain progression and enforcing autonomous isolation before critical systems are compromised."*

### Step 5.1: Clean State Reset (Terminal 4)
Before launching any attack scenario, reset the 2-minute recurrent memory buffer:
```bash
curl -X POST http://localhost:8000/api/v1/simulation/reset
```

### Scenario 1: Botnet Command & Control (C2) & Lateral Movement (Friday Attack)
```bash
# Terminal 3: Stream Friday Botnet C2 telemetry into Kafka
cd logger
uv run logger --day=friday --scenario=attack --rate=100 --max-flows=200
```
- **Backend Output in Terminal 1**:
  ```text
  [WORLD MODEL ALERT] Risk: 93.4% | Stage: Infiltration / Lateral Movement | Policy: ISOLATE_DEVICE
  ```
- **Autoregressive Rollout Inspection (Terminal 4)**:
  ```bash
  curl -s http://localhost:8000/api/v1/simulation/latest | jq '{max_risk: .simulation.max_infiltration_prob, peak_stage: .simulation.peak_stage, policy: .simulation.recommended_policy, rollout: .simulation.rollout_steps}'
  ```
- **What the Judges See in Rollout**:
  - `Step 1 (t+15s)`: Risk = **1.9%** (Benign)
  - `Step 2 (t+30s)`: Risk = **5.8%** (Benign)
  - `Step 3 (t+45s)`: Risk = **6.9%** (Benign)
  - `Step 4 (t+60s)`: Risk = **78.9%** (`ISOLATE_DEVICE`) $\leftarrow$ *Threat Anticipated!*
  - `Step 5 (t+75s)`: Risk = **93.4%** (`ISOLATE_DEVICE`)

### Scenario 2: FTP & SSH Brute-Force Initial Access (Wednesday Attack)
```bash
curl -X POST http://localhost:8000/api/v1/simulation/reset
cd logger
uv run logger --day=wednesday --scenario=attack --rate=100 --max-flows=200
```
- **Result**: Immediate high SYN/SSH precursor detection $\to$ Stage: `Initial Access` $\to$ Policy: `ISOLATE_DEVICE`.

### Scenario 3: Internal Infiltration & Network Reconnaissance (Thursday Attack)
```bash
curl -X POST http://localhost:8000/api/v1/simulation/reset
cd logger
uv run logger --day=thursday --scenario=attack --rate=100 --max-flows=200
```
- **Result**: Port sweep precursor detected $\to$ Stage: `Infiltration / Lateral Movement` $\to$ Policy: `ISOLATE_DEVICE`.

---

## 6. Act 4: Enterprise Dynamic Scaling & Policy Adaptation

> **Judge Pitch**: *"In an enterprise network with 100 workstations, aggregate packet rates can be 50x higher than on a single laptop. Traditional firewalls trigger false volumetric DDoS alarms. Our backend features dynamic scaling that normalizes volumetric features across connected clients via a single REST call without service downtime."*

### Step 6.1: View Current Firewall Network Configuration
```bash
curl -s http://localhost:8000/api/v1/config | jq .network
```

### Step 6.2: Scale Network Capacity to 100 Connected Clients
```bash
curl -X POST http://localhost:8000/api/v1/config \
  -H "Content-Type: application/json" \
  -d '{
    "network": {
      "connected_clients_count": 100,
      "baseline_clients_capacity": 1,
      "auto_scale_volumetric_thresholds": true
    }
  }' | jq .
```
- **Formula applied**:
  $$\text{client\_scale} = \max\left(1.0, \frac{\text{connected\_clients\_count}}{\text{baseline\_clients\_capacity}}\right) = 100.0$$
- Volumetric features (`tot_fwd_pkts`, `flow_bytes_rate`, `flow_pkts_rate`) are automatically scaled by $100\times$, preventing multi-host aggregate traffic from triggering false positive flood alarms.

---

## 7. Act 5: Distributed Telemetry & Fault-Tolerance (Redis & Kafka)

> **Judge Pitch**: *"For production enterprise reliability, our architecture decouples ingestion using Apache Kafka and maintains sub-millisecond operational telemetry in Redis. If a compromised host or faulty logger emits malformed payloads, our worker isolates the payload without crashing the streaming pipeline."*

### Step 7.1: Inspect Redis Ingestion & Telemetry Metrics
```bash
curl -s http://localhost:8000/api/v1/metrics/redis | jq .
```
- **Metrics shown to judges**:
  - `logs_processed`: Total valid flow records evaluated.
  - `logs_webrtc_conferencing`: Count of normalized real-time audio/video streams.
  - `active_loggers`: List of unique registered logger client IDs.
  - `windows_evaluated`: Number of 15-second state matrices processed.
  - `recent_window_evaluations`: Rolling history of risk percentages and policies.

### Step 7.2: Verify Kafka Ingestion Broker Status
```bash
curl -s http://localhost:8000/api/v1/kafka/status | jq .
```

### Step 7.3: Demonstrate Fault-Tolerance Against Corrupt Payloads
Send raw garbage JSON to the flow pipeline to demonstrate that the worker does not crash:
```bash
python3 -c "
import json
from kafka import KafkaProducer
producer = KafkaProducer(bootstrap_servers='localhost:9092', value_serializer=lambda v: json.dumps(v).encode('utf-8'))
producer.send('network_flows', {'corrupted_malformed_key': 999999})
producer.flush()
print('Corrupt packet injected!')
"
```
- **Result**: Backend logs capture the schema anomaly, safely increments Redis `logs_ignored`, saves the snippet to `recent_malformed_samples`, and continues evaluating clean traffic seamlessly!

---

## 8. Act 6: Standalone ML Terminal Walkthrough & Reports (`demo.py`)

> **Judge Pitch**: *"If you want to look under the hood of the machine learning mathematics, we provide an offline evaluation harness that visualizes the raw 32-dimensional state vector, computes attention weights, and exports comprehensive SOC incident reports."*

### Step 8.1: Run Interactive Terminal Forward Simulation
```bash
cd ml
# Execute 5-step autoregressive forward simulation on Thursday Infiltration:
uv run python demo.py --file data/external-network/cic-ids-2018/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv --rollout-steps 5
```
- **Displays**:
  1. 8-window historical observed state table ($S_{t-7} \dots S_t$).
  2. 5-step forward simulated prediction rollout table ($S_{t+1} \dots S_{t+5}$).
  3. Feature attribution table showing top driving weights (e.g. `pkt_len_std`, `syn_ratio`, `ephemeral_port_ratio`).
  4. Autonomous Policy Recommendation (`ISOLATE_DEVICE` / `ALLOW`).

### Step 8.2: Export Formal Markdown SOC Incident Report
```bash
cd ml
uv run python demo.py \
  --file data/external-network/cic-ids-2018/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv \
  --rollout-steps 5 \
  --output reports/judge_presentation_report.md
```
- Generates a full GitHub-Flavored Markdown report with complete tabular kill-chain projections and SOC guidance.

---

## 9. Complete Dataset Attack Replay Reference

The replayer tool supports convenient aliases for both **days** (`--day`) and **attack names** (`--attack`):

| Attack Category | Day Option | Attack Option | Benchmark File | MITRE Stage | Expected Policy |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Benign Baseline** | `--day=monday` | `--attack=benign` | `Wednesday-28-02-2018` | `Benign` | `ALLOW` ($\le 1\%$) |
| **Botnet C2** | `--day=friday` | `--attack=botnet` | `Friday-02-03-2018` | `Command & Control` | `ISOLATE_DEVICE` ($>93\%$) |
| **Infiltration / Lateral**| `--day=thursday` | `--attack=infiltration` | `Thursday-01-03-2018` | `Infiltration` | `ISOLATE_DEVICE` ($>95\%$) |
| **SSH/FTP Brute Force** | `--day=wednesday` | `--attack=bruteforce` | `Wednesday-14-02-2018` | `Initial Access` | `ISOLATE_DEVICE` ($100\%$) |
| **DoS SlowHTTP / Hulk** | `--day=friday-16` | `--attack=dos` | `Friday-16-02-2018` | `Initial Access / DoS` | `ISOLATE_DEVICE` ($99\%$) |
| **DoS GoldenEye / Loris**| `--day=thursday-15`| `--attack=goldeneye` | `Thursday-15-02-2018` | `Command & Control` | `ISOLATE_DEVICE` ($100\%$) |
| **DDoS LOIC HTTP** | `--day=tuesday` | `--attack=ddos` | `Thuesday-20-02-2018` | `Impact` | `ISOLATE_DEVICE` ($98\%$) |
| **Web Exploits / SQLi** | `--day=friday-23` | `--attack=web` | `Friday-23-02-2018` | `Initial Access` | `ISOLATE_DEVICE` ($96\%$) |

### Common CLI Flags:
- `--rate <n>`: Streaming speed in flows/second (default: `100.0`, use `0` for max speed).
- `--max-flows <n>`: Cap number of flow records to send (e.g. `--max-flows=200`).
- `--scenario attack|benign`: Filter specifically for attack flows or benign segments.

---

## 10. REST API & SOC Management Cheat Sheet

All endpoints can be executed from **Terminal 4**:

```bash
# 1. System Health Check
curl -s http://localhost:8000/health | jq .

# 2. Reset World Model State History (Crucial between demo tests)
curl -X POST http://localhost:8000/api/v1/simulation/reset

# 3. Fetch Latest Forward Simulation Rollout
curl -s http://localhost:8000/api/v1/simulation/latest | jq .

# 4. Fetch Active Threat Incidents / Alerts
curl -s http://localhost:8000/api/v1/alerts | jq .

# 5. Enforce Manual Policy Action on Suspicious Host
curl -X POST http://localhost:8000/api/v1/policy/enforce \
  -H "Content-Type: application/json" \
  -d '{"target_ip": "10.0.4.21", "action": "ISOLATE_DEVICE", "reason": "Host exhibiting anomalous lateral movement"}' | jq .

# 6. Read Ingestion Metrics from Redis
curl -s http://localhost:8000/api/v1/metrics/redis | jq .

# 7. Check Kafka Consumer Worker Status
curl -s http://localhost:8000/api/v1/kafka/status | jq .
```

---

## 11. Judge Q&A Defense Sheet (Winning Explanations)

### Q1: "Why did you build an AI World Model instead of using a standard Classifier like Random Forest or XGBoost?"
> **Answer**:  
> *"Traditional classifiers evaluate a single packet or flow in isolation. They have zero temporal context and can only react **after** an attack packet hits the network. An AI World Model learns the underlying network transition dynamics $P(S_{t+1} \mid S_{\le t})$. By predicting the trajectory of the network 5 steps ahead (75 seconds into the future), we detect multi-stage attack progressions like reconnaissance and lateral movement before data exfiltration or host takeover takes place."*

### Q2: "How do you avoid overwhelming the SOC with false positives during normal web surfing or video conferences?"
> **Answer**:  
> *"We implemented a two-tier disambiguation engine:  
> 1. **Threat Precursor Verification**: The AI verifies fundamental attack mechanics (port scan sweeps, SYN floods, RST storms, SSH/FTP brute force, unassigned rogue ports) before elevating risk.  
> 2. **Media Stream Normalization**: High-frequency UDP RTP streams (WebRTC STUN/TURN ports 3478, 19302-19309) are recognized and volumetric rates are dampened so legitimate video calls are kept at nominal baseline ($\le 7.5\%$ risk)."*

### Q3: "What happens when an enterprise network scales from 5 to 500 computers? Doesn't the volume explosion trick the model?"
> **Answer**:  
> *"We designed a Dynamic Client Scaling feature. The network volume is normalized using the formula $\text{client\_scale} = \max\left(1.0, \frac{\text{connected\_clients}}{\text{baseline\_capacity}}\right)$. This proportionally scales packet and byte rate features, allowing the exact same trained model to operate in a single-laptop home office or a 500-seat enterprise corporate environment without retraining."*

### Q4: "How does the system handle high-throughput network logging without dropping packets or crashing?"
> **Answer**:  
> *"Ingestion is decoupled via Apache Kafka message queues running in high-performance KRaft mode. Even if thousands of packets arrive per second, they buffer safely in the `network_flows` topic. The consumer processes them in micro-batches, aggregates 15-second macro-states using fast vectorized Pandas/NumPy operations, and records operational throughput in sub-millisecond Redis stores."*
