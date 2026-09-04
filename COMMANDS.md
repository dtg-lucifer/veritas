# 🛠️ Network World Model Cyber Defense — Operational Command Reference

This document provides a single, unified reference for running, training, demonstrating, and operating all components of the **Internal Firewall & AI World Model** system (SIH 2026).

---

## 📑 Table of Contents
1. [AI World Model (`ml/`)](#1-ai-world-model-ml)
2. [Backend Streaming Service (`backend/`)](#2-backend-streaming-service-backend)
3. [Packet Sniffer & Ingestion Logger (`logger/`)](#3-packet-sniffer--ingestion-logger-logger)
4. [Traffic & Threat Simulator (`simulator/`)](#4-traffic--threat-simulator-simulator)
5. [SOC Web Dashboard (`dashboard/`)](#5-soc-web-dashboard-dashboard)
6. [Full System Integration Run (Step-by-Step)](#6-full-system-integration-run-step-by-step)

---

## 1. AI World Model (`ml/`)

The machine learning core uses an **Attention-Augmented Recurrent World Model** that learns network transition dynamics $P(S_{t+1} \mid S_{\le t})$ over 15-second macro-states ($S_t \in \mathbb{R}^{32}$) and performs $K$-step autoregressive forward simulations to forecast threats before they materialize.

### 1.1 Environment Setup
```bash
cd ml
uv sync
```

### 1.2 Training & Benchmarking
Trains the World Model neural network, trains the static Logistic Regression baseline, benchmarks comparative metrics (F1, FPR, lead time), and saves weights to `models/world_model.pt`:

```bash
cd ml
# Rapid training with 15% subsampling across CIC-IDS-2018 files
uv run python train.py --sample-frac 0.15 --epochs 12 --window-size 15 --seq-len 8

# Full dataset training without cache
uv run python train.py --epochs 20 --window-size 15 --seq-len 8 --no-cache
```

### 1.3 Interactive Forward Simulation Demo (Terminal View)
Runs temporal state windowing on raw telemetry, executes $K$-step autoregressive forward simulation, and prints rich tables of the observed history, forward threat trajectory, and feature attributions:

```bash
cd ml
# Infiltration evaluation (Thursday-01-03-2018)
uv run python demo.py --file data/external-network/cic-ids-2018/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv --rollout-steps 5

# FTP/SSH Brute Force evaluation (Wednesday-14-02-2018)
uv run python demo.py --file data/external-network/cic-ids-2018/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv --rollout-steps 5

# Botnet evaluation (Friday-02-03-2018)
uv run python demo.py --file data/external-network/cic-ids-2018/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv --rollout-steps 5

# Raw PCAP capture evaluation
uv run python demo.py --file data/external-network/sample_capture.pcap --rollout-steps 5
```

### 1.4 Generating Reports in Plain Markdown (.md) or Plain Text (.txt)
Export full evaluation tables, forward simulation timelines, and root-cause feature attributions directly to a file:

```bash
cd ml
# Export report in GitHub-Flavored Markdown (.md)
uv run python demo.py --file data/external-network/cic-ids-2018/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv \
  --rollout-steps 5 \
  --output reports/demo_thursday_infiltration.md

# Export report in plain ASCII Text (.txt)
uv run python demo.py --file data/external-network/cic-ids-2018/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv \
  --rollout-steps 5 \
  --output reports/demo_wednesday_bruteforce.txt \
  --format txt
```

### 1.5 Targeted Scenario Selection
Evaluate specific threat phases or verify normal baseline operation:

```bash
cd ml
# Peak threat sequence (Default: auto-targets peak attack activity when threats exist)
uv run python demo.py --file data/external-network/cic-ids-2018/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv --scenario attack

# Attack onset sequence (4 pre-attack windows + 4 early attack windows)
uv run python demo.py --file data/external-network/cic-ids-2018/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv --scenario onset

# Nominal benign baseline sequence (Verifies low false-alarm rate: Risk < 10%, Status NORMAL, Policy ALLOW)
uv run python demo.py --file data/external-network/cic-ids-2018/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv --scenario benign

# Explicit window index selection
uv run python demo.py --file data/external-network/cic-ids-2018/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv --window-idx 1662
```

---

## 2. Backend Streaming Service (`backend/`)

FastAPI streaming gateway, asynchronous Apache Kafka consumer worker, WebSocket notification hub, and AI World Model forward simulation evaluation API.

### 2.1 Run Message Broker & UI (Apache Kafka KRaft Mode)
Start the passwordless Apache Kafka message broker and web management interface via Docker Compose:
```bash
docker compose up -d kafka kafka-ui
```
- Kafka Broker: `localhost:9092` (Inside containers: `kafka:29092`)
- Kafka Web UI: `http://localhost:8081` (inspect topics, messages, consumer groups)

### 2.2 Run the Backend API Server
```bash
cd backend
WINDOW_SECONDS=15 uv run uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload
```
- Interactive Swagger UI: `http://localhost:8000/docs`
- Health Check: `http://localhost:8000/health`
- Kafka Ingestion Status: `http://localhost:8000/api/v1/kafka/status`
- Latest Forward Simulation Report: `http://localhost:8000/api/v1/simulation/latest`
- Live Alert Stream: `http://localhost:8000/api/v1/alerts`
- WebSocket Incident Feed: `ws://localhost:8000/ws/alerts`

---

## 3. Network Telemetry Logger & Day Replayer (`logger/`)

Day-based network telemetry replayer, live interface sniffer, and Kafka message producer.

### 3.1 Attack & Day Telemetry Replay into Kafka
Replay real-world attack flows or benign traffic traces directly into Kafka topic `network_flows`. You can target attacks by **name** (`--attack`) or by **day** (`--day`):

```bash
cd logger

# 0. Benign Nominal Baseline (Stage: Benign | Risk: < 1% | Policy: ALLOW)
uv run logger --attack=benign --max-flows=200 --rate=100
# or: uv run logger --day=monday --max-flows=200

# 1. Command & Control (Botnet C2 | Stage: Command & Control | Risk: 100% | Policy: ISOLATE_DEVICE)
uv run logger --attack=botnet --scenario=attack --max-flows=200 --rate=100
# or: uv run logger --day=friday --scenario=attack --max-flows=200

# 2. Initial Access (FTP & SSH Brute Force | Stage: Initial Access | Risk: 100% | Policy: ISOLATE_DEVICE)
uv run logger --attack=bruteforce --scenario=attack --max-flows=200 --rate=100
# or: uv run logger --day=wednesday --scenario=attack --max-flows=200

# 3. Denial of Service (DoS SlowHTTPTest & Hulk | Stage: Initial Access / DoS | Risk: 99.9% | Policy: ISOLATE_DEVICE)
uv run logger --attack=dos --scenario=attack --max-flows=200 --rate=100
# or: uv run logger --day=friday-16 --scenario=attack --max-flows=200

# 4. Distributed Denial of Service (DDoS LOIC HTTP | Stage: Exfiltration / Impact | Risk: 98% | Policy: ISOLATE_DEVICE)
uv run logger --attack=ddos --scenario=attack --max-flows=200 --rate=100
# or: uv run logger --day=tuesday --scenario=attack --max-flows=200

# 5. DoS GoldenEye & Slowloris (Stage: Command & Control / Impact | Risk: 100% | Policy: ISOLATE_DEVICE)
uv run logger --attack=goldeneye --scenario=attack --max-flows=200 --rate=100
# or: uv run logger --day=thursday-15 --scenario=attack --max-flows=200

# 6. Infiltration & Lateral Movement (Recon & Pivoting | Stage: Infiltration / Lateral Movement | Risk: 95% | Policy: ISOLATE_DEVICE)
uv run logger --attack=infiltration --scenario=attack --max-flows=200 --rate=100
# or: uv run logger --day=thursday --scenario=attack --max-flows=200

# 7. Web Exploits & SQL Injection (XSS & SQLi | Stage: Initial Access)
uv run logger --attack=web --scenario=attack --max-flows=200 --rate=100
# or: uv run logger --day=friday-23 --scenario=attack --max-flows=200
```

> **Tip: Resetting State Between Attack Runs**  
> To test attacks in isolation without previous attack states lingering in the 2-minute recurrent memory buffer, reset the simulation state:
> ```bash
> curl -X POST http://localhost:8000/api/v1/simulation/reset
> ```


### 3.2 Live Network Interface Sniffing
Captures live packets on network interfaces using PyShark and streams them into Kafka:
```bash
cd logger
# Capture on loopback interface
sudo uv run logger sniff --interface lo

# Capture on primary network interface with BPF filter
sudo uv run logger sniff --interface eth0 --bpf "tcp port 80 or port 443"
```

### 3.3 Static PCAP Trace Replay
Replays offline `.pcap` capture files directly into Kafka:
```bash
cd logger
uv run logger pcap sample_traffic.pcap --topic network_flows
```

---

## 4. Traffic & Threat Simulator (`simulator/`)

Generates calibrated benign baseline traffic or simulated multi-stage attack bursts.

### 4.1 Normal Baseline Traffic Mode
```bash
# Push nominal traffic via direct HTTP POST
uv run --directory simulator python simulate.py --mode normal --target http
```

### 4.2 Suspicious Attack Traffic Mode
```bash
# 5x burst rate with Wikileaks exfiltration simulation
uv run --directory simulator python simulate.py --mode suspicious --multiplier 5 --attack-type wikileaks --target http

# 10x burst rate with Keylogger/Exploit tool transfer
uv run --directory simulator python simulate.py --mode suspicious --multiplier 10 --attack-type hacking_tools --target http
```

---

## 5. SOC Web Dashboard (`dashboard/`)

Real-time Next.js frontend displaying the live radar, incident feed, forward simulation risk trajectory, and MITRE ATT&CK kill-chain progression.

### 5.1 Run Development Server
```bash
cd dashboard
npm run dev
```
Open `http://localhost:3000` in your browser.

---

## 6. Full System Integration Run (Step-by-Step)

To run the complete internal firewall stack simultaneously:

### Step 1: Start Apache Kafka & Kafka UI
```bash
docker compose up -d kafka kafka-ui
```

### Step 2: Start FastAPI Backend Gateway
```bash
cd backend
WINDOW_SECONDS=15 uv run uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload
```

### Step 3: Stream Day Telemetry into Kafka
```bash
cd logger
# Stream Thursday infiltration data into Kafka
uv run logger --day=thursday --scenario=attack --max-flows=200 --rate=100
```

### Step 4: Monitor Forward Threats & Kill-Chain Trajectory
```bash
# Query latest K-step forward simulation rollout
curl -s http://localhost:8000/api/v1/simulation/latest | jq .

# Query recent threat alerts
curl -s http://localhost:8000/api/v1/alerts | jq .
```

### Step 5: SOC Web Dashboard
```bash
cd dashboard
npm run dev
```
Navigate to `http://localhost:3000` to view the live threat alerts and simulated progression.