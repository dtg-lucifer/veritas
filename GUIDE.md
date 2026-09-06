# Network World Model Cyber Defense System — Developer Guide

Welcome to the **Network World Model Cyber Defense & Infiltration Forecasting System** repository (SIH 2026).

This guide provides a single, comprehensive reference for developers, researchers, and maintainers. It explains the system architecture, mathematical and machine learning formulation of the World Model, directory structure, individual file responsibilities, forward simulation dynamics, MITRE ATT&CK tactical mapping, and developer workflows.

---

## Table of Contents

1. [Executive Overview & Problem Statement](#1-executive-overview--problem-statement)
2. [End-to-End System Architecture](#2-end-to-end-system-architecture)
3. [The World Model Paradigm ($P(S_{t+1} \mid S_{\le t})$)](#3-the-world-model-paradigm)
4. [32-Dimensional Network State Vector ($S_t$)](#4-32-dimensional-network-state-vector-s_t)
5. [Complete Codebase File Map](#5-complete-codebase-file-map)
6. [K-Step Autoregressive Forward Simulation](#6-k-step-autoregressive-forward-simulation)
7. [MITRE ATT&CK Tactical Progression Mapping](#7-mitre-attck-tactical-progression-mapping)
8. [Explainable AI (XAI) & Driving Feature Attribution](#8-explainable-ai-xai--driving-feature-attribution)
9. [Benchmark: World Model vs. Static Baseline](#9-benchmark-world-model-vs-static-baseline)
10. [Developer Workflows & CLI Commands](#10-developer-workflows--cli-commands)

---

## 1. Executive Overview & Problem Statement

### The Problem
Traditional intrusion detection systems (IDS) and perimeter firewalls evaluate network packets and flows in isolation, mapping them to a static benign or malicious binary label. This point-in-time approach is fundamentally blind to the **temporal progression and causal physics of modern cyber attacks**:
- The sequence in which reconnaissance ports are probed.
- The subtle TCP SYN flag distribution that precedes an exploit attempt.
- The inter-arrival timing (IAT) of scanning packets before lateral movement and exfiltration begin.

An infiltration is an evolving process unfolding over time, not an isolated anomalous packet.

### The Solution: AI World Model
Our architecture implements an **AI World Model for Proactive Cyber Defense**. Rather than classifying static snapshots, the World Model learns the state transition dynamics of the network environment:

$$P(S_{t+1} \mid S_{\le t})$$

Given an observed history of time-windowed network states $S_t \in \mathbb{R}^{32}$, the model:
1. **Simulates Environment Physics:** Generates predicted future network states $\hat{S}_{t+1}$.
2. **Rolls Out $K$ Steps Ahead:** Autoregressively simulates the trajectory $[\hat{S}_{t+1}, \dots, \hat{S}_{t+K}]$.
3. **Forecasts Infiltration Probability:** Produces a future risk timeline $[P_1, \dots, P_K]$ before compromise is completed.
4. **Anticipates MITRE ATT&CK Stages:** Tracks attacker progression from Reconnaissance to Initial Access, Infiltration, Command & Control, and Impact.
5. **Provides Root-Cause Explainability:** Uses temporal self-attention weights and gradient feature attribution to pinpoint exact driving features (SYN ratios, port scans, byte rates).

### How the System Works in Simple Words (Step-by-Step Pipeline)

1. **System Takes Network Logs**: Continuously captures raw network packets or flow logs from the gateway. It discards any labels or attack names—the model only inspects pure physical connection signals.
2. **Groups Traffic into 15-Second Snapshots**: Rather than evaluating isolated packets, it groups all flows over each 15-second period into a **32-number fingerprint** ($S_t$) representing connection count, port entropy, SYN/ACK flag ratios, byte rates, packet sizes, and inter-arrival timing (IAT).
3. **Watches the Recent Past (The Last 2 Minutes)**: Passes the last 8 snapshots ($8 \times 15\text{s} = 2\text{ minutes}$) through a recurrent neural network with multi-head temporal self-attention to understand traffic velocity and momentum.
4. **Imagines the Immediate Future (The "World Model" Transition)**: Autoregressively predicts what the 32-number network state will look like in the next 15 seconds ($\hat{S}_{t+1}$), and feeds that prediction back into itself to simulate **30s, 45s, 60s, and 75s ahead** ($K=5$ rollout steps).
5. **Forecasts Threat Probability & MITRE ATT&CK Phase**: For each future step, outputs an **Infiltration Probability (%)** and identifies the anticipated tactical attack phase (Reconnaissance, Initial Access, Lateral Movement, C2, Exfiltration).
6. **Enforces Autonomous Proactive Defense**:
   - **Risk < 40%**: Status `NORMAL` $\to$ Policy: `ALLOW`.
   - **40% ≤ Risk < 70%**: Status `SUSPICIOUS` $\to$ Policy: `ALERT_ADMIN`.
   - **Risk ≥ 70%**: Status `CRITICAL` $\to$ Policy: `ISOLATE_DEVICE` (pre-emptively cuts off malicious IPs/ports before damage is done).
7. **Explains the Root Cause**: Highlights the exact driving features (e.g. *25% surge in packet rate, 16% byte velocity, 12% SYN flood*) so SOC analysts know precisely why action was taken.

---

## 2. End-to-End System Architecture

```
[ Network Traffic / L4 & L7 Telemetry ]
                  │
                  ▼
     [ PyShark / Scapy Packet Sniffer / Dataset Flow Replayer ]
                   │
                   ▼ (Async JSON Stream)
     [ Apache Kafka Topic: network_flows ]
                   │
                   ▼ (Kafka Consumer Worker)
[ 15-Second Stateful State Window Aggregator ]
                  │
                  ▼ (32-D State Vector S_t)
[ Temporal Context Buffer: S_{t-W+1} ... S_t (W=8) ]
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│ AI Network World Model                                      │
│   • Latent State Encoder: Linear + LayerNorm (z_t in R^64)  │
│   • Recurrent Dynamics Core: 2-Layer Causal LSTM (h_t)      │
│   • Temporal Multi-Head Attention: Long-Range Attention     │
│   • Transition Dynamics Head: \hat{S}_{t+1}                 │
│   • Infiltration Risk Head: P(Infiltration)                 │
│   • MITRE ATT&CK Stage Head: Phase 0..5                     │
└─────────────────────────────────────────────────────────────┘
                  │
                  ▼ (K-Step Autoregressive Forward Rollout)
┌─────────────────────────────────────────────────────────────┐
│ Forward Simulation Horizon (k = 1 ... K)                    │
│   • Infiltration Risk Timeline: [P_1, P_2, ..., P_K]        │
│   • Projected Network States: [\hat{S}_{t+1} ... \hat{S}_K] │
│   • Tactical Stage Progression: Recon -> Infiltration -> C2 │
│   • Driving Feature Attribution & Attention Heatmaps        │
└─────────────────────────────────────────────────────────────┘
                  │
     ┌────────────┼───────────────────────────┐
     ▼            ▼                           ▼
  P < 40%      40% <= P < 70%               P >= 70%
  NORMAL       SUSPICIOUS                   CRITICAL
  (ALLOW)     (ALERT_ADMIN)             (ISOLATE_DEVICE)
                    │                           │
                    └─────────────┬─────────────┘
                                  ▼
                     [ Real-Time WebSocket Alerts ]
                                  │
                                  ▼
                   [ Next.js SOC Security Dashboard ]
```

---

## 3. The World Model Paradigm

In reinforcement learning and generative world models (Ha & Schmidhuber, Hafner et al.), a world model learns a causal simulator of the environment. In cyber defense, the environment is the computer network, and the transition dynamics capture how legitimate traffic flows transition normally versus how malicious probing transitions into full intrusion:

- **State Encoder ($g_\phi$):** $z_t = g_\phi(S_t)$ maps high-dimensional network observations into continuous latent space.
- **Recurrent Dynamics ($f_\theta$):** $h_t = f_\theta(h_{t-1}, z_t)$ tracks causal sequence dynamics across time windows.
- **Temporal Attention:** Computes self-attention across the history window $[t-W+1, \dots, t]$ to weigh critical precursor windows.
- **Dynamics Transition Head ($p_\psi$):** $\hat{S}_{t+1} = p_\psi(h_t)$ simulates next-state network physics.
- **Composite Training Objective:**
  $$\mathcal{L} = \mathcal{L}_{\text{dynamics}}(\hat{S}_{t+1}, S_{t+1}) + 1.5 \mathcal{L}_{\text{infiltration}}(\hat{y}_{\text{inf}}, y_{\text{inf}}) + 1.0 \mathcal{L}_{\text{stage}}(\hat{y}_{\text{stage}}, y_{\text{stage}})$$

---

## 4. 32-Dimensional Network State Vector ($S_t$)

Every 15 seconds, incoming flow records are aggregated into a standardized state vector $S_t \in \mathbb{R}^{32}$:

| Index | Feature Name | Description | Threat Indicator |
| :---: | :--- | :--- | :--- |
| 1 | `flow_count` | Number of flows in window | Sudden connection floods |
| 2–5 | `tot_fwd_pkts`, `tot_bwd_pkts`, `tot_fwd_bytes`, `tot_bwd_bytes` | Directional packet and byte volumes | Exfiltration bursts & data transfers |
| 6–7 | `flow_bytes_rate`, `flow_pkts_rate` | Rates per second | Volumetric anomalies |
| 8 | `flow_duration_mean` | Average flow duration | Short scan bursts vs lingering C2 |
| 9–10 | `syn_flag_count`, `syn_ratio` | SYN flag count and ratio to total packets | SYN port scans and SYN flooding |
| 11–12 | `ack_flag_count`, `ack_ratio` | ACK flag count and ratio | Normal handshake verification |
| 13–16 | `rst_flag_count`, `fin_flag_count`, `psh_flag_count`, `urg_flag_count` | RST/FIN teardown and PSH/URG counts | Port scan rejections and payload push |
| 17 | `unique_dst_ports` | Count of unique destination ports targeted | **Primary reconnaissance scan signal** |
| 18 | `ephemeral_port_ratio` | Ratio of traffic to ports $\ge 1024$ | Lateral movement & RPC probing |
| 19–21 | `web_port_ratio`, `dns_port_ratio`, `ssh_ftp_port_ratio` | Specific protocol port concentrations | Web exploits, DNS tunneling, brute force |
| 22–23 | `tcp_protocol_ratio`, `udp_protocol_ratio` | L4 protocol ratios | UDP floods vs TCP stateful attacks |
| 24–25 | `pkt_len_mean`, `pkt_len_std` | Packet size distribution statistics | Payload anomaly and buffer injection |
| 26–28 | `flow_iat_mean`, `flow_iat_std`, `flow_iat_max` | Inter-arrival timing statistics | Low-and-slow stealth scans |
| 29 | `down_up_ratio_mean` | Downlink to uplink traffic ratio | Data exfiltration asymmetry |
| 30 | `init_fwd_win_mean` | Initial TCP window size mean | OS fingerprinting & scan probes |
| 31–32 | `active_duration_mean`, `idle_duration_mean` | Active and idle session intervals | C2 beaconing duty cycle |

---

## 5. Complete Codebase File Map

```
internal-firewall-sih-2026/
├── ml/                       # Machine Learning World Model & Benchmarking
│   ├── data/
│   │   ├── external-network/ # CSE-CIC-IDS2018 & CIC-IoT-2023 datasets
│   │   ├── internal-network/ # Legacy insider threat datasets
│   │   └── cache/            # Cached parquet state matrices for instant re-runs
│   ├── models/               # Saved trained checkpoints (.pt, .joblib)
│   │   ├── world_model.pt    # PyTorch Attention-Augmented Recurrent World Model
│   │   └── baseline_classifier.joblib # Trained Logistic Regression baseline
│   ├── reports/              # Evaluation & comparative benchmark reports (JSON)
│   │   └── world_model_benchmark.json
│   ├── src/                  # Core ML source code
│   │   ├── features/         # Feature extraction & state windowing
│   │   │   ├── traffic_extractor.py # CIC-IDS-2018 CSV & PCAP parser
│   │   │   └── state_window.py      # Vectorized 15s state aggregator & sequence window
│   │   ├── world_model/      # World Model neural architecture
│   │   │   ├── network_world_model.py # Attention-Augmented Recurrent Latent World Model
│   │   │   ├── forward_simulator.py   # K-step autoregressive rollout engine
│   │   │   └── explainability.py      # Attention weights & gradient attribution
│   │   ├── baseline/         # Experimental baseline
│   │   │   └── static_baseline.py     # Static Logistic Regression classifier
│   │   ├── evaluation/       # Performance evaluation
│   │   │   └── benchmark.py           # F1, FPR, ROC-AUC, Lead-Time comparator
│   │   └── mitre_mapping.py  # Attack label to MITRE ATT&CK phase mapping
│   ├── train.py              # Unified training & benchmarking CLI
│   ├── demo.py               # Interactive forward simulation demonstration CLI
│   └── README.md             # ML engine documentation
│
├── backend/                  # FastAPI Gateway, Kafka Worker & WebSocket Hub
│   ├── src/
│   │   ├── main.py           # FastAPI application, REST endpoints, WebSocket hub
│   │   ├── kafka_worker.py   # Asynchronous Kafka flow consumer & alert broadcaster
│   │   ├── world_model_service.py # Stateful 15s window aggregator & forward simulation engine
│   │   ├── predictor.py      # Auxiliary/legacy prediction service
│   │   ├── log_buffer.py     # In-memory sliding window state aggregator
│   │   └── redis_worker.py   # Legacy Redis queue consumer & test client worker
│   └── README.md
│
├── logger/                   # Network Telemetry Logger & Kafka Producer
│   ├── main.py               # Unified Typer CLI (--day, --attack, sniff, pcap)
│   ├── src/
│   │   ├── day_replayer.py   # CSE-CIC-IDS2018 day flow stream replayer to Kafka
│   │   ├── sniffer.py        # PyShark live packet sniffer to Kafka
│   │   └── parser.py         # PCAP and network packet parser
│   └── README.md
│
├── simulator/                # Synthetic Threat Traffic Generator
│   ├── simulate.py           # Simulates multi-stage attack scenarios (HTTP REST / Redis)
│   ├── traffic_generator.py  # Asynchronous HTTP / Redis traffic dispatcher
│   ├── scenarios.py          # Workload profiles (normal baseline vs suspicious bursts)
│   └── README.md
│
├── dashboard/                # Next.js SOC Security Frontend (Next.js 16 / React 19)
│   ├── src/
│   │   ├── app/              # App router & global styles
│   │   └── components/
│   │       ├── Dashboard.tsx # Main SOC console with live radar, WebSocket feed, risk charts
│   │       ├── alerts/       # Real-time incident feed & device isolation triggers
│   │       └── charts/       # Threat risk distribution visualizations
│   └── README.md
│
├── COMMANDS.md               # Operational command reference
├── FLOW.md                   # Mermaid architecture pipeline diagram
├── WORKFLOW.md               # End-to-end technical workflow and presentation guide
├── ARCHITECTURE.md           # Deep architectural design rationale
├── MIGRATION.md              # Hackathon problem statement & expected solution
└── GUIDE.md                  # Comprehensive developer guide (this document)
```

---

## 6. K-Step Autoregressive Forward Simulation

Given an observed historical trajectory of $W=8$ states:

```
[ S_{t-7}, S_{t-6}, S_{t-5}, S_{t-4}, S_{t-3}, S_{t-2}, S_{t-1}, S_t ]
                                  │
                                  ▼
                       [ World Model Forward ]
                                  │
         ┌────────────────────────┴────────────────────────┐
         ▼                                                 ▼
   Predicted Next State \hat{S}_{t+1}               Predicted Infiltration Prob P_1
         │                                                 │
         ▼ (Append to sequence, drop oldest)               ▼
   [ S_{t-6} ... S_t, \hat{S}_{t+1} ]               [ P_1 ]
         │
         ▼ (Simulate Step 2)
   Predicted Next State \hat{S}_{t+2} ────────────► [ P_1, P_2 ]
         │
         ▼ (Repeat up to Step K)
   Future Horizon [\hat{S}_{t+1} ... \hat{S}_{t+K}] ─► [ P_1, P_2, P_3, P_4, P_K ]
```

The forward simulation engine outputs:
1. **Future Infiltration Risk Timeline:** Probability of compromise across future time steps $t+1 \dots t+K$.
2. **Early Warning Lead Time:** Detects trajectory convergence $K$ windows *before* the attacker reaches impact.
3. **Simulated Environment State:** Projected flow counts, SYN ratios, and byte volumes under anticipated attack conditions.

---

## 7. MITRE ATT&CK Tactical Progression Mapping

Network traffic states map directly to canonical MITRE ATT&CK tactical stages (`src/mitre_mapping.py`):

| Stage ID | Tactical Phase | Associated MITRE Techniques | Key Traffic Precursors |
| :---: | :--- | :--- | :--- |
| **0** | **Benign** | Operational baseline | Balanced SYN/ACK ratios, standard HTTP/DNS ports |
| **1** | **Reconnaissance** | T1046 (Port Scan), T1595 (Active Scan) | High `unique_dst_ports`, high `syn_ratio`, low `pkt_len` |
| **2** | **Initial Access** | T1110 (Brute Force), T1190 (Exploit Public App) | Repeated high `flow_count` on ports 21/22/80, auth failure surges |
| **3** | **Infiltration / Lateral** | T1210 (Exploit Remote Service), T1021 (Remote Pivot)| Infiltration payloads, SMB/RDP pivot, internal scan bursts |
| **4** | **Command & Control** | T1071 (App Protocol), T1573 (Encrypted Channel) | Periodic beaconing (`flow_iat_std` low), ARES bot check-ins |
| **5** | **Exfiltration / Impact** | T1048 (Exfiltration Over Protocol), T1499 (DoS) | Outbound byte surge (`down_up_ratio` inverted), flooding |

---

## 8. Explainable AI (XAI) & Driving Feature Attribution

To ensure full transparency for Security Operations Center (SOC) analysts:

1. **Temporal Attention Weights:** Attention scores over historical time steps identify which exact preceding window contained the initial probing trigger.
2. **Gradient $\times$ Input Feature Attribution:**
   $$\text{Attribution}_j = \left| S_{t, j} \times \frac{\partial P_{\text{inf}}^{(t+1)}}{\partial S_{t, j}} \right|$$
   Computes exact percentage contribution for each of the 32 state vector features.
3. **Natural Language Root-Cause Translation:** Synthesizes clear explanations:
   > `[CRITICAL] Forward dynamics forecast threat escalation driven by: abnormal SYN packet concentration (42% attribution); rapid multi-port scanning activity across 318 distinct ports (28% attribution).`

---

## 9. Benchmark: World Model vs. Static Baseline

The evaluation suite (`ml/src/evaluation/benchmark.py`) directly compares the World Model against a static Logistic Regression baseline trained on identical features:

- **F1-Score Improvement:** Sequence modeling eliminates false positives by learning normal state transition dynamics.
- **Lower False Positive Rate (FPR):** Avoids ringing alarms on transient benign bursts.
- **Proactive Detection Horizon:** While static classifiers only trigger *after* compromise has arrived ($t=0$), the World Model detects trajectory convergence **$K$ steps in advance** ($t+K$), providing proactive defense.

---

## 10. Developer Workflows & CLI Commands

For a full cheat sheet across all modules, refer to [`COMMANDS.md`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/COMMANDS.md).

### 10.1 Training the World Model & Benchmark Suite
```bash
cd ml
# Rapid training with 15% subsampling across CIC-IDS-2018 files
uv run python train.py --sample-frac 0.15 --epochs 12 --window-size 15 --seq-len 8

# Full dataset training without cache
uv run python train.py --epochs 20 --window-size 15 --seq-len 8 --no-cache
```

### 10.2 Interactive Forward Simulation Demo (Terminal View)
```bash
cd ml
# Infiltration evaluation (Thursday-01-03-2018)
uv run python demo.py --file data/external-network/cic-ids-2018/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv --rollout-steps 5

# FTP/SSH Brute Force evaluation (Wednesday-14-02-2018)
uv run python demo.py --file data/external-network/cic-ids-2018/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv --rollout-steps 5

# Raw PCAP capture evaluation
uv run python demo.py --file path/to/capture.pcap --rollout-steps 5
```

### 10.3 Exporting Demonstration Reports (Markdown or Plain Text)
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

### 10.4 Targeted Scenario Selection
```bash
cd ml
# Attack progression sequence (Auto-targets peak attack activity)
uv run python demo.py --file data/external-network/cic-ids-2018/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv --scenario attack

# Attack onset transition sequence (4 pre-attack windows + 4 early attack windows)
uv run python demo.py --file data/external-network/cic-ids-2018/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv --scenario onset

# Nominal benign baseline sequence (Verifies low false positive rate)
uv run python demo.py --file data/external-network/cic-ids-2018/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv --scenario benign

# Explicit window index evaluation
uv run python demo.py --file data/external-network/cic-ids-2018/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv --window-idx 1662
```

### 10.5 Running the Backend, Logger, and Dashboard Services
```bash
# Terminal 1: Apache Kafka Message Broker & Web UI (KRaft mode, port 9092 & 8081)
docker compose up -d kafka kafka-ui

# Terminal 2: FastAPI Streaming Gateway & AI World Model Service
cd backend && WINDOW_SECONDS=15 uv run uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload

# Terminal 3: Stream Day Telemetry into Kafka (or live packet sniffing)
cd logger && uv run logger --day thursday --scenario attack --max-flows 200 --rate 100
# or live interface sniffing:
# cd logger && sudo uv run logger sniff --interface eth0

# Terminal 4: Next.js SOC Security Dashboard
cd dashboard && npm run dev
```
