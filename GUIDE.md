# 🛡️ Internal Firewall & AI-Powered UEBA System — Developer Guide

Welcome to the **Internal Firewall & AI/ML User and Entity Behavior Analytics (UEBA) System** repository (SIH 2026).

This guide provides a single, comprehensive reference for future developers, researchers, and maintainers. It explains the entire architecture, directory structure, individual file responsibilities, design rationale behind the multi-model ML ensemble, behavioral feature engineering, and developer workflows.

---

## 📑 Table of Contents

1. [Executive Overview & Problem Statement](#1-executive-overview--problem-statement)
2. [End-to-End System Architecture](#2-end-to-end-system-architecture)
3. [Complete Codebase File Map](#3-complete-codebase-file-map)
   - [3.1 `backend/` (FastAPI Gateway & Redis Worker)](#31-backendsrc-fastapi-gateway--redis-worker)
   - [3.2 `ml/` (AI/ML Models, Training & Risk Engine)](#32-ml-aiml-models-training--risk-engine)
   - [3.3 `logger/` (Packet Sniffer & Parser)](#33-loggersrc-packet-sniffer--parser)
   - [3.4 `simulator/` (Threat Traffic Generator)](#34-simulator-threat-traffic-generator)
   - [3.5 `dashboard/` (Next.js SOC Frontend)](#35-dashboard-nextjs-soc-frontend)
   - [3.6 Root Files & Orchestration](#36-root-files--orchestration)
4. [Why These 4 ML Models? (Defense-in-Depth AI Rationale)](#4-why-these-4-ml-models-defense-in-depth-ai-rationale)
5. [Multi-Model Risk Fusion Formula & Policy Matrix](#5-multi-model-risk-fusion-formula--policy-matrix)
6. [30-Dimension Behavioral Feature Vector](#6-30-dimension-behavioral-feature-vector)
7. [Threading & Concurrency Architecture](#7-threading--concurrency-architecture)
8. [Developer Workflows & How-To Guides](#8-developer-workflows--how-to-guides)
9. [Key Conventions & Important Gotchas](#9-key-conventions--important-gotchas)

---

## 1. Executive Overview & Problem Statement

### The Problem
Traditional perimeter firewalls defend the enterprise boundary against incoming external network attacks. However, **insider threats** (malicious employees, compromised credentials, privilege abuse, data exfiltration to USB drives, after-hours cloud uploads) operate *inside* the perimeter. They bypass standard signature-based firewall rules because their network packets appear as legitimate internal traffic.

### The Solution
This system is an **Internal Zero-Trust Firewall & UEBA Gateway** that continuously evaluates user behavior across 5-minute sliding windows using a **4-model ML ensemble**.

```
[ Network Traffic / Host Events ]
              │
              ▼
    [ PyShark Packet Sniffer / SIEM Parser ]
              │
              ▼ (Async JSON Stream)
   [ Redis Queue: network_logs_queue ]
              │
              ▼ (BRPOP Silent Ingestion)
[ 5-Minute Stateful Sliding Window Aggregator ]
              │
              ▼ (Every 300s Evaluation Cycle)
┌─────────────────────────────────────────────────────────────┐
│ 🛡️ 4-Model Ensemble Threat Predictor                        │
│   1. Supervised Threat Classifier (LightGBM)                │
│   2. Statistical User Baseline Profiler (Z-Scores)          │
│   3. Unsupervised Isolation Forest (Decision Trees)         │
│   4. Deep PyTorch Autoencoder (Reconstruction Error)        │
└─────────────────────────────────────────────────────────────┘
              │
              ▼ (Composite Risk Score: 0 - 100)
    ┌───────────────────────────┬───────────────────────────┐
    │ Risk < 35                 │ 35 <= Risk < 65           │ Risk >= 65
    ▼                           ▼                           ▼
  ALLOW                   ALERT_ADMIN                 ISOLATE_DEVICE
 (Normal)                (Warning Feeds)             (Block IP / iptables)
                                │                           │
                                └─────────────┬─────────────┘
                                              ▼
                               [ Real-Time WebSocket Alerts ]
                                              │
                                              ▼
                              [ Next.js SOC Security Dashboard ]
```

---

## 2. End-to-End System Architecture

The pipeline consists of five decoupled layers communicating via **Redis Message Queue** and **WebSockets**:

1. **Ingestion Layer (`logger/` & `simulator/`)**: Captures raw network packets in real-time using PyShark / tshark, extracts L4/L7 metadata (HTTP URLs, emails, USB connects, file copies, byte counts), normalizes them into standard JSON schemas, and pushes them to Redis (`LPUSH network_logs_queue`).
2. **Buffering & Aggregation Layer (`backend/src/log_buffer.py`)**: Implements a memory-efficient `TimeWindowLogAggregator` that silently buffers events per user in a thread-safe sliding window. Every 5 minutes (or configurable interval), it computes a 30-dimension behavioral feature vector.
3. **Inference & Risk Fusion Layer (`backend/src/predictor.py` & `ml/src/risk_engine.py`)**: Evaluates the 30-dimension feature vector through all 4 ML models concurrently, combines predictions through the weighted risk fusion formula, incorporates surge signals, and maps output to a 0–100 composite risk score.
4. **Policy & Communication Layer (`backend/src/main.py` & `redis_worker.py`)**: Automatically triggers security policies (`ALLOW`, `ALERT_ADMIN`, `ISOLATE_DEVICE`), updates isolated host IP tables, and broadcasts structured incident alerts over WebSockets and Redis Pub/Sub.
5. **Presentation Layer (`dashboard/`)**: Next.js SOC interface displaying real-time threat maps, active employee risk meters, explainable AI deviation breakdowns, and manual override controls.

---

## 3. Complete Codebase File Map

```
internal-firewall-sih-2026/
├── backend/                  # FastAPI AI/ML Gateway & Streaming Service
│   ├── src/                  # Consolidated backend source code
│   │   ├── __init__.py       # Package root & ML namespace connector
│   │   ├── main.py           # FastAPI application, REST endpoints, WebSocket hub
│   │   ├── predictor.py      # 4-model ensemble inference wrapper
│   │   ├── log_buffer.py     # 5-minute sliding window stateful aggregator
│   │   ├── redis_worker.py   # Multithreaded Redis queue consumer & timer
│   │   ├── redis_producer.py # Standalone Redis attack simulation CLI
│   │   ├── test_client.py    # Integration test suite (FastAPI & endpoints)
│   │   └── test_multithreaded_pipeline.py # End-to-end worker & pipeline test
│   ├── Dockerfile            # Container definition for backend service
│   ├── pyproject.toml        # Backend Python dependencies (uv)
│   ├── test_eval.py          # Quick CLI test for model loading and scoring
│   └── README.md             # Backend quickstart guide
│
├── ml/                       # Machine Learning Engineering & Model Artifacts
│   ├── models/               # Trained binary model artifacts (.joblib, .pt)
│   │   ├── behavioral_classifier.joblib # LightGBM supervised model
│   │   ├── baseline_profiler.joblib     # Statistical user z-score baselines
│   │   ├── isolation_forest.joblib      # Scikit-learn Isolation Forest
│   │   ├── autoencoder.pt               # PyTorch Deep Autoencoder weights
│   │   └── autoencoder_meta.joblib      # Autoencoder feature scalers & threshold
│   ├── reports/              # Evaluation metrics, confusion matrices, ROC curves
│   ├── src/                  # ML core implementation
│   │   ├── __init__.py       # ML package root
│   │   ├── autoencoders/     # PyTorch Autoencoder architecture & detector
│   │   │   ├── __init__.py
│   │   │   └── autoencoder_model.py
│   │   ├── baseline/         # Statistical user baseline profiler
│   │   │   ├── __init__.py
│   │   │   └── statistical_baseline.py
│   │   ├── evaluation/       # Evaluation metrics, PR-AUC, ROC-AUC, classification reports
│   │   │   ├── __init__.py
│   │   │   └── evaluator.py
│   │   ├── features/         # 30-dimension behavioral feature extractor
│   │   │   ├── __init__.py
│   │   │   └── feature_extractor.py
│   │   ├── isolation_forest/ # Isolation Forest anomaly detector
│   │   │   ├── __init__.py
│   │   │   └── isolation_forest_model.py
│   │   ├── models/           # LightGBM supervised classifier
│   │   │   ├── __init__.py
│   │   │   └── behavioral_classifier.py
│   │   ├── preprocessing/    # CERT r4.2 raw dataset parser
│   │   │   ├── __init__.py
│   │   │   └── dataset_parser.py
│   │   └── risk_engine.py    # Standalone Composite Risk Engine & explainability
│   ├── train.py              # Full ML pipeline training script
│   ├── pyproject.toml        # ML Python dependencies
│   └── README.md             # ML dataset & training instructions
│
├── logger/                   # Network Sniffer & Packet Parser
│   ├── src/                  # Sniffer and parser source code
│   │   ├── __init__.py
│   │   ├── parser.py         # PyShark packet inspector & JSON normalizer
│   │   ├── redis_publisher.py# Redis queue publisher for packet logs
│   │   └── sniffer.py        # Live network interface packet sniffer
│   ├── main.py               # Typer CLI for running the live packet capture
│   ├── test_logger.py        # Unit tests for packet parsing & normalization
│   └── pyproject.toml        # Logger Python dependencies
│
├── simulator/                # Network & Threat Traffic Simulator
│   ├── scenarios.py          # Synthetic scenarios (normal vs attack vectors)
│   ├── simulate.py           # Typer CLI to generate live streams (HTTP / Redis)
│   ├── traffic_generator.py  # Dispatcher engine & WebSocket alert listener
│   └── pyproject.toml        # Simulator Python dependencies
│
├── dashboard/                # SOC Analyst Security Dashboard (Next.js / React)
│   ├── src/                  # Dashboard components, pages, hooks, charts
│   └── package.json          # Node dependencies
│
├── e2e_live_demo.py          # Full system end-to-end integration demo runner
├── docker-compose.yml        # Production Docker orchestration (Redis + Backend)
├── docker-compose.test.yml   # Headless automated testing container configuration
├── run_docker_tests.sh       # One-click Dockerized integration test runner
├── COMMANDS.md               # Quick cheat sheet of all development commands
├── ARCHITECTURE.md           # Deep architectural specification
├── WORKFLOW.md               # Operational workflow and incident triage guide
└── FLOW.md                   # Quick ASCII architectural flow summary
```

---

### 3.1 `backend/src/` (FastAPI Gateway & Redis Worker)

| File | Type | Primary Purpose |
| :--- | :--- | :--- |
| [`__init__.py`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/backend/src/__init__.py) | Python Package Root | Dynamically extends `__path__` to share namespace with `ml/src`, allowing models to unpickle cleanly without path collisions. |
| [`main.py`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/backend/src/main.py) | FastAPI Gateway | Houses REST routes (`/health`, `/api/v1/predict`, `/api/v1/logs/ingest`, `/api/v1/alerts`, `/api/v1/policy/enforce`), the `WebSocketHub` connection manager, CORS middleware, and application lifespan startup/shutdown hooks. |
| [`predictor.py`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/backend/src/predictor.py) | Inference Engine | `SecurityModelPredictor` loads the 4 trained models from `ml/models`, scores the 30-dimension feature vector, evaluates surge signals, and returns risk scores, policy actions, and explainable feature deviations. |
| [`log_buffer.py`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/backend/src/log_buffer.py) | Stateful Sliding Window | `TimeWindowLogAggregator` maintains thread-safe sliding windows per user, buffers raw JSON events silently without per-event scoring, and computes the 30-dimension feature vector upon window expiry. |
| [`redis_worker.py`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/backend/src/redis_worker.py) | Multithreaded Consumer | `MultithreadedRedisLogWorker` runs 2 dedicated background OS threads: Thread 1 continuously pops events from Redis queue; Thread 2 evaluates active user windows every 300s, runs predictions, and dispatches WebSocket alerts. |
| [`redis_producer.py`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/backend/src/redis_producer.py) | Producer CLI | Interactive CLI script that pushes 4-stage synthetic attack sequences directly into Redis for testing without running the full sniffer. |
| [`test_client.py`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/backend/src/test_client.py) | Test Suite | Integration tests verifying all REST routes, normal stream ingestion (`ALLOW`), suspicious 5x burst ingestion (`ISOLATE_DEVICE`), and policy enforcement. |
| [`test_multithreaded_pipeline.py`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/backend/src/test_multithreaded_pipeline.py) | Test Suite | End-to-end verification of multithreaded worker lifecycle, state aggregation, 4-model ensemble prediction, and WebSocket alert triggering. |

---

### 3.2 `ml/` (AI/ML Models, Training & Risk Engine)

| File | Type | Primary Purpose |
| :--- | :--- | :--- |
| [`train.py`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/ml/train.py) | Training Pipeline | Orchestrates the entire training pipeline: loads CERT r4.2 data, extracts 30 features, trains all 4 models, evaluates metrics, and saves binary artifacts to `ml/models/`. |
| [`src/risk_engine.py`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/ml/src/risk_engine.py) | Fusion Logic | `CompositeRiskEngine` implements the mathematical multi-model fusion formula, thresholding logic, and human-readable feature explanation generation. |
| [`src/models/behavioral_classifier.py`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/ml/src/models/behavioral_classifier.py) | Supervised Model | `GradientBoostedBehavioralClassifier` wraps LightGBM with hyperparameter tuning for class imbalance (scale_pos_weight) and tree SHAP explanations. |
| [`src/baseline/statistical_baseline.py`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/ml/src/baseline/statistical_baseline.py) | Statistical Model | `UserBaselineProfiler` builds per-user mean and standard deviation profiles for each metric, calculating empirical Z-score baseline deviations. |
| [`src/isolation_forest/isolation_forest_model.py`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/ml/src/isolation_forest/isolation_forest_model.py) | Unsupervised Model | `IsolationForestAnomalyDetector` wraps Scikit-Learn's Isolation Forest with custom anomaly scoring and tree traversal explanations. |
| [`src/autoencoders/autoencoder_model.py`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/ml/src/autoencoders/autoencoder_model.py) | Neural Model | `AutoencoderAnomalyDetector` implements a PyTorch feedforward bottleneck autoencoder (`30 → 16 → 8 → 4 → 8 → 16 → 30`) using MSE reconstruction loss as the anomaly signal. |
| [`src/features/feature_extractor.py`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/ml/src/features/feature_extractor.py) | Feature Engineering | Transforms raw tabular events (logon, device, file, email, http) into fixed-size daily and 5-minute behavioral feature vectors. |
| [`src/preprocessing/dataset_parser.py`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/ml/src/preprocessing/dataset_parser.py) | Data Ingestion | Parses the raw CERT Insider Threat r4.2 CSV files (`logon.csv`, `device.csv`, `file.csv`, `email.csv`, `http.csv`, `psychometric.csv`). |
| [`src/evaluation/evaluator.py`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/ml/src/evaluation/evaluator.py) | Evaluation Suite | Generates classification reports, Confusion Matrices, Precision-Recall curves, and ROC curves saved into `ml/reports/`. |

---

### 3.3 `logger/src/` (Packet Sniffer & Parser)

| File | Type | Primary Purpose |
| :--- | :--- | :--- |
| [`main.py`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/logger/main.py) | CLI Entrypoint | Typer CLI providing commands to sniff live network interfaces (`sniff`) or parse offline PCAP files (`pcap`). |
| [`src/sniffer.py`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/logger/src/sniffer.py) | Network Capture | `NetworkSniffer` attaches to network interfaces via PyShark / TShark, filters packets, and streams them into the parser. |
| [`src/parser.py`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/logger/src/parser.py) | Packet Parser | `PacketParser` inspects packet headers (TCP/UDP ports, HTTP Host/URI, DNS queries, payload lengths) and maps source IPs to employee identities (`DEFAULT_IP_USER_MAP`). |
| [`src/redis_publisher.py`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/logger/src/redis_publisher.py) | Message Producer | `RedisLogPublisher` serializes parsed packet events to JSON and pushes them via `LPUSH` into Redis queue `network_logs_queue`. |

---

### 3.4 `simulator/` (Threat Traffic Generator)

| File | Type | Primary Purpose |
| :--- | :--- | :--- |
| [`simulate.py`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/simulator/simulate.py) | Simulation CLI | Typer CLI with `--mode normal`, `--mode mild`, and `--mode suspicious` flags to generate controlled test traffic. |
| [`scenarios.py`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/simulator/scenarios.py) | Scenario Generator | Contains scenario generators: standard 9-to-5 workday traffic, subtle after-hours queries, and aggressive multi-stage attacks (Wikileaks, USB archive dumps, credential dumping, exfiltration bursts). |
| [`traffic_generator.py`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/simulator/traffic_generator.py) | Dispatcher & WS Listener | Dispatches generated scenario events to either HTTP endpoints (`/api/v1/logs/ingest`) or Redis MQ (`network_logs_queue`) and listens for real-time WebSocket incident alerts. |

---

### 3.5 `dashboard/` (Next.js SOC Frontend)

- **`src/app/page.tsx`**: Main SOC overview dashboard.
- **`src/components/`**: UI widgets for real-time threat charts, recent incident lists, employee risk score gauges, and firewall policy controls.
- **`src/hooks/useWebSocket.ts`**: Connects to `ws://localhost:8000/ws/alerts` for live alert streaming without page polling.

---

### 3.6 Root Files & Orchestration

- [`docker-compose.yml`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/docker-compose.yml): Production Docker configuration launching Redis, Redis Commander UI (port 8081), and the FastAPI backend (port 8000).
- [`docker-compose.test.yml`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/docker-compose.test.yml): Automated CI/CD test runner executing `src.test_client` inside Docker.
- [`run_docker_tests.sh`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/run_docker_tests.sh): Bash script executing the complete Docker integration test suite and cleaning up containers.
- [`e2e_live_demo.py`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/e2e_live_demo.py): Complete end-to-end demonstration script that runs Uvicorn, attaches the sniffer publisher, executes normal & attack simulator streams, and displays a summary table.
- [`COMMANDS.md`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/COMMANDS.md): Quick command cheatsheet for developers.
- [`ARCHITECTURE.md`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/ARCHITECTURE.md) & [`WORKFLOW.md`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/WORKFLOW.md): In-depth architectural designs and operational manuals.

---

## 4. Why These 4 ML Models? (Defense-in-Depth AI Rationale)

No single machine learning model can adequately solve insider threat detection. Insider threats present three distinct challenges:
1. **Severe Class Imbalance**: Genuine attacks represent <0.01% of all network events.
2. **Personal Behavioral Baselines**: What is anomalous for an HR employee (accessing Git repos, working at 2 AM) is standard for a DevOps engineer.
3. **Zero-Day & Novel Attack Patterns**: Attackers constantly innovate new exfiltration techniques that supervised models trained on historical data have never seen.

To solve this, the system implements a **4-model ensemble**:

```
                   ┌────────────────────────────────────────────────────────┐
                   │               30-Dimension Feature Vector              │
                   └───────────────────────────┬────────────────────────────┘
                                               │
               ┌───────────────────┬───────────┴───────┬───────────────────┐
               ▼                   ▼                   ▼                   ▼
    ┌─────────────────────┐ ┌─────────────┐ ┌─────────────────────┐ ┌─────────────┐
    │ 1. LightGBM Threat  │ │ 2. Baseline │ │ 3. Isolation Forest │ │ 4. Deep AE  │
    │    Classifier       │ │    Profiler │ │    Anomaly Tree     │ │    Loss     │
    │  (Supervised)       │ │ (Statistical│ │   (Unsupervised)    │ │  (Neural)   │
    └──────────┬──────────┘ └──────┬──────┘ └──────────┬──────────┘ └──────┬──────┘
               │ (Weight: 0.50)    │ (Weight: 0.20)    │ (Weight: 0.15)    │ (Weight: 0.15)
               └───────────────────┼───────────────────┴───────────────────┘
                                   │
                                   ▼
                   ┌────────────────────────────────────────┐
                   │ Composite Risk Fusion & Signal Boost   │
                   │ Risk Score = 0.0 - 100.0               │
                   └────────────────────────────────────────┘
```

### 1. Supervised Gradient Boosted Classifier (LightGBM)
- **Role**: Primary threat pattern detector.
- **Weight**: 40% – 50%
- **Why LightGBM**:
  - Extremely fast sub-millisecond tabular inference (<0.5ms).
  - Handles mixed categorical/continuous distributions natively.
  - Trained with `scale_pos_weight` and focal loss to detect rare malicious insider attack signatures (e.g. Wikileaks uploads, after-hours USB copying) with high precision and near-zero false alarms.
  - Native tree-SHAP support for explainable AI outputs.

### 2. Statistical User Baseline Profiler (Z-Scores)
- **Role**: Personalized anomaly detection relative to the individual employee's historical habits.
- **Weight**: 20% – 25%
- **Why Statistical Baseline**:
  - Builds per-user Gaussian profiles $(\mu, \sigma)$ for each of the 30 metrics based on the employee's past 30 days.
  - Prevents false positives: If a developer regularly downloads 500MB zip files during normal work, their $\sigma$ is high and no alarm triggers. If an accountant suddenly copies 500MB of zip archives to a USB drive, their Z-score exceeds $+5.0\sigma$, triggering an instant anomaly score.

### 3. Unsupervised Isolation Forest
- **Role**: Label-free multivariate outlier detection.
- **Weight**: 15% – 20%
- **Why Isolation Forest**:
  - Does not rely on labeled training attacks; isolates anomalies by randomly partitioning feature space with orthogonal decision trees.
  - Anomalous feature combinations (e.g. rare port + unusual protocol + off-hours connection) require very few splits to isolate, yielding high anomaly scores.
  - Detects novel, zero-day threat tactics that supervised models missed.

### 4. Deep PyTorch Autoencoder
- **Role**: Non-linear latent manifold reconstruction error.
- **Weight**: 15%
- **Why Deep Autoencoder**:
  - Architecture: Fully connected bottleneck network (`30 → 16 → 8 → 4 → 8 → 16 → 30`) with LeakyReLU activations and Batch Normalization.
  - Trained exclusively on **normal enterprise traffic** to compress and reconstruct standard behavior.
  - When presented with subtle, coordinated insider activity involving multiple correlated variables, the autoencoder fails to reconstruct the input, producing high Mean Squared Error ($\text{MSE}$) reconstruction loss.
  - Catches complex non-linear feature interactions that linear baselines and axis-aligned trees cannot represent.

---

## 5. Multi-Model Risk Fusion Formula & Policy Matrix

### Risk Fusion Equation

1. **Base Ensemble Fusion**:
   $$\text{BaseEnsemble} = 0.50 \cdot s_{\text{gb}} + 0.20 \cdot s_{\text{base}} + 0.15 \cdot s_{\text{if}} + 0.15 \cdot s_{\text{ae}}$$

2. **Threat Signal Boost**:
   If hard threat signals are present (e.g., `sensitive_web_count > 0`, `device_connect_count > 0`, `file_copy_count > 0`, `after_hours_ratio > 0.4`):
   $$\text{UnsupervisedConsensus} = 0.40 \cdot s_{\text{base}} + 0.35 \cdot s_{\text{ae}} + 0.25 \cdot s_{\text{if}}$$
   $$\text{CompositeProb} = \max\left(s_{\text{gb}}, \; 0.40 \cdot s_{\text{gb}} + 0.60 \cdot \text{UnsupervisedConsensus}\right)$$

3. **Benign Activity Normalization**:
   If zero threat signals exist (pure workday web browsing), the score is capped in the safe zone:
   $$\text{CompositeProb} = \min(0.30, \; \text{BaseEnsemble})$$

4. **Composite Risk Score (0 to 100)**:
   $$\text{RiskScore} = \text{round}(\text{CompositeProb} \times 100.0, \; 1)$$

---

### Automated Policy Decision Matrix

| Risk Score Range | Severity Level | Policy Action | Automated Action Taken |
| :--- | :--- | :--- | :--- |
| **0.0 – 34.9** | `NORMAL` | `ALLOW` | Packet allowed; user window state retained. |
| **35.0 – 64.9** | `SUSPICIOUS` | `ALERT_ADMIN` | Incident alert pushed to SOC WebSocket feed; elevated monitoring enabled. |
| **65.0 – 100.0** | `CRITICAL` | `ISOLATE_DEVICE` | High-priority alert broadcast; automated firewall rule generated to isolate host IP. |

---

## 6. 30-Dimension Behavioral Feature Vector

Every 5-minute aggregation window computes exactly 30 numerical features:

| Category | Feature Name | Type | Description |
| :--- | :--- | :--- | :--- |
| **Removable USB** | `device_connect_count` | `float` | Number of USB/removable drive connect events in window |
| | `device_disconnect_count` | `float` | Number of USB drive disconnect events |
| | `device_after_hours` | `float` | Number of USB connect/disconnect events outside 07:30–18:30 |
| **File Activity** | `file_copy_count` | `float` | Total file copy operations detected |
| | `file_doc_pdf_count` | `float` | Copies of documents (`.pdf`, `.docx`, `.xlsx`, `.csv`) |
| | `file_zip_exe_count` | `float` | Copies of archives or executables (`.zip`, `.rar`, `.7z`, `.exe`) |
| | `file_after_hours` | `float` | File copies executed after hours |
| **Email Activity** | `email_sent_count` | `float` | Total outbound emails sent |
| | `email_total_bytes` | `float` | Cumulative volume of email attachments in bytes |
| | `email_avg_bytes` | `float` | Average size per email in bytes |
| | `email_max_bytes` | `float` | Largest single email payload in bytes |
| | `email_external_count` | `float` | Emails sent to non-company domains (e.g. personal Gmail, competitors) |
| | `email_bcc_count` | `float` | Emails containing BCC recipients |
| | `email_after_hours` | `float` | Emails transmitted outside working hours |
| **Web & HTTP** | `http_request_count` | `float` | Total HTTP requests / connection events |
| | `http_wikileaks_count` | `float` | Requests to whistleblowing / leak platforms |
| | `http_job_search_count`| `float` | Requests to job boards (Monster, LinkedIn, Indeed) |
| | `http_cloud_storage_count`| `float` | Requests to personal cloud storage (Mega.nz, Dropbox, Google Drive) |
| | `http_hacking_count` | `float` | Requests to hacking tools, keyloggers, exploit databases |
| | `http_after_hours` | `float` | Web connections opened after hours |
| **Temporal Signals** | `is_weekend` | `float` | Binary flag (1.0 if Saturday/Sunday, 0.0 otherwise) |
| | `total_activity_count` | `float` | Sum of all events across USB, file, email, and HTTP |
| | `total_after_hours_count`| `float` | Sum of all after-hours operations |
| | `after_hours_ratio` | `float` | Fraction of total activity occurring after hours ($0.0 - 1.0$) |
| **Ratios & Surges** | `sensitive_web_count` | `float` | Total requests to sensitive web categories |
| | `sensitive_web_ratio` | `float` | Ratio of sensitive web requests to total HTTP requests |
| | `external_email_ratio`| `float` | Ratio of external emails to total emails sent |
| **Baseline Surges** | `usb_surge_zscore` | `float` | Calibrated Z-score for USB drive activity surge |
| | `file_surge_zscore` | `float` | Calibrated Z-score for file copy volume surge |
| | `email_bytes_surge_zscore`| `float` | Calibrated Z-score for outbound email payload surge |

---

## 7. Threading & Concurrency Architecture

To guarantee **zero packet drops** under heavy enterprise traffic, the backend utilizes a **two-thread worker model**:

```
                              ┌────────────────────────────────────────┐
                              │     FastAPI Main ASGI Event Loop       │
                              └───────────────────┬────────────────────┘
                                                  │ (Lifespan Startup)
                         ┌────────────────────────┴────────────────────────┐
                         ▼                                                 ▼
             ┌────────────────────────┐                        ┌───────────────────────┐
             │ Thread 1: Consumer     │                        │ Thread 2: Timer       │
             │ (RedisConsumerThread)  │                        │ (WindowTimerThread)   │
             └───────────┬────────────┘                        └───────────┬───────────┘
                         │                                                 │
                         ▼                                                 ▼
                 BRPOP from Redis                                   Every WINDOW_SECONDS
                         │                                                 │
                         ▼                                                 ▼
               Silent Buffer Ingest                                Aggregate User Windows
          (TimeWindowLogAggregator)                              (Drain & Compute 30 Feats)
                         │                                                 │
                         └─────────────────┬───────────────────────────────┘
                                           │
                                           ▼
                                 4-Model Ensemble Predict
                                           │
                                           ▼ (If Risk >= 65)
                         ┌─────────────────────────────────┐
                         │ Thread-Safe WebSocket Dispatch  │
                         │ asyncio.run_coroutine_threadsafe│
                         └─────────────────────────────────┘
```

- **Thread 1 (`RedisConsumerThread`)**: Performs blocking `BRPOP` on `network_logs_queue`. Ingests events silently into memory under a thread lock. Performs **no ML computation** and **no console logging**, maintaining sub-millisecond response times.
- **Thread 2 (`WindowTimerThread`)**: Sleeps for `WINDOW_SECONDS` (default: 300s / 5 min). Wakes up, locks the aggregator, drains active user events, calculates the 30-dimension feature vector, executes the 4-model ensemble, and uses `asyncio.run_coroutine_threadsafe` to push high-risk alerts to connected WebSockets on the FastAPI event loop.

---

## 8. Developer Workflows & How-To Guides

### 8.1 Setting Up the Environment

Ensure you have [`uv`](https://github.com/astral-sh/uv) installed:

```bash
# Clone the repository
git clone https://github.com/dtg-lucifer/internal-firewall-sih-2026.git
cd internal-firewall-sih-2026

# Set up virtual environment and dependencies for backend
cd backend
uv sync
```

---

### 8.2 Running the Backend

```bash
cd backend
# Run with 30-second window for fast local testing
WINDOW_SECONDS=30 uv run uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload
```
Interactive Swagger Documentation: **`http://localhost:8000/docs`**

---

### 8.3 Running the Live Packet Sniffer

```bash
cd logger
sudo uv run python main.py sniff --interface any --user LOCAL-USER
```

---

### 8.4 Generating Simulated Traffic

```bash
cd simulator
# Normal Workday Stream
uv run python simulate.py --mode normal

# Suspicious 5x Burst with Wikileaks Exfiltration
uv run python simulate.py --mode suspicious --multiplier 5 --attack-type wikileaks
```

---

### 8.5 Running Tests

```bash
# 1. Quick Model Unpickling & Inference Verification
cd backend
uv run python test_eval.py

# 2. FastAPI Endpoint Integration Tests
uv run python src/test_client.py

# 3. Multithreaded Pipeline & 5-Minute Window Tests
uv run python src/test_multithreaded_pipeline.py

# 4. Full Dockerized Test Suite
cd ..
./run_docker_tests.sh
```

---

### 8.6 Retraining ML Models

To retrain all 4 models on new or updated CERT dataset CSV files:

```bash
cd ml
# Run the complete end-to-end training pipeline
uv run python train.py
```
This will automatically parse the data, extract features, train LightGBM, Statistical Baselines, Isolation Forest, and PyTorch Autoencoder, and update the serialized binaries in `ml/models/`.

---

## 9. Key Conventions & Important Gotchas

### 1. Unified `src/` Layout
- All backend operational code resides strictly in `backend/src/`.
- Do not create parallel `backend/app/` folders.
- Internal imports within the backend should use `from src.predictor import ...`, `from src.log_buffer import ...`, etc.

### 2. Python `sys.path` & ML Model Unpickling
- Joblib-serialized models (`ml/models/*.joblib`) reference module paths under `src.*` (such as `src.models.behavioral_classifier` and `src.features.feature_extractor`).
- To prevent module namespace collisions between `backend/src` and `ml/src`, both [`backend/src/__init__.py`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/backend/src/__init__.py) and [`ml/src/__init__.py`](file:///home/piush/Prog/hackathons/internal-firewall-sih-2026/ml/src/__init__.py) dynamically extend `__path__` to include both directories. Always preserve this mechanism.

### 3. Silent Ingestion Principle
- **Never** trigger ML model scoring inside individual event ingestion routes or `BRPOP` consumer loops.
- Individual packets in enterprise networks number in the millions and lack contextual behavioral statistics.
- Accumulate raw events inside `TimeWindowLogAggregator` and only score aggregated 5-minute sliding windows during the timer evaluation cycle.

---

*Internal Firewall & AI/ML Behavioral Anomaly Gateway — SIH 2026*
