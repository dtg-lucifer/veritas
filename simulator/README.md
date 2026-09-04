# 🛡️ Synthetic Network Traffic & Threat Simulator

Synthetic multi-mode traffic generator for the **Internal Network Firewall & Threat Detection Gateway**.

Simulates both calibrated benign enterprise workday traffic and multi-stage suspicious/malicious attack bursts. Supports direct HTTP REST ingestion into the FastAPI gateway or message queue buffering.

> **Note on Telemetry Ingestion Tools:**  
> - **`logger/`** is the primary telemetry producer for SIH 2026: it streams real-world **CSE-CIC-IDS2018** packet and flow datasets directly into **Apache Kafka** (`network_flows`).  
> - **`simulator/`** (this package) generates synthetic workloads and insider threat scenarios for standalone load testing, resilience checks, and direct REST API benchmarking.

---

## 🎯 Operation Modes

### 1. Normal Mode (`--mode normal`)
Simulates standard corporate enterprise workday telemetry (09:00 – 17:00):
- **Request Density:** Moderate rate (20 – 50 HTTP requests per aggregation window).
- **Payload Dynamics:** Typical payload sizes (5 KB – 80 KB).
- **Domains:** Corporate and business-appropriate destinations (GitHub, Jira, Google Workspace, Confluence, StackOverflow).
- **Authentication & Email:** Legitimate corporate accounts (`@dtaa.com`).
- **Activity Profile:** Zero sensitive keyword triggers, zero unauthorized after-hours bursts.
- **Expected Defense Evaluation:** Risk Score `< 40%`, Status `NORMAL`, Policy `ALLOW`.

### 2. Suspicious Mode (`--mode suspicious`)
Simulates active multi-stage cyber attacks and insider threat trajectories with 3x – 10x burst multipliers:
- **High Request Burst:** 150 – 450+ requests per window targeting sensitive destinations.
- **Data Exfiltration:** Large file transfers (10 MB – 100 MB+ `.zip`, `.tar.gz`, `.exe`).
- **Timing Anomaly:** Late-night off-hours operations (23:30).
- **Target Profiles:**
  - `wikileaks`: Classified data transfer to anonymous upload repositories.
  - `cloud_drop`: High-volume exfiltration to unauthorized cloud lockers (Mega, Dropbox).
  - `hacking_tools`: Transfer of exploit scripts, port scanners, and keyloggers.
  - `job_hunt`: Bulk database downloads paired with recruiter uploads.
- **Expected Defense Evaluation:** Risk Score `≥ 70%`, Status `CRITICAL`, Policy `ISOLATE_DEVICE`.

---

## 📦 Usage Examples

### 1. Direct HTTP Ingestion into FastAPI Gateway (Recommended)
Sends synthetic flow events directly to the running FastAPI server at `POST /api/v1/logs/ingest`:

```bash
# Push normal enterprise baseline traffic
uv run --directory simulator python simulate.py --mode normal --target http

# 5x request burst with Wikileaks exfiltration simulation
uv run --directory simulator python simulate.py --mode suspicious --multiplier 5 --attack-type wikileaks --target http

# 10x massive burst with Keylogger/Exploit tool transfer
uv run --directory simulator python simulate.py --mode suspicious --multiplier 10 --attack-type hacking_tools --target http
```

### 2. Message Broker Queue Mode
Pushes serialized event payloads to a Redis queue:

```bash
uv run --directory simulator python simulate.py --mode normal --target redis --redis-url redis://localhost:6379/0
```

### 3. Interactive CLI Wizard
Launches a rich terminal menu to select user profiles, multiplier factors, and attack types interactively:

```bash
uv run --directory simulator python simulate.py --interactive
```

---

## ⚙️ CLI Options Reference

| Option | Flag | Default | Description |
| :--- | :--- | :--- | :--- |
| `--mode` | `-m` | `normal` | Simulation profile: `normal` or `suspicious` |
| `--target` | `-t` | `http` | Ingestion target: `http` (direct REST) or `redis` (queue broker) |
| `--multiplier` | `-x` | `1` | Activity volume multiplier (1 = nominal, 3 = probe, 5 = heavy, 10 = massive) |
| `--attack-type` | `-a` | `wikileaks` | Attack scenario: `wikileaks`, `cloud_drop`, `hacking_tools`, `job_hunt` |
| `--user` | `-u` | `AAM0658` | User / Host identity identifier |
| `--api-url` | | `http://localhost:8000` | Base URL of the FastAPI gateway |
| `--redis-url` | | `redis://localhost:6379/0` | Connection string for Redis broker |
| `--redis-queue`| | `network_logs_queue` | Target Redis queue key |
| `--interactive`| `-i` | `False` | Launch interactive configuration wizard |
