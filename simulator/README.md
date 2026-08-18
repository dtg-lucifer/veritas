# 🛡️ Internal Firewall - Network Traffic & Insider Threat Simulator

Interactive attack and baseline traffic generator designed to simulate realistic enterprise network events and test the **FastAPI Gateway**, **Redis Queue Consumer**, and **Real-Time WebSocket Alerts**.

---

## ⚡ Quickstart

### 1. Run the Backend (in one terminal)
```bash
cd backend
uv run uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 2. Launch Interactive Simulation Menu
```bash
cd simulator
uv run python simulate.py --interactive
```

---

## 🎯 Threat Scenarios Included

| Scenario Key | Threat Name | Description | Expected Gateway Policy |
| :--- | :--- | :--- | :--- |
| **`normal`** | Normal Baseline Activity | Routine daytime GitHub, Google Docs browsing, internal emails | `NORMAL (Score: 0-15)` $\to$ `ALLOW` |
| **`wikileaks`** | Wikileaks & USB Exfiltration | Late-night USB insert, large confidential PDF/ZIP copies, Wikileaks upload | `CRITICAL (Score: 85-95)` $\to$ `ISOLATE_DEVICE` |
| **`job_theft`** | Job Hunting & IP Theft | Indeed / Monster job searches, USB file copy, external email to competitor | `SUSPICIOUS (Score: 65-85)` $\to$ `ALERT_ADMIN` |
| **`keylogger`** | Admin Keylogger Sabotage | Exploit / keylogger site visits, payload executable download, server USB drop | `CRITICAL (Score: 85-95)` $\to$ `ISOLATE_DEVICE` |
| **`mass_exfil`**| Mass Cloud Drop | After-hours 50MB+ archive upload to Mega.nz / Dropbox | `CRITICAL (Score: 85-95)` $\to$ `ISOLATE_DEVICE` |
| **`continuous`**| Multi-User Enterprise Stream| Live continuous stream with 8 normal users and random stealth attack spikes | Real-Time Continuous Anomaly Stream |

---

## 🛠️ CLI Usage & Options

### 1. Direct HTTP Stream Testing (Default)
Sends events directly to FastAPI gateway endpoint (`http://localhost:8000/api/v1/logs/ingest`):
```bash
# Run Scenario 1 (Wikileaks Exfiltration)
uv run python simulate.py --scenario wikileaks --delay 0.5

# Run Normal Baseline Workday
uv run python simulate.py --scenario normal

# Run Continuous Multi-User Stream
uv run python simulate.py --scenario continuous --delay 0.3
```

### 2. Redis Message Queue Testing
Pumps logs directly into the Redis queue (`network_logs_queue`):
```bash
uv run python simulate.py --target redis --scenario wikileaks
```

---

## 📊 Live Terminal Monitor Example
When running via HTTP target:
```
┏━━━━┳━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┓
┃  # ┃ Type      ┃ User    ┃ Payload Details                     ┃      Gateway Assessment ┃ Policy Action ┃
┡━━━━╇━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━┩
│  1 │ device    │ AAM0658 │ Kingston 64GB DataTraveler          │       LOW RISK (35/100) │       MONITOR │
│  2 │ file_copy │ AAM0658 │ Classified_Defense_Architecture...  │     SUSPICIOUS (62/100) │   ALERT_ADMIN │
│  3 │ file_copy │ AAM0658 │ Core_Proprietary_Algorithms.zip     │     SUSPICIOUS (78/100) │   ALERT_ADMIN │
│  4 │ http      │ AAM0658 │ https://wikileaks.org/leak/subm...  │       CRITICAL (91/100) │ ISOLATE_DEVICE│
└────┴───────────┴─────────┴─────────────────────────────────────┴─────────────────────────┴───────────────┘
```
All alerts are broadcast instantly over WebSocket `/ws/alerts` for live visualization on the dashboard!
