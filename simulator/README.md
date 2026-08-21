# 🛡️ Dual-Mode Network Traffic & Threat Simulator

Redesigned dual-mode simulation engine calibrated with the **CERT r4.2 Insider Threat Dataset**.

---

## 🎯 Operation Modes

### 1. Normal Mode (`--mode normal`)
- **Simulates standard workday enterprise activity (09:00 - 17:00)**:
  - Moderate request rate (20 - 50 HTTP requests per window).
  - Normal download and payload sizes (5 KB - 80 KB).
  - Business-appropriate domains (GitHub, Jira, Google Docs, Confluence, StackOverflow).
  - Internal legitimate corporate emails (`@dtaa.com`).
  - Zero USB after-hours activity, zero sensitive URL triggers.
  - **Expected ML Evaluation**: Composite Risk Score `< 35`, Status `NORMAL`, Policy `ALLOW`.

### 2. Suspicious Mode (`--mode suspicious`)
- **Simulates active insider threat attack scenarios with 3x - 10x bursts**:
  - **3x - 10x higher request burst rate** in a 5-minute window (150 - 450+ requests).
  - **Massive download / exfiltration rates** (10 MB - 100 MB+ transfers of `.zip`, `.exe`, `.tar.gz`, `.pdf`).
  - **After-hours timing** (23:30 late night).
  - **Sensitive target domains** (Wikileaks upload portal, Mega.nz cloud storage drops, Keyloggers/Exploits, Competitor Job Poaching).
  - **Removable USB storage connect/disconnect spikes** and large external emails with hidden BCCs.
  - **Expected ML Evaluation**: Composite Risk Score `>= 70`, Status `CRITICAL`, Policy `ISOLATE_DEVICE`.

---

## 📦 Usage Examples

### 1. Normal Baseline Traffic
```bash
# Push normal traffic to Redis MQ
uv run --directory simulator python simulate.py --mode normal --target redis

# Direct HTTP evaluation
uv run --directory simulator python simulate.py --mode normal --target http
```

### 2. Suspicious Threat Attack with 5x Burst
```bash
# 5x request burst with Wikileaks exfiltration to Redis MQ
uv run --directory simulator python simulate.py --mode suspicious --multiplier 5 --attack-type wikileaks --target redis

# 10x massive burst with Keylogger download
uv run --directory simulator python simulate.py --mode suspicious --multiplier 10 --attack-type hacking_tools --target redis
```

### 3. Interactive Menu
```bash
uv run --directory simulator python simulate.py --interactive
```
