# 🔮 AI World Model Cyber Defense — Forward Simulation Report

- **Generated At:** `2026-09-04 22:59:11`
- **Evaluated Telemetry Source:** `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv`
- **Temporal Window Size ($W$):** `15s`
- **Forecast Horizon ($K$):** `5 steps` (+75s lead time)
- **Scenario Context:** Active attack progression sequence centered near peak FTP-BruteForce activity (Window 1738)
- **Max Forecasted Risk:** **99.9%** (CRITICAL)
- **Peak Anticipated MITRE Stage:** **Initial Access**
- **Recommended Autonomous Policy:** `ISOLATE_DEVICE`

---

## 1. 📊 Observed Network State History (Context Windows)

| Window Time | Flows | SYN Ratio | Unique Ports | Byte Rate (KB/s) | Dominant Label |
| :--- | :---: | :---: | :---: | :---: | :--- |
| 11:09:30 | 783 | 0.003 | 75 | 338.8 | FTP-BruteForce |
| 11:09:45 | 831 | 0.004 | 63 | 41.1 | FTP-BruteForce |
| 11:10:00 | 801 | 0.003 | 51 | 104.4 | FTP-BruteForce |
| 11:10:15 | 1,176 | 0.002 | 60 | 101.0 | FTP-BruteForce |
| 11:10:30 | 2,095 | 0.002 | 157 | 237.0 | FTP-BruteForce |
| 11:10:45 | 790 | 0.003 | 54 | 113.9 | FTP-BruteForce |
| 11:11:00 | 977 | 0.005 | 106 | 101.0 | FTP-BruteForce |
| 11:11:15 | 1,000 | 0.003 | 67 | 47.8 | FTP-BruteForce |

---

## 2. 🔮 K-Step Forward Simulation Rollout

| Forecast Step | Lead Time | Infiltration Prob | Predicted MITRE Stage | Simulated Flows | Simulated SYN Ratio | Security Status | Enforced Policy |
| :--- | :---: | :---: | :--- | :---: | :---: | :---: | :---: |
| Step t+1 | +15s | 98.9% | Initial Access | 144 | 0.005 | CRITICAL | `ISOLATE_DEVICE` |
| Step t+2 | +30s | 99.4% | Initial Access | 145 | 0.004 | CRITICAL | `ISOLATE_DEVICE` |
| Step t+3 | +45s | 99.7% | Initial Access | 145 | 0.004 | CRITICAL | `ISOLATE_DEVICE` |
| Step t+4 | +60s | 99.9% | Initial Access | 145 | 0.004 | CRITICAL | `ISOLATE_DEVICE` |
| Step t+5 | +75s | 99.9% | Initial Access | 145 | 0.004 | CRITICAL | `ISOLATE_DEVICE` |

---

## 3. 🧠 Explainability & Threat Attribution

- **Peak Infiltration Escalation Risk:** 99.9%
- **Anticipated MITRE ATT&CK Stage:** Initial Access

### Top Contributing Network Telemetry Signals:

- **`flow_count`**: 25.6% attribution (Observed Value: `1000.00`)
- **`flow_pkts_rate`**: 16.5% attribution (Observed Value: `631277.31`)
- **`psh_flag_count`**: 9.5% attribution (Observed Value: `638.00`)
- **`ack_flag_count`**: 7.2% attribution (Observed Value: `122.00`)
- **`tot_bwd_pkts`**: 4.9% attribution (Observed Value: `2244.00`)

### SOC Guidance & Incident Attribution:
> [HIGH RISK] Forward dynamics forecast threat escalation driven primarily by: flow count: 1000.00; sudden volumetric traffic surge (16% attribution); psh flag count: 638.00.
