# 🔮 AI World Model Cyber Defense — Forward Simulation Report

- **Generated At:** `2026-09-04 23:10:20`
- **Evaluated Telemetry Source:** `Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv`
- **Temporal Window Size ($W$):** `15s`
- **Forecast Horizon ($K$):** `5 steps` (+75s lead time)
- **Scenario Context:** Baseline nominal operation evaluation (8 continuous benign windows)
- **Max Forecasted Risk:** **24.3%** (NORMAL)
- **Peak Anticipated MITRE Stage:** **Benign**
- **Recommended Autonomous Policy:** `ALLOW`

---

## 1. 📊 Observed Network State History (Context Windows)

| Window Time | Flows | SYN Ratio | Unique Ports | Byte Rate (KB/s) | Dominant Label |
| :--- | :---: | :---: | :---: | :---: | :--- |
| 01:00:00 | 47 | 0.000 | 18 | 15.1 | Benign |
| 01:00:15 | 57 | 0.000 | 16 | 0.6 | Benign |
| 01:00:30 | 100 | 0.000 | 17 | 52.2 | Benign |
| 01:00:45 | 59 | 0.002 | 19 | 59.7 | Benign |
| 01:01:00 | 43 | 0.008 | 14 | 0.7 | Benign |
| 01:01:15 | 39 | 0.002 | 13 | 21.9 | Benign |
| 01:01:30 | 43 | 0.002 | 14 | 7.0 | Benign |
| 01:01:45 | 45 | 0.000 | 15 | 45.2 | Benign |

---

## 2. 🔮 K-Step Forward Simulation Rollout

| Forecast Step | Lead Time | Infiltration Prob | Predicted MITRE Stage | Simulated Flows | Simulated SYN Ratio | Security Status | Enforced Policy |
| :--- | :---: | :---: | :--- | :---: | :---: | :---: | :---: |
| Step t+1 | +15s | 5.2% | Benign | 38 | 0.008 | NORMAL | `ALLOW` |
| Step t+2 | +30s | 6.7% | Benign | 33 | 0.009 | NORMAL | `ALLOW` |
| Step t+3 | +45s | 7.9% | Benign | 40 | 0.009 | NORMAL | `ALLOW` |
| Step t+4 | +60s | 7.0% | Benign | 44 | 0.008 | NORMAL | `ALLOW` |
| Step t+5 | +75s | 24.3% | Benign | 31 | 0.010 | NORMAL | `ALLOW` |

---

## 3. 🧠 Explainability & Threat Attribution

- **Peak Infiltration Escalation Risk:** 24.3%
- **Anticipated MITRE ATT&CK Stage:** Benign

### Top Contributing Network Telemetry Signals:

- **`pkt_len_std`**: 16.9% attribution (Observed Value: `151.51`)
- **`active_duration_mean`**: 12.6% attribution (Observed Value: `1920059.50`)
- **`ephemeral_port_ratio`**: 11.0% attribution (Observed Value: `0.62`)
- **`web_port_ratio`**: 10.9% attribution (Observed Value: `0.04`)
- **`idle_duration_mean`**: 9.1% attribution (Observed Value: `10872041.00`)

### SOC Guidance & Incident Attribution:
> Traffic behavior aligns with baseline nominal distributions. No threat precursors detected.
