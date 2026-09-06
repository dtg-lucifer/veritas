# AI World Model for Proactive Cyber Defense & Infiltration Forecasting

This package implements the **Network World Model Cyber Defense Engine** for the **Internal Network Security Gateway** (Smart India Hackathon 2026).

---

## Paradigm Shift: From Static Classification to World Models

Traditional machine learning intrusion detection systems (IDS) treat each network packet or flow in isolation, mapping it statically to a binary benign/malicious label. This discards the fundamental **temporal and causal structure** of real-world cyber infiltration:
- The sequence in which reconnaissance ports are probed.
- The pattern in which stealthy SYN flags precede exploitation and lateral movement.
- The inter-arrival timing (IAT) of scanning packets before privilege escalation begins.

### The World Model Approach
Rather than classifying static traffic snapshots, a **World Model** learns the internal causal simulation of how environment states evolve:

$$P(S_{t+1} \mid S_{\le t})$$

Given an observed history of time-windowed network states $S_t \in \mathbb{R}^{32}$ (active flows, TCP flag distributions, port diversity, packet size variance, timing dynamics), the World Model:
1. **Simulates Environment Physics**: Predicts the next network state $\hat{S}_{t+1}$.
2. **Performs $K$-Step Forward Simulation**: Autoregressively rolls forward $K$ steps into the future $[\hat{S}_{t+1}, \dots, \hat{S}_{t+K}]$.
3. **Forecasts Infiltration Probability**: Outputs a time-series likelihood of infiltration $[P_1, \dots, P_K]$ across future time windows before compromise is completed.
4. **Maps MITRE ATT&CK Progression**: Anticipates tactical escalation through canonical phases:
   $$\text{Reconnaissance} \longrightarrow \text{Initial Access} \longrightarrow \text{Infiltration / Lateral Movement} \longrightarrow \text{Command \& Control} \longrightarrow \text{Exfiltration / Impact}$$
5. **Explainable AI (XAI)**: Identifies exact driving signals (e.g. `syn_ratio`, `unique_dst_ports`, `flow_bytes_rate`) via temporal self-attention weights and gradient-based input feature attribution.

---

## Deep World Model Architecture

```
Observed Sequence [S_{t-W+1}, ..., S_t] (History Window W=8)
                         │
                         ▼
        [ State Latent Encoder (Linear + LayerNorm) ]
                         │  z_t in R^64
                         ▼
     [ Recurrent Causal Core (2-Layer LSTM) ]
                         │
                         ▼
        [ Temporal Multi-Head Self-Attention ] ──► Sequence Attention Weights
                         │  h_t in R^64
     ┌───────────────────┼───────────────────┐
     ▼                   ▼                   ▼
[ Dynamics Head ]  [ Infiltration Head ]  [ MITRE Stage Head ]
  \hat{S}_{t+1}       P(Infiltration)        P(Stage 0..5)
     │
     └── Autoregressive Rollout Loop (k = 1 ... K) ──► Forward Risk Trajectory
```

### Composite Multi-Task Training Objective
$$\mathcal{L} = \mathcal{L}_{\text{dynamics}} + 1.5 \mathcal{L}_{\text{infiltration}} + 1.0 \mathcal{L}_{\text{stage}}$$

- **Dynamics Loss**: $\frac{1}{D} \|\hat{S}_{t+1} - S_{t+1}\|_2^2$ (State transition error).
- **Infiltration Loss**: Binary Cross-Entropy with Logits.
- **MITRE Stage Loss**: Categorical Cross-Entropy across canonical attack phases.

---

## 32-Dimensional Network State Vector ($S_t$)

Each consecutive time window ($\Delta t = 15\text{s}$) aggregates individual flows into a structured state vector:

| Category | Extracted Features |
| :--- | :--- |
| **Volumetric Dynamics** | `flow_count`, `tot_fwd_pkts`, `tot_bwd_pkts`, `tot_fwd_bytes`, `tot_bwd_bytes`, `flow_bytes_rate`, `flow_pkts_rate`, `flow_duration_mean` |
| **TCP Flag Bitmasks** | `syn_flag_count`, `syn_ratio`, `ack_flag_count`, `ack_ratio`, `rst_flag_count`, `fin_flag_count`, `psh_flag_count`, `urg_flag_count` |
| **Port & Protocol Diversity** | `unique_dst_ports`, `ephemeral_port_ratio` ($\ge 1024$), `web_port_ratio` (80/443), `dns_port_ratio` (53), `ssh_ftp_port_ratio` (21/22), `tcp_protocol_ratio`, `udp_protocol_ratio` |
| **Timing & Packet Stats** | `pkt_len_mean`, `pkt_len_std`, `flow_iat_mean`, `flow_iat_std`, `flow_iat_max`, `down_up_ratio_mean` |
| **Session State** | `init_fwd_win_mean` (TCP window size), `active_duration_mean`, `idle_duration_mean` |

---

## Project Structure

```
ml/
├── data/
│   ├── external-network/
│   │   ├── cic-ids-2018/          # CSE-CIC-IDS2018 multi-attack flow CSVs
│   │   └── cic-iot-2023/          # CIC-IoT-2023 reconnaissance & attack captures
│   ├── internal-network/          # Legacy insider threat datasets
│   └── cache/                     # Cached parquet state matrices for instant re-runs
├── models/
│   ├── world_model.pt             # Trained PyTorch World Model weights & scalers
│   └── baseline_classifier.joblib # Trained static Logistic Regression baseline
├── reports/
│   └── world_model_benchmark.json # Head-to-head comparison metrics & lead time
├── src/
│   ├── features/
│   │   ├── traffic_extractor.py   # Flow CSV (CIC-IDS-2018) & raw PCAP parser
│   │   └── state_window.py        # 15s state aggregator & sequence windowing
│   ├── world_model/
│   │   ├── network_world_model.py # Attention-augmented recurrent World Model
│   │   ├── forward_simulator.py   # K-step autoregressive rollout engine
│   │   └── explainability.py      # Temporal attention & gradient attribution
│   ├── baseline/
│   │   └── static_baseline.py     # Static Logistic Regression classifier
│   ├── evaluation/
│   │   └── benchmark.py           # Evaluation metrics & comparative reporting
│   └── mitre_mapping.py           # Attack label to MITRE ATT&CK phase mapping
├── train.py                       # Unified training and benchmarking CLI
├── demo.py                        # Interactive forward simulation demonstration CLI
└── pyproject.toml                 # Package dependencies
```

---

## Quickstart: Training & Running Inference

### 1. Run the Training Pipeline
Trains the World Model, trains the Logistic Regression baseline, computes benchmark metrics, and runs a live forward simulation:

```bash
cd ml
uv run python train.py --sample-frac 0.15 --epochs 12
```

**Key CLI Options:**
- `--sample-frac`: Subsampling fraction per file for rapid prototyping (default: `0.15`).
- `--epochs`: Training epochs (default: `12`).
- `--window-size`: Aggregation window in seconds (default: `15`).
- `--seq-len`: Context history window length $W$ (default: `8`).
- `--no-cache`: Force re-extraction from raw CSV files.

### 2. Run Interactive Forward Simulation Demo
Accepts any network flow CSV or PCAP capture file, runs forward simulation $K$ steps ahead, and displays or exports the infiltration probability timeline, predicted MITRE stage, and driving feature attributions:

```bash
cd ml
# Run simulation and output to terminal
uv run python demo.py --file data/external-network/cic-ids-2018/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv --rollout-steps 5

# Export publication-quality report to Markdown or Plain Text file:
uv run python demo.py --file data/external-network/cic-ids-2018/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv --output reports/thursday_report.md
uv run python demo.py --file data/external-network/cic-ids-2018/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv --output reports/wednesday_report.txt --format txt

# Evaluate specific scenarios (attack progression, onset transition, or benign baseline):
uv run python demo.py --file data/external-network/cic-ids-2018/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv --scenario benign
uv run python demo.py --file data/external-network/cic-ids-2018/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv --scenario attack
```

**Key Demo CLI Options:**
- `--file`: Path to input flow CSV (e.g. CIC-IDS-2018) or raw `.pcap` capture.
- `--output` / `-o`: File path to dump the simulation report (e.g. `reports/report.md` or `reports/report.txt`).
- `--format`: Report format: `markdown` or `txt` (auto-inferred from file extension).
- `--scenario`: Evaluation scenario: `auto` (targets active threat progression if attacks exist, else benign), `attack` (evaluates peak threat sequence), `onset` (evaluates benign-to-attack transition), or `benign` (evaluates nominal operation).
- `--window-idx`: Explicit integer window index to simulate.
- `--rollout-steps`: Number of forecast rollout steps $K$ into the future (default: `5`).
- `--window-size`: Temporal state window size $W$ in seconds (default: `15`).

---

## Benchmark: World Model vs. Static Baseline

The evaluation suite automatically measures the measurable advantage provided by temporal dynamics learning:
- **Higher F1-Score and Precision**: Reduces false positives by learning normal flow progression patterns.
- **Lower False Positive Rate (FPR)**: Distinguishes between harmless spikes and coordinated kill chains.
- **Proactive Early Warning Lead Time**: While static classifiers only trigger *after* an attack completes, the World Model detects trajectory convergence **$K$ steps in advance**, enabling automated quarantine before compromise is finalized.
