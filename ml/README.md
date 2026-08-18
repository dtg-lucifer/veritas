# 🛡️ Internal Firewall - ML Behavioral Anomaly Detection Engine

This package implements the behavioral machine learning engine for the **Internal Network Security Gateway** (Smart India Hackathon MVP).

Instead of relying solely on perimeter defenses or external threat intelligence, this engine establishes behavioral baselines for authenticated internal identities, extracts multi-stream network & device behavioral feature vectors, and detects anomalous deviations (data exfiltration, lateral movement, unauthorized access, privilege abuse, abnormal hours/protocols/volumes) using an ensemble of statistical and unsupervised ML models.

---

## 🏗️ Architecture & Model Hierarchy

```
Raw Activity Logs (USB, File, Email, HTTP, LDAP)
                       │
                       ▼
         Time-Windowed Feature Extractor
         (23 Behavioral Vector Dimensions)
                       │
         ┌─────────────┼─────────────┐
         ▼             ▼             ▼
  User Baseline   Isolation Forest  PyTorch Autoencoder
    (Z-Scores)      (Tree Isolation) (Reconstruction Loss)
         │             │             │
         └─────────────┼─────────────┘
                       ▼
             Composite Risk Engine
                 (0 - 100 Score)
                       │
         ┌─────────────┼─────────────┐
         ▼             ▼             ▼
       NORMAL      SUSPICIOUS     CRITICAL
       (ALLOW)    (ALERT ADMIN) (ISOLATE DEVICE)
```

### Detection Models

1. **Statistical User Baseline Profiler (`src/baseline/`)**:
   - Calculates running mean, standard deviation, and 95th percentiles per employee across all behavioral features.
   - Computes feature-wise Z-scores: $Z_{u, f} = \frac{x_{u, f} - \mu_{u, f}}{\sigma_{u, f} + \epsilon}$.
   - Provides instant explainability (e.g. `+420% USB Activity, 4.8σ above baseline`).

2. **Isolation Forest (`src/isolation_forest/`)**:
   - Unsupervised tree ensemble isolating rare multi-dimensional feature combinations.
   - RobustScaler normalization to handle extreme activity spikes.
   - Outputs calibrated $[0, 1]$ anomaly probabilities.

3. **Deep PyTorch Autoencoder (`src/autoencoders/`)**:
   - Deep neural network ($D \to 64 \to 32 \to 16 \to 32 \to 64 \to D$) trained to reconstruct normal behavior manifold.
   - Computes anomaly score from MSE reconstruction error: $||X - \hat{X}||_2^2$.
   - Identifies non-linear anomalies that evade classical threshold rules.

4. **Composite Risk Engine (`src/risk_engine.py`)**:
   - Fuses all three models: $\text{Risk} = 100 \times (0.35 S_{\text{base}} + 0.35 S_{\text{IF}} + 0.30 S_{\text{AE}})$.
   - Outputs policy decisions: `ALLOW`, `MONITOR`, `ALERT_ADMIN`, `ISOLATE_DEVICE`.

---

## 📊 Dataset: CERT Insider Threat Test Dataset (r4.2)

The engine trains and benchmarks against the **CMU CERT r4.2** dataset located in `data/`:
- `data/r4.2/device.csv`: Removable USB drives connection/disconnection logs.
- `data/r4.2/file.csv`: Files copied to removable media (.doc, .pdf, .zip, .exe).
- `data/r4.2/email.csv`: Internal and external communications (size, external recipients, BCCs).
- `data/r4.2/http.csv`: Web requests (URLs, search terms, cloud storage, hacking portals).
- `data/r4.2/LDAP/`: Organizational role and department hierarchy.
- `data/answers/`: Ground truth red team insider attacks:
  - **Scenario 1**: After-hours USB connection + sensitive file copy + Wikileaks upload.
  - **Scenario 2**: Job searching + massive data theft to USB before resignation.
  - **Scenario 3**: System administrator keylogger sabotage & impersonation.

---

## 🚀 Running the Training & Evaluation Pipeline

### 1. Install Dependencies
```bash
uv sync
```

### 2. Run Full Training & Benchmarking
```bash
uv run python train.py
```

### Options:
- `--data-dir`: Path to dataset directory (default: `data`)
- `--models-dir`: Output directory for trained models (default: `models`)
- `--reports-dir`: Output directory for benchmark JSON reports (default: `reports`)
- `--max-http-chunks`: Max chunks to stream from 14GB `http.csv` (default: 50)
- `--epochs`: Training epochs for PyTorch Autoencoder (default: 35)
- `--no-cache`: Re-extract features directly from raw CSV files

---

## 📁 Project Structure

```
ml/
├── data/
│   ├── r4.2/               # CERT activity logs
│   ├── answers/            # Ground truth insider scenarios
│   └── cache/              # Cached parquet feature vectors
├── models/                 # Serialized model checkpoints (.joblib, .pt)
├── reports/                # Evaluation & benchmark metrics (JSON)
├── src/
│   ├── preprocessing/      # Chunked streaming CSV loaders
│   ├── features/           # 23-dimension behavioral feature extractor
│   ├── baseline/           # Statistical Z-score baseline engine
│   ├── isolation_forest/   # Scikit-learn Isolation Forest detector
│   ├── autoencoders/       # PyTorch Autoencoder deep neural network
│   ├── evalutation/        # Precision, Recall, ROC-AUC, scenario benchmark
│   └── risk_engine.py      # Multi-model risk fusion & policy engine
├── train.py                # Unified CLI entry point
└── pyproject.toml          # Project configuration & dependencies
```
