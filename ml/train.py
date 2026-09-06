"""
Unified Training & Evaluation Pipeline for AI World Model Cyber Defense.
Learns Network State Transition Dynamics P(S_{t+1} | S_{<=t}),
predicts Infiltration likelihood and MITRE ATT&CK progression,
trains a static baseline classifier, and runs comparative benchmark evaluation.
"""

import sys
import argparse
from pathlib import Path
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import TensorDataset, DataLoader
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn

from src.features.traffic_extractor import TrafficExtractor
from src.features.state_window import StateWindowAggregator, build_temporal_sequences, STATE_FEATURE_NAMES, STATE_DIM
from src.world_model.network_world_model import NetworkWorldModel, WorldModelWrapper
from src.world_model.forward_simulator import ForwardSimulator
from src.world_model.explainability import ThreatExplainer
from src.baseline.static_baseline import StaticBaselineClassifier
from src.evaluation.benchmark import ModelBenchmark
from src.mitre_mapping import STAGE_NAMES

console = Console()


def set_seed(seed: int = 42) -> None:
    """Ensures deterministic, reproducible training runs."""
    torch.manual_seed(seed)
    np.random.seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def load_and_prepare_dataset(
    data_dir: Path,
    cache_dir: Path,
    window_size_sec: int = 15,
    sample_frac: float = 0.25,
    use_cache: bool = True,
) -> pd.DataFrame:
    """
    Ingests and caches multi-attack flow records from external network datasets,
    aggregating them into continuous chronological state vectors S_t.
    """
    cache_file = cache_dir / f"aggregated_states_w{window_size_sec}s.parquet"
    if use_cache and cache_file.exists():
        console.print(f"[green]Loading cached time-windowed states from: {cache_file}[/green]")
        return pd.read_parquet(cache_file)

    console.print("[yellow]Ingesting raw network flow records from external-network datasets...[/yellow]")
    extractor = TrafficExtractor()

    # Target key representative attack and benign datasets in CIC-IDS-2018
    target_files = [
        # Infiltration scenario (insider pivoting & lateral movement)
        ("Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv", sample_frac),
        # Botnet Command & Control (ARES bot)
        ("Friday-02-03-2018_TrafficForML_CICFlowMeter.csv", sample_frac),
        # Web & Brute Force Initial Access
        ("Friday-23-02-2018_TrafficForML_CICFlowMeter.csv", sample_frac),
        ("Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv", sample_frac),
        # Benign Operational Baseline
        ("Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv", sample_frac),
    ]

    cic_dir = data_dir / "cic-ids-2018"
    if not cic_dir.exists():
        # Fallback to check relative to workspace
        cic_dir = data_dir

    all_flow_dfs = []
    for fname, frac in target_files:
        fpath = cic_dir / fname
        if fpath.exists():
            console.print(f"  • Loading {fname} (subsample {frac*100:.0f}%)...")
            try:
                df_part = extractor.load_cic_ids_2018_csv(fpath, sample_frac=frac)
                all_flow_dfs.append(df_part)
                console.print(f"    Loaded {len(df_part):,} flows.")
            except Exception as e:
                console.print(f"    [red]Warning loading {fname}: {e}[/red]")
        else:
            console.print(f"  [yellow]File not found: {fpath}[/yellow]")

    if not all_flow_dfs:
        raise RuntimeError(f"No flow files could be loaded from {cic_dir}")

    # Concatenate and sort chronologically
    combined_flows = pd.concat(all_flow_dfs, ignore_index=True)
    combined_flows = combined_flows.sort_values(by="timestamp").reset_index(drop=True)
    console.print(f"[green]Ingested total of {len(combined_flows):,} flows across multi-stage attack scenarios.[/green]")

    # Aggregate into state windows
    console.print(f"[cyan]Aggregating flows into {window_size_sec}-second Network State Vectors S_t...[/cyan]")
    aggregator = StateWindowAggregator(window_size_seconds=window_size_sec)
    df_states = aggregator.aggregate_flows_to_states(combined_flows)

    if df_states.empty:
        raise RuntimeError("Aggregation produced 0 state windows. Check timestamp formatting.")

    attack_windows = int(df_states["is_attack"].sum())
    total_windows = len(df_states)
    console.print(
        f"[green]Generated {total_windows} chronological state windows "
        f"({attack_windows} threat/attack windows, {attack_windows/total_windows*100:.1f}% contamination).[/green]"
    )

    # Cache result
    cache_dir.mkdir(parents=True, exist_ok=True)
    df_states.to_parquet(cache_file, index=False)
    console.print(f"[green]Cached state matrix to: {cache_file}[/green]")

    return df_states


def run_training_pipeline(
    data_dir: str = "data/external-network",
    models_dir: str = "models",
    reports_dir: str = "reports",
    cache_dir: str = "data/cache",
    window_size: int = 15,
    seq_len: int = 8,
    sample_frac: float = 0.20,
    epochs: int = 15,
    batch_size: int = 64,
    learning_rate: float = 1e-3,
    use_cache: bool = True,
) -> None:
    set_seed(42)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    models_path = Path(models_dir)
    reports_path = Path(reports_dir)
    cache_path = Path(cache_dir)
    models_path.mkdir(parents=True, exist_ok=True)
    reports_path.mkdir(parents=True, exist_ok=True)

    console.print(Panel.fit(
        "[bold cyan]AI World Model Cyber Defense Engine — Training Pipeline[/bold cyan]\n"
        "[bold white]Objective: Learn Transition Dynamics P(S_{t+1} | S_{<=t}) & Forecast Infiltration Horizon[/bold white]\n"
        f"[yellow]Device: {device} | Sequence Length: {seq_len} | Window: {window_size}s | Epochs: {epochs}[/yellow]",
        border_style="cyan"
    ))

    # 1. Dataset Loading & State Windowing
    df_states = load_and_prepare_dataset(
        data_dir=Path(data_dir),
        cache_dir=cache_path,
        window_size_sec=window_size,
        sample_frac=sample_frac,
        use_cache=use_cache,
    )

    # 2. Build Temporal Sequences [S_{t-W+1} .. S_t] -> S_{t+1}
    console.print(f"\n[bold]Step 2: Constructing Temporal State Trajectories (Context Window W = {seq_len})...[/bold]")
    X_seq, Y_state, Y_inf, Y_stage = build_temporal_sequences(
        df_states, seq_len=seq_len, forecast_horizon=1
    )
    console.print(f"[green]Created {len(X_seq)} temporal sequence samples for dynamics modeling.[/green]")

    # Chronological Train/Test Split (80% Train, 20% Test)
    split_idx = int(0.80 * len(X_seq))
    X_train_seq, X_test_seq = X_seq[:split_idx], X_seq[split_idx:]
    Y_train_state, Y_test_state = Y_state[:split_idx], Y_state[split_idx:]
    Y_train_inf, Y_test_inf = Y_inf[:split_idx], Y_inf[split_idx:]
    Y_train_stage, Y_test_stage = Y_stage[:split_idx], Y_stage[split_idx:]

    # 3. Fit State Scaler
    console.print("\n[bold]Step 3: Fitting Robust Normalization Scaler on Baseline Trajectories...[/bold]")
    world_model_wrapper = WorldModelWrapper(device=device)
    # Fit scaler on flattened train states
    train_states_flat = X_train_seq.reshape(-1, STATE_DIM)
    world_model_wrapper.fit_scaler(train_states_flat)

    # Normalize train and test sequences
    N_tr, T, D = X_train_seq.shape
    X_train_norm = world_model_wrapper.transform_states(train_states_flat).reshape(N_tr, T, D)
    Y_train_state_norm = world_model_wrapper.transform_states(Y_train_state)

    N_te = len(X_test_seq)
    X_test_norm = world_model_wrapper.transform_states(X_test_seq.reshape(-1, STATE_DIM)).reshape(N_te, T, D)
    Y_test_state_norm = world_model_wrapper.transform_states(Y_test_state)

    # PyTorch DataLoaders
    train_dataset = TensorDataset(
        torch.tensor(X_train_norm, dtype=torch.float32),
        torch.tensor(Y_train_state_norm, dtype=torch.float32),
        torch.tensor(Y_train_inf, dtype=torch.float32),
        torch.tensor(Y_train_stage, dtype=torch.long),
    )
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)

    # 4. Train Attention-Augmented Recurrent World Model
    console.print("\n[bold]Step 4: Training Attention-Augmented Recurrent Latent World Model...[/bold]")
    model = world_model_wrapper.model
    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

    # Loss weights
    w_dyn = 1.0
    w_inf = 1.5
    w_stage = 1.0

    model.train()
    for epoch in range(1, epochs + 1):
        total_loss = 0.0
        total_dyn_loss = 0.0
        total_inf_loss = 0.0
        total_stage_loss = 0.0

        for b_x_seq, b_y_state, b_y_inf, b_y_stage in train_loader:
            b_x_seq = b_x_seq.to(device)
            b_y_state = b_y_state.to(device)
            b_y_inf = b_y_inf.to(device)
            b_y_stage = b_y_stage.to(device)

            optimizer.zero_grad()
            pred_state, inf_logits, stage_logits, _ = model(b_x_seq)

            # 1. Dynamics Transition Loss: P(S_{t+1} | S_{<=t})
            loss_dyn = F.mse_loss(pred_state, b_y_state)
            # 2. Infiltration Threat Loss
            loss_inf = F.binary_cross_entropy_with_logits(inf_logits.squeeze(-1), b_y_inf)
            # 3. MITRE Stage Loss
            loss_stage = F.cross_entropy(stage_logits, b_y_stage)

            composite_loss = (w_dyn * loss_dyn) + (w_inf * loss_inf) + (w_stage * loss_stage)
            composite_loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()

            total_loss += composite_loss.item()
            total_dyn_loss += loss_dyn.item()
            total_inf_loss += loss_inf.item()
            total_stage_loss += loss_stage.item()

        scheduler.step()
        n_batches = len(train_loader)
        if epoch % 3 == 0 or epoch == epochs:
            console.print(
                f"  Epoch {epoch:02d}/{epochs:02d} | "
                f"Total Loss: {total_loss/n_batches:.4f} | "
                f"Dynamics MSE: {total_dyn_loss/n_batches:.4f} | "
                f"Infiltration BCE: {total_inf_loss/n_batches:.4f} | "
                f"MITRE CE: {total_stage_loss/n_batches:.4f}"
            )

    # Save trained World Model
    wm_save_path = str(models_path / "world_model.pt")
    world_model_wrapper.save(wm_save_path)
    console.print(f"[green]World Model saved to: {wm_save_path}[/green]")

    # 5. Train Static Baseline Classifier (Logistic Regression on single-window snapshots)
    console.print("\n[bold]Step 5: Training Static Logistic Regression Baseline (Single-Window Snapshot)...[/bold]")
    baseline = StaticBaselineClassifier(model_type="logistic_regression", random_state=42)
    # Train baseline on the latest state vector of each train sequence
    X_train_static = X_train_seq[:, -1, :]
    baseline.fit(X_train_static, Y_train_inf)
    baseline_save_path = str(models_path / "baseline_classifier.joblib")
    baseline.save(baseline_save_path)
    console.print(f"[green]Static baseline classifier trained and saved to: {baseline_save_path}[/green]")

    # 6. Evaluation & Comparative Benchmarking
    console.print("\n[bold]Step 6: Running Comparative Evaluation & Benchmark...[/bold]")
    model.eval()
    with torch.no_grad():
        test_seq_tensor = torch.tensor(X_test_norm, dtype=torch.float32, device=device)
        pred_test_states, pred_test_inf_logits, _, _ = model(test_seq_tensor)
        wm_inf_probs = torch.sigmoid(pred_test_inf_logits).squeeze(-1).cpu().numpy()
        test_dyn_mse = float(F.mse_loss(pred_test_states, torch.tensor(Y_test_state_norm, dtype=torch.float32, device=device)).item())

    # Static baseline inference on latest observed state of test sequences
    X_test_static = X_test_seq[:, -1, :]
    baseline_probs = baseline.predict_proba(X_test_static)

    benchmark = ModelBenchmark(output_dir=reports_dir)
    wm_metrics = benchmark.evaluate_binary_predictions(Y_test_inf, wm_inf_probs, threshold=0.50)
    baseline_metrics = benchmark.evaluate_binary_predictions(Y_test_inf, baseline_probs, threshold=0.50)

    benchmark.generate_comparison_report(
        wm_metrics=wm_metrics,
        baseline_metrics=baseline_metrics,
        dynamics_mse=test_dyn_mse,
        lead_time_steps=seq_len // 2,
        filename="world_model_benchmark.json",
    )

    # 7. Live Threat Forward Simulation & Rollout Demonstration
    console.print("\n[bold]Step 7: Real-Time K-Step Forward Simulation & Explainability Demonstration...[/bold]")
    simulator = ForwardSimulator(world_model_wrapper)
    explainer = ThreatExplainer(world_model_wrapper)

    # Pick an attack sequence from the test split
    attack_indices = np.where(Y_test_inf == 1)[0]
    sample_idx = attack_indices[0] if len(attack_indices) > 0 else 0
    sample_history = X_test_seq[sample_idx]  # (W, STATE_DIM)

    report = simulator.simulate(sample_history, k_steps=5)
    explanation = explainer.explain_sequence(sample_history)

    # Render Simulation Alert Panel
    status_style = "bold red" if report.max_infiltration_prob >= 0.70 else "bold yellow"
    panel_text = (
        f"[bold cyan]Input Context Window:[/bold cyan] {seq_len} observed time steps\n"
        f"[bold]Forecast Horizon:[/bold] 5 steps ahead (t+1 .. t+5)\n"
        f"[bold]Max Projected Infiltration Probability:[/bold] [{status_style}]{report.max_infiltration_prob*100:.1f}%[/{status_style}]\n"
        f"[bold]Projected Attack Stage:[/bold] [magenta]{report.peak_stage_name}[/magenta]\n"
        f"[bold]Early Convergence Step:[/bold] Step t+{report.convergence_step or 1}\n\n"
        f"[bold yellow]Predicted Infiltration Timeline:[/bold yellow]\n"
    )
    for s in report.rollout_steps:
        panel_text += f"  • Step t+{s.step}: Prob={s.infiltration_prob*100:.1f}% | Stage={s.mitre_stage_name} | Action={s.policy_action}\n"

    panel_text += f"\n[bold green]Root Cause & Feature Attribution:[/bold green]\n"
    for feat in explanation["top_driving_features"][:3]:
        panel_text += f"  • {feat['feature']}: attribution={feat['score']*100:.1f}%, observed value={feat['raw_value']:.2f}\n"

    panel_text += f"\n[bold white]SOC Analyst Summary:[/bold white] {explanation['soc_explanation']}\n"

    console.print(Panel(panel_text, title="World Model Forward Simulation Live Rollout", border_style="cyan"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Unified World Model Training & Benchmarking Pipeline")
    parser.add_argument("--data-dir", type=str, default="data/external-network", help="Path to external network datasets")
    parser.add_argument("--models-dir", type=str, default="models", help="Directory to save model weights")
    parser.add_argument("--reports-dir", type=str, default="reports", help="Directory to save evaluation reports")
    parser.add_argument("--cache-dir", type=str, default="data/cache", help="Cache directory for aggregated state parquets")
    parser.add_argument("--window-size", type=int, default=15, help="State window aggregation size in seconds")
    parser.add_argument("--seq-len", type=int, default=8, help="Temporal sequence context length W")
    parser.add_argument("--sample-frac", type=float, default=0.15, help="Subsampling fraction per file for rapid prototyping")
    parser.add_argument("--epochs", type=int, default=15, help="Training epochs")
    parser.add_argument("--batch-size", type=int, default=64, help="Batch size")
    parser.add_argument("--lr", type=float, default=1e-3, help="Learning rate")
    parser.add_argument("--no-cache", action="store_true", help="Ignore cached parquets and re-extract from CSVs")

    args = parser.parse_args()

    run_training_pipeline(
        data_dir=args.data_dir,
        models_dir=args.models_dir,
        reports_dir=args.reports_dir,
        cache_dir=args.cache_dir,
        window_size=args.window_size,
        seq_len=args.seq_len,
        sample_frac=args.sample_frac,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.lr,
        use_cache=not args.no_cache,
    )
