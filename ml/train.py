"""
Unified ML Training & Evaluation Pipeline for SIH Internal Firewall MVP.
Executes high-speed feature extraction, supervised gradient boosting, baseline profiling,
Isolation Forest, PyTorch Autoencoder training, composite risk engine inference, and benchmarking.
"""

import sys
import argparse
from pathlib import Path
import numpy as np
import pandas as pd
from rich.console import Console
from rich.panel import Panel

from src.features.feature_extractor import BehavioralFeatureExtractor, get_feature_columns
from src.models.behavioral_classifier import GradientBoostedBehavioralClassifier
from src.baseline.statistical_baseline import UserBaselineProfiler
from src.isolation_forest.isolation_forest_model import IsolationForestAnomalyDetector
from src.autoencoders.autoencoder_model import AutoencoderAnomalyDetector
from src.risk_engine import CompositeRiskEngine, RiskAssessment
from src.evalutation.evaluator import ModelEvaluator

console = Console()


def run_training_pipeline(
    data_dir: str = "data",
    models_dir: str = "models",
    reports_dir: str = "reports",
    max_http_chunks: int = 60,
    epochs: int = 25,
    use_cache: bool = True
):
    models_path = Path(models_dir)
    reports_path = Path(reports_dir)
    models_path.mkdir(parents=True, exist_ok=True)
    reports_path.mkdir(parents=True, exist_ok=True)

    console.print(Panel.fit(
        "[bold green]🛡️ Internal Firewall - Advanced ML Behavioral Engine[/bold green]\n"
        "[cyan]Dataset: CERT Insider Threat Test Dataset r4.2[/cyan]\n"
        f"[yellow]Data Directory: {data_dir} | Models: {models_dir} | Reports: {reports_dir}[/yellow]",
        border_style="green"
    ))

    # 1. High-Speed Vectorized Feature Extraction & Alignment
    console.print("\n[bold]Step 1: Vectorized Extraction & Ground-Truth Alignment...[/bold]")
    extractor = BehavioralFeatureExtractor(data_dir=data_dir)
    df = extractor.extract_features(max_http_chunks=max_http_chunks, use_cache=use_cache)
    
    if df.empty:
        console.print("[bold red]Failed to load features. Exiting pipeline.[/bold red]")
        sys.exit(1)

    total_records = len(df)
    total_anomalies = int(df["is_anomaly"].sum())
    total_users = df["user"].nunique()
    console.print(
        f"[green]✓ Processed {total_records} user-day activity records across {total_users} employees.[/green]\n"
        f"[yellow]✓ Labeled {total_anomalies} exact malicious attack days ({total_anomalies/total_records*100:.2f}% true contamination).[/yellow]"
    )

    # 2. Train Supervised Behavioral Classifier (LightGBM)
    console.print("\n[bold]Step 2: Training Supervised Gradient Boosted Behavioral Classifier...[/bold]")
    gb_model = GradientBoostedBehavioralClassifier(n_estimators=150, learning_rate=0.05, random_state=42)
    gb_model.fit(df)
    gb_save_path = str(models_path / "behavioral_classifier.joblib")
    gb_model.save(gb_save_path)
    console.print(f"[green]✓ Gradient Boosted Classifier trained. Saved to {gb_save_path}[/green]")

    # 3. Train Statistical Baseline Profiler
    console.print("\n[bold]Step 3: Training Statistical User Baseline Profiler...[/bold]")
    baseline_model = UserBaselineProfiler(feature_cols=get_feature_columns())
    baseline_model.fit(df)
    baseline_save_path = str(models_path / "baseline_profiler.joblib")
    baseline_model.save(baseline_save_path)
    console.print(f"[green]✓ Statistical baseline fitted for {len(baseline_model.user_profiles)} employees. Saved to {baseline_save_path}[/green]")

    # 4. Train Isolation Forest
    console.print("\n[bold]Step 4: Training Unsupervised Isolation Forest...[/bold]")
    if_model = IsolationForestAnomalyDetector(feature_cols=get_feature_columns(), n_estimators=150, contamination=0.01, random_state=42)
    if_model.fit(df)
    if_save_path = str(models_path / "isolation_forest.joblib")
    if_model.save(if_save_path)
    console.print(f"[green]✓ Isolation Forest trained. Saved to {if_save_path}[/green]")

    # 5. Train Deep PyTorch Autoencoder
    console.print("\n[bold]Step 5: Training PyTorch Deep Behavioral Autoencoder...[/bold]")
    ae_model = AutoencoderAnomalyDetector(feature_cols=get_feature_columns(), epochs=epochs, batch_size=128, lr=1e-3)
    ae_model.fit(df)
    ae_model_path = str(models_path / "autoencoder.pt")
    ae_meta_path = str(models_path / "autoencoder_meta.joblib")
    ae_model.save(ae_model_path, ae_meta_path)
    console.print(f"[green]✓ Deep Autoencoder trained ({epochs} epochs, latent dim=16). Saved to {ae_model_path}[/green]")

    # 6. Composite Risk Engine Evaluation
    console.print("\n[bold]Step 6: Fusing Multi-Model Signals into Composite Risk Engine...[/bold]")
    risk_engine = CompositeRiskEngine(
        baseline_model=baseline_model,
        if_model=if_model,
        ae_model=ae_model,
        gb_model=gb_model,
        w_gb=0.55,
        w_baseline=0.15,
        w_if=0.15,
        w_ae=0.15
    )
    df_evaluated = risk_engine.evaluate_dataframe(df)

    # 7. Comprehensive Model Benchmarking
    console.print("\n[bold]Step 7: Running Comprehensive Model Benchmarking...[/bold]")
    evaluator = ModelEvaluator(output_dir=reports_dir)
    evaluator.generate_report(df_evaluated, report_filename="evaluation_results.json")

    # 8. Real-Time Threat Simulation
    console.print("\n[bold]Step 8: Live Threat Simulation & Policy Action Verification...[/bold]")
    simulate_attack_scenario(risk_engine)


def simulate_attack_scenario(risk_engine: CompositeRiskEngine):
    """
    Demonstrates real-time inference on a synthetic insider attack vector:
    Employee performs massive after-hours USB connection + copying sensitive files + Wikileaks upload.
    """
    sample_attack_vector = {
        "device_connect_count": 8,
        "device_disconnect_count": 8,
        "device_after_hours": 8,
        "file_copy_count": 45,
        "file_doc_pdf_count": 38,
        "file_zip_exe_count": 7,
        "file_after_hours": 45,
        "email_sent_count": 12,
        "email_total_bytes": 85000000,
        "email_avg_bytes": 7083333,
        "email_max_bytes": 45000000,
        "email_external_count": 9,
        "email_bcc_count": 5,
        "email_after_hours": 12,
        "http_request_count": 350,
        "http_wikileaks_count": 15,
        "http_job_search_count": 0,
        "http_cloud_storage_count": 22,
        "http_hacking_count": 4,
        "http_after_hours": 350,
        "is_weekend": 1,
        "total_activity_count": 423,
        "total_after_hours_count": 423,
        "after_hours_ratio": 1.0,
        "sensitive_web_count": 41,
        "sensitive_web_ratio": 0.117,
        "external_email_ratio": 0.75,
        "usb_surge_zscore": 7.8,
        "file_surge_zscore": 12.4,
        "email_bytes_surge_zscore": 15.2,
    }

    user_id = "AAM0658"
    date_str = "2026-08-19"
    assessment: RiskAssessment = risk_engine.evaluate_record(user_id, date_str, sample_attack_vector)

    status_color = "red" if assessment.status == "CRITICAL" else "yellow"
    
    panel_content = (
        f"[bold]Target Identity:[/bold] {assessment.user}\n"
        f"[bold]Timestamp:[/bold] {assessment.date}\n"
        f"[bold]Composite Risk Score:[/bold] [{status_color}]{assessment.risk_score} / 100[/{status_color}]\n"
        f"[bold]Security Status:[/bold] [{status_color}]{assessment.status}[/{status_color}]\n"
        f"[bold]Enforced Firewall Policy:[/bold] [bold red]{assessment.action}[/bold red]\n\n"
        f"[bold cyan]Sub-Engine Signals:[/bold cyan]\n"
        f"  • Supervised Threat Score:    {assessment.supervised_score}\n"
        f"  • Statistical Baseline Score: {assessment.baseline_score}\n"
        f"  • Isolation Forest Score:     {assessment.isolation_forest_score}\n"
        f"  • Deep Autoencoder Score:     {assessment.autoencoder_score}\n\n"
        f"[bold yellow]Root Cause / Explainability Breakdown:[/bold yellow]\n"
    )
    for dev in assessment.top_deviations:
        panel_content += f"  ⚠️ {dev}\n"

    console.print(Panel(panel_content, title="🚨 Real-Time Security Gateway Alert", border_style="red"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Internal Firewall Advanced ML Pipeline")
    parser.add_argument("--data-dir", type=str, default="data", help="Path to data directory")
    parser.add_argument("--models-dir", type=str, default="models", help="Directory to save model artifacts")
    parser.add_argument("--reports-dir", type=str, default="reports", help="Directory to save evaluation reports")
    parser.add_argument("--max-http-chunks", type=int, default=60, help="Max chunks of http.csv to process")
    parser.add_argument("--epochs", type=int, default=25, help="Autoencoder training epochs")
    parser.add_argument("--no-cache", action="store_true", help="Ignore cached parquet features")
    
    args = parser.parse_args()
    
    run_training_pipeline(
        data_dir=args.data_dir,
        models_dir=args.models_dir,
        reports_dir=args.reports_dir,
        max_http_chunks=args.max_http_chunks,
        epochs=args.epochs,
        use_cache=not args.no_cache
    )
