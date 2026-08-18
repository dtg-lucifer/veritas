"""
Model Evaluation and Benchmarking Suite.
Computes Precision, Recall, F1, ROC-AUC, PR-AUC, and Scenario-by-Scenario detection rates
against CERT r4.2 exact ground-truth insider threat scenarios.
"""

from typing import Dict, List, Optional, Tuple, Any
import json
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
    confusion_matrix
)
from rich.console import Console
from rich.table import Table

console = Console()


class ModelEvaluator:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def evaluate_model(
        self,
        y_true: np.ndarray,
        y_scores: np.ndarray,
        threshold: float = 0.5,
        model_name: str = "Model"
    ) -> Dict[str, Any]:
        """
        Evaluates a single model given ground truth binary labels and continuous anomaly scores [0..1].
        """
        y_pred = (y_scores >= threshold).astype(int)
        
        # Confusion matrix
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
        
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        precision = float(precision_score(y_true, y_pred, zero_division=0))
        recall = float(recall_score(y_true, y_pred, zero_division=0))
        f1 = float(f1_score(y_true, y_pred, zero_division=0))
        
        try:
            roc_auc = float(roc_auc_score(y_true, y_scores)) if len(np.unique(y_true)) > 1 else 0.0
            pr_auc = float(average_precision_score(y_true, y_scores)) if len(np.unique(y_true)) > 1 else 0.0
        except Exception:
            roc_auc = 0.0
            pr_auc = 0.0

        return {
            "model_name": model_name,
            "threshold": threshold,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(roc_auc, 4),
            "pr_auc": round(pr_auc, 4),
            "false_positive_rate": round(fpr, 4),
            "confusion_matrix": {
                "true_positives": int(tp),
                "false_positives": int(fp),
                "true_negatives": int(tn),
                "false_negatives": int(fn),
            }
        }

    def evaluate_scenarios(self, df: pd.DataFrame, score_col: str, threshold: float = 0.5) -> Dict[str, Any]:
        """
        Evaluates detection rates across specific attack scenarios in answers/.
        """
        scenario_results = {}
        scenario_names = {
            1: "Scenario 1 (Wikileaks/USB Exfiltration)",
            2: "Scenario 2 (Job Surfing + Data Theft)",
            3: "Scenario 3 (Admin Keylogger Sabotage)",
        }

        for scen_id, scen_name in scenario_names.items():
            scen_df = df[df["scenario"] == scen_id]
            if len(scen_df) == 0:
                continue
            detected = (scen_df[score_col] >= threshold).sum()
            total = len(scen_df)
            rate = (detected / total) * 100.0 if total > 0 else 0.0
            scenario_results[scen_name] = {
                "detected": int(detected),
                "total_events": int(total),
                "detection_rate_pct": round(rate, 2)
            }
        return scenario_results

    def generate_report(
        self,
        df_evaluated: pd.DataFrame,
        report_filename: str = "evaluation_results.json"
    ) -> Dict[str, Any]:
        """
        Generates and prints a complete comparative benchmark across all models and scenarios.
        """
        y_true = df_evaluated["is_anomaly"].values

        all_models = []
        if "supervised_score" in df_evaluated.columns:
            all_models.append(
                self.evaluate_model(
                    y_true, df_evaluated["supervised_score"].values, threshold=0.5, model_name="Supervised Gradient Boosting (LightGBM)"
                )
            )

        all_models.extend([
            self.evaluate_model(
                y_true, df_evaluated["baseline_score"].values, threshold=0.5, model_name="Statistical Baseline"
            ),
            self.evaluate_model(
                y_true, df_evaluated["isolation_forest_score"].values, threshold=0.5, model_name="Isolation Forest (Unsupervised)"
            ),
            self.evaluate_model(
                y_true, df_evaluated["autoencoder_score"].values, threshold=0.5, model_name="PyTorch Autoencoder (Deep Learning)"
            ),
            self.evaluate_model(
                y_true, df_evaluated["risk_score"].values / 100.0, threshold=0.55, model_name="Composite Risk Engine (Ensemble)"
            ),
        ])

        # 2. Evaluate scenarios on composite risk engine
        scenario_metrics = self.evaluate_scenarios(
            df_evaluated, score_col="risk_score", threshold=55.0
        )

        # Build output structure
        report = {
            "total_evaluated_records": int(len(df_evaluated)),
            "total_ground_truth_anomalies": int(y_true.sum()),
            "models": all_models,
            "scenarios": scenario_metrics
        }

        # Save to JSON
        json_path = self.output_dir / report_filename
        with open(json_path, "w") as f:
            json.dump(report, f, indent=2)

        # Print Rich Summary Table
        table = Table(title="🛡️ Internal Firewall - ML Behavioral Engine Benchmark", show_header=True, header_style="bold magenta")
        table.add_column("Model Architecture", style="cyan")
        table.add_column("Precision", justify="right")
        table.add_column("Recall", justify="right")
        table.add_column("F1-Score", justify="right", style="bold green")
        table.add_column("ROC-AUC", justify="right", style="bold yellow")
        table.add_column("PR-AUC", justify="right")
        table.add_column("FPR (False Positives)", justify="right", style="red")

        for m in all_models:
            table.add_row(
                m["model_name"],
                f"{m['precision']:.3f}",
                f"{m['recall']:.3f}",
                f"{m['f1_score']:.3f}",
                f"{m['roc_auc']:.3f}",
                f"{m['pr_auc']:.3f}",
                f"{m['false_positive_rate']:.4f}",
            )
        console.print(table)

        # Print Scenario Breakdown Table
        scen_table = Table(title="🎯 Insider Attack Scenario Detection Rates", show_header=True, header_style="bold blue")
        scen_table.add_column("Threat Scenario", style="cyan")
        scen_table.add_column("Detected Anomaly Days", justify="right")
        scen_table.add_column("Total Attack Days", justify="right")
        scen_table.add_column("Detection Rate (%)", justify="right", style="bold green")

        for name, stats in scenario_metrics.items():
            scen_table.add_row(
                name,
                str(stats["detected"]),
                str(stats["total_events"]),
                f"{stats['detection_rate_pct']:.1f}%"
            )
        console.print(scen_table)
        console.print(f"[bold green]Saved evaluation report to {json_path}[/bold green]")

        return report
