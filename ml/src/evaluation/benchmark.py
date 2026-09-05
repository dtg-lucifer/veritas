"""
Benchmarking & Evaluation Suite for World Model vs. Static Baseline.
Calculates F1-Score, Precision, Recall, False Positive Rate (FPR), ROC-AUC,
and Early Detection Lead-Time metrics, exporting comprehensive benchmark reports.
"""

from pathlib import Path
from typing import Dict, Any, Tuple
import json
import numpy as np
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    accuracy_score,
    roc_auc_score,
    confusion_matrix,
)
from rich.console import Console
from rich.table import Table

console = Console()


class ModelBenchmark:
    """
    Evaluates and compares World Model forward simulation against static baseline classifier.
    """

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def evaluate_binary_predictions(
        self,
        y_true: np.ndarray,
        y_probs: np.ndarray,
        threshold: float = 0.5,
    ) -> Dict[str, float]:
        """Calculates standard classification performance metrics."""
        y_pred = (y_probs >= threshold).astype(int)
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)

        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        acc = float(accuracy_score(y_true, y_pred))
        prec = float(precision_score(y_true, y_pred, zero_division=0))
        rec = float(recall_score(y_true, y_pred, zero_division=0))
        f1 = float(f1_score(y_true, y_pred, zero_division=0))

        try:
            auc = float(roc_auc_score(y_true, y_probs))
        except Exception:
            auc = 0.5

        return {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "false_positive_rate": round(fpr, 4),
            "roc_auc": round(auc, 4),
            "true_positives": int(tp),
            "false_positives": int(fp),
            "true_negatives": int(tn),
            "false_negatives": int(fn),
        }

    def generate_comparison_report(
        self,
        wm_metrics: Dict[str, float],
        baseline_metrics: Dict[str, float],
        dynamics_mse: float,
        lead_time_steps: int = 3,
        filename: str = "world_model_benchmark.json",
    ) -> Dict[str, Any]:
        """
        Synthesizes head-to-head comparison metrics, renders terminal table,
        and saves JSON report.
        """
        # Calculate improvements
        f1_improvement = ((wm_metrics["f1_score"] - baseline_metrics["f1_score"]) / max(baseline_metrics["f1_score"], 1e-4)) * 100
        fpr_reduction = ((baseline_metrics["false_positive_rate"] - wm_metrics["false_positive_rate"]) / max(baseline_metrics["false_positive_rate"], 1e-4)) * 100

        report = {
            "title": "Internal Firewall AI World Model Benchmark vs Static Baseline",
            "summary": {
                "dynamics_mse_loss": round(float(dynamics_mse), 4),
                "forward_simulation_lead_time_steps": lead_time_steps,
                "f1_improvement_percent": round(float(f1_improvement), 2),
                "fpr_reduction_percent": round(float(fpr_reduction), 2),
            },
            "world_model": wm_metrics,
            "static_baseline": baseline_metrics,
        }

        # Save to JSON
        json_path = self.output_dir / filename
        with open(json_path, "w") as f:
            json.dump(report, f, indent=2)

        # Render rich table
        table = Table(title="⚔️ Benchmark Comparison: World Model vs. Static Baseline")
        table.add_column("Metric", style="cyan", justify="left")
        table.add_column("Static Baseline (LogReg)", style="yellow", justify="center")
        table.add_column("World Model (Dynamics)", style="green", justify="center")
        table.add_column("Improvement / Advantage", style="magenta", justify="center")

        table.add_row(
            "F1-Score",
            f"{baseline_metrics['f1_score']:.4f}",
            f"{wm_metrics['f1_score']:.4f}",
            f"[bold green]+{f1_improvement:.1f}%[/bold green]",
        )
        table.add_row(
            "Precision",
            f"{baseline_metrics['precision']:.4f}",
            f"{wm_metrics['precision']:.4f}",
            f"{wm_metrics['precision'] - baseline_metrics['precision']:+.4f}",
        )
        table.add_row(
            "Recall (Detection Rate)",
            f"{baseline_metrics['recall']:.4f}",
            f"{wm_metrics['recall']:.4f}",
            f"{wm_metrics['recall'] - baseline_metrics['recall']:+.4f}",
        )
        table.add_row(
            "False Positive Rate (FPR)",
            f"{baseline_metrics['false_positive_rate']:.4f}",
            f"{wm_metrics['false_positive_rate']:.4f}",
            f"[bold green]-{fpr_reduction:.1f}%[/bold green]",
        )
        table.add_row(
            "ROC-AUC",
            f"{baseline_metrics['roc_auc']:.4f}",
            f"{wm_metrics['roc_auc']:.4f}",
            f"{wm_metrics['roc_auc'] - baseline_metrics['roc_auc']:+.4f}",
        )
        table.add_row(
            "Forward Prediction Horizon",
            "0 steps (static)",
            f"{lead_time_steps} steps ahead",
            "[bold green]Proactive Defense[/bold green]",
        )
        table.add_row(
            "Transition Dynamics MSE",
            "N/A (no physics)",
            f"{dynamics_mse:.4f}",
            "Learned P(S_t+1 | S_t)",
        )

        console.print(table)
        console.print(f"[green]✓ Full benchmark report saved to: {json_path}[/green]")

        return report
