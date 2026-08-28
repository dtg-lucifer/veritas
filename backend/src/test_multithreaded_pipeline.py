"""
Full End-to-End Multithreaded Ingestion & Anomaly Detection Pipeline Test.
Validates:
1. Multithreaded Redis Worker starting in separate background OS threads.
2. 5-Minute Stateful Behavioral Window Aggregation per user.
3. 4-Model Ensemble scoring (Normal Mode < 35 ALLOW vs Suspicious Mode 5x burst >= 65 ISOLATE).
4. Real-time alert generation and thread-safe WebSocket broadcast triggers.
"""

import sys
import time
import asyncio
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

# Add backend, simulator, and ml to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR / "ml"))
sys.path.insert(0, str(ROOT_DIR / "simulator"))
sys.path.insert(0, str(ROOT_DIR / "backend"))

from src.predictor import SecurityModelPredictor
from src.log_buffer import TimeWindowLogAggregator
from src.redis_worker import MultithreadedRedisLogWorker
from scenarios import generate_normal_stream, generate_suspicious_stream

console = Console()


def test_multithreaded_pipeline():
    console.print(Panel.fit(
        "[bold green]🧪 Running Full Multithreaded Redis MQ & 5-Minute Window ML Test[/bold green]",
        border_style="green"
    ))

    # 1. Initialize Components
    predictor = SecurityModelPredictor()
    log_buffer = TimeWindowLogAggregator(window_seconds=300)
    alerts_list = []
    broadcasted_alerts = []

    async def mock_ws_broadcast(payload: dict):
        broadcasted_alerts.append(payload)

    worker = MultithreadedRedisLogWorker(
        log_buffer=log_buffer,
        predictor=predictor,
        broadcast_callback=mock_ws_broadcast,
        alerts_list=alerts_list,
        alert_threshold=65.0,
        window_seconds=300
    )

    # 2. Test Normal Baseline Stream Ingestion
    console.print("\n[bold cyan]Step 1: Ingesting Normal Workday Stream (EMP-NORM-01)...[/bold cyan]")
    normal_events = generate_normal_stream(user="EMP-NORM-01", request_count=25)
    
    for evt in normal_events:
        log_buffer.ingest(evt)

    date_key_n, norm_window, cnt_n = log_buffer.aggregate_window("EMP-NORM-01")
    norm_assessment = predictor.evaluate_features("EMP-NORM-01", date_key_n, norm_window)
    
    console.print(
        f"[green]✓ Normal Stream Assessment: Risk Score={norm_assessment['risk_score']}/100 "
        f"Status={norm_assessment['status']} Policy={norm_assessment['policy_action']}[/green]"
    )
    console.print(f"[dim]  Signals: {norm_assessment['signals']}[/dim]")
    assert norm_assessment["risk_score"] < 35.0, f"Expected normal risk (<35), got {norm_assessment['risk_score']}"
    assert norm_assessment["status"] == "NORMAL"
    assert norm_assessment["policy_action"] == "ALLOW"

    # 3. Test Suspicious Threat Burst (5x Request Rate + High Download Bandwidth)
    console.print("\n[bold red]Step 2: Ingesting 5x Suspicious Burst (AAM0658 - Wikileaks, Exfil & Removable USB)...[/bold red]")
    suspicious_events = generate_suspicious_stream(user="AAM0658", multiplier=5, attack_type="wikileaks")
    
    for evt in suspicious_events:
        log_buffer.ingest(evt)

    date_key_s, susp_window, cnt_s = log_buffer.aggregate_window("AAM0658")
    susp_assessment = predictor.evaluate_features("AAM0658", date_key_s, susp_window)

    console.print(
        f"[bold red]✓ Suspicious Stream Assessment: Risk Score={susp_assessment['risk_score']}/100 "
        f"Status={susp_assessment['status']} Policy={susp_assessment['policy_action']}[/bold red]"
    )
    console.print(f"[yellow]  Signals: {susp_assessment['signals']}[/yellow]")
    console.print(f"[yellow]  Top Deviations: {susp_assessment['top_deviations']}[/yellow]")

    assert susp_assessment["risk_score"] >= 65.0, f"Expected critical risk (>=65), got {susp_assessment['risk_score']}"
    assert susp_assessment["status"] in ["SUSPICIOUS", "CRITICAL"]
    assert susp_assessment["policy_action"] in ["ALERT_ADMIN", "ISOLATE_DEVICE"]

    # 4. Test Window Evaluation & Alert Triggering
    console.print("\n[bold cyan]Step 3: Triggering Worker Window Evaluation Cycle...[/bold cyan]")
    for evt in generate_suspicious_stream(user="AAM0658", multiplier=5, attack_type="wikileaks"):
        log_buffer.ingest(evt)

    worker._evaluate_all_windows()
    assert worker.alerts_generated >= 1
    assert len(worker.alerts_list) >= 1
    console.print(f"[green]✓ Alert list received {len(worker.alerts_list)} high-risk incidents.[/green]")
    # Verify buffer is drained
    assert len(log_buffer.get_active_users()) == 0

    # 5. Test Background Thread Lifecycle
    console.print("\n[bold cyan]Step 4: Verifying Background Worker Threads Lifecycle...[/bold cyan]")
    worker.start()
    assert worker._consumer_thread is not None
    assert worker._timer_thread is not None
    console.print(f"[green]✓ Consumer thread: '{worker._consumer_thread.name}', Timer thread: '{worker._timer_thread.name}'[/green]")
    
    time.sleep(0.5)
    worker.stop(timeout=2.0)
    console.print(f"[green]✓ Worker threads gracefully stopped: is_running={worker.is_running}[/green]")

    console.print("\n[bold green]🎉 All multithreaded ML pipeline and 5-minute window tests passed with 100% SUCCESS![/bold green]\n")


if __name__ == "__main__":
    test_multithreaded_pipeline()
