"""
Backend Test Script.
Tests /health, /api/v1/predict, /api/v1/logs/ingest, and /api/v1/alerts endpoints.
"""

import sys
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from fastapi.testclient import TestClient

from .main import app

console = Console()
client = TestClient(app)


def run_backend_tests():
    console.print(Panel.fit("[bold green]🧪 Running Backend & Model Integration Tests[/bold green]"))

    # 1. Test Health
    res = client.get("/health")
    assert res.status_code == 200, f"Health check failed: {res.text}"
    console.print(f"[green]✓ Health check passed:[/green] {res.json()}")

    # 2. Test Direct Feature Prediction
    predict_payload = {
        "user": "AAM0658",
        "timestamp": "2026-08-19",
        "features": {
            "device_connect_count": 6,
            "device_after_hours": 6,
            "file_copy_count": 30,
            "file_doc_pdf_count": 28,
            "file_zip_exe_count": 2,
            "file_after_hours": 30,
            "http_request_count": 250,
            "http_wikileaks_count": 12,
            "http_after_hours": 250,
            "usb_surge_zscore": 8.4,
            "file_surge_zscore": 11.2,
            "after_hours_ratio": 1.0,
            "sensitive_web_count": 12,
            "sensitive_web_ratio": 0.048,
        }
    }
    res = client.post("/api/v1/predict", json=predict_payload)
    assert res.status_code == 200, f"Predict failed: {res.text}"
    data = res.json()
    console.print(f"[bold green]✓ Prediction output:[/bold green] User={data['user']} Risk={data['risk_score']} Status={data['status']} Action={data['policy_action']}")

    # 3. Test Live Log Ingest Event (Suspicious USB & Sensitive File Copy)
    log_event = {
        "event_id": "evt-live-9001",
        "timestamp": "2026-08-19T02:30:00Z",
        "user": "EMP-042",
        "src_ip": "10.0.4.42",
        "event_type": "file_copy",
        "filename": "Classified_Internal_Blueprints.zip",
        "file_extension": ".zip"
    }
    res = client.post("/api/v1/logs/ingest", json=log_event)
    assert res.status_code == 200, f"Ingest failed: {res.text}"
    ingest_res = res.json()
    console.print(f"[bold green]✓ Ingest response:[/bold green] Status={ingest_res['status']} User={ingest_res['user']}")

    # 4. Test Alerts History
    res = client.get("/api/v1/alerts")
    assert res.status_code == 200
    console.print(f"[bold green]✓ Alerts endpoint passed:[/bold green] Count={res.json()['total_alerts']}")

    console.print("[bold green]🎉 All backend routes verified successfully![/bold green]")


if __name__ == "__main__":
    run_backend_tests()
