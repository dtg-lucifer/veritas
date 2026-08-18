"""
Backend Test Script.
Tests /health, /api/v1/redis/status, /api/v1/predict, /api/v1/logs/ingest, and /api/v1/alerts endpoints.
"""

import sys
import asyncio
from rich.console import Console
from rich.panel import Panel
from fastapi.testclient import TestClient

from app.main import app, redis_worker

console = Console()
client = TestClient(app)


def run_backend_tests():
    console.print(Panel.fit("[bold green]🧪 Running Backend & Redis Worker Integration Tests[/bold green]"))

    # 1. Test Health
    res = client.get("/health")
    assert res.status_code == 200, f"Health check failed: {res.text}"
    console.print(f"[green]✓ Health check passed:[/green] {res.json()}")

    # 2. Test Redis Status
    res = client.get("/api/v1/redis/status")
    assert res.status_code == 200
    console.print(f"[green]✓ Redis worker status endpoint passed:[/green] {res.json()}")

    # 3. Test Direct Feature Prediction with Fast Composite Model
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
    console.print(f"[bold green]✓ Fast composite prediction:[/bold green] User={data['user']} Risk={data['risk_score']} Status={data['status']} Action={data['policy_action']}")

    # 4. Test Direct Redis Worker Event Ingestion (simulating queue pop)
    suspicious_event = {
        "event_id": "queue-sim-001",
        "timestamp": "2026-08-19T03:30:00Z",
        "user": "EMP-042",
        "src_ip": "10.0.4.42",
        "event_type": "file_copy",
        "filename": "Classified_Internal_Blueprints.zip",
        "file_extension": ".zip"
    }
    # Test worker's process_event directly
    asyncio.run(redis_worker.process_event(suspicious_event))
    console.print(f"[bold green]✓ Redis worker event processing simulated:[/bold green] Total processed={redis_worker.processed_count}")

    # 5. Test Live Log Ingest REST Route
    res = client.post("/api/v1/logs/ingest", json=suspicious_event)
    assert res.status_code == 200
    console.print(f"[bold green]✓ Direct REST ingest passed[/bold green]")

    # 6. Test Policy Enforcement
    policy_payload = {
        "user": "EMP-042",
        "target_ip": "10.0.4.42",
        "action": "ISOLATE_DEVICE",
        "reason": "Exfiltration anomaly detected"
    }
    res = client.post("/api/v1/policy/enforce", json=policy_payload)
    assert res.status_code == 200
    console.print(f"[bold green]✓ Policy enforcement passed:[/bold green] {res.json()['message']}")

    console.print("[bold green]🎉 All backend and Redis worker tests verified successfully![/bold green]")


if __name__ == "__main__":
    run_backend_tests()
