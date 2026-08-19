"""
Backend Integration & 5-Minute Window Test Suite.
Tests /health, /api/v1/redis/status, /api/v1/predict, /api/v1/logs/ingest,
/api/v1/users/{user}/window, policy enforcement, and multi-scenario threat simulation.
"""

import sys
import asyncio
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from fastapi.testclient import TestClient

# Add backend and simulator to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR / "backend"))
sys.path.insert(0, str(ROOT_DIR / "simulator"))

from app.main import app, redis_worker, log_buffer
from scenarios import (
    generate_normal_baseline_events,
    generate_scenario_1_wikileaks,
    generate_scenario_2_job_theft,
    generate_scenario_3_keylogger,
    generate_scenario_mass_cloud_exfil
)

console = Console()
client = TestClient(app)


def run_backend_tests():
    console.print(Panel.fit("[bold green]🧪 Running Backend & 5-Minute Window Integration Tests[/bold green]"))

    # 1. Test Health Check
    res = client.get("/health")
    assert res.status_code == 200, f"Health check failed: {res.text}"
    health_data = res.json()
    assert health_data["models_ready"] is True
    console.print(f"[green]✓ Health check passed:[/green] models_ready={health_data['models_ready']}")

    # 2. Test Redis Status Endpoint
    res = client.get("/api/v1/redis/status")
    assert res.status_code == 200
    console.print(f"[green]✓ Redis worker status endpoint passed:[/green] queue_key={res.json()['queue_key']}")

    # 3. Test Direct Feature Prediction with 4-Model Ensemble
    predict_payload = {
        "user": "AAM0658",
        "timestamp": "2026-08-19",
        "features": {
            "device_connect_count": 2,
            "device_after_hours": 2,
            "file_copy_count": 4,
            "file_doc_pdf_count": 2,
            "file_zip_exe_count": 2,
            "file_after_hours": 4,
            "http_request_count": 5,
            "http_wikileaks_count": 2,
            "http_after_hours": 5,
            "usb_surge_zscore": 6.5,
            "file_surge_zscore": 9.0,
            "after_hours_ratio": 1.0,
            "sensitive_web_count": 2,
            "sensitive_web_ratio": 0.40,
        }
    }
    res = client.post("/api/v1/predict", json=predict_payload)
    assert res.status_code == 200, f"Predict failed: {res.text}"
    data = res.json()
    assert data["risk_score"] >= 40.0, f"Expected elevated risk, got {data['risk_score']}"
    assert data["status"] in ["SUSPICIOUS", "CRITICAL"]
    assert data["policy_action"] in ["ALERT_ADMIN", "ISOLATE_DEVICE"]
    console.print(f"[bold green]✓ 4-Model Ensemble prediction:[/bold green] User={data['user']} Risk={data['risk_score']} Status={data['status']} Action={data['policy_action']}")

    # 4. Test 5-Minute Window Ingestion via REST (/api/v1/logs/ingest) with Wikileaks Scenario
    wikileaks_events = generate_scenario_1_wikileaks(user="AAM0658")
    last_assessment = None
    for evt in wikileaks_events:
        res = client.post("/api/v1/logs/ingest", json=evt)
        assert res.status_code == 200
        last_assessment = res.json()["assessment"]
    
    assert last_assessment["risk_score"] >= 70.0, f"Expected critical score for Wikileaks, got {last_assessment['risk_score']}"
    assert last_assessment["status"] == "CRITICAL"
    assert last_assessment["policy_action"] == "ISOLATE_DEVICE"
    console.print(f"[bold green]✓ Wikileaks 5-minute burst ingestion passed:[/bold green] Final Risk={last_assessment['risk_score']}/100 Status={last_assessment['status']} Action={last_assessment['policy_action']}")

    # 5. Test Window Inspection Endpoint (/api/v1/users/{user}/window)
    res = client.get("/api/v1/users/AAM0658/window")
    assert res.status_code == 200
    win_data = res.json()
    assert win_data["summary"]["active_events_count"] == len(wikileaks_events)
    console.print(f"[bold green]✓ 5-Minute window status query passed:[/bold green] Active Events={win_data['summary']['active_events_count']}")

    # 6. Test Redis Worker Direct Process Event
    suspicious_event = {
        "event_id": "queue-sim-001",
        "timestamp": "2026-08-19T03:30:00Z",
        "user": "EMP-WORKER-01",
        "src_ip": "10.0.4.42",
        "event_type": "device",
        "activity": "Connect",
        "device_name": "SanDisk Extreme"
    }
    worker_res = asyncio.run(redis_worker.process_event(suspicious_event))
    assert redis_worker.processed_count >= 1
    console.print(f"[bold green]✓ Redis worker event processing simulated:[/bold green] Total processed={redis_worker.processed_count}")

    # 7. Test Policy Enforcement Endpoint
    policy_payload = {
        "user": "AAM0658",
        "target_ip": "10.0.4.21",
        "action": "ISOLATE_DEVICE",
        "reason": "Critical after-hours Wikileaks exfiltration"
    }
    res = client.post("/api/v1/policy/enforce", json=policy_payload)
    assert res.status_code == 200
    console.print(f"[bold green]✓ Policy enforcement passed:[/bold green] {res.json()['message']}")

    # 8. Test Normal Baseline Evaluation
    norm_events = generate_normal_baseline_events(user="EMP-TEST-NORM")
    norm_assessment = None
    for evt in norm_events:
        res = client.post("/api/v1/logs/ingest", json=evt)
        assert res.status_code == 200
        norm_assessment = res.json()["assessment"]
    
    assert norm_assessment["risk_score"] < 40.0, f"Expected normal risk, got {norm_assessment['risk_score']}"
    assert norm_assessment["status"] == "NORMAL"
    assert norm_assessment["policy_action"] == "ALLOW"
    console.print(f"[bold green]✓ Normal baseline stream test passed:[/bold green] Risk={norm_assessment['risk_score']}/100 Status={norm_assessment['status']} Action={norm_assessment['policy_action']}")

    console.print("[bold green]🎉 All 5-minute window backend integration tests passed with 100% success![/bold green]")


if __name__ == "__main__":
    run_backend_tests()
