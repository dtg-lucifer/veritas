from src.predictor import SecurityModelPredictor
import asyncio

predictor = SecurityModelPredictor()

features = {
    "device_connect_count": 0.0,
    "device_disconnect_count": 0.0,
    "device_after_hours": 0.0,
    "file_copy_count": 0.0,
    "file_doc_pdf_count": 0.0,
    "file_zip_exe_count": 0.0,
    "file_after_hours": 0.0,
    "email_sent_count": 0.0,
    "email_total_bytes": 0.0,
    "email_avg_bytes": 0.0,
    "email_max_bytes": 0.0,
    "email_external_count": 0.0,
    "email_bcc_count": 0.0,
    "email_after_hours": 0.0,
    "http_request_count": 75.0,
    "http_wikileaks_count": 0.0,
    "http_job_search_count": 8.0,
    "http_cloud_storage_count": 7.0,
    "http_hacking_count": 0.0,
    "http_after_hours": 75.0,
    "is_weekend": 0.0,
    "total_activity_count": 75.0,
    "total_after_hours_count": 75.0,
    "after_hours_ratio": 1.0,
    "sensitive_web_count": 15.0,
    "sensitive_web_ratio": 0.2,
    "external_email_ratio": 0.0,
    "usb_surge_zscore": 0.0,
    "file_surge_zscore": 0.0,
    "email_bytes_surge_zscore": 0.0
}

res = predictor.evaluate_features("EMP-MILD-01", "2026-08-21", features)
print(res["status"], res["risk_score"], res["signals"])
