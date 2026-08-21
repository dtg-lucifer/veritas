"""
Dual-Mode Threat & Traffic Scenario Engine for Internal Firewall.
Calibrated strictly against the CERT r4.2 ML training dataset.

Modes of Operation:
1. Normal Mode: Standard enterprise workday baseline (09:00 - 17:00).
   - Normal request volume (~20-50 reqs/window).
   - Normal download rates (5 KB - 100 KB typical).
   - Legitimate enterprise domains (GitHub, Jira, Docs, StackOverflow).
   - Routine internal emails, 0 USB after-hours, 0 sensitive URLs.
   - Evaluates to Risk Score < 35 (NORMAL / ALLOW).

2. Suspicious Mode: Coordinated insider threat and anomaly attack.
   - 3x - 10x higher request burst rate (150 - 450+ reqs/window).
   - Very high download / exfiltration rates (10 MB - 100 MB+ transfers of .zip, .exe, .pdf).
   - After-hours timing (23:30 / weekend).
   - Sensitive domains (Wikileaks, Cloud Storage Mega/Dropbox, Keyloggers/Exploits, Competitor Job Search).
   - USB removable drive insertions and large external emails with hidden BCCs.
   - Evaluates to Risk Score >= 70 (CRITICAL / ISOLATE_DEVICE).
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta, timezone
import random
import uuid

def generate_mild_suspicious_stream(
    user: str = "EMP-MILD-01",
    ip: str = "10.0.2.55",
    request_count: int = 75,
    base_time: Optional[datetime] = None
) -> List[Dict[str, Any]]:
    """
    Generates mildly anomalous traffic to trigger a SUSPICIOUS alert (Risk 35-64).
    - Slightly elevated request count (75).
    - Some larger downloads but not extreme.
    - Mostly normal URLs but maybe a few non-standard ones.
    - No critical overrides triggered (No USB, No extreme after-hours data hoarding).
    """
    if base_time is None:
        base_time = datetime.now(timezone.utc)

    events: List[Dict[str, Any]] = []

    for i in range(request_count):
        ts = (base_time + timedelta(milliseconds=i * 20)).isoformat()
        
        # 1 in 5 requests is to a job theft or cloud exfil site
        if i % 5 == 0:
            url = random.choice(SUSPICIOUS_SENSITIVE_URLS["job_theft"] + SUSPICIOUS_SENSITIVE_URLS["cloud_exfil"])
            size_bytes = float(random.randint(1_000_000, 5_000_000))
        else:
            url = random.choice(NORMAL_ENTERPRISE_URLS)
            size_bytes = float(random.randint(50_000, 200_000))

        events.append({
            "event_id": f"mild-http-{uuid.uuid4().hex[:8]}",
            "timestamp": ts,
            "user": user,
            "src_ip": ip,
            "dst_ip": "142.250.190.46",
            "src_port": 50000 + i,
            "dst_port": 443,
            "protocol": "TCP",
            "event_type": "http",
            "activity": f"GET {url[:50]}",
            "url": url,
            "size": size_bytes,
            "download_bytes": size_bytes,
            "upload_bytes": 1024.0,
            "is_after_hours": True
        })

    events.sort(key=lambda x: x["timestamp"])
    return events


# Legitimate enterprise URLs for Normal Mode
NORMAL_ENTERPRISE_URLS = [
    "https://github.com/internal-corp/core-microservices/pull/189",
    "https://docs.google.com/document/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms/edit",
    "https://stackoverflow.com/questions/6543210/fastapi-async-worker-pool",
    "https://jira.internal-corp.local/browse/SEC-4029",
    "https://confluence.internal-corp.local/display/ENG/System+Architecture+2026",
    "https://aws.amazon.com/console/cloudwatch/metrics",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status",
    "https://internal-wiki.corp.local/it-support/vpn-guide",
    "https://pypi.org/project/pyshark/",
    "https://hub.docker.com/_/redis"
]

# Sensitive anomaly URLs for Suspicious Mode
SUSPICIOUS_SENSITIVE_URLS = {
    "wikileaks": [
        "https://wikileaks.org/leak/submission_portal_v3",
        "https://wikileaks.org/upload/secure_drop_classified_archive",
        "https://wikileaks.org/tor_hidden_service_endpoint"
    ],
    "cloud_exfil": [
        "https://mega.nz/file/transfer_bulk_unrestricted_dump",
        "https://dropbox.com/upload/personal_vault_sync_100gb",
        "https://mediafire.com/api/v2/file/upload_anonymous",
        "https://rapidshare.com/storage/backup_raw_partitions"
    ],
    "hacking_tools": [
        "https://dailykeylogger.com/download/stealth_spectorsoft_agent.exe",
        "https://exploit-db.com/privilege-escalation/rootkit_payload.bin",
        "https://wellresearchedreviews.com/exploits/zero_day_kernel_patch.exe"
    ],
    "job_theft": [
        "https://www.indeed.com/jobs?q=Principal+Staff+Architect+Competitor+Corp",
        "https://www.monster.com/job-openings/cybersecurity-lead-defense-tech",
        "https://www.dice.com/jobs/senior-firmware-engineer-lockheedmartin",
        "https://linkedin.com/jobs/search?keywords=Raytheon+Security+Clearance"
    ]
}


def generate_normal_stream(
    user: str = "EMP-NORM-01",
    ip: str = "10.0.1.15",
    request_count: int = 25,
    base_time: Optional[datetime] = None
) -> List[Dict[str, Any]]:
    """
    Generates a stream of normal baseline enterprise traffic during business hours.
    - Normal request rate (20 - 30 requests)
    - Normal download sizes (5 KB - 80 KB)
    - Legitimate enterprise domains (GitHub, Docs, StackOverflow, Jira)
    - Routine internal emails, zero unauthorized actions.
    - Evaluates to Risk Score < 35 (NORMAL / ALLOW).
    """
    if base_time is None:
        base_time = datetime.now(timezone.utc)

    events: List[Dict[str, Any]] = []

    # 1. Standard HTTP requests with normal download sizes (5KB - 80KB)
    for i in range(request_count):
        ts = (base_time + timedelta(milliseconds=i * 20)).isoformat()
        url = random.choice(NORMAL_ENTERPRISE_URLS)
        size_bytes = float(random.randint(5_000, 80_000))

        events.append({
            "event_id": f"norm-http-{uuid.uuid4().hex[:8]}",
            "timestamp": ts,
            "user": user,
            "src_ip": ip,
            "dst_ip": "142.250.190.46",
            "src_port": 50000 + i,
            "dst_port": 443,
            "protocol": "TCP",
            "event_type": "http",
            "activity": f"GET {url[:50]}",
            "url": url,
            "size": size_bytes,
            "download_bytes": size_bytes,
            "upload_bytes": 512.0,
            "is_after_hours": False
        })

    # 2. Routine internal business emails
    events.append({
        "event_id": f"norm-email-{uuid.uuid4().hex[:8]}",
        "timestamp": (base_time + timedelta(milliseconds=request_count * 20 + 20)).isoformat(),
        "user": user,
        "src_ip": ip,
        "dst_ip": "10.0.0.25",
        "src_port": 51234,
        "dst_port": 587,
        "protocol": "TCP",
        "event_type": "email",
        "activity": "Internal Project Status Update",
        "to": "manager@dtaa.com",
        "bcc": "",
        "size": 18500.0,
        "download_bytes": 18500.0,
        "upload_bytes": 18500.0,
        "is_after_hours": False
    })
    events.append({
        "event_id": f"norm-email-{uuid.uuid4().hex[:8]}",
        "timestamp": (base_time + timedelta(milliseconds=request_count * 20 + 40)).isoformat(),
        "user": user,
        "src_ip": ip,
        "dst_ip": "10.0.0.25",
        "src_port": 51235,
        "dst_port": 587,
        "protocol": "TCP",
        "event_type": "email",
        "activity": "Engineering Sprint Planning",
        "to": "dev-team@dtaa.com",
        "bcc": "",
        "size": 42000.0,
        "download_bytes": 42000.0,
        "upload_bytes": 42000.0,
        "is_after_hours": False
    })

    events.sort(key=lambda x: x["timestamp"])
    return events


def generate_suspicious_stream(
    user: str = "AAM0658",
    ip: str = "10.0.4.21",
    multiplier: int = 5,
    attack_type: str = "wikileaks",
    base_time: Optional[datetime] = None
) -> List[Dict[str, Any]]:
    """
    Generates suspicious insider threat traffic with:
    - 3x to 10x request burst in the window (50 - 150 requests).
    - Very high download / exfiltration rates (15 MB - 85 MB per request).
    - After-hours timing tag.
    - Sensitive target domains (Wikileaks, Cloud Dumps, Keyloggers, Competitor Job Poaching).
    - USB drive insertions and high-volume external emails with hidden BCCs.
    - Evaluates to Risk Score >= 65 (CRITICAL / ISOLATE_DEVICE).
    """
    mult = max(3, min(10, multiplier))
    
    if base_time is None:
        base_time = datetime.now(timezone.utc)

    events: List[Dict[str, Any]] = []

    # 1. Suspicious Removable USB Device Connect Spike
    events.append({
        "event_id": f"susp-usb-{uuid.uuid4().hex[:8]}",
        "timestamp": base_time.isoformat(),
        "user": user,
        "src_ip": ip,
        "dst_ip": "127.0.0.1",
        "src_port": 0,
        "dst_port": 0,
        "protocol": "USB",
        "event_type": "device",
        "activity": "Connect",
        "device_name": "SanDisk Extreme 128GB Removable Media",
        "size": 0.0,
        "is_after_hours": True
    })

    # 2. Large Volume File Copies / Downloads of sensitive archives (.zip, .exe, .pdf)
    files_to_copy = [
        ("Classified_Defense_Architecture_v2.pdf", ".pdf", 28_500_000.0),
        ("Core_Proprietary_Algorithms_Master.zip", ".zip", 64_000_000.0),
        ("Customer_PII_Database_Export.tar.gz", ".tar", 85_000_000.0),
        ("Internal_Financial_Audit_2026.docx", ".docx", 12_400_000.0),
        ("Stealth_Keylogger_Service.exe", ".exe", 8_200_000.0),
    ]

    for idx, (fname, fext, fsize) in enumerate(files_to_copy[:max(2, mult - 1)]):
        ts = (base_time + timedelta(milliseconds=10 + idx * 15)).isoformat()
        events.append({
            "event_id": f"susp-file-{uuid.uuid4().hex[:8]}",
            "timestamp": ts,
            "user": user,
            "src_ip": ip,
            "dst_ip": "10.0.4.1",
            "src_port": 52000 + idx,
            "dst_port": 445,
            "protocol": "SMB",
            "event_type": "file_copy",
            "activity": f"File Transfer {fname}",
            "filename": fname,
            "file_extension": fext,
            "size": fsize,
            "download_bytes": fsize,
            "upload_bytes": fsize,
            "is_after_hours": True
        })

    # 3. 3x - 10x Burst of HTTP Requests with High Download/Upload Rates & Sensitive Domains
    total_http_requests = 10 * mult
    sensitive_urls_pool = (
        SUSPICIOUS_SENSITIVE_URLS.get(attack_type)
        or SUSPICIOUS_SENSITIVE_URLS["wikileaks"]
        + SUSPICIOUS_SENSITIVE_URLS["cloud_exfil"]
        + SUSPICIOUS_SENSITIVE_URLS["hacking_tools"]
    )

    for i in range(total_http_requests):
        is_sensitive = (i % 3 == 0)
        url = random.choice(sensitive_urls_pool) if is_sensitive else random.choice(NORMAL_ENTERPRISE_URLS)
        
        # High download/upload size on sensitive requests: 5MB to 45MB
        size_bytes = float(random.randint(5_000_000, 45_000_000)) if is_sensitive else float(random.randint(200_000, 2_000_000))
        
        ts = (base_time + timedelta(milliseconds=100 + i * 20)).isoformat()

        events.append({
            "event_id": f"susp-http-{uuid.uuid4().hex[:8]}",
            "timestamp": ts,
            "user": user,
            "src_ip": ip,
            "dst_ip": "185.199.110.153",
            "src_port": 53000 + (i % 1000),
            "dst_port": 443,
            "protocol": "TCP",
            "event_type": "http",
            "activity": f"POST {url[:50]}",
            "url": url,
            "size": size_bytes,
            "download_bytes": size_bytes,
            "upload_bytes": size_bytes * 0.8,
            "is_after_hours": True
        })

    # 4. Suspicious External Email with Large Confidential Attachment & Hidden BCC
    events.append({
        "event_id": f"susp-email-{uuid.uuid4().hex[:8]}",
        "timestamp": (base_time + timedelta(milliseconds=150 + total_http_requests * 20)).isoformat(),
        "user": user,
        "src_ip": ip,
        "dst_ip": "198.51.100.25",
        "src_port": 54100,
        "dst_port": 587,
        "protocol": "TCP",
        "event_type": "email",
        "activity": "Exfiltrate Master Source Code",
        "to": "recruiter@competitor-tech.com",
        "bcc": "personal_vault_drop@gmail.com",
        "size": 48_500_000.0,
        "download_bytes": 48_500_000.0,
        "upload_bytes": 48_500_000.0,
        "is_after_hours": True
    })

    # 5. USB Removable Device Disconnect
    events.append({
        "event_id": f"susp-usb-{uuid.uuid4().hex[:8]}",
        "timestamp": (base_time + timedelta(milliseconds=200 + total_http_requests * 20)).isoformat(),
        "user": user,
        "src_ip": ip,
        "dst_ip": "127.0.0.1",
        "src_port": 0,
        "dst_port": 0,
        "protocol": "USB",
        "event_type": "device",
        "activity": "Disconnect",
        "device_name": "SanDisk Extreme 128GB Removable Media",
        "size": 0.0,
        "is_after_hours": True
    })

    # Sort events chronologically
    events.sort(key=lambda x: x["timestamp"])
    return events

