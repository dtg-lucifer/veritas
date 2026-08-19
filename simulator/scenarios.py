"""
Network Traffic & Threat Scenario Generator.
Generates realistic 5-minute window event bursts for normal enterprise baseline traffic
and CERT r4.2 red-team attack scenarios to validate real-time ML anomaly detection.
"""

from typing import List, Dict, Any
from datetime import datetime, timedelta, timezone
import random


def generate_normal_baseline_events(user: str = "EMP-NORM-01", ip: str = "10.0.1.15") -> List[Dict[str, Any]]:
    """
    Simulates standard workday activity (09:00 - 17:00):
    - Normal daytime browsing (GitHub, Google Docs, Internal Jira, Confluence)
    - Routine internal corporate emails
    - Zero USB usage, zero sensitive keyword triggers.
    """
    events = []
    base_time = datetime.now(timezone.utc).replace(hour=10, minute=15, second=0, microsecond=0)

    urls = [
        "https://github.com/internal-org/repo/pull/42",
        "https://docs.google.com/document/d/12345/edit",
        "https://stackoverflow.com/questions/54321/fastapi-performance",
        "https://internal-jira.corp.local/browse/PROJ-108",
        "https://confluence.corp.local/pages/viewpage.action?pageId=99",
        "https://medium.com/engineering/microservices-architecture",
        "https://aws.amazon.com/console/dashboard"
    ]

    # Standard daytime web traffic
    for i in range(10):
        ts = (base_time + timedelta(seconds=i * 25 + random.randint(1, 5))).isoformat()
        events.append({
            "event_id": f"norm-http-{i+1:02d}",
            "timestamp": ts,
            "user": user,
            "src_ip": ip,
            "event_type": "http",
            "url": random.choice(urls)
        })

    # Routine internal emails
    events.append({
        "event_id": "norm-email-01",
        "timestamp": (base_time + timedelta(minutes=2, seconds=10)).isoformat(),
        "user": user,
        "src_ip": ip,
        "event_type": "email",
        "to": "manager@dtaa.com",
        "bcc": "",
        "size": 15400
    })
    events.append({
        "event_id": "norm-email-02",
        "timestamp": (base_time + timedelta(minutes=4, seconds=30)).isoformat(),
        "user": user,
        "src_ip": ip,
        "event_type": "email",
        "to": "dev-team@dtaa.com",
        "bcc": "",
        "size": 42000
    })

    return events


def generate_scenario_1_wikileaks(user: str = "AAM0658", ip: str = "10.0.4.21") -> List[Dict[str, Any]]:
    """
    Scenario 1: After-Hours Data Exfiltration to Wikileaks & USB Drive
    - Late night (23:30)
    - USB connect & disconnect
    - Sensitive PDFs and ZIP copies to removable media
    - HTTP POST to Wikileaks upload portal
    """
    base_time = datetime.now(timezone.utc).replace(hour=23, minute=30, second=0, microsecond=0)
    events = [
        {
            "event_id": "scen1-usb-01",
            "timestamp": base_time.isoformat(),
            "user": user,
            "src_ip": ip,
            "event_type": "device",
            "activity": "Connect",
            "device_name": "Kingston 64GB DataTraveler"
        },
        {
            "event_id": "scen1-file-01",
            "timestamp": (base_time + timedelta(seconds=20)).isoformat(),
            "user": user,
            "src_ip": ip,
            "event_type": "file_copy",
            "filename": "Classified_Defense_Architecture_v2.pdf",
            "file_extension": ".pdf",
            "size": 18500000
        },
        {
            "event_id": "scen1-file-02",
            "timestamp": (base_time + timedelta(seconds=45)).isoformat(),
            "user": user,
            "src_ip": ip,
            "event_type": "file_copy",
            "filename": "Internal_Audit_Report_2026.docx",
            "file_extension": ".docx",
            "size": 4200000
        },
        {
            "event_id": "scen1-file-03",
            "timestamp": (base_time + timedelta(minutes=1, seconds=15)).isoformat(),
            "user": user,
            "src_ip": ip,
            "event_type": "file_copy",
            "filename": "Core_Proprietary_Algorithms.zip",
            "file_extension": ".zip",
            "size": 34000000
        },
        {
            "event_id": "scen1-http-01",
            "timestamp": (base_time + timedelta(minutes=2, seconds=10)).isoformat(),
            "user": user,
            "src_ip": ip,
            "event_type": "http",
            "url": "https://wikileaks.org/leak/submission_portal"
        },
        {
            "event_id": "scen1-http-02",
            "timestamp": (base_time + timedelta(minutes=3, seconds=5)).isoformat(),
            "user": user,
            "src_ip": ip,
            "event_type": "http",
            "url": "https://wikileaks.org/upload/secure_drop_files"
        },
        {
            "event_id": "scen1-usb-02",
            "timestamp": (base_time + timedelta(minutes=4, seconds=20)).isoformat(),
            "user": user,
            "src_ip": ip,
            "event_type": "device",
            "activity": "Disconnect",
            "device_name": "Kingston 64GB DataTraveler"
        }
    ]
    return events


def generate_scenario_2_job_theft(user: str = "BMB0720", ip: str = "10.0.3.44") -> List[Dict[str, Any]]:
    """
    Scenario 2: Job Hunting & Competitor Data Theft Before Resignation
    - Browsing job search boards (Indeed, Monster, LinkedIn)
    - Copying project blueprints to USB
    - Sending external email with archive to recruiter / competitor address
    """
    base_time = datetime.now(timezone.utc).replace(hour=14, minute=10, second=0, microsecond=0)
    events = [
        {
            "event_id": "scen2-http-01",
            "timestamp": base_time.isoformat(),
            "user": user,
            "src_ip": ip,
            "event_type": "http",
            "url": "https://www.indeed.com/jobs?q=Principal+Engineer+Competitor+Corp"
        },
        {
            "event_id": "scen2-http-02",
            "timestamp": (base_time + timedelta(seconds=35)).isoformat(),
            "user": user,
            "src_ip": ip,
            "event_type": "http",
            "url": "https://www.monster.com/job-openings/cybersecurity-lead"
        },
        {
            "event_id": "scen2-usb-01",
            "timestamp": (base_time + timedelta(minutes=1, seconds=10)).isoformat(),
            "user": user,
            "src_ip": ip,
            "event_type": "device",
            "activity": "Connect",
            "device_name": "SanDisk Ultra 32GB"
        },
        {
            "event_id": "scen2-file-01",
            "timestamp": (base_time + timedelta(minutes=1, seconds=45)).isoformat(),
            "user": user,
            "src_ip": ip,
            "event_type": "file_copy",
            "filename": "Q3_Strategic_Client_Accounts.xlsx",
            "file_extension": ".xlsx",
            "size": 8900000
        },
        {
            "event_id": "scen2-file-02",
            "timestamp": (base_time + timedelta(minutes=2, seconds=20)).isoformat(),
            "user": user,
            "src_ip": ip,
            "event_type": "file_copy",
            "filename": "Client_Contracts_Master.zip",
            "file_extension": ".zip",
            "size": 15600000
        },
        {
            "event_id": "scen2-email-01",
            "timestamp": (base_time + timedelta(minutes=3, seconds=40)).isoformat(),
            "user": user,
            "src_ip": ip,
            "event_type": "email",
            "to": "recruiter@competitor-tech.com",
            "bcc": "personal_vault@gmail.com",
            "size": 18200000
        }
    ]
    return events


def generate_scenario_3_keylogger(user: str = "HDB0541", ip: str = "10.0.2.89") -> List[Dict[str, Any]]:
    """
    Scenario 3: Admin Keylogger Sabotage / Unauthorized Tools
    - Late night (22:15)
    - Browsing exploit & keylogger websites
    - Downloading executable binary (.exe)
    - USB insert and executable file copy
    """
    base_time = datetime.now(timezone.utc).replace(hour=22, minute=15, second=0, microsecond=0)
    events = [
        {
            "event_id": "scen3-http-01",
            "timestamp": base_time.isoformat(),
            "user": user,
            "src_ip": ip,
            "event_type": "http",
            "url": "https://dailykeylogger.com/download/spectorsoft_agent.exe"
        },
        {
            "event_id": "scen3-http-02",
            "timestamp": (base_time + timedelta(seconds=40)).isoformat(),
            "user": user,
            "src_ip": ip,
            "event_type": "http",
            "url": "https://exploit-db.com/privilege-escalation/payload.bin"
        },
        {
            "event_id": "scen3-usb-01",
            "timestamp": (base_time + timedelta(minutes=1, seconds=20)).isoformat(),
            "user": user,
            "src_ip": ip,
            "event_type": "device",
            "activity": "Connect",
            "device_name": "Corsair Flash Stealth"
        },
        {
            "event_id": "scen3-file-01",
            "timestamp": (base_time + timedelta(minutes=2, seconds=10)).isoformat(),
            "user": user,
            "src_ip": ip,
            "event_type": "file_copy",
            "filename": "agent_payload.exe",
            "file_extension": ".exe",
            "size": 3200000
        },
        {
            "event_id": "scen3-file-02",
            "timestamp": (base_time + timedelta(minutes=3, seconds=15)).isoformat(),
            "user": user,
            "src_ip": ip,
            "event_type": "file_copy",
            "filename": "keylogger_dump.bin",
            "file_extension": ".bin",
            "size": 5800000
        }
    ]
    return events


def generate_scenario_mass_cloud_exfil(user: str = "EXF0999", ip: str = "10.0.5.12") -> List[Dict[str, Any]]:
    """
    Scenario 4: Mass Cloud Storage Exfiltration
    - Late night upload to Mega.nz & Dropbox (01:45)
    - 50MB+ archive copy and cloud upload
    """
    base_time = datetime.now(timezone.utc).replace(hour=1, minute=45, second=0, microsecond=0)
    events = [
        {
            "event_id": "scen4-http-01",
            "timestamp": base_time.isoformat(),
            "user": user,
            "src_ip": ip,
            "event_type": "http",
            "url": "https://mega.nz/storage/direct_upload"
        },
        {
            "event_id": "scen4-file-01",
            "timestamp": (base_time + timedelta(seconds=30)).isoformat(),
            "user": user,
            "src_ip": ip,
            "event_type": "file_copy",
            "filename": "Database_Financial_Audit_Full.zip",
            "file_extension": ".zip",
            "size": 52000000
        },
        {
            "event_id": "scen4-file-02",
            "timestamp": (base_time + timedelta(minutes=1, seconds=15)).isoformat(),
            "user": user,
            "src_ip": ip,
            "event_type": "file_copy",
            "filename": "Customer_PII_Export_2026.zip",
            "file_extension": ".zip",
            "size": 68000000
        },
        {
            "event_id": "scen4-http-02",
            "timestamp": (base_time + timedelta(minutes=2, seconds=45)).isoformat(),
            "user": user,
            "src_ip": ip,
            "event_type": "http",
            "url": "https://dropbox.com/upload/bulk_archive"
        }
    ]
    return events
