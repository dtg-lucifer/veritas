"""
Unit and Integration Tests for PyShark Packet Logger & Redis Producer.
"""

import sys
from pathlib import Path
from datetime import datetime, timezone
from rich.console import Console
from rich.panel import Panel

# Add logger to sys.path
LOGGER_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(LOGGER_DIR))

from src.parser import PacketParser, DEFAULT_IP_USER_MAP
from src.redis_publisher import RedisLogPublisher

console = Console()


class MockHttpLayer:
    def __init__(self):
        self.request_method = "POST"
        self.host = "wikileaks.org"
        self.request_uri = "/upload/classified_archive.zip"
        self.content_length = "45000000"
        self.user_agent = "Mozilla/5.0 (X11; Linux x86_64)"


class MockIpLayer:
    def __init__(self, src="10.0.4.21", dst="185.199.110.153"):
        self.src = src
        self.dst = dst
        self.len = "45001024"


class MockTcpLayer:
    def __init__(self, srcport=54321, dstport=443):
        self.srcport = srcport
        self.dstport = dstport


class MockPacket:
    def __init__(self, src_ip="10.0.4.21", is_after_hours=True):
        # Use a fixed Wednesday (weekday=2) to test hours deterministically
        base_date = datetime(2026, 9, 2, tzinfo=timezone.utc)
        self.sniff_time = base_date.replace(hour=23, minute=30) if is_after_hours else base_date.replace(hour=11, minute=15)
        self.ip = MockIpLayer(src=src_ip)
        self.tcp = MockTcpLayer()
        self.http = MockHttpLayer()
        self.length = 45001024


def test_logger_parsing():
    console.print(Panel.fit("[bold green]Running PyShark Logger & Packet Parser Tests[/bold green]"))

    parser = PacketParser(default_user="AAM0658")

    # 1. Test Mock Threat Packet
    threat_pkt = MockPacket(src_ip="10.0.4.21", is_after_hours=True)
    event = parser.parse_packet(threat_pkt)

    assert event is not None, "Failed to parse threat packet"
    assert event["user"] == "AAM0658", f"Expected user AAM0658, got {event['user']}"
    assert event["src_ip"] == "10.0.4.21"
    assert event["event_type"] in ["http", "file_copy"]
    assert "wikileaks.org" in event["url"]
    assert event["file_extension"] == ".zip"
    assert event["size"] >= 45_000_000
    assert event["is_after_hours"] is True
    # Verify new 32-D flow schema fields
    assert "protocol" in event and event["protocol"] == 6
    assert "dst_port" in event and event["dst_port"] == 443
    assert "flow_bytes_per_sec" in event
    assert "syn_flag_cnt" in event
    assert event["label"] == "Benign"
    console.print(f"[green]Threat packet parsed successfully:[/green] User={event['user']} URL={event['url']} Type={event['event_type']} Size={event['size']:,.0f}B Proto={event['protocol_name']}")

    # 2. Test Normal Packet
    normal_pkt = MockPacket(src_ip="10.0.1.15", is_after_hours=False)
    normal_pkt.http.request_method = "GET"
    normal_pkt.http.host = "github.com"
    normal_pkt.http.request_uri = "/internal-org/repo/pull/42"
    normal_pkt.http.content_length = "15400"
    normal_pkt.ip.len = "15400"

    norm_event = parser.parse_packet(normal_pkt)
    assert norm_event is not None
    assert norm_event["user"] == "EMP-NORM-01"
    assert norm_event["is_after_hours"] is False
    assert "github.com" in norm_event["url"]
    assert norm_event["protocol"] == 6
    assert norm_event["dst_port"] == 443
    console.print(f"[green]Normal packet parsed successfully:[/green] User={norm_event['user']} URL={norm_event['url']} AfterHours={norm_event['is_after_hours']}")

    # 3. Test Redis Publisher Fallback & Batching
    publisher = RedisLogPublisher(redis_url="redis://localhost:6379/0", queue_key="test_logs_queue")
    # Should handle offline redis without crashing
    published = publisher.publish_event(event)
    console.print(f"[green]Redis publisher connection tolerance verified (Published={published})[/green]")

    console.print("[bold green]All PyShark logger parser unit tests passed with 100% SUCCESS![/bold green]")


if __name__ == "__main__":
    test_logger_parsing()
