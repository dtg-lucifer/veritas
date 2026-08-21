"""
Packet Parser & Feature Normalizer for Pyshark Packet Sniffer.
Extracts protocol layers (IP, TCP, UDP, HTTP, TLS SNI, DNS, SMTP/Email)
and normalizes raw network traffic into the structured event format expected by the AI/ML backend.
"""

from typing import Dict, Any, Optional
from datetime import datetime, timezone
import uuid
import re


# Common file extension regex pattern
FILE_EXT_PATTERN = re.compile(r"\.([a-zA-Z0-9]{2,5})(?:\?|#|$)", re.IGNORECASE)

# Default IP-to-User identity mapping
DEFAULT_IP_USER_MAP: Dict[str, str] = {
    "10.0.4.21": "AAM0658",      # Red-team threat actor / insider
    "10.0.3.44": "BMB0720",      # Scenario 2 threat actor
    "10.0.2.89": "HDB0541",      # Scenario 3 threat actor
    "10.0.1.15": "EMP-NORM-01",  # Normal employee 1
    "10.0.1.16": "EMP-NORM-02",  # Normal employee 2
    "10.0.1.17": "EMP-NORM-03",  # Normal employee 3
    "127.0.0.1": "LOCAL-USER",   # Loopback local traffic
}


class PacketParser:
    """
    Parses pyshark packet objects into standardized security event dictionaries.
    """
    def __init__(
        self,
        ip_user_map: Optional[Dict[str, str]] = None,
        default_user: str = "AAM0658"
    ):
        self.ip_user_map = dict(DEFAULT_IP_USER_MAP)
        if ip_user_map:
            self.ip_user_map.update(ip_user_map)
        self.default_user = default_user

    @staticmethod
    def is_after_hours(dt: datetime) -> bool:
        """Determines if timestamp falls outside 07:30 - 18:30 or on weekends."""
        hour = dt.hour + dt.minute / 60.0
        return (dt.weekday() >= 5) or (hour < 7.5) or (hour > 18.5)

    def resolve_user(self, src_ip: str, headers: Optional[Dict[str, str]] = None) -> str:
        """Resolves user identity from custom headers or IP mapping table."""
        if headers:
            for k, v in headers.items():
                if k.lower() in ["x-user-id", "x-user", "user-id", "user", "x-employee-id"]:
                    if v and str(v).strip():
                        return str(v).strip()

        if src_ip in self.ip_user_map:
            return self.ip_user_map[src_ip]

        return self.default_user

    def parse_packet(self, packet: Any) -> Optional[Dict[str, Any]]:
        """
        Parses a single pyshark packet into a normalized event dictionary.
        Returns None if packet is not relevant (e.g. ARP, link-layer control).
        """
        try:
            # 1. Timestamp extraction
            raw_sniff_time = getattr(packet, "sniff_time", None)
            if isinstance(raw_sniff_time, datetime):
                dt = raw_sniff_time if raw_sniff_time.tzinfo else raw_sniff_time.replace(tzinfo=timezone.utc)
            else:
                try:
                    sniff_ts = float(getattr(packet, "sniff_timestamp", 0))
                    dt = datetime.fromtimestamp(sniff_ts, tz=timezone.utc) if sniff_ts > 0 else datetime.now(timezone.utc)
                except Exception:
                    dt = datetime.now(timezone.utc)

            iso_timestamp = dt.isoformat()
            after_hours = self.is_after_hours(dt)

            # 2. IP Layer Extraction
            src_ip = "127.0.0.1"
            dst_ip = "127.0.0.1"
            pkt_len = 0

            if hasattr(packet, "ip"):
                src_ip = getattr(packet.ip, "src", "127.0.0.1")
                dst_ip = getattr(packet.ip, "dst", "127.0.0.1")
                pkt_len = int(getattr(packet.ip, "len", getattr(packet, "length", 0)))
            elif hasattr(packet, "ipv6"):
                src_ip = getattr(packet.ipv6, "src", "::1")
                dst_ip = getattr(packet.ipv6, "dst", "::1")
                pkt_len = int(getattr(packet.ipv6, "plen", getattr(packet, "length", 0)))
            else:
                pkt_len = int(getattr(packet, "length", 0))

            # 3. Transport Layer Extraction (TCP / UDP)
            protocol = "RAW"
            src_port = 0
            dst_port = 0

            if hasattr(packet, "tcp"):
                protocol = "TCP"
                src_port = int(getattr(packet.tcp, "srcport", 0))
                dst_port = int(getattr(packet.tcp, "dstport", 0))
            elif hasattr(packet, "udp"):
                protocol = "UDP"
                src_port = int(getattr(packet.udp, "srcport", 0))
                dst_port = int(getattr(packet.udp, "dstport", 0))

            event_type = "connection"
            url = None
            filename = None
            file_extension = None
            email_to = None
            email_bcc = None
            size_bytes = pkt_len
            headers: Dict[str, str] = {}
            activity = f"{protocol} {src_port}->{dst_port}"

            # 4. HTTP Layer Parsing
            if hasattr(packet, "http"):
                event_type = "http"
                method = getattr(packet.http, "request_method", None)
                host = getattr(packet.http, "host", None)
                uri = getattr(packet.http, "request_uri", "") or getattr(packet.http, "request_full_uri", "")
                
                # Check headers
                for field_name in dir(packet.http):
                    if field_name.startswith("header_") or field_name.startswith("request_"):
                        val = getattr(packet.http, field_name, None)
                        if val and isinstance(val, str):
                            headers[field_name] = val

                user_agent = getattr(packet.http, "user_agent", "")
                if user_agent:
                    headers["User-Agent"] = str(user_agent)

                content_len = getattr(packet.http, "content_length", None)
                if content_len:
                    try:
                        size_bytes = max(size_bytes, int(content_len))
                    except ValueError:
                        pass

                if host and uri:
                    scheme = "https" if dst_port == 443 else "http"
                    url = f"{scheme}://{host}{uri}" if not uri.startswith("http") else uri
                elif host:
                    url = f"http://{host}"
                elif uri:
                    url = uri

                if method:
                    activity = f"HTTP {method} {uri[:60]}"
                else:
                    activity = "HTTP Response"

                # Check for file transfers in HTTP URI
                if uri:
                    match = FILE_EXT_PATTERN.search(uri)
                    if match:
                        file_extension = f".{match.group(1).lower()}"
                        filename = uri.split("/")[-1].split("?")[0]
                        if file_extension in [".pdf", ".doc", ".docx", ".zip", ".exe", ".bin", ".tar", ".gz", ".rar", ".7z"]:
                            event_type = "file_copy"

            # 5. TLS / SSL Server Name Indication (SNI) for HTTPS
            elif hasattr(packet, "tls") or hasattr(packet, "ssl"):
                tls_layer = getattr(packet, "tls", getattr(packet, "ssl", None))
                sni = getattr(tls_layer, "handshake_extensions_server_name", None)
                if sni:
                    event_type = "http"
                    url = f"https://{sni}"
                    activity = f"HTTPS CONNECT {sni}"
                else:
                    activity = f"TLS {src_port}->{dst_port}"

            # 6. DNS Layer Parsing
            elif hasattr(packet, "dns"):
                qry_name = getattr(packet.dns, "qry_name", None)
                if qry_name:
                    event_type = "http"
                    url = f"https://{qry_name}"
                    activity = f"DNS Query {qry_name}"

            # 7. Email Protocol Detection (SMTP, IMAP, POP3)
            elif dst_port in [25, 587, 465] or src_port in [25, 587, 465]:
                event_type = "email"
                activity = "SMTP Email Transmission"
                if hasattr(packet, "smtp"):
                    email_to = getattr(packet.smtp, "req_parameter", None)
                size_bytes = max(size_bytes, pkt_len)

            # Resolve user identity
            user = self.resolve_user(src_ip, headers)

            # Build standardized log event
            event_id = f"pkt-{uuid.uuid4().hex[:12]}"
            log_event = {
                "event_id": event_id,
                "timestamp": iso_timestamp,
                "user": user,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "event_type": event_type,
                "activity": activity,
                "url": url,
                "filename": filename,
                "file_extension": file_extension,
                "size": float(size_bytes),
                "download_bytes": float(size_bytes),
                "upload_bytes": 0.0,
                "to": email_to,
                "bcc": email_bcc,
                "is_after_hours": bool(after_hours),
                "raw_summary": f"{protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port} [{pkt_len} bytes]"
            }

            return log_event

        except Exception as e:
            # Fallback for parsing edge-cases
            return None
