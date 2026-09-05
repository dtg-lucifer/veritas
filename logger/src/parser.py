"""
Packet Parser & Feature Normalizer for PyShark Packet Sniffer.
Extracts network and transport layer metrics (IP, TCP, UDP, HTTP, DNS, TLS SNI),
tracks micro-flow session dynamics, and normalizes raw network traffic into the
standardized flow record schema expected by the AI World Model and StateWindowAggregator.
"""

from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timezone
import uuid
import re
import math
import numpy as np

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


class FlowSession:
    """Tracks state and rolling metrics for an active 5-tuple network session."""
    __slots__ = (
        "start_ts", "last_ts", "fwd_src",
        "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes",
        "pkt_lens", "iats", "fwd_iats", "bwd_iats",
        "init_fwd_win", "init_bwd_win"
    )

    def __init__(self, start_ts: float, fwd_src: str, init_win: int = 65535):
        self.start_ts = start_ts
        self.last_ts = start_ts
        self.fwd_src = fwd_src
        self.fwd_pkts = 0
        self.bwd_pkts = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        self.pkt_lens = []
        self.iats = []
        self.fwd_iats = []
        self.bwd_iats = []
        self.init_fwd_win = init_win
        self.init_bwd_win = 0


class PacketParser:
    """
    Parses PyShark packet objects into standardized flow telemetry records
    compatible with the AI World Model and Apache Kafka 'network_flows' stream.
    """
    def __init__(
        self,
        ip_user_map: Optional[Dict[str, str]] = None,
        default_user: str = "AAM0658",
        max_active_sessions: int = 10000,
    ):
        self.ip_user_map = dict(DEFAULT_IP_USER_MAP)
        if ip_user_map:
            self.ip_user_map.update(ip_user_map)
        self.default_user = default_user
        self.max_active_sessions = max_active_sessions
        # session_key -> FlowSession
        self.sessions: Dict[Tuple[str, str, int], FlowSession] = {}

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

    def _get_or_create_session(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: int,
        epoch_now: float,
        window_size: int = 65535,
    ) -> Tuple[FlowSession, bool]:
        """
        Retrieves or initializes a bidirectional flow session tracker.
        Returns: (session, is_forward_direction)
        """
        # Bidirectional session key
        endpoint_a = f"{src_ip}:{src_port}"
        endpoint_b = f"{dst_ip}:{dst_port}"
        if endpoint_a <= endpoint_b:
            key = (endpoint_a, endpoint_b, protocol)
        else:
            key = (endpoint_b, endpoint_a, protocol)

        session = self.sessions.get(key)
        # If session is older than 60 seconds of inactivity, reset it
        if session and (epoch_now - session.last_ts > 60.0):
            session = None

        if session is None:
            # Enforce max table size to prevent unbounded memory growth
            if len(self.sessions) >= self.max_active_sessions:
                # Evict 10% oldest sessions
                cutoff = epoch_now - 30.0
                stale_keys = [k for k, s in self.sessions.items() if s.last_ts < cutoff]
                for sk in stale_keys[:1000]:
                    self.sessions.pop(sk, None)

            session = FlowSession(start_ts=epoch_now, fwd_src=src_ip, init_win=window_size)
            self.sessions[key] = session

        is_fwd = (src_ip == session.fwd_src)
        return session, is_fwd

    def parse_packet(self, packet: Any) -> Optional[Dict[str, Any]]:
        """
        Parses a single PyShark packet into a standardized network flow record
        matching the CSE-CIC-IDS2018 / StateWindowAggregator schema.
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

            epoch_now = dt.timestamp()
            iso_timestamp = dt.isoformat()
            formatted_timestamp = dt.strftime("%d/%m/%Y %H:%M:%S")
            after_hours = self.is_after_hours(dt)

            # 2. IP Layer Extraction
            src_ip = "127.0.0.1"
            dst_ip = "127.0.0.1"
            pkt_len = 0

            if hasattr(packet, "ip"):
                src_ip = str(getattr(packet.ip, "src", "127.0.0.1"))
                dst_ip = str(getattr(packet.ip, "dst", "127.0.0.1"))
                pkt_len = int(getattr(packet.ip, "len", getattr(packet, "length", 0)))
            elif hasattr(packet, "ipv6"):
                src_ip = str(getattr(packet.ipv6, "src", "::1"))
                dst_ip = str(getattr(packet.ipv6, "dst", "::1"))
                pkt_len = int(getattr(packet.ipv6, "plen", getattr(packet, "length", 0)))
            else:
                pkt_len = int(getattr(packet, "length", 0))

            if pkt_len <= 0:
                pkt_len = int(getattr(packet, "length", 64))

            # 3. Transport Layer & Protocol Mapping
            protocol_num = 6  # default TCP
            protocol_name = "TCP"
            src_port = 0
            dst_port = 0

            syn_flag = 0
            ack_flag = 0
            rst_flag = 0
            fin_flag = 0
            psh_flag = 0
            urg_flag = 0
            ece_flag = 0
            window_size = 65535

            if hasattr(packet, "tcp"):
                protocol_num = 6
                protocol_name = "TCP"
                src_port = int(getattr(packet.tcp, "srcport", 0))
                dst_port = int(getattr(packet.tcp, "dstport", 0))
                window_size = int(getattr(packet.tcp, "window_size", 65535) or 65535)

                # Extract bitmask flags
                try:
                    if hasattr(packet.tcp, "flags"):
                        flag_str = str(packet.tcp.flags)
                        raw_flags = int(flag_str, 16) if flag_str.startswith("0x") else int(flag_str)
                        fin_flag = 1 if (raw_flags & 0x01) else 0
                        syn_flag = 1 if (raw_flags & 0x02) else 0
                        rst_flag = 1 if (raw_flags & 0x04) else 0
                        psh_flag = 1 if (raw_flags & 0x08) else 0
                        ack_flag = 1 if (raw_flags & 0x10) else 0
                        urg_flag = 1 if (raw_flags & 0x20) else 0
                        ece_flag = 1 if (raw_flags & 0x40) else 0
                    else:
                        syn_flag = int(getattr(packet.tcp, "flags_syn", 0) or 0)
                        ack_flag = int(getattr(packet.tcp, "flags_ack", 0) or 0)
                        rst_flag = int(getattr(packet.tcp, "flags_reset", 0) or 0)
                        fin_flag = int(getattr(packet.tcp, "flags_fin", 0) or 0)
                        psh_flag = int(getattr(packet.tcp, "flags_push", 0) or 0)
                        urg_flag = int(getattr(packet.tcp, "flags_urg", 0) or 0)
                except Exception:
                    pass

            elif hasattr(packet, "udp"):
                protocol_num = 17
                protocol_name = "UDP"
                src_port = int(getattr(packet.udp, "srcport", 0))
                dst_port = int(getattr(packet.udp, "dstport", 0))

            elif hasattr(packet, "icmp") or hasattr(packet, "icmpv6"):
                protocol_num = 1
                protocol_name = "ICMP"
                src_port = 0
                dst_port = 0
            else:
                protocol_num = 0
                protocol_name = "RAW"

            # 4. Micro-Flow Session Tracking & Dynamics
            session, is_fwd = self._get_or_create_session(
                src_ip, dst_ip, src_port, dst_port, protocol_num, epoch_now, window_size
            )

            iat_us = max(0.0, (epoch_now - session.last_ts) * 1_000_000.0)
            session.last_ts = epoch_now
            session.pkt_lens.append(pkt_len)
            if len(session.pkt_lens) > 50:
                session.pkt_lens.pop(0)

            if iat_us > 0:
                session.iats.append(iat_us)
                if len(session.iats) > 50:
                    session.iats.pop(0)

            if is_fwd:
                session.fwd_pkts += 1
                session.fwd_bytes += pkt_len
                if iat_us > 0:
                    session.fwd_iats.append(iat_us)
                    if len(session.fwd_iats) > 50:
                        session.fwd_iats.pop(0)
            else:
                session.bwd_pkts += 1
                session.bwd_bytes += pkt_len
                if session.init_bwd_win == 0:
                    session.init_bwd_win = window_size
                if iat_us > 0:
                    session.bwd_iats.append(iat_us)
                    if len(session.bwd_iats) > 50:
                        session.bwd_iats.pop(0)

            duration_us = max(0.0, (epoch_now - session.start_ts) * 1_000_000.0)
            duration_sec = max(duration_us / 1_000_000.0, 0.0001)

            total_pkts = session.fwd_pkts + session.bwd_pkts
            total_bytes = session.fwd_bytes + session.bwd_bytes

            flow_bytes_per_sec = float(total_bytes) / duration_sec
            flow_pkts_per_sec = float(total_pkts) / duration_sec

            pkt_lens_arr = np.array(session.pkt_lens, dtype=np.float32)
            pkt_len_mean = float(np.mean(pkt_lens_arr)) if len(pkt_lens_arr) > 0 else float(pkt_len)
            pkt_len_std = float(np.std(pkt_lens_arr)) if len(pkt_lens_arr) > 1 else 0.0

            iats_arr = np.array(session.iats, dtype=np.float32) if session.iats else np.array([0.0], dtype=np.float32)
            flow_iat_mean = float(np.mean(iats_arr))
            flow_iat_std = float(np.std(iats_arr)) if len(iats_arr) > 1 else 0.0
            flow_iat_max = float(np.max(iats_arr))

            fwd_iats_arr = np.array(session.fwd_iats, dtype=np.float32) if session.fwd_iats else np.array([0.0], dtype=np.float32)
            fwd_iat_mean = float(np.mean(fwd_iats_arr))
            bwd_iats_arr = np.array(session.bwd_iats, dtype=np.float32) if session.bwd_iats else np.array([0.0], dtype=np.float32)
            bwd_iat_mean = float(np.mean(bwd_iats_arr))

            down_up_ratio = float(session.bwd_pkts) / max(float(session.fwd_pkts), 1.0)

            # 5. Application Layer Inspection (HTTP, TLS, DNS, Email)
            event_type = "connection"
            url = None
            filename = None
            file_extension = None
            email_to = None
            email_bcc = None
            headers: Dict[str, str] = {}
            activity = f"{protocol_name} {src_port}->{dst_port}"

            if hasattr(packet, "http"):
                event_type = "http"
                method = getattr(packet.http, "request_method", None)
                host = getattr(packet.http, "host", None)
                uri = getattr(packet.http, "request_uri", "") or getattr(packet.http, "request_full_uri", "")

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
                        pkt_len = max(pkt_len, int(content_len))
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

                if uri:
                    match = FILE_EXT_PATTERN.search(uri)
                    if match:
                        file_extension = f".{match.group(1).lower()}"
                        filename = uri.split("/")[-1].split("?")[0]
                        if file_extension in [".pdf", ".doc", ".docx", ".zip", ".exe", ".bin", ".tar", ".gz", ".rar", ".7z"]:
                            event_type = "file_copy"

            elif hasattr(packet, "tls") or hasattr(packet, "ssl"):
                tls_layer = getattr(packet, "tls", getattr(packet, "ssl", None))
                sni = getattr(tls_layer, "handshake_extensions_server_name", None)
                if sni:
                    event_type = "http"
                    url = f"https://{sni}"
                    activity = f"HTTPS CONNECT {sni}"
                else:
                    activity = f"TLS {src_port}->{dst_port}"

            elif hasattr(packet, "dns"):
                qry_name = getattr(packet.dns, "qry_name", None)
                if qry_name:
                    event_type = "http"
                    url = f"https://{qry_name}"
                    activity = f"DNS Query {qry_name}"

            elif dst_port in [25, 587, 465] or src_port in [25, 587, 465]:
                event_type = "email"
                activity = "SMTP Email Transmission"
                if hasattr(packet, "smtp"):
                    email_to = getattr(packet.smtp, "req_parameter", None)

            user = self.resolve_user(src_ip, headers)
            event_id = f"pkt-{uuid.uuid4().hex[:12]}"

            # Compute pure control ACK flag (matches CICFlowMeter standard, avoiding 100% ACK ratio inflation on data packets)
            is_pure_ack = 1 if (ack_flag == 1 and syn_flag == 0 and fin_flag == 0 and psh_flag == 0 and pkt_len <= 66) else 0

            # 6. Build Standardized Flow Record for AI World Model & Kafka
            flow_record = {
                # Required features for StateWindowAggregator (32-D State Vector)
                # Note: Per-packet deltas are used so StateWindowAggregator sums reflect actual window totals
                "event_id": event_id,
                "timestamp": formatted_timestamp,
                "iso_timestamp": iso_timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": int(protocol_num),
                "protocol_name": protocol_name,
                "flow_duration": float(duration_us),
                "tot_fwd_pkts": 1 if is_fwd else 0,
                "tot_bwd_pkts": 0 if is_fwd else 1,
                "tot_fwd_bytes": int(pkt_len) if is_fwd else 0,
                "tot_bwd_bytes": 0 if is_fwd else int(pkt_len),
                "flow_bytes_per_sec": float(flow_bytes_per_sec),
                "flow_pkts_per_sec": float(flow_pkts_per_sec),
                "flow_iat_mean": float(flow_iat_mean),
                "flow_iat_std": float(flow_iat_std),
                "flow_iat_max": float(flow_iat_max),
                "fwd_iat_mean": float(fwd_iat_mean),
                "bwd_iat_mean": float(bwd_iat_mean),
                "syn_flag_cnt": int(syn_flag),
                "ack_flag_cnt": int(is_pure_ack),
                "rst_flag_cnt": int(rst_flag),
                "fin_flag_cnt": int(fin_flag),
                "psh_flag_cnt": int(psh_flag),
                "urg_flag_cnt": int(urg_flag),
                "ece_flag_cnt": int(ece_flag),
                "pkt_len_mean": float(pkt_len_mean),
                "pkt_len_std": float(pkt_len_std),
                "down_up_ratio": float(down_up_ratio),
                "init_fwd_win_bytes": int(window_size) if protocol_num == 6 else 0,
                "init_bwd_win_bytes": int(session.init_bwd_win) if protocol_num == 6 else 0,
                "active_mean": float(duration_us),
                "idle_mean": 0.0,
                "label": "Benign",

                # Auxiliary metadata for logging / SOC inspection
                "user": user,
                "event_type": event_type,
                "activity": activity,
                "url": url,
                "filename": filename,
                "file_extension": file_extension,
                "size": float(pkt_len),
                "download_bytes": float(session.fwd_bytes),
                "upload_bytes": float(session.bwd_bytes),
                "to": email_to,
                "bcc": email_bcc,
                "is_after_hours": bool(after_hours),
                "raw_summary": f"{protocol_name} {src_ip}:{src_port} -> {dst_ip}:{dst_port} [{pkt_len}B SYN={syn_flag} ACK={ack_flag}]",
            }

            return flow_record

        except Exception as e:
            return None
