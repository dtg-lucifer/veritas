"""
Network Packet Sniffer powered by PyShark.
Captures live network packets from interface or reads PCAP files,
normalizes them using PacketParser, and streams them into Apache Kafka topic 'network_flows'.
"""

import os
import sys
import time
import json
from pathlib import Path
from typing import Optional, Dict, Any, Callable
import pyshark
from rich.console import Console
from rich.table import Table
from kafka import KafkaProducer

from src.parser import PacketParser

console = Console()

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "network_flows")


class NetworkSniffer:
    """
    Continuous packet sniffer capturing live interface traffic or replaying PCAP files
    and publishing normalized network flow records directly to Apache Kafka.
    """
    def __init__(
        self,
        interface: str = "any",
        pcap_file: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        kafka_bootstrap_servers: Optional[str] = None,
        kafka_topic: Optional[str] = None,
        default_user: str = "AAM0658",
        on_packet_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        # Backward compatibility arguments
        redis_url: Optional[str] = None,
        redis_queue: Optional[str] = None,
        ip_user_map: Optional[Dict[str, str]] = None,
    ):
        self.interface = interface
        self.pcap_file = pcap_file
        self.bpf_filter = bpf_filter
        self.bootstrap_servers = kafka_bootstrap_servers or KAFKA_BOOTSTRAP_SERVERS
        self.topic = kafka_topic or KAFKA_TOPIC
        self.parser = PacketParser(ip_user_map=ip_user_map, default_user=default_user)
        self.on_packet_callback = on_packet_callback

        self._producer: Optional[KafkaProducer] = None
        self.is_running = False
        self.captured_count = 0
        self.ingested_count = 0
        self.capture_obj: Optional[Any] = None

    def get_producer(self) -> KafkaProducer:
        """Lazily initializes and returns the Kafka producer."""
        if self._producer is None:
            self._producer = KafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                acks=1,
                linger_ms=10,
            )
        return self._producer

    def start_live_sniff(self, packet_count: Optional[int] = None, timeout: Optional[int] = None):
        """
        Starts live packet capture on the selected network interface.
        """
        self.is_running = True
        try:
            # Initialize Kafka producer connection
            self.get_producer()
            console.print(f"[bold green]Connected to Kafka broker at {self.bootstrap_servers} (target topic: '{self.topic}')[/bold green]")
        except Exception as e:
            console.print(f"[bold red]Failed to connect to Kafka at {self.bootstrap_servers}: {e}[/bold red]")
            return

        console.print(f"[bold cyan]Starting live packet capture on interface '{self.interface}'...[/bold cyan]")
        if self.bpf_filter:
            console.print(f"[yellow]BPF Filter applied: '{self.bpf_filter}'[/yellow]")

        try:
            self.capture_obj = pyshark.LiveCapture(
                interface=self.interface,
                bpf_filter=self.bpf_filter,
                use_json=False,
                include_raw=False
            )

            # Apply capture timeout or count if specified
            if packet_count:
                for packet in self.capture_obj.sniff_continuously(packet_count=packet_count):
                    if not self.is_running:
                        break
                    self._process_single_packet(packet)
            else:
                for packet in self.capture_obj.sniff_continuously():
                    if not self.is_running:
                        break
                    self._process_single_packet(packet)

        except KeyboardInterrupt:
            console.print("[yellow]Live sniffing stopped by user.[/yellow]")
        except Exception as e:
            console.print(f"[bold red]Live capture error: {e}[/bold red]")
        finally:
            self.stop()

    def process_pcap_file(self, pcap_path: str):
        """
        Reads and parses a static .pcap or .pcapng file and streams normalized flow records to Kafka.
        """
        path = Path(pcap_path)
        if not path.exists():
            console.print(f"[bold red]PCAP file not found: {pcap_path}[/bold red]")
            return

        self.is_running = True
        try:
            self.get_producer()
            console.print(f"[bold green]Connected to Kafka broker at {self.bootstrap_servers} (topic: '{self.topic}')[/bold green]")
        except Exception as e:
            console.print(f"[bold red]Failed to connect to Kafka at {self.bootstrap_servers}: {e}[/bold red]")
            return

        console.print(f"[bold cyan]Reading PCAP file: {path.name}...[/bold cyan]")

        try:
            self.capture_obj = pyshark.FileCapture(
                input_file=str(path),
                display_filter=self.bpf_filter
            )

            for packet in self.capture_obj:
                if not self.is_running:
                    break
                self._process_single_packet(packet)

            console.print(f"[bold green]Completed PCAP replay: {self.captured_count} packets processed, {self.ingested_count} flow records published to Kafka topic '{self.topic}'.[/bold green]")

        except Exception as e:
            console.print(f"[bold red]Error parsing PCAP file: {e}[/bold red]")
        finally:
            self.stop()

    def _process_single_packet(self, packet: Any):
        """
        Parses raw packet, publishes flow record to Kafka, and prints status.
        """
        self.captured_count += 1
        flow_record = self.parser.parse_packet(packet)
        if not flow_record:
            return

        self.ingested_count += 1

        # Publish to Apache Kafka
        producer = self.get_producer()
        producer.send(self.topic, value=flow_record)

        # Trigger optional callback
        if self.on_packet_callback:
            try:
                self.on_packet_callback(flow_record)
            except Exception:
                pass

        # Streamlined console reporting
        dst_port = flow_record.get("dst_port", 0)
        proto = flow_record.get("protocol_name", "TCP")
        size = flow_record.get("size", 0)
        syn = flow_record.get("syn_flag_cnt", 0)
        ack = flow_record.get("ack_flag_cnt", 0)
        src = f"{flow_record.get('src_ip')}:{flow_record.get('src_port')}"
        dst = f"{flow_record.get('dst_ip')}:{dst_port}"

        if self.ingested_count % 10 == 0 or dst_port in [80, 443, 21, 22, 53, 8080] or syn == 1:
            console.print(
                f"[dim]#{self.ingested_count:05d}[/dim] [cyan][{proto}][/cyan] "
                f"[white]{src}[/white] -> [yellow]{dst}[/yellow] "
                f"Size=[green]{size:,.0f}B[/green] [SYN={syn} ACK={ack}] "
                f"-> [magenta]Kafka '{self.topic}'[/magenta]"
            )

    def stop(self):
        """Gracefully closes capture and flushes Kafka producer."""
        self.is_running = False
        if self.capture_obj:
            try:
                self.capture_obj.close()
            except Exception:
                pass
        if self._producer:
            try:
                self._producer.flush()
                self._producer.close()
            except Exception:
                pass
        console.print(f"[green]Sniffer stopped. (Captured: {self.captured_count} packets, Published: {self.ingested_count} flow records to Kafka '{self.topic}')[/green]")
