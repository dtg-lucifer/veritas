"""
Network Packet Sniffer powered by PyShark.
Captures live network packets from interface or reads PCAP files,
normalizes them using PacketParser, and streams them into Redis MQ.
"""

import sys
import time
import asyncio
from pathlib import Path
from typing import Optional, Dict, Any, Callable
import pyshark
from rich.console import Console
from rich.table import Table

from src.parser import PacketParser
from src.redis_publisher import RedisLogPublisher

console = Console()


class NetworkSniffer:
    """
    Continuous packet sniffer capturing live interface traffic or replaying PCAP files.
    """
    def __init__(
        self,
        interface: str = "any",
        pcap_file: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        redis_url: str = "redis://localhost:6379/0",
        redis_queue: str = "network_logs_queue",
        ip_user_map: Optional[Dict[str, str]] = None,
        default_user: str = "AAM0658",
        on_packet_callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ):
        self.interface = interface
        self.pcap_file = pcap_file
        self.bpf_filter = bpf_filter
        self.parser = PacketParser(ip_user_map=ip_user_map, default_user=default_user)
        self.publisher = RedisLogPublisher(redis_url=redis_url, queue_key=redis_queue)
        self.on_packet_callback = on_packet_callback
        
        self.is_running = False
        self.captured_count = 0
        self.ingested_count = 0
        self.capture_obj: Optional[Any] = None

    def start_live_sniff(self, packet_count: Optional[int] = None, timeout: Optional[int] = None):
        """
        Starts live packet capture on the selected network interface.
        """
        self.is_running = True
        self.publisher.connect()

        console.print(f"[bold cyan]🔍 Starting live packet capture on interface '{self.interface}'...[/bold cyan]")
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
        Reads and parses a static .pcap or .pcapng file and streams events to Redis.
        """
        path = Path(pcap_path)
        if not path.exists():
            console.print(f"[bold red]PCAP file not found: {pcap_path}[/bold red]")
            return

        self.is_running = True
        self.publisher.connect()
        console.print(f"[bold cyan]📂 Reading PCAP file: {path.name}...[/bold cyan]")

        try:
            self.capture_obj = pyshark.FileCapture(
                input_file=str(path),
                display_filter=self.bpf_filter
            )

            for packet in self.capture_obj:
                if not self.is_running:
                    break
                self._process_single_packet(packet)

            console.print(f"[bold green]✓ Completed PCAP replay: {self.captured_count} packets processed, {self.ingested_count} events dumped to Redis.[/bold green]")

        except Exception as e:
            console.print(f"[bold red]Error parsing PCAP file: {e}[/bold red]")
        finally:
            self.stop()

    def _process_single_packet(self, packet: Any):
        """
        Parses raw packet, prints snippet, and publishes to Redis MQ.
        """
        self.captured_count += 1
        event = self.parser.parse_packet(packet)
        if not event:
            return

        self.ingested_count += 1
        
        # Publish to Redis MQ
        self.publisher.publish_event(event)

        # Trigger optional callback
        if self.on_packet_callback:
            try:
                self.on_packet_callback(event)
            except Exception:
                pass

        # Streamlined console reporting (every 25 packets or for high-value file/email events)
        evt_type = event.get("event_type", "conn")
        if self.ingested_count % 25 == 0 or evt_type in ["file_copy", "email"] or "wikileaks" in str(event.get("url", "")).lower():
            user = event.get("user", "UNKNOWN")
            url_or_act = event.get("url") or event.get("activity") or "traffic"
            size = event.get("size", 0)
            console.print(
                f"[dim]#{self.ingested_count:05d}[/dim] [cyan][{evt_type.upper()}][/cyan] "
                f"User=[yellow]{user}[/yellow] Size=[green]{size:,.0f}B[/green] "
                f"[white]{url_or_act[:45]}[/white] -> [magenta]Redis MQ[/magenta]"
            )

    def stop(self):
        """Gracefully closes capture and Redis connections."""
        self.is_running = False
        if self.capture_obj:
            try:
                self.capture_obj.close()
            except Exception:
                pass
        self.publisher.close()
        console.print(f"[green]✓ Sniffer stopped. (Captured: {self.captured_count}, Published: {self.ingested_count})[/green]")
