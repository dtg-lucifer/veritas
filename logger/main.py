"""
Unified CLI Entrypoint for Pyshark Network Packet Logger.
Captures live network packets or reads PCAP traces and streams normalized logs into Redis MQ.
"""

import sys
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.panel import Panel

# Add logger to sys.path
LOGGER_DIR = Path(__file__).resolve().parent
if str(LOGGER_DIR) not in sys.path:
    sys.path.insert(0, str(LOGGER_DIR))

from src.sniffer import NetworkSniffer
from src.parser import DEFAULT_IP_USER_MAP

app = typer.Typer(help="🛡️ Internal Firewall - Pyshark Packet Logger & Redis Producer")
console = Console()


@app.command()
def sniff(
    interface: str = typer.Option("any", "--interface", "-i", help="Network interface to sniff on (e.g. any, eth0, lo, wlan0)"),
    bpf: Optional[str] = typer.Option(None, "--bpf", "-b", help="BPF packet filter (e.g. 'tcp or udp')"),
    count: Optional[int] = typer.Option(None, "--count", "-c", help="Number of packets to capture before stopping"),
    redis_url: str = typer.Option("redis://localhost:6379/0", "--redis-url", help="Redis connection URL"),
    redis_queue: str = typer.Option("network_logs_queue", "--redis-queue", help="Redis target queue key"),
    default_user: str = typer.Option("AAM0658", "--user", "-u", help="Default fallback user identity for unmapped IPs")
):
    """
    Starts live packet capture on the specified network interface using PyShark.
    """
    console.print(Panel.fit(
        "[bold green]🛡️ Internal Firewall - Pyshark Live Packet Sniffer[/bold green]\n"
        f"[cyan]Interface: {interface} | Default User: {default_user} | Queue: '{redis_queue}'[/cyan]\n"
        f"[yellow]Streaming normalized packet features into Redis MQ at {redis_url}[/yellow]",
        border_style="green"
    ))

    sniffer = NetworkSniffer(
        interface=interface,
        bpf_filter=bpf,
        redis_url=redis_url,
        redis_queue=redis_queue,
        default_user=default_user
    )
    sniffer.start_live_sniff(packet_count=count)


@app.command()
def pcap(
    file_path: str = typer.Argument(..., help="Path to .pcap or .pcapng file"),
    redis_url: str = typer.Option("redis://localhost:6379/0", "--redis-url", help="Redis connection URL"),
    redis_queue: str = typer.Option("network_logs_queue", "--redis-queue", help="Redis target queue key"),
    default_user: str = typer.Option("AAM0658", "--user", "-u", help="Default fallback user identity")
):
    """
    Parses a static PCAP packet trace file and streams logs into Redis MQ.
    """
    console.print(Panel.fit(
        f"[bold cyan]📂 Ingesting PCAP File: {file_path}[/bold cyan]\n"
        f"[yellow]Target Redis MQ: {redis_url} -> '{redis_queue}'[/yellow]",
        border_style="cyan"
    ))

    sniffer = NetworkSniffer(
        pcap_file=file_path,
        redis_url=redis_url,
        redis_queue=redis_queue,
        default_user=default_user
    )
    sniffer.process_pcap_file(file_path)


if __name__ == "__main__":
    app()
