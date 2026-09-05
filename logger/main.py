"""
Unified CLI Entrypoint for Network Telemetry Logger & Kafka Producer.
Supports:
1. Day-based dataset flow replay into Kafka:
   uv run logger --day monday
   uv run logger --day thursday --rate 200
2. Live interface packet sniffing:
   uv run logger sniff --interface lo
3. PCAP capture trace replay:
   uv run logger pcap sample.pcap
"""

import os
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

from src.day_replayer import DayTelemetryReplayer, DAY_FILE_MAPPING

app = typer.Typer(
    help="🛡️ Internal Firewall - Telemetry Logger, Replayer & Kafka Message Producer",
    invoke_without_command=True,
)
console = Console()


@app.callback()
def main_callback(
    ctx: typer.Context,
    day: Optional[str] = typer.Option(
        None,
        "--day",
        "-d",
        help="Replay traffic dataset for a specific day (monday, tuesday, wednesday, thursday, friday)",
    ),
    attack: Optional[str] = typer.Option(
        None,
        "--attack",
        "-a",
        help="Replay traffic for specific attack type (botnet, bruteforce, dos, ddos, web, infiltration, benign)",
    ),
    kafka_server: str = typer.Option(
        os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
        "--kafka-server",
        help="Kafka bootstrap server address",
    ),
    topic: str = typer.Option(
        os.getenv("KAFKA_TOPIC", "network_flows"),
        "--topic",
        "-t",
        help="Kafka target topic",
    ),
    rate: float = typer.Option(
        100.0,
        "--rate",
        "-r",
        help="Flow streaming rate (records/sec, 0 for unthrottled)",
    ),
    max_flows: Optional[int] = typer.Option(
        None,
        "--max-flows",
        "-m",
        help="Maximum flow records to stream",
    ),
    scenario: str = typer.Option(
        "auto",
        "--scenario",
        "-s",
        help="Filter scenario: 'auto', 'attack', or 'benign'",
    ),
):
    """
    If --day or --attack is supplied, streams the selected flow logs into Kafka.
    """
    target_choice = attack or day
    if target_choice is not None:
        console.print(Panel.fit(
            "[bold green]🛡️ Internal Firewall — Telemetry Replay to Kafka[/bold green]\n"
            f"[cyan]Target: {target_choice.upper()} | Broker: {kafka_server} | Topic: '{topic}'[/cyan]",
            border_style="green",
        ))
        replayer = DayTelemetryReplayer(kafka_bootstrap_servers=kafka_server, topic=topic)
        try:
            replayer.stream_day(day=target_choice, max_flows=max_flows, rate=rate, scenario=scenario)
        except Exception as e:
            console.print(f"[bold red]Replay error: {e}[/bold red]")
            sys.exit(1)
        raise typer.Exit()

    # If no subcommand and no --day, show help
    if ctx.invoked_subcommand is None:
        console.print(Panel.fit(
            "[bold cyan]🛡️ Internal Firewall — Telemetry Logger & Kafka Producer[/bold cyan]\n\n"
            "[yellow]Quickstart Examples:[/yellow]\n"
            "  • Replay Monday baseline:    [green]uv run logger --day monday[/green]\n"
            "  • Replay Thursday attack:    [green]uv run logger --day thursday --rate 200[/green]\n"
            "  • Replay Wednesday brute:    [green]uv run logger --day wednesday --max-flows 5000[/green]\n"
            "  • Replay Friday botnet:      [green]uv run logger --day friday[/green]\n"
            "  • Sniff live interface:      [green]uv run logger sniff --interface eth0[/green]\n"
            "  • Replay static PCAP:        [green]uv run logger pcap sample.pcap[/green]\n\n"
            f"[dim]Available days: {', '.join(sorted(DAY_FILE_MAPPING.keys()))}[/dim]",
            border_style="cyan",
        ))


@app.command()
def replay(
    day: str = typer.Option(
        "thursday",
        "--day",
        "-d",
        help="Day to replay (monday, tuesday, wednesday, thursday, friday)",
    ),
    kafka_server: str = typer.Option(
        os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
        "--kafka-server",
        help="Kafka bootstrap server address",
    ),
    topic: str = typer.Option(
        os.getenv("KAFKA_TOPIC", "network_flows"),
        "--topic",
        "-t",
        help="Kafka target topic",
    ),
    rate: float = typer.Option(
        100.0,
        "--rate",
        "-r",
        help="Flow streaming rate in records/sec (0 for unthrottled)",
    ),
    max_flows: Optional[int] = typer.Option(
        None,
        "--max-flows",
        "-m",
        help="Maximum flow records to stream",
    ),
):
    """
    Streams flow dataset records for the designated day into Kafka.
    """
    replayer = DayTelemetryReplayer(kafka_bootstrap_servers=kafka_server, topic=topic)
    replayer.stream_day(day=day, max_flows=max_flows, rate=rate)


@app.command()
def sniff(
    interface: str = typer.Option("any", "--interface", "-i", help="Network interface to sniff on"),
    bpf: Optional[str] = typer.Option(None, "--bpf", "-b", help="BPF packet filter"),
    count: Optional[int] = typer.Option(None, "--count", "-c", help="Number of packets to capture"),
    kafka_server: str = typer.Option(
        os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
        "--kafka-server",
        help="Kafka bootstrap server address",
    ),
    topic: str = typer.Option(
        os.getenv("KAFKA_TOPIC", "network_flows"),
        "--topic",
        "-t",
        help="Kafka target topic",
    ),
    default_user: str = typer.Option("AAM0658", "--user", "-u", help="Default user identity"),
):
    """
    Starts live packet capture on the specified network interface using PyShark and streams into Kafka.
    """
    from src.sniffer import NetworkSniffer
    console.print(Panel.fit(
        "[bold green]🛡️ Internal Firewall - PyShark Live Packet Sniffer[/bold green]\n"
        f"[cyan]Interface: {interface} | Kafka Broker: {kafka_server} | Topic: '{topic}'[/cyan]",
        border_style="green",
    ))
    sniffer = NetworkSniffer(
        interface=interface,
        bpf_filter=bpf,
        kafka_bootstrap_servers=kafka_server,
        kafka_topic=topic,
        default_user=default_user,
    )
    # Stream live packets
    sniffer.start_live_sniff(packet_count=count)


@app.command()
def pcap(
    file_path: str = typer.Argument(..., help="Path to .pcap or .pcapng file"),
    kafka_server: str = typer.Option(
        os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
        "--kafka-server",
        help="Kafka bootstrap server address",
    ),
    topic: str = typer.Option(
        os.getenv("KAFKA_TOPIC", "network_flows"),
        "--topic",
        "-t",
        help="Kafka target topic",
    ),
    default_user: str = typer.Option("AAM0658", "--user", "-u", help="Default user identity"),
):
    """
    Parses a static PCAP packet trace file and streams flows into Kafka.
    """
    from src.sniffer import NetworkSniffer
    console.print(Panel.fit(
        f"[bold cyan]📂 Ingesting PCAP File: {file_path}[/bold cyan]\n"
        f"[yellow]Target Kafka Broker: {kafka_server} -> '{topic}'[/yellow]",
        border_style="cyan",
    ))
    sniffer = NetworkSniffer(
        pcap_file=file_path,
        kafka_bootstrap_servers=kafka_server,
        kafka_topic=topic,
        default_user=default_user,
    )
    sniffer.process_pcap_file(file_path)


def cli():
    app()


if __name__ == "__main__":
    cli()
