"""
Internal Firewall - Dual-Mode Network Traffic & Threat Simulator.

Operating Modes:
  1. normal:      Standard enterprise workday activity (~25 requests, 5KB-80KB downloads, legitimate URLs, low risk < 35 ALLOW).
  2. suspicious:  Insider threat burst (3x-10x requests, 15MB-85MB downloads/uploads, Wikileaks/cloud exfil/exploits, USB connects, risk >= 65 ISOLATE).
"""

import sys
import asyncio
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.panel import Panel

# Add simulator to sys.path
SIM_DIR = Path(__file__).resolve().parent
if str(SIM_DIR) not in sys.path:
    sys.path.insert(0, str(SIM_DIR))

from scenarios import generate_normal_stream, generate_suspicious_stream
from traffic_generator import TrafficDispatcher

app = typer.Typer(help="🛡️ Internal Firewall - Dual-Mode Traffic & Threat Simulator")
console = Console()


async def run_simulation(
    mode: str,
    target: str,
    user: str,
    multiplier: int,
    attack_type: str,
    delay: float,
    redis_url: str,
    redis_queue: str,
    api_url: str
):
    dispatcher = TrafficDispatcher(
        target_mode=target,
        redis_url=redis_url,
        redis_queue=redis_queue,
        api_base_url=api_url
    )

    try:
        await dispatcher.connect()
    except Exception as e:
        console.print(f"[bold red]Connection failed: {e}[/bold red]")
        sys.exit(1)

    try:
        if mode.lower() == "normal":
            events = generate_normal_stream(user=user, request_count=25)
            await dispatcher.run_scenario(
                scenario_name=f"Normal Enterprise Workday Traffic (User: {user})",
                events=events,
                delay_seconds=delay
            )
            console.print(Panel.fit(
                "[bold green]✓ Normal Mode Stream Completed[/bold green]\n"
                f"[white]Injected {len(events)} baseline events into Redis queue '{redis_queue}'.[/white]\n"
                "[cyan]Expected 5-Min Rolling Assessment: Risk Score < 35 (NORMAL / ALLOW)[/cyan]",
                border_style="green"
            ))

        elif mode.lower() in ["suspicious", "attack", "anomaly"]:
            events = generate_suspicious_stream(
                user=user,
                multiplier=multiplier,
                attack_type=attack_type
            )
            await dispatcher.run_scenario(
                scenario_name=f"Suspicious Insider Threat Burst [{multiplier}x Rate & High Bandwidth] (User: {user})",
                events=events,
                delay_seconds=delay
            )
            console.print(Panel.fit(
                "[bold red]🚨 Suspicious Mode Attack Stream Completed[/bold red]\n"
                f"[white]Injected {len(events)} high-risk attack events into Redis queue '{redis_queue}'.[/white]\n"
                "[yellow]Expected 5-Min Rolling Assessment: Risk Score >= 65 (CRITICAL / ISOLATE_DEVICE)[/yellow]\n"
                "[cyan]An alert will be broadcasted to WebSocket subscribers upon window evaluation.[/cyan]",
                border_style="red"
            ))
        else:
            console.print(f"[red]Invalid mode: '{mode}'. Available modes: 'normal' or 'suspicious'[/red]")

    finally:
        await asyncio.sleep(0.5)
        await dispatcher.close()


@app.command()
def main(
    mode: str = typer.Option("normal", "--mode", "-m", help="Operation mode: 'normal' or 'suspicious'"),
    multiplier: int = typer.Option(5, "--multiplier", "-x", help="Burst multiplier for suspicious mode (3 to 10)"),
    attack_type: str = typer.Option("wikileaks", "--attack-type", "-a", help="Suspicious vector: wikileaks, cloud_exfil, hacking_tools, job_theft"),
    user: Optional[str] = typer.Option(None, "--user", "-u", help="User identity (default: EMP-NORM-01 for normal, AAM0658 for suspicious)"),
    target: str = typer.Option("redis", "--target", "-t", help="Target: 'redis' (MQ broker) or 'http' (direct REST)"),
    delay: float = typer.Option(0.02, "--delay", "-d", help="Delay between injected events in seconds"),
    redis_url: str = typer.Option("redis://localhost:6379/0", "--redis-url", help="Redis connection URL"),
    redis_queue: str = typer.Option("network_logs_queue", "--redis-queue", help="Redis queue key"),
    api_url: str = typer.Option("http://localhost:8000", "--api-url", help="FastAPI gateway URL")
):
    """
    Simulates enterprise baseline traffic (Normal Mode) or 3x-10x insider threat attack (Suspicious Mode).
    """
    resolved_user = user or ("EMP-NORM-01" if mode.lower() == "normal" else "AAM0658")

    asyncio.run(run_simulation(
        mode=mode,
        target=target,
        user=resolved_user,
        multiplier=multiplier,
        attack_type=attack_type,
        delay=delay,
        redis_url=redis_url,
        redis_queue=redis_queue,
        api_url=api_url
    ))


if __name__ == "__main__":
    app()
