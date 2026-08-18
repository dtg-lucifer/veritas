"""
Unified Network Traffic & Insider Threat Simulation CLI.
Generates baseline enterprise traffic and CERT r4.2 attack vectors
to test real-time ML anomaly detection, Redis queue processing, and WebSocket alerts.
"""

import sys
import asyncio
import random
from typing import Optional
import typer
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel

from scenarios import (
    generate_normal_baseline_events,
    generate_scenario_1_wikileaks,
    generate_scenario_2_job_theft,
    generate_scenario_3_keylogger,
    generate_scenario_mass_cloud_exfil
)
from traffic_generator import TrafficDispatcher

app = typer.Typer(help="🛡️ Internal Firewall - Network Traffic & Threat Simulator")
console = Console()


async def run_scenario_flow(
    scenario: str,
    target: str,
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

    scenarios_map = {
        "normal": ("Normal Baseline Activity", generate_normal_baseline_events),
        "wikileaks": ("Scenario 1: Wikileaks USB Exfiltration", generate_scenario_1_wikileaks),
        "job_theft": ("Scenario 2: Job Surfing & Data Theft", generate_scenario_2_job_theft),
        "keylogger": ("Scenario 3: Admin Keylogger Sabotage", generate_scenario_3_keylogger),
        "mass_exfil": ("Scenario 4: Mass Cloud Storage Exfiltration", generate_scenario_mass_cloud_exfil),
    }

    try:
        if scenario == "all":
            for key, (name, gen_func) in scenarios_map.items():
                events = gen_func()
                await dispatcher.run_scenario(name, events, delay_seconds=delay)
                await asyncio.sleep(1.0)
        elif scenario == "continuous":
            console.print(Panel.fit(
                "[bold green]🌐 Multi-User Continuous Enterprise Stream Running[/bold green]\n"
                "[yellow]Simulating 8 normal employees with intermittent stealth attack spikes. Press Ctrl+C to stop.[/yellow]",
                border_style="green"
            ))
            users = [f"EMP-NORM-{i:02d}" for i in range(1, 9)]
            attacker = "AAM0658"
            
            while True:
                # 80% normal event, 20% stealth attack snippet
                is_attack = random.random() < 0.25
                if is_attack:
                    scen_choice = random.choice([generate_scenario_1_wikileaks, generate_scenario_2_job_theft, generate_scenario_3_keylogger])
                    attack_events = scen_choice(user=attacker)
                    single_evt = random.choice(attack_events)
                    console.print(f"[bold red]⚡ Injecting Attack Event: [{single_evt['event_type']}] for {attacker}[/bold red]")
                    await dispatcher.dispatch_event(single_evt)
                else:
                    norm_user = random.choice(users)
                    norm_events = generate_normal_baseline_events(user=norm_user)
                    single_evt = random.choice(norm_events)
                    console.print(f"[green]✓ Normal Event: [{single_evt['event_type']}] for {norm_user}[/green]")
                    await dispatcher.dispatch_event(single_evt)

                await asyncio.sleep(delay)

        elif scenario in scenarios_map:
            name, gen_func = scenarios_map[scenario]
            events = gen_func()
            await dispatcher.run_scenario(name, events, delay_seconds=delay)
        else:
            console.print(f"[red]Unknown scenario: {scenario}. Available: {list(scenarios_map.keys())} or 'all', 'continuous'[/red]")
    finally:
        await dispatcher.close()


def interactive_menu(target: str, delay: float, redis_url: str, redis_queue: str, api_url: str):
    """Interactive CLI menu for live SIH presentations & demos."""
    console.print(Panel.fit(
        "[bold cyan]🛡️ Internal Firewall - Live Attack & Traffic Simulator[/bold cyan]\n"
        "[white]Select a threat scenario to transmit live network activity into the AI/ML gateway.[/white]",
        border_style="cyan"
    ))

    choices = {
        "1": ("normal", "Normal Baseline Activity (09:00-17:00 Workday)"),
        "2": ("wikileaks", "Scenario 1: Wikileaks USB Exfiltration (Late Night)"),
        "3": ("job_theft", "Scenario 2: Job Hunting & Competitor Data Theft"),
        "4": ("keylogger", "Scenario 3: Admin Keylogger Sabotage / Payload Download"),
        "5": ("mass_exfil", "Scenario 4: Mass Cloud Storage Exfiltration"),
        "6": ("all", "Run All Scenarios Sequentially"),
        "7": ("continuous", "Continuous Multi-User Enterprise Traffic Stream"),
        "0": ("exit", "Exit Simulator")
    }

    for key, (_, desc) in choices.items():
        console.print(f"  [bold yellow][{key}][/bold yellow] {desc}")

    choice = Prompt.ask("\nSelect scenario option", choices=list(choices.keys()), default="2")
    if choice == "0":
        console.print("[yellow]Exiting simulator.[/yellow]")
        return

    scenario_key = choices[choice][0]
    asyncio.run(run_scenario_flow(
        scenario=scenario_key,
        target=target,
        delay=delay,
        redis_url=redis_url,
        redis_queue=redis_queue,
        api_url=api_url
    ))


@app.command()
def main(
    scenario: str = typer.Option("wikileaks", "--scenario", "-s", help="Scenario: normal, wikileaks, job_theft, keylogger, mass_exfil, all, continuous"),
    target: str = typer.Option("http", "--target", "-t", help="Target mode: 'http' (FastAPI REST) or 'redis' (Message Queue)"),
    delay: float = typer.Option(0.5, "--delay", "-d", help="Delay between events in seconds"),
    redis_url: str = typer.Option("redis://localhost:6379/0", "--redis-url", help="Redis connection URL"),
    redis_queue: str = typer.Option("network_logs_queue", "--redis-queue", help="Redis queue key"),
    api_url: str = typer.Option("http://localhost:8000", "--api-url", help="FastAPI gateway base URL"),
    interactive: bool = typer.Option(False, "--interactive", "-i", help="Launch interactive menu mode")
):
    """
    Simulates enterprise baseline traffic and insider threats against the ML Gateway.
    """
    if interactive:
        interactive_menu(target, delay, redis_url, redis_queue, api_url)
    else:
        asyncio.run(run_scenario_flow(
            scenario=scenario,
            target=target,
            delay=delay,
            redis_url=redis_url,
            redis_queue=redis_queue,
            api_url=api_url
        ))


if __name__ == "__main__":
    app()
