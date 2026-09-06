"""
Interactive Demonstration CLI for Network World Model.
Accepts a network flow CSV or PCAP capture, runs temporal state windowing,
performs K-step autoregressive forward simulation, and displays or exports the
infiltration probability timeline, MITRE ATT&CK stage progression, and feature attributions.
Supports outputting reports in plain Markdown (.md) or Text (.txt) formats.
Runs fully offline without cloud API dependencies.
"""

import sys
import argparse
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List
import numpy as np
import pandas as pd
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from src.features.traffic_extractor import TrafficExtractor
from src.features.state_window import StateWindowAggregator, build_temporal_sequences, STATE_FEATURE_NAMES, STATE_DIM
from src.world_model.network_world_model import WorldModelWrapper
from src.world_model.forward_simulator import ForwardSimulator, ForwardSimulationReport
from src.world_model.explainability import ThreatExplainer

console = Console()


def generate_markdown_report(
    fpath: Path,
    window_size: int,
    rollout_steps: int,
    scenario_note: str,
    chosen_states: pd.DataFrame,
    report: ForwardSimulationReport,
    explanation: Dict[str, Any],
) -> str:
    """Generates a GitHub-flavored Markdown demonstration report."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    peak_step = max(report.rollout_steps, key=lambda s: s.infiltration_prob)

    lines = [
        "# AI World Model Cyber Defense — Forward Simulation Report",
        "",
        f"- **Generated At:** `{now_str}`",
        f"- **Evaluated Telemetry Source:** `{fpath.name}`",
        f"- **Temporal Window Size ($W$):** `{window_size}s`",
        f"- **Forecast Horizon ($K$):** `{rollout_steps} steps` (+{rollout_steps * window_size}s lead time)",
        f"- **Scenario Context:** {scenario_note}",
        f"- **Max Forecasted Risk:** **{report.max_infiltration_prob * 100:.1f}%** ({peak_step.status})",
        f"- **Peak Anticipated MITRE Stage:** **{report.peak_stage_name}**",
        f"- **Recommended Autonomous Policy:** `{peak_step.policy_action}`",
        "",
        "---",
        "",
        "## 1. Observed Network State History (Context Windows)",
        "",
        "| Window Time | Flows | SYN Ratio | Unique Ports | Byte Rate (KB/s) | Dominant Label |",
        "| :--- | :---: | :---: | :---: | :---: | :--- |",
    ]

    for _, row in chosen_states.iterrows():
        t_str = str(row["window_timestamp"]).split(" ")[-1] if pd.notna(row["window_timestamp"]) else "t"
        lines.append(
            f"| {t_str} | {int(row['flow_count']):,} | {row['syn_ratio']:.3f} | {int(row['unique_dst_ports'])} | {row['flow_bytes_rate']/1024:.1f} | {row['dominant_label']} |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## 2. K-Step Forward Simulation Rollout",
        "",
        "| Forecast Step | Lead Time | Infiltration Prob | Predicted MITRE Stage | Simulated Flows | Simulated SYN Ratio | Security Status | Enforced Policy |",
        "| :--- | :---: | :---: | :--- | :---: | :---: | :---: | :---: |",
    ])

    for s in report.rollout_steps:
        lines.append(
            f"| Step t+{s.step} | +{s.step * window_size}s | {s.infiltration_prob * 100:.1f}% | {s.mitre_stage_name} | {int(s.predicted_state_denorm.get('flow_count', 0)):,} | {s.predicted_state_denorm.get('syn_ratio', 0.0):.3f} | {s.status} | `{s.policy_action}` |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## 3. Explainability & Threat Attribution",
        "",
        f"- **Peak Infiltration Escalation Risk:** {report.max_infiltration_prob * 100:.1f}%",
        f"- **Anticipated MITRE ATT&CK Stage:** {report.peak_stage_name}",
        "",
        "### Top Contributing Network Telemetry Signals:",
        "",
    ])

    for feat in explanation["top_driving_features"]:
        lines.append(f"- **`{feat['feature']}`**: {feat['score'] * 100:.1f}% attribution (Observed Value: `{feat['raw_value']:.2f}`)")

    lines.extend([
        "",
        "### SOC Guidance & Incident Attribution:",
        f"> {explanation['soc_explanation']}",
        "",
    ])

    return "\n".join(lines)


def generate_text_report(
    fpath: Path,
    window_size: int,
    rollout_steps: int,
    scenario_note: str,
    chosen_states: pd.DataFrame,
    report: ForwardSimulationReport,
    explanation: Dict[str, Any],
) -> str:
    """Generates a plain ASCII text demonstration report."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    peak_step = max(report.rollout_steps, key=lambda s: s.infiltration_prob)

    lines = [
        "=" * 85,
        " AI WORLD MODEL CYBER DEFENSE — FORWARD SIMULATION REPORT",
        "=" * 85,
        f"Generated At:             {now_str}",
        f"Evaluated File:           {fpath.name}",
        f"Aggregation Window:       {window_size}s",
        f"Forecast Horizon:         {rollout_steps} steps (+{rollout_steps * window_size}s)",
        f"Scenario Context:         {scenario_note}",
        f"Max Forecasted Risk:      {report.max_infiltration_prob * 100:.1f}% ({peak_step.status})",
        f"Peak Anticipated Stage:   {report.peak_stage_name}",
        f"Enforced Policy Action:   {peak_step.policy_action}",
        "-" * 85,
        "",
        "1. OBSERVED NETWORK STATE HISTORY",
        "-" * 85,
        f"{'Window Time':<15} {'Flows':>8} {'SYN Ratio':>12} {'Unique Ports':>14} {'Byte Rate(KB/s)':>16} {'Dominant Label':<18}",
        "-" * 85,
    ]

    for _, row in chosen_states.iterrows():
        t_str = str(row["window_timestamp"]).split(" ")[-1] if pd.notna(row["window_timestamp"]) else "t"
        lines.append(
            f"{t_str:<15} {int(row['flow_count']):>8} {row['syn_ratio']:>12.3f} {int(row['unique_dst_ports']):>14} {row['flow_bytes_rate']/1024:>16.1f} {str(row['dominant_label']):<18}"
        )

    lines.extend([
        "-" * 85,
        "",
        "2. K-STEP FORWARD SIMULATION ROLLOUT",
        "-" * 85,
        f"{'Forecast Step':<16} {'Lead Time':<12} {'Risk %':>8} {'MITRE Stage':<22} {'Sim Flows':>10} {'Status':<12} {'Policy Action':<16}",
        "-" * 85,
    ])

    for s in report.rollout_steps:
        lines.append(
            f"Step t+{s.step:<10} +{s.step * window_size}s{'':<5} {s.infiltration_prob*100:>7.1f}% {s.mitre_stage_name:<22} {int(s.predicted_state_denorm.get('flow_count', 0)):>10} {s.status:<12} {s.policy_action:<16}"
        )

    lines.extend([
        "-" * 85,
        "",
        "3. EXPLAINABILITY & THREAT FEATURE ATTRIBUTION",
        "-" * 85,
        f"Max Forecasted Infiltration Risk: {report.max_infiltration_prob * 100:.1f}%",
        f"Anticipated Attack Stage:         {report.peak_stage_name}",
        "",
        "Top Contributing Network Signals:",
    ])

    for feat in explanation["top_driving_features"]:
        lines.append(f"  • {feat['feature']:<25}: {feat['score'] * 100:>5.1f}% attribution (Observed: {feat['raw_value']:.2f})")

    lines.extend([
        "",
        "SOC Guidance & Incident Attribution:",
        f"  {explanation['soc_explanation']}",
        "=" * 85,
    ])

    return "\n".join(lines)


def run_demo(
    file_path: str,
    model_path: str = "models/world_model.pt",
    window_size: int = 15,
    seq_len: int = 8,
    rollout_steps: int = 5,
    max_flows: Optional[int] = None,
    scenario: str = "auto",
    window_idx: Optional[int] = None,
    output_path: Optional[str] = None,
    output_format: Optional[str] = None,
) -> None:
    fpath = Path(file_path)
    if not fpath.exists():
        console.print(f"[bold red]File not found: {fpath}[/bold red]")
        sys.exit(1)

    mpath = Path(model_path)
    if not mpath.exists():
        console.print(f"[bold red]Trained World Model weights not found at: {mpath}[/bold red]")
        console.print("[yellow]Please run `uv run python train.py` first to train the model.[/yellow]")
        sys.exit(1)

    console.print(Panel.fit(
        "[bold cyan]AI World Model Cyber Defense — Forward Simulation Demo[/bold cyan]\n"
        f"[white]Input File: {fpath.name} | Aggregation Window: {window_size}s | Forecast Horizon: {rollout_steps} Steps[/white]",
        border_style="cyan"
    ))

    # 1. Ingest Traffic File
    extractor = TrafficExtractor()
    console.print(f"\n[bold]1. Ingesting traffic records from: {fpath.name}...[/bold]")
    if fpath.suffix.lower() == ".pcap":
        df_flows = extractor.parse_pcap(fpath, max_packets=max_flows or 50000)
    else:
        df_flows = extractor.load_cic_ids_2018_csv(fpath, max_rows=max_flows)

    console.print(f"[green]Ingested {len(df_flows):,} flow records.[/green]")

    # 2. Window Aggregation
    console.print(f"[bold]2. Aggregating flows into continuous {window_size}s State Vectors S_t...[/bold]")
    aggregator = StateWindowAggregator(window_size_seconds=window_size)
    df_states = aggregator.aggregate_flows_to_states(df_flows)

    if len(df_states) < seq_len:
        console.print(f"[bold red]Insufficient state windows ({len(df_states)}) for sequence length {seq_len}.[/bold red]")
        sys.exit(1)

    console.print(f"[green]Constructed {len(df_states)} time-windowed network state vectors.[/green]")

    # 3. Load Trained World Model
    console.print(f"[bold]3. Loading World Model checkpoint from: {mpath}...[/bold]")
    world_model = WorldModelWrapper.load(str(mpath))
    simulator = ForwardSimulator(world_model)
    explainer = ThreatExplainer(world_model)

    # 4. Scenario Context & Sequence Selection
    attack_indices = df_states.index[df_states["is_attack"] == 1].tolist()
    
    if window_idx is not None:
        start_idx = max(0, min(window_idx, len(df_states) - seq_len))
        scenario_note = f"Manual window selection at index {start_idx}..{start_idx + seq_len - 1}"
    elif scenario.lower() == "benign":
        # Search for a contiguous window of purely benign states
        benign_indices = df_states.index[df_states["is_attack"] == 0].tolist()
        if len(benign_indices) >= seq_len:
            start_idx = benign_indices[0]
            scenario_note = f"Baseline nominal operation evaluation ({seq_len} continuous benign windows)"
        else:
            start_idx = 0
            scenario_note = "Baseline nominal operation evaluation"
    elif scenario.lower() == "onset" and attack_indices:
        # Precursor / transition: 4 pre-attack windows + 4 early attack windows
        first_att = attack_indices[0]
        start_idx = max(0, min(first_att - seq_len // 2, len(df_states) - seq_len))
        scenario_note = f"Attack onset transition sequence leading into {df_states.iloc[first_att]['dominant_label']} (Window {first_att})"
    elif (scenario.lower() in ["attack", "auto", "peak"]) and attack_indices:
        # Active attack progression: target peak or sustained attack activity
        att_states = df_states.loc[attack_indices]
        peak_idx = att_states["flow_count"].idxmax()
        start_idx = max(0, min(peak_idx - seq_len // 2, len(df_states) - seq_len))
        peak_label = df_states.loc[peak_idx, "dominant_label"]
        scenario_note = f"Active attack progression sequence centered near peak {peak_label} activity (Window {peak_idx})"
    else:
        # Fallback to session tail
        start_idx = max(0, len(df_states) - seq_len)
        scenario_note = f"Evaluating final {seq_len} observed windows of the session (Nominal baseline)"

    chosen_states = df_states.iloc[start_idx : start_idx + seq_len]
    console.print(f"[yellow]• Scenario Context: {scenario_note}[/yellow]")

    # 5. Display Observed History Windows
    obs_table = Table(title=f"Observed Network State History (Windows {start_idx}..{start_idx + seq_len - 1} of {window_size}s)")
    obs_table.add_column("Window Time", style="cyan")
    obs_table.add_column("Flows", justify="right")
    obs_table.add_column("SYN Ratio", justify="right")
    obs_table.add_column("Unique Ports", justify="right")
    obs_table.add_column("Byte Rate (KB/s)", justify="right")
    obs_table.add_column("Dominant Label", style="magenta")

    for _, row in chosen_states.iterrows():
        t_str = str(row["window_timestamp"]).split(" ")[-1] if pd.notna(row["window_timestamp"]) else "t"
        obs_table.add_row(
            t_str,
            f"{int(row['flow_count']):,}",
            f"{row['syn_ratio']:.3f}",
            f"{int(row['unique_dst_ports'])}",
            f"{row['flow_bytes_rate']/1024:.1f}",
            str(row["dominant_label"]),
        )
    console.print(obs_table)

    # 6. Execute K-Step Forward Simulation
    raw_history = chosen_states[STATE_FEATURE_NAMES].values.astype(np.float32)
    report = simulator.simulate(raw_history, k_steps=rollout_steps)
    explanation = explainer.explain_sequence(raw_history)

    # 7. Render Forward Simulation Timeline Table
    sim_table = Table(title=f"K-Step Forward Simulation Rollout ({rollout_steps} Steps Ahead)")
    sim_table.add_column("Forecast Step", style="bold cyan")
    sim_table.add_column("Infiltration Prob", justify="center")
    sim_table.add_column("Predicted MITRE Stage", style="magenta", justify="left")
    sim_table.add_column("Simulated Flows", justify="right")
    sim_table.add_column("Simulated SYN Ratio", justify="right")
    sim_table.add_column("Security Status", justify="center")
    sim_table.add_column("Enforced Policy", style="bold", justify="center")

    for s in report.rollout_steps:
        prob_color = "red" if s.infiltration_prob >= 0.70 else ("yellow" if s.infiltration_prob >= 0.40 else "green")
        prob_str = f"[{prob_color}]{s.infiltration_prob*100:.1f}%[/{prob_color}]"
        
        status_color = "bold red" if s.status == "CRITICAL" else ("bold yellow" if s.status == "SUSPICIOUS" else "bold green")
        status_str = f"[{status_color}]{s.status}[/{status_color}]"

        act_color = "bold red" if s.policy_action == "ISOLATE_DEVICE" else ("bold yellow" if s.policy_action == "ALERT_ADMIN" else "green")
        act_str = f"[{act_color}]{s.policy_action}[/{act_color}]"

        sim_table.add_row(
            f"Step t+{s.step} (+{s.step * window_size}s)",
            prob_str,
            s.mitre_stage_name,
            f"{int(s.predicted_state_denorm.get('flow_count', 0)):,}",
            f"{s.predicted_state_denorm.get('syn_ratio', 0.0):.3f}",
            status_str,
            act_str,
        )
    console.print(sim_table)

    # 8. Render Explainability & Attribution
    attr_panel = (
        f"[bold cyan]Max Forecasted Infiltration Risk:[/bold cyan] {report.max_infiltration_prob*100:.1f}%\n"
        f"[bold]Anticipated Attack Stage:[/bold] [magenta]{report.peak_stage_name}[/magenta]\n\n"
        f"[bold yellow]Top Contributing Network Signals (Feature Attribution):[/bold yellow]\n"
    )
    for feat in explanation["top_driving_features"]:
        attr_panel += f"  • [bold]{feat['feature']}[/bold]: {feat['score']*100:.1f}% attribution (Observed: {feat['raw_value']:.2f})\n"

    attr_panel += f"\n[bold white]SOC Interpretability Guidance:[/bold white]\n  {explanation['soc_explanation']}\n"
    console.print(Panel(attr_panel, title="World Model Interpretability & Attribution", border_style="yellow"))

    # 9. Optional Report File Export (Markdown or Plain Text)
    if output_path:
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Determine format
        fmt = (output_format or out_file.suffix.lstrip(".").lower() or "markdown").lower()
        if fmt in ["txt", "text"]:
            content = generate_text_report(
                fpath=fpath,
                window_size=window_size,
                rollout_steps=rollout_steps,
                scenario_note=scenario_note,
                chosen_states=chosen_states,
                report=report,
                explanation=explanation,
            )
        else:
            content = generate_markdown_report(
                fpath=fpath,
                window_size=window_size,
                rollout_steps=rollout_steps,
                scenario_note=scenario_note,
                chosen_states=chosen_states,
                report=report,
                explanation=explanation,
            )

        out_file.write_text(content, encoding="utf-8")
        console.print(f"\n[bold green]Report successfully exported to: [underline]{out_file.resolve()}[/underline][/bold green]")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="World Model Inference & Forward Simulation CLI Demo")
    parser.add_argument("--file", type=str, default="data/external-network/cic-ids-2018/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv", help="Path to input CSV or PCAP file")
    parser.add_argument("--model", type=str, default="models/world_model.pt", help="Path to trained World Model checkpoint")
    parser.add_argument("--window-size", type=int, default=15, help="Window aggregation size in seconds")
    parser.add_argument("--seq-len", type=int, default=8, help="Context sequence length")
    parser.add_argument("--rollout-steps", type=int, default=5, help="Number of forward simulation steps K")
    parser.add_argument("--max-flows", type=int, default=None, help="Max flows to load for demo (default: None, loads entire file or safe limit for large files)")
    parser.add_argument("--scenario", type=str, default="auto", choices=["auto", "attack", "onset", "benign", "peak"], help="Evaluation scenario (auto, attack/peak, onset, benign)")
    parser.add_argument("--window-idx", type=int, default=None, help="Explicit start window index to evaluate")
    parser.add_argument("--output", "-o", type=str, default=None, help="Path to output file to save report (.md or .txt)")
    parser.add_argument("--format", type=str, default=None, choices=["markdown", "txt"], help="Report export format (markdown or txt, auto-detected from file extension)")

    args = parser.parse_args()

    run_demo(
        file_path=args.file,
        model_path=args.model,
        window_size=args.window_size,
        seq_len=args.seq_len,
        rollout_steps=args.rollout_steps,
        max_flows=args.max_flows,
        scenario=args.scenario,
        window_idx=args.window_idx,
        output_path=args.output,
        output_format=args.format,
    )
