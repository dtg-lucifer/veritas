"""
Configuration manager for the Veritas & AI World Model Service.
Loads baseline parameters, network client scaling, traffic whitelists,
and Redis credentials from firewall_config.yaml with dynamic reload support.
"""

import os
from pathlib import Path
from typing import List, Optional, Dict, Any
import yaml
from pydantic import BaseModel, Field
from rich.console import Console

console = Console()

CONFIG_FILE_PATH = Path(os.getenv("FIREWALL_CONFIG_PATH", Path(__file__).resolve().parent.parent / "firewall_config.yaml"))


class NetworkConfig(BaseModel):
    connected_clients_count: int = Field(1, ge=1, description="Number of connected workstations/clients in network")
    baseline_clients_capacity: int = Field(1, ge=1, description="Baseline client capacity model was trained on")
    auto_scale_volumetric_thresholds: bool = Field(True, description="Scale volumetric features proportionally to client count")


class TrafficPolicyConfig(BaseModel):
    allow_webrtc_conferencing: bool = Field(True, description="Permit and normalize Google Meet / Zoom STUN/TURN traffic")
    conferencing_ports: List[int] = Field(
        default_factory=lambda: [3478, 19302, 19303, 19304, 19305, 19306, 19307, 19308, 19309],
        description="Known WebRTC STUN/TURN media ports"
    )
    whitelisted_ports: List[int] = Field(
        default_factory=lambda: [53, 80, 443, 3478, 8080, 8443],
        description="Standard enterprise whitelisted ports"
    )
    whitelisted_ips: List[str] = Field(default_factory=list, description="Whitelisted destination IP addresses")


class ThresholdsConfig(BaseModel):
    alert_threshold: float = Field(0.40, ge=0.0, le=1.0, description="Risk threshold to trigger ALERT_ADMIN")
    critical_threshold: float = Field(0.70, ge=0.0, le=1.0, description="Risk threshold to trigger ISOLATE_DEVICE")
    window_size_seconds: int = Field(15, ge=1, description="Flow temporal aggregation window in seconds")
    min_warmup_windows: int = Field(4, ge=1, description="Minimum state windows before firing alerts")


class RedisConfig(BaseModel):
    url: str = Field("redis://localhost:6379/0", description="Redis connection URL")
    key_prefix: str = Field("firewall:", description="Redis key prefix for metric keys")
    enabled: bool = Field(True, description="Enable Redis metric ingestion tracking")
    metrics_ttl_seconds: int = Field(86400, description="TTL in seconds for metrics in Redis")


class FirewallConfig(BaseModel):
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    traffic_policy: TrafficPolicyConfig = Field(default_factory=TrafficPolicyConfig)
    thresholds: ThresholdsConfig = Field(default_factory=ThresholdsConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)


_active_config: Optional[FirewallConfig] = None


def load_config() -> FirewallConfig:
    """Loads configuration from YAML file, with environment variable overrides."""
    global _active_config
    data: Dict[str, Any] = {}

    if CONFIG_FILE_PATH.exists():
        try:
            with open(CONFIG_FILE_PATH, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
                if isinstance(loaded, dict):
                    data = loaded
        except Exception as e:
            console.print(f"[bold red]Error reading {CONFIG_FILE_PATH}: {e}. Using defaults.[/bold red]")

    config = FirewallConfig(**data)

    # Environment variable overrides
    if os.getenv("CONNECTED_CLIENTS_COUNT"):
        try:
            config.network.connected_clients_count = int(os.environ["CONNECTED_CLIENTS_COUNT"])
        except ValueError:
            pass

    if os.getenv("ALERT_THRESHOLD"):
        try:
            val = float(os.environ["ALERT_THRESHOLD"])
            config.thresholds.alert_threshold = val / 100.0 if val > 1.0 else val
        except ValueError:
            pass

    if os.getenv("REDIS_URL"):
        config.redis.url = os.environ["REDIS_URL"]

    _active_config = config
    return _active_config


def get_config() -> FirewallConfig:
    """Returns the cached active configuration or loads it if not loaded."""
    global _active_config
    if _active_config is None:
        _active_config = load_config()
    return _active_config


def save_config(new_config: FirewallConfig) -> bool:
    """Saves updated configuration to YAML file and refreshes in-memory cache."""
    global _active_config
    try:
        data = new_config.model_dump()
        with open(CONFIG_FILE_PATH, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
        _active_config = new_config
        console.print(f"[bold green]Updated firewall configuration written to {CONFIG_FILE_PATH}[/bold green]")
        return True
    except Exception as e:
        console.print(f"[bold red]Failed to write config to {CONFIG_FILE_PATH}: {e}[/bold red]")
        return False
