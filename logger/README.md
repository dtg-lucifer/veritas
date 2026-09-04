# 🛡️ Network Telemetry Logger & Kafka Message Producer

High-speed network telemetry replayer and packet sniffer powered by **Apache Kafka**, **Pandas**, and **PyShark**.
Streams standardized flow records into Kafka topic `network_flows` for continuous 15-second state aggregation and AI World Model forward simulation.

---

## 🚀 Key Capabilities

1. **Day-Based Telemetry Replayer (`--day`)**:
   - Stream actual traffic from any designated day of the CSE-CIC-IDS2018 benchmark:
     - `monday`: Nominal baseline traffic (pure benign flows)
     - `thursday`: Infiltration, network reconnaissance & lateral movement
     - `wednesday`: FTP & SSH Brute Force attacks
     - `friday`: Botnet C2 telemetry
     - `tuesday`: DDoS flood attacks
   - Configurable streaming rate (`--rate`, flows/sec) and maximum flow count (`--max-flows`).
   - Scenario filtering: `--scenario=attack` or `--scenario=benign` to test specific security states.

2. **Live Interface Sniffing (`sniff`)**:
   - Captures live network packets on any interface (`lo`, `eth0`, etc.) using PyShark and streams them into Kafka.

3. **PCAP Capture File Replay (`pcap`)**:
   - Parses offline `.pcap` files and streams normalized flow records into Kafka.

---

## 📦 Usage Examples

### 1. Attack & Day Telemetry Replay (Recommended for Testing & Benchmarks)
```bash
cd logger

# 1. Replay Command & Control (Botnet C2) -> Stage: Command & Control
uv run logger --attack=botnet --scenario=attack --max-flows=200 --rate=100

# 2. Replay Initial Access (FTP / SSH Brute Force) -> Stage: Initial Access
uv run logger --attack=bruteforce --scenario=attack --max-flows=200 --rate=100

# 3. Replay Denial of Service (SlowHTTPTest / Hulk) -> Stage: Initial Access / DoS
uv run logger --attack=dos --scenario=attack --max-flows=200 --rate=100

# 4. Replay Distributed Denial of Service (LOIC Flood) -> Stage: Exfiltration / Impact
uv run logger --attack=ddos --scenario=attack --max-flows=200 --rate=100

# 5. Replay Infiltration & Lateral Movement -> Stage: Infiltration / Lateral Movement
uv run logger --attack=infiltration --scenario=attack --max-flows=200 --rate=100

# 6. Replay GoldenEye / Slowloris -> Stage: Command & Control / Impact
uv run logger --attack=goldeneye --scenario=attack --max-flows=200 --rate=100

# 7. Replay Clean Benign Baseline -> Stage: Benign (Risk < 1%)
uv run logger --attack=benign --max-flows=200 --rate=100
```


### 2. Live Interface Sniffing
```bash
cd logger
# Capture packets on loopback interface
sudo uv run logger sniff --interface lo

# Capture packets on eth0 with BPF filter
sudo uv run logger sniff --interface eth0 --bpf "tcp port 80 or port 443"
```

### 3. PCAP File Replay
```bash
cd logger
uv run logger pcap sample_traffic.pcap --topic network_flows
```

---

## ⚙️ CLI Options

| Flag | Shorthand | Default | Description |
| :--- | :--- | :--- | :--- |
| `--day` | `-d` | `None` | Day to replay (`monday`, `tuesday`, `wednesday`, `thursday`, `friday`) |
| `--scenario` | `-s` | `auto` | Scenario filter: `auto`, `attack`, or `benign` |
| `--rate` | `-r` | `100.0` | Emission rate in records per second (0 for max speed) |
| `--max-flows` | `-m` | `None` | Maximum number of records to emit |
| `--kafka-server` | | `localhost:9092` | Address of Kafka bootstrap broker |
| `--topic` | `-t` | `network_flows` | Target Kafka topic |
