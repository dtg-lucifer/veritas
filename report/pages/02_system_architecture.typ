#import "common.typ": callout, takeaway, primary-color, secondary-color

= End-to-End System Architecture

== Architectural Blueprint & Multi-Layer Pipeline

The Veritas architecture is designed as a distributed, modular, seven-layer streaming pipeline. It unifies line-rate network telemetry ingestion, temporal state representation, deep sequence dynamics modeling, forward simulation, explainable AI, and closed-loop mitigation into a coherent, production-grade system.

#figure(
  image("../assets/veritas_technical_diagram_transparent.png", width: 95%),
  caption: [Veritas End-to-End Multi-Layer System Architecture: From Line-Rate Telemetry Ingestion to Automated Closed-Loop Mitigation.]
)

The system operates across seven distinct functional layers, each decoupled to ensure sub-millisecond ingestion latencies, horizontal scaling, and strict fault tolerance:

=== Layer 1: Heterogeneous Telemetry Collection & Normalization
Network telemetry is captured from diverse enterprise environments without requiring intrusive host-based modifications:
- *Flow-Level Records (NetFlow v9 / IPFIX):* Standard flow collectors export 5-tuple connection records, byte and packet volumes, flow duration, and TCP flag bitmasks.
- *Live Packet Sniffers (PyShark / Scapy):* High-fidelity network probes perform line-rate packet capture, extracting packet-level attributes including Time-To-Live (TTL), TCP window sizing, fragmentation flags, payload length distributions, and packet arrival timestamps.
- *Standardized Replay Feeds:* Support for benchmark research datasets including CSE-CIC-IDS2018 and CIC-IoT-2023, converted into asynchronous JSON event streams for reproducible training, evaluation, and system stress-testing.

=== Layer 2: Decoupled High-Throughput Streaming Broker (Apache Kafka)
To prevent network ingestion backpressure from blocking machine learning inference, telemetry ingestion is decoupled using an *Apache Kafka* message broker running in modern KRaft mode (Kafka Raft Metadata mode, eliminating Apache ZooKeeper dependencies):
- *Topic Architecture:* All normalized flow records are dispatched into the partitioned `network_flows` topic.
- *Partitioned Concurrency:* Configured with 3 partitions to support high-throughput parallel ingestion across multiple network interfaces.
- *Consumer Groups:* Backend inference workers belong to the `firewall_world_model_group`, allowing dynamic horizontal scaling of worker processes without data loss.
- *Observability:* Dedicated Kafka Web UI on port 8081 provides live monitoring of consumer lag, broker partition health, and message throughput.

=== Layer 3: Temporal State Window Aggregation
Single packets and isolated flow records lack the macro-level context required to understand multi-stage cyber campaigns. The `StateWindowAggregator` accumulates incoming flow events across uniform *15-second time windows* ($Delta t = 15"s"$):
- Evaluates flows within the window and extracts a dense, standardized *32-dimensional Network State Vector* $S_t in bb(R)^(32)$.
- Maintains an in-memory *Sliding History Buffer* containing the $W=8$ most recent state vectors:
  $ X_("hist") = [ S_(t-W+1), S_(t-W+2), dots, S_t ] in bb(R)^(8 times 32) $
- Represents a sliding 120-second historical trajectory of enterprise network behavior, preserving temporal momentum, acceleration, and early warning precursors.

=== Layer 4: Latent World Model Neural Engine
The core intelligence of Veritas resides in its attention-augmented recurrent neural network:
- *State Latent Encoder ($g_phi$):* Projects raw 32-D state vectors through Layer Normalization and non-linear LeakyReLU projections into a dense 64-dimensional latent embedding $z_t in bb(R)^(64)$.
- *Recurrent Dynamics Core ($f_theta$):* A 2-layer causal Long Short-Term Memory (LSTM) network updates its internal hidden state $h_t in bb(R)^(64)$ upon receiving each latent state $z_t$, encoding the causal progression of network physics over time.
- *Temporal Multi-Head Self-Attention:* Computes scaled dot-product attention across all historical time steps in the context window, computing dynamic weights that highlight the exact historical windows containing reconnaissance or scanning activity.
- *Transition Dynamics Head:* Simulates the next physical network state snapshot $hat(S)_(t+1) in bb(R)^(32)$ via a multi-layer perceptron.

=== Layer 5: $K$-Step Autoregressive Forward Simulation Engine
Rather than evaluating security risk based solely on the current state, the forward simulation engine projects the network trajectory into the future:
- Feeds the predicted state $hat(S)_(t+1)$ autoregressively back into the World Model to forecast $hat(S)_(t+2)$, repeating for $k = 1, 2, dots, K$ steps (default $K=5$, corresponding to $+75$ seconds into the future).
- Computes an *Infiltration Risk Timeline* $[P_1, P_2, dots, P_K]$ reflecting the probability of system compromise at each future step.
- Predicts the evolving *MITRE ATT&CK Tactical Stage* across the forecast horizon.

=== Layer 6: Explainable AI (XAI) & Driving Feature Attribution
To satisfy the stringent transparency requirements of mission-critical Security Operations Centers (SOC):
- Extracts temporal attention weights to show which historical window triggered the alert.
- Computes *Gradient $times$ Input Attribution* scores for each of the 32 state vector features to identify the primary mechanical drivers of the threat.
- Synthesizes clear, automated, plain-English incident summaries for SOC security analysts.

=== Layer 7: Automated Closed-Loop Policy Mitigation
The final layer executes autonomous defenses according to a deterministic policy matrix:
- `NORMAL (Risk < 40%)`: Pass traffic normally (`ALLOW`); update running normal baseline statistics.
- `SUSPICIOUS (40% <= Risk < 70%)`: Broadcast real-time WebSocket warning (`ALERT_ADMIN`); escalate to deep packet capture; throttle suspect host.
- `CRITICAL (Risk >= 70%)`: Pre-emptively isolate target device (`ISOLATE_DEVICE`) by injecting kernel-level firewall rules (`iptables -A INPUT -s <IP> -j DROP`) *before* the attacker completes lateral movement or data exfiltration.

#callout(title: "In Simple Words: How Packets Flow Through the Veritas Pipeline in Real Time", label: "DATA PIPELINE SUMMARY")[
  1. *Capture:* Raw network packets zip into the system from routers and servers without slowing down active traffic.
  2. *Buffer:* They are streamed into Apache Kafka—like a high-speed conveyor belt that never gets overwhelmed, even if millions of packets arrive in seconds.
  3. *Summarize:* Every 15 seconds, Veritas takes all the packets on the belt and compresses them into a 32-number "health card" of the network.
  4. *Remember:* It lines up the last 8 health cards (the last 2 minutes) to understand network velocity, momentum, and acceleration.
  5. *Simulate:* The World Model looks at those 8 cards and predicts the next 5 cards—imagining what the network will look like 15, 30, 45, 60, and 75 seconds from now.
  6. *Decide & Defend:* If the projected future shows a high probability of a breach in 60 seconds, Veritas doesn't wait. It isolates the suspicious machine immediately, stopping the attack dead in its tracks.
]

#takeaway(title: "Decoupled Scalability", label: "SCALABILITY PRINCIPLE")[
  By isolating line-rate packet ingestion into Kafka and performing state aggregation on 15-second boundaries, Veritas isolates computationally intensive neural inference from network I/O. The system achieves sub-millisecond ingestion latency while maintaining full multi-step temporal simulation.
]
