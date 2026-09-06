#import "common.typ": callout, takeaway, primary-color, secondary-color

= Mathematical Formulation, Feature Engineering & Neural Architecture

== Telemetry Ingestion & Feature Selection Rationale

Traditional intrusion detection mechanisms inspect individual packets or isolated 5-tuple flow records, attempting to classify them into benign or malicious categories without understanding the physics of the network environment. In Veritas, telemetry ingestion is structured as the continuous physical observation of a complex dynamical system.

=== Raw Telemetry Fields Extracted from Network Logs
Network telemetry enters the pipeline from diverse sources: NetFlow v9 / IPFIX flow collectors, live kernel-level packet sniffers (PyShark / Scapy), or historical PCAP archives. For every active connection, the extraction engine extracts:
1. *Connection 5-Tuple:* Source IP, Destination IP, Source Port (`src_port`), Destination Port (`dst_port`), and Transport Protocol (`protocol`: 6 for TCP, 17 for UDP).
2. *Temporal Timestamps:* High-resolution packet arrival and flow start/end timestamps (`timestamp`).
3. *Volumetric Metrics:* Forward packet counts (`tot_fwd_pkts`), backward packet counts (`tot_bwd_pkts`), forward byte volume (`tot_fwd_bytes`), backward byte volume (`tot_bwd_bytes`), byte transfer rates (`flow_bytes_per_sec`), and packet transfer rates (`flow_pkts_per_sec`).
4. *TCP Control Flags:* Counts of individual TCP flags across the flow: `syn_flag_cnt`, `ack_flag_cnt`, `rst_flag_cnt`, `fin_flag_cnt`, `psh_flag_cnt`, `urg_flag_cnt`.
5. *Timing & Session Characteristics:* Flow duration (`flow_duration`), inter-arrival time (IAT) statistics (`flow_iat_mean`, `flow_iat_std`, `flow_iat_max`), packet length statistics (`pkt_len_mean`, `pkt_len_std`), bidirectional volume ratio (`down_up_ratio`), initial TCP window size (`init_fwd_win_bytes`), and active/idle interval durations (`active_mean`, `idle_mean`).

=== Why These Exact 32 Features Were Selected
Every feature in the 32-dimensional state vector was deliberately chosen to map to a specific physical anomaly or MITRE ATT&CK technique:

- *Volumetric Dynamics (Features 1–8):* `flow_count`, `tot_fwd_pkts`, `tot_bwd_pkts`, `tot_fwd_bytes`, `tot_bwd_bytes`, `flow_bytes_rate`, `flow_pkts_rate`, `flow_duration_mean`.
  *Threat Physics Rationale:* Denial-of-Service (DoS) and volumetric floods abruptly saturate packet and byte rates by 100$times$ normal baselines. Conversely, data exfiltration campaigns manifest as extreme asymmetries in forward-to-backward byte ratios. Short flow durations characterize automated port sweeps, while unusually lingering durations signal established Command & Control (C2) interactive shells.

- *TCP Flag Distributions & Handshake Integrity (Features 9–16):* `syn_flag_count`, `syn_ratio`, `ack_flag_count`, `ack_ratio`, `rst_flag_count`, `fin_flag_count`, `psh_flag_count`, `urg_flag_count`.
  *Threat Physics Rationale:* Legitimate TCP communication strictly adheres to the three-way handshake ($"SYN" arrow.r "SYN-ACK" arrow.r "ACK"$). In contrast, reconnaissance port scanners (e.g., Nmap SYN stealth scans) transmit raw SYN packets without ever completing the handshake, resulting in extreme `syn_ratio` spikes. When scanning closed ports, target operating systems reply with TCP RST packets, creating identifiable `rst_flag_count` storms. Push (`psh`) and Urgent (`urg`) flags highlight immediate buffer delivery characteristic of exploit payload delivery.

- *Port & Protocol Diversity (Features 17–23):* `unique_dst_ports`, `ephemeral_port_ratio`, `web_port_ratio`, `dns_port_ratio`, `ssh_ftp_port_ratio`, `tcp_protocol_ratio`, `udp_protocol_ratio`.
  *Threat Physics Rationale:* Horizontal port scanning probes dozens or hundreds of distinct ports on a target host within seconds; tracking `unique_dst_ports` provides the primary mathematical signal of active reconnaissance. The `ephemeral_port_ratio` ($"ports" >= 1024$) detects lateral movement via Windows RPC, SMB, or dynamic high ports. Concentration on administrative ports (SSH 22, FTP 21) exposes brute-force authentication attacks, while protocol ratios isolate UDP amplification floods from stateful TCP attacks.

- *Timing Dynamics & Payload Signatures (Features 24–29):* `pkt_len_mean`, `pkt_len_std`, `flow_iat_mean`, `flow_iat_std`, `flow_iat_max`, `down_up_ratio_mean`.
  *Threat Physics Rationale:* Stealthy "low-and-slow" intrusions deliberately space scanning probes across minutes to evade static rate thresholds. By tracking Inter-Arrival Time (IAT) mean and standard deviation, Veritas detects automated machine-generated timing consistency. Packet length standard deviation exposes uniform automated probing packets versus high-entropy payload transfers.

- *Session Duty Cycles & Stack Fingerprinting (Features 30–32):* `init_fwd_win_mean`, `active_duration_mean`, `idle_duration_mean`.
  *Threat Physics Rationale:* The initial TCP receiver window size reveals operating system kernel defaults, exposing automated scanning scripts. Active and idle session durations capture periodic beaconing intervals characteristic of malware check-ins to Command & Control infrastructure.

== Transforming Raw Flow Telemetry into a 32-D State Vector ($S_t$)

The transformation of raw asynchronous flow logs into structured mathematical state vectors occurs inside the `StateWindowAggregator` (`ml/src/features/state_window.py`) via high-speed vectorized operations:

=== 1. Temporal Interval Flooring
Raw flow records possess arbitrary floating-point timestamps. To construct discrete, non-overlapping macro-observations, incoming timestamps are floored to 15-second boundaries ($Delta t = 15"s"$):

$ T_("window") = floor( t / (15" seconds") ) times 15" seconds" $

All flow records whose timestamps fall within $[T_("window"), T_("window") + 15"s")$ are grouped together.

=== 2. Numerical Imputation and Categorical Masking
Missing numerical values are imputed with $0.0$, and invalid infinities resulting from division-by-zero rates are replaced:

$ x arrow.l cases(0.0 & "if" x "is NaN or" plus.minus infinity, x & "otherwise") $

Vectorized boolean bitmasks are applied across the flow table:
- $"is_ephemeral" = bb(I)( "dst_port" >= 1024 and "dst_port" in.not {3478, 8080, 8443} )$
- $"is_web" = bb(I)( "dst_port" in {80, 443, 8080} )$
- $"is_dns" = bb(I)( "dst_port" == 53 )$
- $"is_ssh_ftp" = bb(I)( "dst_port" in {21, 22} )$
- $"is_tcp" = bb(I)( "protocol" == 6 ), quad "is_udp" = bb(I)( "protocol" == 17 )$

=== 3. Vectorized Aggregations
For each 15-second temporal bucket, fast GroupBy aggregation rules compile the traffic summary:
- *Sums:* Forward/backward packets, forward/backward bytes, and individual TCP flags ($"SYN", "ACK", "RST", "FIN", "PSH", "URG"$).
- *Means:* Byte rates, packet rates, flow duration, packet length statistics, IAT statistics, down/up volume ratios, and protocol ratios.
- *Cardinality (nunique):* Count of unique destination ports targeted in the 15-second interval:
  $ "unique_dst_ports" = abs({ "dst_port"_i mid(|) i in "Window" }) $
- *Handshake Normalization:*
  $ "syn_ratio" = (sum "SYN") / (max(sum "tot_fwd_pkts" + sum "tot_bwd_pkts", 1.0)), quad "ack_ratio" = (sum "ACK") / (max(sum "tot_fwd_pkts" + sum "tot_bwd_pkts", 1.0)) $

The resulting 32 values are packed into the standardized observation vector $S_t in bb(R)^(32)$:

$ S_t = [s_(t, 1), s_(t, 2), dots, s_(t, 32)]^top in bb(R)^(32) $

#figure(
  table(
    columns: (0.6fr, 1.8fr, 3.2fr, 2.4fr),
    stroke: 0.5pt + rgb("#cbd5e1"),
    fill: (x, y) => if y == 0 { rgb("#f1f5f9") } else if calc.even(y) { rgb("#f8fafc") } else { white },
    inset: 6pt,
    table.header(
      [*Index*],
      [*Feature Name*],
      [*Mathematical / Physical Formula*],
      [*Threat Defense Function*]
    ),
    [1], [`flow_count`], [$N_t = sum_(i in "Window") 1$], [Volumetric connection surge],
    [2–3], [`tot_fwd_pkts`, `tot_bwd_pkts`], [$P_("fwd") = sum p_("fwd", i), quad P_("bwd") = sum p_("bwd", i)$], [Asymmetry / volumetric floods],
    [4–5], [`tot_fwd_bytes`, `tot_bwd_bytes`], [$B_("fwd") = sum b_("fwd", i), quad B_("bwd") = sum b_("bwd", i)$], [Bulk exfiltration / large payloads],
    [6–7], [`flow_bytes_rate`, `flow_pkts_rate`], [$1/N sum ("bytes"_i / d_i), quad 1/N sum ("pkts"_i / d_i)$], [Line-rate bandwidth saturation],
    [8], [`flow_duration_mean`], [$1/N sum d_i$ (seconds)], [Short probe vs lingering session],
    [9–10], [`syn_flag_count`, `syn_ratio`], [$sum "SYN"_i, quad (sum "SYN"_i) / (max(P_("tot"), 1))$], [SYN floods & half-open port scans],
    [11–12], [`ack_flag_count`, `ack_ratio`], [$sum "ACK"_i, quad (sum "ACK"_i) / (max(P_("tot"), 1))$], [Established session verification],
    [13–14], [`rst_flag_count`, `fin_flag_count`], [$sum "RST"_i, quad sum "FIN"_i$], [Closed port rejection storms],
    [15–16], [`psh_flag_count`, `urg_flag_count`], [$sum "PSH"_i, quad sum "URG"_i$], [Immediate buffer exploit pushes],
    [17], [`unique_dst_ports`], [$abs( union.big_i { "dst_port"_i } )$], [Reconnaissance sweep detection],
    [18], [`ephemeral_port_ratio`], [$1/N sum bb(I)("dst_port"_i >= 1024)$], [Lateral RPC & SMB movement],
    [19–21], [`web_`, `dns_`, `ssh_ftp_port_ratio`], [$1/N sum bb(I)("dst_port"_i in cal(P)_"target")$], [Targeted protocol exploitation],
    [22–23], [`tcp_ratio`, `udp_protocol_ratio`], [$1/N sum bb(I)("protocol"_i == 6 "or" 17)$], [Stateful TCP vs UDP floods],
    [24–25], [`pkt_len_mean`, `pkt_len_std`], [Empirical mean and standard deviation of packet length], [Buffer injection / payload anomaly],
    [26–28], [`flow_iat_mean`, `_std`, `_max`], [Empirical mean, std, and max of inter-arrival timing], [Low-and-slow automated scans],
    [29], [`down_up_ratio_mean`], [$1/N sum (B_("bwd", i) / max(B_("fwd", i), 1))$], [Exfiltration ratio inversion],
    [30], [`init_fwd_win_mean`], [$1/N sum "win_bytes"_i$], [Operating system fingerprinting],
    [31–32], [`active_mean`, `idle_duration_mean`], [$1/N sum t_("active", i), quad 1/N sum t_("idle", i)$], [C2 periodic beaconing intervals]
  ),
  caption: [Complete Specification of the 32-Dimensional Veritas Network State Vector ($S_t$).]
)

== Aggregating 8 Windows (120-Second History) into PyTorch Tensors

A single 15-second state snapshot $S_t$ reveals current traffic composition but cannot expose acceleration, trajectory momentum, or multi-step adversary progression. An intrusion is a continuous temporal movie, not a static photograph.

=== Sliding Context Ring Buffer
Veritas maintains a stateful sliding First-In, First-Out (FIFO) ring buffer containing the $W=8$ most recent consecutive state vectors:

$ X_("hist") = [ S_(t-7), S_(t-6), S_(t-5), S_(t-4), S_(t-3), S_(t-2), S_(t-1), S_t ] in bb(R)^(8 times 32) $

Because each window covers $Delta t = 15" seconds"$, the history sequence spans exactly:

$ T_("context") = W times Delta t = 8 times 15" seconds" = 120" seconds (2 minutes)" $

=== Robust Scaling & Normalization
To prevent high-magnitude features (such as byte counts reaching $10^7$) from drowning out subtle features (such as fractional SYN ratios), each vector in $X_("hist")$ is transformed using a fitted `RobustScaler`:

$ tilde(S)_tau = (S_tau - "Median") / "Interquartile Range (IQR)" in bb(R)^(32), quad forall tau in [t-7, t] $

The `RobustScaler` uses the median and the 25th–75th percentile range, making the normalization impervious to extreme outliers generated during massive volumetric attacks.

=== Construction of the 3D PyTorch Tensor
The normalized sequence of 8 states is packaged into a contiguous 3-dimensional PyTorch floating-point tensor:

$ bold(X)_("seq") in bb(R)^(B times T times D) = bb(R)^(B times 8 times 32) $

where:
- $B$ is the batch size ($B=1$ during real-time streaming inference, and $B in [32, 128]$ during batch training).
- $T = 8$ is the temporal sequence length (8 consecutive 15-second windows).
- $D = 32$ is the physical state vector feature dimension.

== Passing the Tensor Through the World Model Architecture

Once the input tensor $bold(X)_("seq") in bb(R)^(B times 8 times 32)$ is constructed, it traverses four sequential neural stages:

=== Stage 1: Latent State Compression ($g_phi$)
The raw 32-D physical observations are projected into a 64-dimensional latent manifold to decouple raw scaling and capture non-linear feature interactions. The tensor is reshaped to $(B times 8, 32)$ and processed through a two-layer feedforward network with Layer Normalization and LeakyReLU ($alpha = 0.1$):

$ z_tau^((1)) = "LeakyReLU"( "LN"( W_1 tilde(S)_tau + b_1 ) ) in bb(R)^(64), quad W_1 in bb(R)^(64 times 32) $

$ z_tau = "LeakyReLU"( "LN"( W_2 z_tau^((1)) + b_2 ) ) in bb(R)^(64), quad W_2 in bb(R)^(64 times 64) $

The output is reshaped back to form the latent sequence tensor $bold(Z) in bb(R)^(B times 8 times 64)$.

=== Stage 2: Recurrent Causal Dynamics Core (2-Layer LSTM)
The sequence of latent vectors $bold(Z) = [z_(t-7), dots, z_t]$ is fed into a 2-layer causal Long Short-Term Memory (LSTM) network ($f_theta$):

$ bold(H), (h_t, c_t) = "LSTM"(bold(Z)) $

where $bold(H) = [h_(t-7), dots, h_t] in bb(R)^(B times 8 times 64)$ represents the hidden state sequence across all 8 time windows.

*Why LSTM is Essential:*
Feedforward classifiers have zero memory—they evaluate time $t$ in complete isolation. The LSTM maintains two internal vector states:
1. *The Cell State ($c_t in bb(R)^(64)$):* Serves as an internal continuous "memory conveyor belt" that carries multi-minute context across long time horizons. The *forget gate* ($f_t$) selectively clears benign, transient spikes, while the *input gate* ($i_t$) commits attack precursors (such as an ephemeral port scan that began 75 seconds ago) into long-term memory.
2. *The Hidden State ($h_t in bb(R)^(64)$):* Captures the *velocity, momentum, and rate of change* of network behavior. An intrusion is characterized not just by high numbers, but by *acceleration*—a rapid shift from reconnaissance into credential brute-force. The LSTM explicitly models this state transition momentum.

=== Stage 3: Temporal Multi-Head Self-Attention Pooling
While the LSTM models causal recurrence, the final hidden state $h_t$ can suffer from recency bias. To allow the model to attend directly to critical precursor events occurring earlier in the 2-minute history, Veritas applies Multi-Head Temporal Self-Attention ($M=4$ heads, head dimension $d_k = 16$):

$ Q_m = bold(H) W_Q^((m)), quad K_m = bold(H) W_K^((m)), quad V_m = bold(H) W_V^((m)) in bb(R)^(B times 8 times 16) $

$ A_m = "Softmax"( (Q_m K_m^top) / sqrt(16) ) in bb(R)^(B times 8 times 8) $

To generate an attended summary representation for the current time step, the query is anchored at the most recent historical step ($T-1$):

$ alpha = 1/4 sum_(m=1)^4 A_(m, :, T-1, :) in bb(R)^(B times 8) $

$ h_("attn") = "LN"( h_t^((2)) + "Dropout"("MultiHead"(bold(H))_(T-1)) ) in bb(R)^(B times 64) $

The attention weights $alpha in bb(R)^(B times 8)$ provide transparent mathematical weights showing exactly how much influence each of the 8 historical time windows had on the forward forecast.

=== Stage 4: Multi-Task Prediction Heads
The unified latent representation $h_("attn") in bb(R)^(B times 64)$ is passed in parallel to three dedicated task heads:

1. *Transition Dynamics Head:* Predicts the next physical network state snapshot $hat(S)_(t+1) in bb(R)^(B times 32)$:
   $ hat(S)_(t+1) = W_("dyn", 2) dot "LeakyReLU"( "LN"( W_("dyn", 1) h_("attn") + b_("dyn", 1) ) ) + b_("dyn", 2) $
2. *Infiltration Probability Head:* Predicts the scalar probability of intrusion $P_("inf") in [0, 1]$:
   $ P_("inf") = sigma( W_("inf", 2) dot "LeakyReLU"( W_("inf", 1) h_("attn") + b_("inf", 1) ) + b_("inf", 2) ) $
3. *MITRE ATT&CK Stage Head:* Classifies the tactical attack stage across 6 classes ($c in {0..5}$):
   $ hat(y)_("stage") = "Softmax"( W_("stage", 2) dot "LeakyReLU"( W_("stage", 1) h_("attn") + b_("stage", 1) ) + b_("stage", 2) ) in Delta^5 $

#callout(title: "In Simple Words: How Raw Network Packets Become an AI Threat Forecast", label: "STEP-BY-STEP SUMMARY")[
  1. *From Packets to Table:* Every single packet flowing through the router is collected. Every 15 seconds, Veritas counts how many packets arrived, how many were SYN scans, how many bytes were sent, and how many different ports were touched.
  2. *From Table to Vector:* These 32 summary numbers are packed into a single list called the *Network State Vector* ($S_t$).
  3. *From Vectors to a 2-Minute Movie:* Veritas keeps the last 8 vectors in memory ($8 times 15" seconds" = 120" seconds"$). This forms a 2-minute "movie" of network activity, packaged as a 3D tensor of shape $(1, 8, 32)$.
  4. *The Encoder Compresses:* The State Encoder strips away noise and translates the 32 raw numbers into 64 deep mathematical features.
  5. *The LSTM Understands Momentum:* The LSTM watches the 2-minute movie from beginning to end. It notes whether traffic is speeding up, slowing down, or shifting from quiet scouting into an aggressive attack.
  6. *The Attention Spotlight:* The Attention mechanism shines a spotlight on the exact moment in the last 2 minutes when the trouble started.
  7. *The Output Heads Decide:* One head predicts what the network will look like 15 seconds from now; the second head calculates the exact breach probability; the third head identifies the MITRE attack stage.
]

#takeaway(title: "Architectural Symmetry", label: "SYSTEM PRINCIPLE")[
  By coupling temporal aggregation ($W=8$), latent projection ($bb(R)^(32) arrow.r bb(R)^(64)$), and multi-task learning ($hat(S)_(t+1), P_("inf"), hat(y)_("stage")$), Veritas guarantees that the neural representation respects physical network causality rather than fitting isolated statistical noise.
]
