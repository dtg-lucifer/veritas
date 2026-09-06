#import "common.typ": callout, takeaway, primary-color, secondary-color

= $K$-Step Autoregressive Forward Simulation & Threat Forecasting

== The Forward Simulation Paradigm

Traditional intrusion detection systems operate strictly *in the present*: an alert is triggered only when malicious packets match a static signature or when a heuristic threshold is crossed. By that point, the adversary has already penetrated the perimeter, established persistence, or begun payload execution.

Veritas fundamentally alters this timeline through *$K$-Step Autoregressive Forward Simulation*. Leveraging the learned transition dynamics $P(S_(t+1) | S_(<= t))$, the World Model treats network defense as an anticipatory simulation problem:

#align(center)[
  #block(
    fill: rgb("#f8fafc"),
    stroke: 1pt + rgb("#cbd5e1"),
    inset: 12pt,
    radius: 6pt,
    [
      $ S_t $ (Current Observed State) $arrow.r$
      $ hat(S)_(t+1) $ ($+15"s"$) $arrow.r$
      $ hat(S)_(t+2) $ ($+30"s"$) $arrow.r$
      $ hat(S)_(t+3) $ ($+45"s"$) $arrow.r$
      $ hat(S)_(t+4) $ ($+60"s"$) $arrow.r$
      $ hat(S)_(t+5) $ ($+75"s"$)
    ]
  )
]

== Autoregressive Rollout Mechanics

Given an observed historical trajectory of $W=8$ standardized network states:

$ X_0 = [S_(t-W+1), S_(t-W+2), dots, S_(t-1), S_t] in bb(R)^(8 times 32) $

The simulation engine performs a recursive forward rollout for $k = 1, 2, dots, K$ steps (default $K=5$, projecting $5 times 15"s" = 75" seconds"$ into the future):

#figure(
  table(
    columns: (1fr, 3fr, 2fr),
    stroke: 0.5pt + rgb("#cbd5e1"),
    fill: (x, y) => if y == 0 { rgb("#f1f5f9") } else if calc.even(y) { rgb("#f8fafc") } else { white },
    inset: 7pt,
    table.header(
      [*Step ($k$)*],
      [*Input Context Sequence ($X_(k-1)$)*],
      [*Generated Outputs*]
    ),
    [Step 1 ($+15"s"$)],
    [$[S_(t-7), S_(t-6), dots, S_t]$ (Pure Historical Observation)],
    [$hat(S)_(t+1), quad P_1 = P("Infiltration"_(t+1)), quad hat(y)_("stage")^((1))$],

    [Step 2 ($+30"s"$)],
    [$[S_(t-6), dots, S_t, bold(hat(S)_(t+1))]$ (Observed + 1 Simulated)],
    [$hat(S)_(t+2), quad P_2 = P("Infiltration"_(t+2)), quad hat(y)_("stage")^((2))$],

    [Step 3 ($+45"s"$)],
    [$[S_(t-5), dots, S_t, bold(hat(S)_(t+1)), bold(hat(S)_(t+2))]$ (Observed + 2 Simulated)],
    [$hat(S)_(t+3), quad P_3 = P("Infiltration"_(t+3)), quad hat(y)_("stage")^((3))$],

    [Step 4 ($+60"s"$)],
    [$[S_(t-4), dots, S_t, bold(hat(S)_(t+1)), dots, bold(hat(S)_(t+3))]$ (Observed + 3 Simulated)],
    [$hat(S)_(t+4), quad P_4 = P("Infiltration"_(t+4)), quad hat(y)_("stage")^((4))$],

    [Step 5 ($+75"s"$)],
    [$[S_(t-3), dots, S_t, bold(hat(S)_(t+1)), dots, bold(hat(S)_(t+4))]$ (Observed + 4 Simulated)],
    [$hat(S)_(t+5), quad P_5 = P("Infiltration"_(t+5)), quad hat(y)_("stage")^((5))$]
  ),
  caption: [Recursive Autoregressive Forward Rollout Sequence across a 75-Second Prediction Horizon.]
)

At each rollout step $k$:
1. The model evaluates the contextual sequence $X_(k-1)$ to generate the next simulated state vector $hat(S)_(t+k) = p_psi(X_(k-1))$ and threat probability $P_k = sigma(W_("inf") h_("attn") + b_("inf"))$.
2. The oldest state $S_(t-W+k)$ is dropped from the context buffer.
3. The simulated state $hat(S)_(t+k)$ is appended to form the context for the subsequent step $X_k$.

== Infiltration Trajectory Analysis & Early Warning Horizon

The output of the forward simulation is a continuous *Threat Probability Vector*:

$ bold(P) = [P_1, P_2, P_3, P_4, P_5] in [0, 1]^5 $

The system evaluates the trajectory slope to determine if the network state is rapidly converging toward an intrusion:

$ "Trajectory Slope" (Delta P) = (P_K - P_1) / (K - 1) $

A positive slope ($Delta P > 0$) combined with a maximum probability exceeding operational alert thresholds ($max_k P_k >= tau_("alert")$) triggers anticipatory defense actions.

=== Lead-Time Mathematical Formulation
Let $tau_("critical") = 0.70$ represent the threshold for severe system compromise. The *Early Warning Lead Time* ($T_("lead")$) is defined as the time interval between the initial forecast detection at step $t$ and the predicted moment of compromise at step $t + k^*$:

$ k^* = min { k in {1, dots, K} mid(|) P_k >= tau_("critical") } $

$ T_("lead") = k^* times Delta t $

In empirical benchmark evaluations against CSE-CIC-IDS2018 multi-stage attack scenarios, Veritas achieves a mean lead time of $k^* = 4$ steps, granting security teams a *60-second window of proactive intervention* before the attacker establishes a permanent foothold.

== MITRE ATT&CK Tactical Progression Mapping

Infiltration is mapped directly to canonical MITRE ATT&CK tactical phases (`ml/src/mitre_mapping.py`), transforming raw mathematical probability into actionable operational intelligence:

#figure(
  table(
    columns: (0.8fr, 1.8fr, 2.5fr, 2.5fr),
    stroke: 0.5pt + rgb("#cbd5e1"),
    fill: (x, y) => if y == 0 { rgb("#f1f5f9") } else if calc.even(y) { rgb("#f8fafc") } else { white },
    inset: 7pt,
    table.header(
      [*Stage ID*],
      [*Tactical Phase*],
      [*Associated MITRE Techniques*],
      [*Observable Physical Network Precursors*]
    ),
    [*0*], [*Benign Baseline*], [Nominal Operations], [Balanced SYN/ACK ratios, standard HTTP/DNS port distributions, low variance in packet length.],
    [*1*], [*Reconnaissance*], [T1046 (Network Service Scan)\ T1595 (Active Scanning)], [High `unique_dst_ports` ($>= 15$), elevated `syn_ratio`, low mean packet length, rapid inter-arrival rate.],
    [*2*], [*Initial Access*], [T1110 (Brute Force)\ T1190 (Exploit Public App)], [Surge in `flow_count` on administrative ports (SSH 22, FTP 21, RDP 3389), repeated RST teardowns.],
    [*3*], [*Infiltration / Lateral*], [T1210 (Exploit Remote Service)\ T1021 (Remote Services)], [High `ephemeral_port_ratio` ($>= 0.70$), internal IP-to-IP payload pushes, SMB/RPC protocol spikes.],
    [*4*], [*Command & Control*], [T1071 (App Protocol)\ T1573 (Encrypted Channel)], [Periodic beaconing with low `flow_iat_std`, persistent session durations, fixed heartbeat payload sizes.],
    [*5*], [*Exfiltration / Impact*], [T1048 (Exfiltration Over Protocol)\ T1499 (Endpoint DoS)], [Severe downlink-to-uplink ratio inversion (`down_up_ratio`), massive packet rate surges ($>= 8000$ pkts/sec).]
  ),
  caption: [Veritas MITRE ATT&CK Tactical Progression and Traffic Mapping Matrix.]
)

#callout(title: "In Simple Words: Playing Network \"Chess\" 5 Moves Ahead", label: "TACTICAL FORESIGHT")[
  In a game of chess, a grandmaster doesn't wait for their opponent to capture their Queen. They look at the board and realize: *"If they move their knight here, in three moves my Queen will be trapped."* They make a defensive move right now to neutralize the threat before it develops.
  
  *Veritas does the exact same thing for computer networks.* Instead of waiting for an attacker to start stealing sensitive files, it looks at the early moves—a quick port scan, a series of failed logins, an unusual internal connection. It simulates the next 5 "moves" (75 seconds of network traffic). If the simulation reveals that move 4 is going to be a devastating ransomware lockout or data breach, Veritas makes its defensive move at move 1!
]

#takeaway(title: "The Lead-Time Advantage", label: "EARLY WARNING ADVANTAGE")[
  A 60-second early warning is the difference between a minor incident and a catastrophic corporate breach. It allows firewalls to isolate suspect IP addresses, terminate active authentication sessions, and quarantine internal subnets *while the attacker is still in the reconnaissance phase*.
]
