#import "common.typ": callout, takeaway, primary-color, secondary-color

= Executive Summary & Mission Overview

== The Cyber Defense Crisis: The Failure of Point-in-Time Detection

Modern enterprise networks and Critical Information Infrastructure (CII) face an unprecedented wave of sophisticated, multi-stage cyber threats. Advanced Persistent Threats (APTs), zero-day exploits, stealthy port scans, and automated ransomware do not strike in a single instantaneous burst. Instead, an intrusion is an evolving, causal progression that unfolds deliberately over time:

1. *Reconnaissance & Probing:* An adversary spaces low-frequency port scans across minutes or hours to slip under volumetric alert thresholds.
2. *Initial Access & Credential Harvesting:* Repeated authentication attempts or targeted application exploits probe edge defenses.
3. *Internal Infiltration & Lateral Movement:* Attackers pivot across internal subnets using remote service exploits (e.g., SMB, RDP).
4. *Command & Control (C2) Establishment:* Covert beaconing channels establish persistent communication with external servers.
5. *Exfiltration or Disruptive Impact:* Sensitive data is siphoned off, or systems are paralyzed by denial-of-service and encryption payloads.

Despite billions of dollars invested in cybersecurity, traditional perimeter security appliances—including Next-Generation Firewalls (NGFW) and Network Intrusion Detection Systems (NIDS)—suffer from a foundational architectural flaw: *static, point-in-time classification*.

#figure(
  table(
    columns: (1.2fr, 2fr, 2fr),
    stroke: 0.5pt + rgb("#cbd5e1"),
    fill: (x, y) => if y == 0 { rgb("#f1f5f9") } else if calc.even(y) { rgb("#f8fafc") } else { white },
    inset: 8pt,
    table.header(
      [*Dimension*],
      [*Traditional Point-in-Time NIDS / NGFW*],
      [*Veritas Predictive AI World Model*]
    ),
    [Observation Scope],
    [Inspects individual packets or isolated flows with zero temporal context.],
    [Processes continuous sliding sequences of network state snapshots ($W=8$, 120 seconds of context).],
    
    [Decision Paradigm],
    [Static classification: $P(y = "malicious" | x_t)$ at the current instant.],
    [Transition dynamics simulation: $P(S_{t+1} | S_{<= t})$, forecasting future network physics.],
    
    [Response Timing],
    [Purely reactive: generates alerts *after* the payload is delivered and compromise has occurred.],
    [Proactive & anticipatory: simulates $K$ steps ahead, predicting compromise 60–75s in advance.],
    
    [Kill-Chain Awareness],
    [Blind to multi-stage tactical progression; generates isolated alarms for each signature hit.],
    [Explicitly tracks and forecasts MITRE ATT&CK progression from Reconnaissance to Exfiltration.],
    
    [Explainability],
    [Opaque black-box risk scores or rigid static signature regex matches.],
    [Temporal attention heatmaps + mathematical Gradient $times$ Input feature attributions.],
    
    [Deployment Mode],
    [Often dependent on external cloud threat feeds and proprietary vendor signatures.],
    [Fully autonomous, edge-capable, open-source architecture with zero external API dependencies.]
  ),
  caption: [Systemic Comparison: Conventional Point-in-Time Firewalls vs. The Veritas AI World Model.]
)

== The World Model Paradigm Shift

In cognitive science and model-based reinforcement learning (Ha & Schmidhuber, Hafner et al.), an intelligent agent maintains an internal mental simulation—a *World Model*—of its operating environment. By learning the physical laws and state transition mechanics of the world, the agent can "imagine" the future outcomes of actions without having to suffer catastrophic real-world failures.

Veritas transposes this revolutionary concept into autonomous cybersecurity. The computer network itself is modeled as a complex dynamical system. Instead of asking:

#align(center)[
  #block(
    fill: rgb("#fef2f2"),
    stroke: 1pt + rgb("#f87171"),
    inset: 10pt,
    radius: 4pt,
    text(fill: rgb("#991b1b"), weight: "bold")[
      "Is this specific flow malicious or benign at this exact microsecond?"
    ]
  )
]

Veritas continuously formulates and answers the predictive question:

#align(center)[
  #block(
    fill: rgb("#f0fdf4"),
    stroke: 1pt + rgb("#4ade80"),
    inset: 10pt,
    radius: 4pt,
    text(fill: rgb("#166534"), weight: "bold")[
      "Given the sequence of network physical states observed over the recent history, what is the probability distribution over future network states $P(S_{t+1} | S_{<= t})$, and does this projected trajectory forward-simulate into an infiltration state before the adversary concludes the attack?"
    ]
  )
]

This shifts network defense from passive forensic post-mortem analysis to *pre-emptive, forward-simulated containment*.

#callout(title: "In Simple Words: Why Traditional Firewalls Fail and What Veritas Does Differently", label: "OPERATIONAL PARADIGM")[
  Imagine a security guard standing at the gate of a high-security facility. A traditional firewall acts like a guard who only looks at one visitor's badge for a fraction of a second. If an attacker walks by carrying a normal-looking briefcase, the guard lets them in. Even if that same visitor walks past 50 different doors trying door handles over 10 minutes, the guard forgets what happened 2 minutes ago because each glance is completely isolated.
  
  *Veritas acts like an intelligent surveillance system with memory and foresight.* It does not just look at one person at one instant; it watches the pattern of movement across the entire building over time. It notices that 60 seconds ago someone checked door #1, 30 seconds ago they probed door #2, and right now they are walking toward the server vault. Before the attacker even touches the vault door, Veritas has already simulated where they are going, sounds the alarm, and locks down the corridor pre-emptively.
]

#v(10pt)

== Key Innovation Highlights

Veritas introduces five foundational breakthroughs in predictive network intelligence:

1. *High-Dimensional Temporal State Windowing:* Raw line-rate packets and flows are continuously compressed into uniform 15-second multi-variate snapshots ($S_t in bb(R)^(32)$). These snapshots capture volumetric velocity, TCP handshake integrity, port entropy, inter-arrival timing (IAT), and session duty cycles.
2. *Attention-Augmented Recurrent Dynamics Core:* A deep causal 2-layer Long Short-Term Memory (LSTM) network coupled with Multi-Head Self-Attention projects network states into a 64-dimensional latent space, capturing non-linear temporal momentum and multi-step attack precursors.
3. *$K$-Step Autoregressive Forward Rollout:* Veritas recursively loops predicted network states back into its own dynamics engine to forecast future network states up to 75 seconds ahead ($K=5$ steps), producing an *Infiltration Probability Timeline* $[P_1, P_2, dots, P_K]$.
4. *Dual-Tier Transparent Explainability (XAI):* Veritas eliminates black-box opacity by combining temporal attention weights (which historical time window contained the attack trigger) with Gradient $times$ Input feature attributions (which exact network parameters drove the prediction).
5. *Autonomous Closed-Loop Mitigation Matrix:* Proactive enforcement policies map predicted risk trajectories directly to system actions: nominal traffic is forwarded normally (`ALLOW`), suspicious probes trigger deep packet inspection (`ALERT_ADMIN`), and projected high-risk trajectories trigger pre-emptive device isolation (`ISOLATE_DEVICE`) before lateral damage occurs.

#takeaway(title: "Key Takeaway: Defense Before Compromise", label: "CORE RESULT")[
  By replacing static classification with state-transition dynamics, Veritas achieves an empirical *+16.26% relative F1-score improvement*, a *31.73% relative reduction in False Positive Rates*, and provides SOC operators with a *4-step (60-second) early warning horizon* before compromise completes.
]
