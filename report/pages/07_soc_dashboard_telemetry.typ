#import "common.typ": callout, takeaway, primary-color, secondary-color

= Real-Time SOC Dashboard & Observability Suite

== The Operational Security Operations Center (SOC) Console

To enable seamless human-AI teaming, Veritas provides a comprehensive, production-grade Next.js (React 19) Security Operations Center (SOC) dashboard. The interface is engineered for real-time situational awareness, multi-step threat anticipation, forensic investigation, and instant policy intervention.

=== 1. Primary Autonomous Threat Radar Dashboard
The central command console (Figure below) displays the real-time threat posture of the enterprise network:

#figure(
  image("../assets/dashboard.png", width: 92%),
  caption: [Veritas Primary SOC Security Console: Real-Time Threat Score Radar, MITRE Attack Stage Indicator, and Incident Stream.]
)

- *Live Threat Risk Meter:* An interactive radial gauge displaying the maximum forward-simulated infiltration probability across the $K=5$ projection horizon.
- *Active Attack Stage Badge:* Displays the anticipated MITRE ATT&CK tactical phase (e.g., *Reconnaissance*, *Infiltration*, *Impact*).
- *Automated Policy Trigger:* Reflects current system defense status (`ALLOW`, `ALERT_ADMIN`, or `ISOLATE_DEVICE`).
- *Live Alert Stream:* Real-time incident feed powered by WebSockets, allowing analysts to filter between *All Alerts*, *Suspicious*, or *Critical* events with zero page reloads.

=== 2. Real-Time Telemetry & Active Ingestion Monitor
The telemetry monitor provides line-rate visibility into the ingestion broker and state window aggregation pipeline:

#figure(
  image("../assets/telemetry_dashboard.png", width: 92%),
  caption: [Veritas Telemetry Console: Active Flow Ingestion Counters, Redis Persistence Status, and Arrival Velocity.]
)

- *Flow Velocity Counter:* Tracks cumulative and per-second flow ingestion volume.
- *Redis Persistence Monitor:* Verifies state synchronization and sliding history buffer integrity.
- *Network Bandwidth & Packet Velocity:* Real-time charts of forward and backward byte throughput.

=== 3. Statistical Analysis & Risk Distribution Suite
The statistical dashboard delivers macro-level insights into long-term network behavior and model inference consistency:

#figure(
  image("../assets/statistics.png", width: 92%),
  caption: [Veritas Statistical Evaluation Console: Window Processing Throughput, Risk Distribution, and Historical Drift.]
)

- *Window Processing Throughput:* Measures the execution rate of 15-second vectorized window aggregations.
- *Risk Distribution Breakdown:* Displays historical frequencies of Benign ($< 40%$), Suspicious ($40% - 70%$), and Critical ($>= 70%$) events.
- *Inference Latency Tracking:* Monitors forward simulation inference times (consistently $< 15"ms"$ on standard CPU hardware).

=== 4. Deep Forensic Incident Explorer
When an alert is flagged, analysts can drill down into the granular flow records that composed the suspicious state window:

#figure(
  image("../assets/foresnsics_explorer.png", width: 92%),
  caption: [Veritas Forensic Explorer: Granular Packet Flow Inspection, Temporal Timeline, and MITRE Technique Tagging.]
)

- *Chronological Flow Stream:* Exact 5-tuple records (Source IP/Port, Destination IP/Port, Protocol).
- *TCP Flag Breakdown:* Individual SYN, ACK, RST, FIN bitmasks for every flow in the incident window.
- *MITRE ATT&CK Technique Tagging:* Automated attribution linking specific packet sequences to known adversary procedures (e.g., T1046, T1110).

=== 5. Subsystem Health & Fault-Tolerance Matrix
Autonomous defense requires uncompromised infrastructure reliability. Veritas features a dedicated Subsystem Health matrix:

#figure(
  image("../assets/system_health.png", width: 92%),
  caption: [Veritas Subsystem Health Matrix: Real-Time Heartbeat, Ingestion Lag, and Component Status.]
)

- *Apache Kafka Message Broker:* Broker status, active partitions, and consumer group lag.
- *Redis State Cache:* Cache hit rates, memory utilization, and key persistence.
- *PyTorch Neural Engine:* Torch execution status, checkpoint verification, and forward simulation latency.
- *FastAPI Gateway Hub:* Active WebSocket client count and REST endpoint response latency.

=== 6. Prometheus & Grafana Unified Observability Dashboard
For infrastructure engineers, Veritas integrates natively with Prometheus and Grafana Loki:

#figure(
  image("../assets/grafana_dashboard.png", width: 92%),
  caption: [Unified Grafana Observability Dashboard: Prometheus System Metrics and Loki Structured Log Stream.]
)

- Single-pane-of-glass correlation of server CPU/memory, network traffic rates, and structured security event logs.

#callout(title: "In Simple Words: What the SOC Operator Sees and Does During an Attack", label: "OPERATOR ANALOGY")[
  Imagine being an air traffic controller. You don't have time to read thousands of lines of raw radar code; you need a screen that clearly shows the altitude, speed, and heading of every plane, highlighting any plane on a collision course in bright red.
  
  *The Veritas Dashboard is that air traffic control screen for cybersecurity.*
  - The *Threat Radar* tells you the danger level at a glance.
  - The *MITRE Badge* tells you what the attacker is trying to do (e.g., scouting doors vs stealing data).
  - The *Live Alert Stream* beeps the moment suspicious activity begins.
  - If a device goes rogue, the screen turns red and shows that Veritas has already isolated the infected machine, protecting the rest of the company before the operator even has to click a button!
]
