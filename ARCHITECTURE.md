Your meeting notes describe a coherent MVP, but I would not start by building a deep-learning model. The model is only one component of the system.

The core idea in your notes is:

Put a monitoring/control point at the internal-network chokepoint, observe each employee's network activity, learn their normal behavioral pattern, detect deviations, and optionally enforce access control when the deviation becomes severe.

And your intended implementation is a VPN/DNS resolver sitting at that chokepoint and continuously monitoring behavioral changes.

For an SIH MVP, I would structure it like this.

1. What you are actually building

Think of the system as three layers:

                    INTERNAL NETWORK
                           │
              ┌────────────▼────────────┐
              │     Network Gateway     │
              │                         │
              │ VPN / DNS / Firewall    │
              │ Traffic Collector       │
              └────────────┬────────────┘
                           │
                     Network Events
                           │
              ┌────────────▼────────────┐
              │ Feature Extraction      │
              │                         │
              │ Per-user behavioral     │
              │ feature generation      │
              └────────────┬────────────┘
                           │
                    Feature Vectors
                           │
              ┌────────────▼────────────┐
              │ Behavioral Engine       │
              │                         │
              │ User baseline           │
              │ + anomaly detection     │
              └────────────┬────────────┘
                           │
                  Anomaly Score 0..1
                           │
              ┌────────────▼────────────┐
              │ Policy / Response       │
              │                         │
              │ NORMAL                  │
              │ SUSPICIOUS              │
              │ CRITICAL                │
              └────────────┬────────────┘
                           │
             ┌─────────────┴──────────────┐
             │                            │
         Dashboard                    Firewall
             │                            │
       Investigation               Block user/device

This is much stronger as an SIH project than:

"We trained an LSTM and it detects anomalies."

Your actual innovation/demo becomes:

An adaptive internal-network security gateway that establishes behavioral baselines for users and detects deviations from those baselines in real time.

2. Don't model "employees" directly

This is an important architectural distinction.

Don't make the model input:

employee_id = 123

and have it learn:

employee 123 normally does X
employee 456 normally does Y

Instead, construct a behavioral profile for every identity.

For example:

User: employee_123


Typical working hours:
    09:15 - 18:30


DNS behavior:
    ~420 requests/day
    mostly internal domains
    8 external domains frequently accessed


Network behavior:
    ~2.1 GB/day
    mostly HTTPS
    internal servers:
        git
        jira
        fileserver


Typical destinations:
    github.com
    company-jira.local
    api.company.local


Typical request rate:
    2-5 requests/sec


Typical active period:
    8h 42m


Typical access level:
    developer

Then today's behavior becomes:

Current window:


DNS requests:        1830
External domains:    127
Data transferred:    8.4 GB
Request rate:        32/sec
New destinations:    74
Activity:            02:17 AM

The system doesn't need to understand that:

"Piush is doing something suspicious."

It detects:

This behavioral vector is very different from this identity's historical distribution.

That's much easier to defend technically.

3. What should the model actually see?

This is probably the most important part of your project.

Do not feed raw logs directly into an LSTM.

Suppose your raw event is:

{
  "timestamp": "...",
  "user": "u123",
  "src_ip": "10.0.4.21",
  "dst_ip": "172.16.2.14",
  "protocol": "HTTPS",
  "dst_port": 443,
  "bytes_sent": 38291,
  "bytes_received": 102392,
  "dns_query": "github.com"
}

Turn thousands of events into a time-windowed feature vector.

For example, every 5 minutes:

User u123
Window: 14:00 - 14:05


dns_requests             = 43
unique_domains            = 12
new_domains               = 3
internal_requests         = 29
external_requests         = 14


bytes_sent                = 1.2 MB
bytes_received            = 18.4 MB


unique_destinations       = 7
new_destinations          = 2


ssh_connections           = 1
http_connections          = 0
https_connections         = 39


failed_connections        = 3


request_rate              = 8.6/sec


hour_of_day               = 14
day_of_week               = Tuesday


after_hours               = false

Now your ML input is:

X =
[
  43,
  12,
   3,
  29,
  14,
  1.2,
 18.4,
   7,
   2,
   1,
   0,
  39,
   3,
  8.6,
  14,
   2,
   0
]

That is something an anomaly-detection model can actually learn from.

4. The first model should probably NOT be LSTM/GRU

For your MVP, I recommend building this progression:

Phase 1
   ↓
Statistical baseline
   ↓
Phase 2
   ↓
Isolation Forest
   ↓
Phase 3
   ↓
Autoencoder
   ↓
Phase 4
   ↓
LSTM/GRU/Transformer

This gives you a very good engineering/research story.

5. Start with a statistical behavioral baseline

For each user:

mean
standard deviation
median
percentiles
historical distribution

For example:

Normal DNS requests / 5 min:


mean = 42
std  = 11


Current = 94

Compute:

z=
σ
x−μ
	​


So:

z=
11
94−42
	​

z≈4.73

That's already suspicious.

Do this for multiple features.

                    anomaly
DNS requests       ██████████
new domains        ███████
bytes sent         █████████
SSH connections    ██████████
request rate       ████████

Combine them into an anomaly score.

This gives you a baseline that is:

extremely easy to implement
explainable
fast
useful for your demo
useful as a comparison against your ML model
6. Then use Isolation Forest

This is where I would start your actual ML implementation.

Isolation Forest is particularly attractive because your problem is fundamentally:

unsupervised anomaly detection

You don't necessarily have labels saying:

user = malicious

You mostly have normal network behavior.

Isolation Forest attempts to isolate unusual observations.

For example:

Normal behavior


      ● ●
    ● ● ● ●
   ● ● ● ● ●
    ● ● ●
       ●




Anomalous behavior


      ● ●
    ● ● ● ●
   ● ● ● ● ●




                         X

That X gets a high anomaly score.

You can train either:

Global model
all users
   ↓
one Isolation Forest

or, preferably for your concept:

Per-role / per-user models
Developers
    ↓
Isolation Forest


HR
    ↓
Isolation Forest


Finance
    ↓
Isolation Forest

For the MVP I'd actually use:

Global model
+
user-specific behavioral statistics

because training a separate ML model for every employee will become awkward with limited data.

7. Then comes the deep-learning component

Once the classical model works, add an autoencoder.

This is probably a better first deep-learning architecture for your problem than an LSTM.

Suppose your behavioral vector is:

[43, 12, 3, 29, 14, 1.2, 18.4, 7, 2, ...]

An autoencoder learns:

Input
  │
  ▼
Encoder
  │
  ▼
Latent representation
  │
  ▼
Decoder
  │
  ▼
Reconstructed input

For normal behavior:

input:


[43,12,3,29,14,...]


reconstruction:


[42,13,3,30,14,...]


error = small

For abnormal behavior:

input:


[1830,127,74,4,98,...]


reconstruction:


[48,13,4,30,15,...]


error = huge

Then:

AnomalyScore=∣∣X−
X
^
∣∣
2

This is a very natural deep-learning formulation for your problem.

8. Where does LSTM/GRU come in?

This is where your original idea becomes interesting.

Your system isn't only asking:

"Is this activity unusual?"

It can eventually ask:

"Is the sequence of behavior changing?"

For example:

Monday


09:00 ─ normal
10:00 ─ normal
11:00 ─ normal
12:00 ─ normal
13:00 ─ normal
14:00 ─ normal




Tuesday


09:00 ─ normal
10:00 ─ normal
11:00 ─ slightly unusual
12:00 ─ unusual
13:00 ─ very unusual
14:00 ─ extremely unusual

That's a temporal anomaly.

Now an LSTM/GRU becomes useful.

You could feed:

X₁ = behavior at 09:00
X₂ = behavior at 10:00
X₃ = behavior at 11:00
...
X₂₄ = behavior at 14:00

and have the model learn temporal patterns.

9. Your eventual architecture could therefore be
                    Network Traffic
                           │
                           ▼
                 ┌───────────────────┐
                 │ VPN / DNS Gateway │
                 └─────────┬─────────┘
                           │
                           ▼
                    Event Collector
                           │
                           ▼
                  Feature Aggregator
                           │
                  5 min / 15 min
                           │
                           ▼
              ┌─────────────────────────┐
              │ Behavioral Feature Store│
              └────────────┬────────────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
       User Baseline              ML Detector
              │                         │
              │                 ┌───────┴────────┐
              │                 │                │
              │            Isolation Forest   Autoencoder
              │                 │                │
              └─────────────────┴────────────────┘
                                │
                                ▼
                         Anomaly Score
                                │
                                ▼
                       Temporal Analyzer
                                │
                                ▼
                           GRU / LSTM
                                │
                                ▼
                       Final Risk Score
                                │
              ┌─────────────────┼────────────────┐
              ▼                 ▼                ▼
           NORMAL           SUSPICIOUS        CRITICAL
                                │                │
                                │                ▼
                                │            Firewall rule
                                │                │
                                ▼                ▼
                            Dashboard        Block device

But don't implement this entire thing initially.

10. Your MVP should be much smaller

For SIH, I would target this:

┌───────────────────────────────────────┐
│          Simulated Enterprise         │
│                                       │
│  Employee A ─┐                        │
│  Employee B ─┤                        │
│  Employee C ─┼──► Gateway             │
│  Employee D ─┘                        │
└────────────────────┬──────────────────┘
                     │
                     ▼
              Network Logger
                     │
                     ▼
             Feature Generator
                     │
                     ▼
              Isolation Forest
                     │
                     ▼
               Risk Engine
                     │
          ┌──────────┴─────────┐
          ▼                    ▼
      Dashboard             Firewall

That's enough for a convincing MVP.

11. Build a network simulator first

Your teammate is already working on this according to the meeting notes:

Mainak is developing a basic VPN/DNS resolver and simulation software to generate network access logs for model training.

This is actually extremely useful.

You can simulate:

Employee 1
    ↓
normal behavior


Employee 2
    ↓
normal behavior


Employee 3
    ↓
normal behavior


Employee 4
    ↓
normal behavior
          ↓
      compromise
          ↓
DNS tunneling
mass downloads
new destinations
unusual hours
port scanning

Your model should detect the transition.

12. Create synthetic attack scenarios

This will make your SIH demo much stronger.

For example:

Scenario A — DNS tunneling

Normal:

github.com
google.com
jira.company.local
api.company.local

Attack:

aj3k2j4k2j3k4j23.example.com
k2j34k2j34k2j3.example.com
92j3k42j3k42j3.example.com
...

Behavior changes:

unique domains ↑↑↑
domain entropy ↑↑↑
DNS request rate ↑↑↑
new domain ratio ↑↑↑
Scenario B — Data exfiltration

Normal:

100 MB/day

Attack:

8.4 GB in 30 minutes

Features:

bytes_sent ↑↑↑
external destinations ↑↑
request rate ↑
Scenario C — Compromised employee

Normal:

09:00 → 18:00

Attack:

02:37 AM

Combined with:

new destination
large data transfer
new protocol

Risk becomes very high.

Scenario D — Lateral movement

Normal:

Employee → Git server
Employee → Jira
Employee → Internet

Attack:

Employee
   ↓
Server A
   ↓
Server B
   ↓
Server C
   ↓
Database

Features:

unique_internal_hosts ↑↑
new_ports ↑↑
connection_frequency ↑
13. Your dashboard should show behavior, not raw logs

This aligns very closely with what you wrote in the meeting notes:

"we will map the change instead of daily logs of what they are doing currently."

That's a good product decision.

Don't make your main dashboard:

10:32:21 DNS request
10:32:22 DNS request
10:32:22 TCP connection
10:32:23 DNS request
...

Instead:

┌─────────────────────────────────────────────┐
│ Employee: USER-042                          │
│ Role: Developer                             │
│                                             │
│ Risk Score                         87/100   │
│ ████████████████████████░░░░               │
│                                             │
│ Behavioral deviation                        │
│                                             │
│ DNS activity             +340%              │
│ External traffic         +210%              │
│ New destinations         +780%              │
│ Data upload              +510%              │
│ Activity outside hours  DETECTED            │
│                                             │
│ Status: CRITICAL                            │
│                                             │
│ [ISOLATE USER] [INVESTIGATE]               │
└─────────────────────────────────────────────┘

Then another screen:

Employee behavioral timeline


Risk
100 ┤                         ╭───
 80 ┤                    ╭────╯
 60 ┤               ╭────╯
 40 ┤───────────────╯
 20 ┤
  0 ┼──────────────────────────────
       Mon   Tue   Wed   Thu   Fri

This demonstrates your behavioral change concept directly.

14. The most important metric isn't accuracy

For anomaly detection, don't present:

"Our model has 97% accuracy."

That's often misleading because anomaly datasets are highly imbalanced.

Imagine:

1,000,000 normal events
1,000 anomalous events

A model that predicts:

everything = normal

gets:

1,001,000
1,000,000
	​

≈99.9%

accuracy.

Yet it detects zero attacks.

Instead measure:

Precision
Recall
F1
False-positive rate
False-negative rate
PR-AUC
Detection latency

For your system, false positives are particularly important.

If your firewall blocks employees every time they behave slightly differently, nobody will use it.

15. Use a risk score rather than a binary prediction

Don't do:

if anomaly:
    BLOCK

Do:

Risk = 0 → 100

For example:

0–30
NORMAL


30–60
LOW RISK


60–80
SUSPICIOUS


80–100
CRITICAL

Then combine signals:

R=w
1
	​

A
statistical
	​

+w
2
	​

A
isolation
	​

+w
3
	​

A
autoencoder
	​

+w
4
	​

A
temporal
	​


For your MVP, you might simply use:

R=0.4A
IF
	​

+0.6A
baseline
	​


Later:

R=w
1
	​

A
baseline
	​

+w
2
	​

A
IF
	​

+w
3
	​

A
AE
	​

+w
4
	​

A
GRU
	​

16. Don't immediately disconnect the employee

Your notes propose cutting network access when the anomaly exceeds a threshold.

For the MVP, implement policy simulation first.

For example:

Risk = 43
→ monitor


Risk = 67
→ alert administrator


Risk = 82
→ restrict high-risk destinations


Risk = 94
→ isolate device

Your demo can then show:

AI ENGINE
    │
    ▼
Risk = 94
    │
    ▼
Policy Engine
    │
    ▼
BLOCK 10.0.4.21
    │
    ▼
Firewall

That is safer and much easier to demonstrate.

17. Recommended technology stack

Given your team's likely skillset, I'd keep it simple.

Network layer
WireGuard
        +
CoreDNS / dnsmasq
        +
nftables

or for an even simpler prototype:

Python/Go gateway
      +
DNS logging
      +
iptables/nftables
Collector

I'd use Go or Python.

For MVP:

Python
├── log collector
├── feature engineering
├── scikit-learn
└── FastAPI

Then move the network-critical components to Go if needed.

ML
pandas
numpy
scikit-learn
PyTorch

Start:

IsolationForest

Then:

PyTorch Autoencoder

Then potentially:

GRU
Backend
FastAPI
Database

For MVP:

PostgreSQL

Potentially:

TimescaleDB

for time-series network data.

Dashboard

Your existing React/Next.js knowledge makes:

Next.js
+
Tailwind
+
Recharts

a reasonable choice.

18. Suggested repository architecture

I'd structure it something like:

internal-network-anomaly/
│
├── gateway/
│   ├── vpn/
│   ├── dns/
│   ├── firewall/
│   └── collector/
│
├── simulator/
│   ├── employees/
│   ├── normal_behavior/
│   ├── attack_scenarios/
│   └── generator/
│
├── ml/
│   ├── preprocessing/
│   ├── features/
│   ├── baseline/
│   ├── isolation_forest/
│   ├── autoencoder/
│   └── evaluation/
│
├── backend/
│   ├── api/
│   ├── risk_engine/
│   └── policy_engine/
│
├── dashboard/
│   └── ...
│
└── docker-compose.yml
19. Your first end-to-end demo

This is the demo I would target for SIH.

Step 1

Start simulated organization:

20 employees
5 roles


Developer
HR
Finance
Admin
Manager
Step 2

Generate normal behavior for 7 days.

Day 1
Day 2
...
Day 7
Step 3

Train behavioral model.

Historical data
      ↓
Feature extraction
      ↓
User baseline
      ↓
Isolation Forest
Step 4

Start real-time simulation.

Employee 07
   ↓
normal traffic
   ↓
normal traffic
   ↓
normal traffic

Dashboard:

Risk: 12
Step 5

Inject an attack.

For example:

Employee 07
   ↓
DNS tunneling
   ↓
massive DNS requests
   ↓
new external domains
Step 6

Model detects:

DNS requests       +840%
New domains        +620%
Entropy            +400%
Request rate       +720%


Risk:
12 → 28 → 51 → 74 → 91
Step 7

Policy engine responds:

91 > 90


ISOLATE DEVICE


10.0.4.27
Step 8

Dashboard shows:

CRITICAL INCIDENT


Employee: USER-007
Reason:


✓ Abnormal DNS behavior
✓ New destinations
✓ Unusual request frequency
✓ Behavioral deviation


Action:
DEVICE ISOLATED

That is a very demonstrable MVP.

20. What I would NOT build for the first SIH version

Avoid these initially:

❌ Full enterprise VPN
❌ Deep packet inspection
❌ Kubernetes deployment
❌ Distributed ML infrastructure
❌ Transformer model
❌ Complex LSTM architecture
❌ Per-employee deep learning models
❌ Automated HR analytics
❌ Automatic permanent account blocking

The HR idea in your notes—analyzing employee behavior around meetings/holidays, etc.—could be an interesting secondary capability, but I would keep it out of the cybersecurity MVP. It introduces privacy, governance, and false-inference issues without strengthening your core security demonstration.

21. Your research question becomes much clearer

Instead of:

"Which deep learning model can predict whether an employee is malicious?"

I would formulate the technical problem as:

Can an adaptive behavioral baseline combined with unsupervised anomaly detection identify significant deviations in an authenticated user's network behavior without requiring labeled attack data?

Then you can experimentally compare:

                    Detection
                      │
       ┌──────────────┼───────────────┐
       ▼              ▼               ▼
 Statistical     Isolation       Autoencoder
  Baseline         Forest
       │              │               │
       └──────────────┼───────────────┘
                      ▼
                GRU / LSTM

And answer:

Does temporal modeling improve
detection of gradual behavioral drift?

That's a much more defensible ML/research problem.

22. The development order I recommend

Given what your team has already divided up in the meeting, I'd make the next milestones:

Milestone 1 — Network simulation
[ ] Employee identities
[ ] Roles/access levels
[ ] DNS events
[ ] Connection events
[ ] Traffic volume
[ ] Timestamp
[ ] Normal behavior generator
[ ] Attack behavior generator
Milestone 2 — Feature engine
[ ] 5-minute windows
[ ] DNS features
[ ] Traffic features
[ ] Destination features
[ ] Temporal features
[ ] Per-user normalization
Milestone 3 — Baseline
[ ] Mean/std baseline
[ ] Behavioral deviation score
[ ] User profile
Milestone 4 — ML
[ ] Isolation Forest
[ ] Threshold calibration
[ ] Precision/recall/F1
[ ] Attack detection evaluation
Milestone 5 — Dashboard
[ ] User list
[ ] Risk score
[ ] Behavioral timeline
[ ] Anomaly explanation
[ ] Incident view
Milestone 6 — Enforcement
[ ] Policy engine
[ ] Simulated isolation
[ ] nftables integration
Milestone 7 — Deep learning
[ ] Autoencoder
[ ] Compare against Isolation Forest
[ ] Temporal sequences
[ ] GRU/LSTM experiment
The key decision

If you ask me:

"Should we use GRU, LSTM, RNN, or Isolation Forest?"

For your current SIH MVP:

Isolation Forest first.

Then:

Autoencoder second.

Then, if your experiments show that temporal evolution matters:

GRU/LSTM third.

I would actually prefer GRU over vanilla RNN if you reach the temporal stage, because vanilla RNNs are generally a poor choice for longer sequences due to optimization issues.

The important thing is that the model should come after your behavioral representation. Your biggest technical challenge isn't choosing between GRU and LSTM; it's deciding what constitutes a user's behavior and converting raw network activity into meaningful temporal feature vectors.

Your meeting notes already have the right high-level product idea: observe behavioral change rather than force a human network engineer to manually inspect enormous volumes of logs.

For SIH, I would make the MVP:

VPN/DNS gateway → network events → 5-minute behavioral vectors → per-user baseline + Isolation Forest → risk score → dashboard → simulated firewall isolation.

Then make the Autoencoder/GRU component your advanced ML layer, rather than making the entire project depend on a deep-learning model from day one.