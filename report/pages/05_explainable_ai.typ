#import "common.typ": callout, takeaway, primary-color, secondary-color

= Explainable AI (XAI), Attention Interpretation & Feature Saliency

== The Black-Box Dilemma in Mission-Critical SOC Environments

In enterprise Security Operations Centers (SOC) and Critical Information Infrastructure (CII), raw predictive accuracy is insufficient. When an autonomous defense system initiates high-impact interventions—such as severing an executive workstation from the core network or dropping active sessions on an internal database—human security analysts must be equipped with immediate, mathematically verifiable explanations:

1. *The Danger of Opaque Confidence Scores:* A model that merely outputs $"Threat Probability" = 94.2%$ without explanation forces analysts into blind trust or paralysis. If the alert is a false positive caused by legitimate backup transfers, critical business operations are needlessly disrupted.
2. *Accelerating Incident Triage:* Sifting through millions of lines of raw PCAP captures to find an exploit trigger takes hours. Explainable AI pinpoints the exact anomalous features within milliseconds.
3. *Forensic & Regulatory Compliance:* Strict cybersecurity regulations (e.g., NIST, ISO 27001, CII mandates) require an immutable audit trail explaining why automated mitigation actions were taken.

Veritas eliminates black-box opacity through a dual-tier Explainable AI (XAI) engine combining *Temporal Attention Attribution* (when did the threat begin?) and *Gradient $times$ Input Feature Saliency* (what physical network parameters drove the decision?).

#figure(
  image("../assets/xai_live_attention_map.png", width: 92%),
  caption: [Veritas Explainable AI Console: Live Multi-Head Temporal Attention Heatmap and Gradient $times$ Input Feature Attribution.]
)

== Tier 1: Multi-Head Temporal Attention Interpretation (When?)

The Multi-Head Attention layer maintains an explicit attention distribution across the sliding sequence of $W=8$ time windows ($[t-7, dots, t]$). During the forward pass, the query vector is derived from the most recent state (at time $t$), which actively queries the key vectors of all preceding historical states:

For each attention head $m in {1, dots, M}$ (where $M=4$ and head dimension $d_k = 16$):

$ A_m = "Softmax"( (Q_m K_m^top) / sqrt(16) ) in bb(R)^(B times 8 times 8) $

The temporal attention vector $alpha in bb(R)^8$ is obtained by averaging attention across all 4 heads for the final time step:

$ alpha_i = 1/4 sum_(m=1)^4 A_(m, :, 7, i), quad sum_(i=0)^7 alpha_i = 1, quad forall i in {0, dots, 7} $

=== Physical Interpretation of the Attention Heatmap
As displayed in the Veritas Attention Heatmap console (Figure above), the attention scores reveal the temporal trajectory of the threat:
- In nominal traffic, attention is evenly distributed or focused entirely on the immediate present ($alpha_7 approx 0.85$).
- During an unfolding multi-stage attack (e.g., an initial port scan at window $t-4$ followed by credential stuffing at window $t$), the attention weights shift backward. The model assigns high attention ($alpha_4 = 0.46$) to the historical reconnaissance window that occurred 60 seconds prior.
- This provides mathematical proof to the SOC analyst that the current high risk score is not an isolated random spike, but a direct consequence of the adversary's earlier reconnaissance activity.

== Tier 2: Gradient $times$ Input Feature Saliency (What?)

To determine which of the 32 individual state vector dimensions contributed to the threat forecast, Veritas utilizes first-order gradient saliency scaled by input magnitude (`ml/src/world_model/explainability.py`).

=== 1. PyTorch Automatic Differentiation
During live evaluation, the sliding history tensor $bold(X)_("seq") in bb(R)^(1 times 8 times 32)$ is loaded into memory, and gradient tracking is dynamically enabled:

```python
seq_tensor = torch.tensor(history_norm, dtype=torch.float32, device=device).unsqueeze(0)
seq_tensor.requires_grad_(True)
```

The forward pass computes the unnormalized infiltration logit and threat probability:

$ P_("inf") = sigma( "InfiltrationHead"( h_("attn") ) ) $

A backward pass is initiated directly from the scalar infiltration probability:

```python
inf_prob.backward()
```

By propagating the gradient back through the output head, through the multi-head attention projection, through the 2-layer LSTM recurrent core, and through the latent state encoder, PyTorch computes the exact Jacobian gradient vector with respect to the input state features:

$ bold(J)_(t, j) = (partial P_("inf")) / (partial S_(t, j)), quad forall j in {1, dots, 32} $

=== 2. Why Pure Gradients Fail and Gradient $times$ Input Succeeds
Evaluating pure gradient values $((partial P_("inf")) / (partial S_(t, j)))$ can produce misleading attributions: a feature might have an extremely steep slope in a region where its actual physical value is zero.

To capture true physical attribution, Veritas computes *Gradient $times$ Input*, multiplying the local gradient by the normalized feature value itself:

$ "Attribution"_j = abs( tilde(S)_(t, j) times (partial P_("inf")) / (partial tilde(S)_(t, j)) ) $

This formulation guarantees that a feature is only flagged as a driving factor if:
1. The model is highly sensitive to changes in that feature ($abs((partial P) / (partial S)) "is large"$).
2. The feature was actively anomalous or non-zero in the observed traffic ($abs(tilde(S)) "is significant"$).

=== 3. Percentage Attribution Normalization
The raw attribution values are normalized across all 32 dimensions to generate an intuitive percentage score:

$ "Contribution"_j = ("Attribution"_j) / (sum_(m=1)^(32) "Attribution"_m + epsilon) times 100% $

The features are sorted in descending order to identify the top driving factors behind the alert:
- `syn_ratio`: *42.1%* (Severe half-open TCP handshake imbalance)
- `unique_dst_ports`: *28.4%* (Targeted scanning across 318 distinct ports)
- `flow_pkts_rate`: *14.8%* (Volumetric packet flood exceeding normal thresholds)
- `pkt_len_std`: *8.2%* (Anomalous uniform small-payload probe packets)
- Other features: *6.5%*

== Natural Language SOC Incident Synthesis

To ensure that frontline security analysts do not have to interpret raw tensors during active zero-day attacks, Veritas features an automated translation engine. The engine correlates the top contributing features, the active MITRE stage, and the forward simulation lead-time into a human-readable operational brief:

#align(center)[
  #block(
    fill: rgb("#f8fafc"),
    stroke: 1pt + rgb("#cbd5e1"),
    inset: 14pt,
    radius: 4pt,
    [
      #text(weight: "bold", fill: rgb("#991b1b"))[[OPERATIONAL ALERT: CRITICAL INFILTRATION FORECAST]] \
      #v(5pt)
      #text(size: 0.95em, fill: rgb("#1e293b"))[
        "Forward dynamics forecast threat escalation to *Stage 1: Reconnaissance (T1046)* with *89.4% probability* at step $+45s$. Primary driving anomaly: abnormal TCP SYN concentration (42.1% attribution) combined with multi-port sweep across 318 distinct ports (28.4% attribution). Pre-emptive device isolation recommended."
      ]
    ]
  )
]

#callout(title: "In Simple Words: Why Interpretability Matters and How Veritas Explains Its Decisions", label: "EXPLAINABILITY SUMMARY")[
  Imagine taking your car to a mechanic because the check engine light came on. If the mechanic says: *"The computer says your car is 92% broken, so I threw away the engine,"* you would be furious. You want to know: *"Which part broke? Was it the alternator? The spark plug? Or just a loose gas cap?"*
  
  Many AI security systems act like that bad mechanic—they shout *"Threat detected!"* but refuse to explain why.
  
  *Veritas gives you the full diagnostic report.* It says: *"We triggered an alert because in the last 60 seconds, 42% of the alarm was caused by an abnormal flood of SYN packets, and 28% was caused by someone probing 318 different doors."* This lets the security team verify the threat in seconds and take confident, decisive action.
]

#takeaway(title: "Forensic Auditability", label: "COMPLIANCE ASSURANCE")[
  By pairing temporal attention heatmaps with Gradient $times$ Input feature attributions, Veritas provides an immutable, mathematically verifiable audit trail for every automated isolation event, fully satisfying enterprise compliance and incident response standards.
]
