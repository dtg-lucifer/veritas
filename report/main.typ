#import "pages/common.typ": primary-color, secondary-color, accent-red

// Global Document Configuration
#set document(
  title: "Veritas: Autonomous Predictive Network Defense via AI World Models",
  author: ("Veritas Engineering Team", "SIH 2026"),
  date: auto,
)

#set page(
  paper: "a4",
  margin: (top: 2.6cm, bottom: 2.6cm, left: 2.5cm, right: 2.5cm),
  header: context {
    // Suppress header on cover page
    if here().page() > 1 [
      #grid(
        columns: (1fr, auto),
        align(left)[#text(size: 8.5pt, fill: rgb("#64748b"), font: "IBM Plex Serif")[*Veritas* — Autonomous Predictive Network Defense & Infiltration Forecasting]],
        align(right)[#text(size: 8.5pt, fill: rgb("#64748b"), font: "IBM Plex Serif")[SIH 2026 Technical Report]]
      )
      #v(-3pt)
      #line(length: 100%, stroke: 0.4pt + rgb("#cbd5e1"))
    ]
  },
  footer: context {
    // Suppress footer on cover page
    if here().page() > 1 [
      #line(length: 100%, stroke: 0.4pt + rgb("#cbd5e1"))
      #v(2pt)
      #grid(
        columns: (1fr, auto),
        align(left)[#text(size: 8.5pt, fill: rgb("#94a3b8"), font: "IBM Plex Serif")[Confidential & Proprietary — Veritas Project]],
        align(right)[#text(size: 8.5pt, fill: rgb("#475569"), font: "IBM Plex Serif", weight: "bold")[Page #here().page()]]
      )
    ]
  }
)

// Typography Configuration (IBM Plex Serif)
#set text(
  font: ("IBM Plex Serif", "Libertinus Serif"),
  size: 10.5pt,
  fill: rgb("#0f172a"),
  lang: "en",
)

#set par(
  justify: true,
  leading: 0.72em,
)

#show heading: it => {
  set text(fill: primary-color, font: ("IBM Plex Serif", "Libertinus Serif"))
  if it.level == 1 {
    v(1.4em)
    text(size: 1.65em, weight: "bold")[#it.body]
    v(0.6em)
  } else if it.level == 2 {
    v(1.1em)
    text(size: 1.3em, weight: "bold")[#it.body]
    v(0.4em)
  } else if it.level == 3 {
    v(0.8em)
    text(size: 1.1em, weight: "bold", fill: secondary-color)[#it.body]
    v(0.3em)
  } else {
    v(0.6em)
    text(size: 1.0em, weight: "bold")[#it.body]
    v(0.2em)
  }
}

#set heading(numbering: "1.1")

#show figure: it => {
  v(0.8em)
  it
  v(0.8em)
}

#show raw: set text(font: ("IBM Plex Mono", "JetBrains Mono", "DejaVu Sans Mono"), size: 9pt)

// --- COVER PAGE ---
#align(center + horizon)[
  #block(
    fill: rgb("#f8fafc"),
    stroke: 1.5pt + primary-color,
    radius: 12pt,
    inset: (x: 28pt, y: 36pt),
    width: 100%,
    [
      #text(size: 14pt, tracking: 3pt, weight: "bold", fill: secondary-color)[SMART INDIA HACKATHON 2026]
      
      #v(8pt)
      #line(length: 40%, stroke: 1.5pt + secondary-color)
      #v(14pt)

      #text(size: 32pt, weight: "bold", fill: primary-color)[VERITAS]
      
      #v(8pt)
      #text(size: 15pt, weight: "medium", fill: rgb("#334155"))[
        Autonomous Predictive Network Defense &\ Infiltration Forecasting via AI World Models
      ]

      #v(20pt)
      #block(
        fill: rgb("#eff6ff"),
        stroke: 0.8pt + rgb("#bfdbfe"),
        radius: 6pt,
        inset: 12pt,
        width: 90%,
        [
          #text(size: 10pt, style: "italic", fill: rgb("#1e3a8a"))[
            A Comprehensive Engineering Report on Causal Transition Dynamics $P(S_{t+1} mid(|) S_{<= t})$, Multi-Step Autoregressive Rollouts, MITRE ATT&CK Mapping, Dual-Tier Explainability, and Enterprise Scalability.
          ]
        ]
      )

      #v(32pt)
      #grid(
        columns: (1fr, 1fr),
        align: (center, center),
        [
          #text(weight: "bold", size: 10pt, fill: rgb("#475569"))[SYSTEM DOMAIN]\
          #text(size: 10pt)[Predictive Cybersecurity / AI World Models]
        ],
        [
          #text(weight: "bold", size: 10pt, fill: rgb("#475569"))[DOCUMENT VERSION]\
          #text(size: 10pt)[Release 2.4.0 (Production Candidate)]
        ]
      )

      #v(24pt)
      #line(length: 80%, stroke: 0.5pt + rgb("#cbd5e1"))
      #v(12pt)
      #text(size: 9pt, fill: rgb("#64748b"))[
        Date: September 2026 $dot$ Fully Offline Capable $dot$ Open-Source Architecture
      ]
    ]
  )
]

#pagebreak()

// --- TABLE OF CONTENTS ---
#outline(
  title: [Table of Contents],
  indent: auto,
  depth: 3,
)

#v(14pt)
#line(length: 100%, stroke: 0.5pt + rgb("#cbd5e1"))
#v(14pt)

#outline(
  title: [List of Figures],
  target: figure.where(kind: image),
)

#v(14pt)
#line(length: 100%, stroke: 0.5pt + rgb("#cbd5e1"))
#v(14pt)

#outline(
  title: [List of Tables],
  target: figure.where(kind: table),
)

#pagebreak()

// --- SECTION 1: EXECUTIVE SUMMARY ---
#include "pages/01_executive_summary.typ"

#pagebreak()

// --- SECTION 2: SYSTEM ARCHITECTURE ---
#include "pages/02_system_architecture.typ"

#pagebreak()

// --- SECTION 3: MATHEMATICAL FORMULATION ---
#include "pages/03_mathematical_formulation.typ"

#pagebreak()

// --- SECTION 4: FORWARD SIMULATION & FORECASTING ---
#include "pages/04_forward_simulation.typ"

#pagebreak()

// --- SECTION 5: EXPLAINABLE AI ---
#include "pages/05_explainable_ai.typ"

#pagebreak()

// --- SECTION 6: TECHNICAL CHALLENGES & SOLUTIONS ---
#include "pages/06_technical_challenges.typ"

#pagebreak()

// --- SECTION 7: REAL-TIME SOC DASHBOARD & OBSERVABILITY ---
#include "pages/07_soc_dashboard_telemetry.typ"

#pagebreak()

// --- SECTION 8: COMPARATIVE EMPIRICAL BENCHMARKS ---
#include "pages/08_comparative_benchmarks.typ"

#pagebreak()

// --- SECTION 9: CONCLUSION & FUTURE HORIZONS ---
#include "pages/09_conclusion_future_scope.typ"
