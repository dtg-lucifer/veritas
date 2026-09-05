# 📊 SOC Security Operations Center Dashboard (Next.js & WebSocket Feed)

Real-time Next.js Security Operations Center (SOC) dashboard for the **Internal Network Firewall & AI World Model** system (SIH 2026).

Streams live forward simulation threat alerts, displays dynamic risk distributions, monitors model and streaming broker connectivity, and provides manual or automated device isolation controls.

---

## 🏗️ Architecture & Features

```
┌─────────────────────────────────────────────────────────────┐
│                    Next.js SOC Dashboard                    │
│                     (http://localhost:3000)                 │
└──────────────────────────────┬──────────────────────────────┘
                               │
               ┌───────────────┴───────────────┐
               │                               │
               ▼ (WebSocket ws://:8000/ws)     ▼ (REST Polling & Actions)
   [ Live Security Alerts ]        [ System Health & Policy ]
   • Max Infiltration Risk %       • Model Readiness Badge
   • MITRE ATT&CK Stage            • Kafka Consumer Status
   • Temporal Root Cause XAI       • ISOLATE_DEVICE Action
   • Policy Action Enforced        • /api/v1/simulation/latest
```

### Key Capabilities
1. **Live WebSocket Stream (`/ws/alerts`)**:
   - Zero-polling, sub-second threat notifications as the AI World Model evaluates 15-second network state windows.
   - Real-time incident feed featuring threat severity (`NORMAL`, `SUSPICIOUS`, `CRITICAL`), target host/IP, risk probability, and MITRE phase.
2. **Dynamic Risk Distribution Radar (`recharts`)**:
   - Interactive visual breakdown of network traffic states (Nominal Baseline vs. Suspicious Probes vs. Critical Infiltration).
3. **Automated & Manual Policy Enforcement**:
   - One-click device quarantine and firewall policy enforcement (`ISOLATE_DEVICE`) calling `POST /api/v1/policy/enforce`.
4. **Resilient Health & Telemetry Polling**:
   - Heartbeat polling (`GET /health`) checking Kafka consumer group health, model weights loaded status, and active subscribers.

---

## 📁 Directory Structure

```
dashboard/
├── src/
│   ├── app/
│   │   ├── layout.tsx         # Root layout with dark cybersecurity aesthetic
│   │   ├── page.tsx           # Main page rendering Dashboard component
│   │   └── globals.css        # Tailwind v4 styles & custom design tokens
│   ├── components/
│   │   ├── Dashboard.tsx      # Main SOC security dashboard view & state manager
│   │   ├── alerts/
│   │   │   └── LiveAlertFeed.tsx # Real-time scrolling threat alert feed
│   │   ├── charts/
│   │   │   └── RiskDistributionChart.tsx # Threat classification distribution
│   │   └── ui/                # Reusable UI primitives (cards, badges, buttons)
│   └── lib/                   # Utility helpers and classnames merger
├── public/                    # Static assets
├── package.json               # Next.js 16, React 19, Recharts, TailwindCSS v4
├── biome.json                 # Fast linter & formatter configuration
└── tsconfig.json              # TypeScript configuration
```

---

## 🚀 Getting Started

### 1. Prerequisites
- Node.js 20+
- `pnpm` (recommended), `npm`, or `bun`
- Running FastAPI backend service on `http://localhost:8000`

### 2. Install Dependencies
```bash
cd dashboard
pnpm install
# or: npm install
```

### 3. Run Development Server
```bash
pnpm dev
# or: npm run dev
```

Open **`http://localhost:3000`** in your browser to view the live dashboard.

### 4. Build for Production
```bash
pnpm build
pnpm start
```

---

## ⚙️ Configuration

The dashboard connects by default to the local FastAPI backend:
- **REST API Base URL:** `http://localhost:8000`
- **WebSocket Endpoint:** `ws://localhost:8000/api/v1/ws/alerts` (or `ws://localhost:8000/ws/alerts`)

If deploying across separate hosts or Docker networks, configure environment variables in `.env.local`:
```env
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_WS_URL=ws://localhost:8000/api/v1/ws/alerts
```

---

## 🛠️ Code Quality & Formatting
We use **Biome** for fast linting and formatting:
```bash
# Check code quality
pnpm lint

# Format code automatically
pnpm format
```

---

## 📖 Complete Backend API & Telemetry Guide
For full payload schemas, Redis ingestion metrics (`/api/v1/metrics/redis`), dynamic network scale configuration (`/api/v1/config`), and recommended UI widgets, consult:
👉 **[DASHBOARD_INTEGRATION.md](../DASHBOARD_INTEGRATION.md)**

