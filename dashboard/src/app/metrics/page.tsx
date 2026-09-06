"use client";

import {
  Activity,
  ArrowUpRight,
  BarChart2,
  CheckCircle2,
  Copy,
  Cpu,
  Database,
  ExternalLink,
  Filter,
  Gauge,
  Layers,
  LineChart as LineChartIcon,
  PieChart as PieIcon,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Zap,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

interface MetricItem {
  name: string;
  type: string;
  value: number | string;
  help: string;
}

interface TelemetryPoint {
  time: string;
  flows: number;
  windows: number;
  memMb: number;
  logsProc: number;
  logsConf: number;
  logsMal: number;
  logsIgn: number;
}

function ChartTooltip({ active, payload, label }: any) {
  if (!active || !payload || !payload.length) return null;
  return (
    <div className="rounded-lg border border-border bg-popover/95 p-2.5 shadow-lg backdrop-blur-sm text-xs font-mono">
      {label && (
        <div className="font-semibold text-popover-foreground mb-1.5 border-b border-border/50 pb-1">
          {label}
        </div>
      )}
      <div className="space-y-1">
        {payload.map((entry: any, index: number) => (
          <div key={`item-${index}`} className="flex items-center justify-between gap-3">
            <span className="flex items-center gap-1.5 text-muted-foreground text-[11px]">
              <span
                className="h-2 w-2 rounded-full shrink-0"
                style={{ backgroundColor: entry.color || entry.stroke || entry.fill }}
              />
              {entry.name}:
            </span>
            <span className="font-bold text-foreground font-mono text-[11px]">
              {typeof entry.value === "number" ? entry.value.toLocaleString() : entry.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function BarChartTooltip({ active, payload }: any) {
  if (!active || !payload || !payload.length) return null;
  const item = payload[0];
  return (
    <div className="rounded-lg border border-border bg-popover/95 p-2.5 shadow-lg backdrop-blur-sm text-xs font-mono">
      <div className="font-semibold text-popover-foreground mb-1 flex items-center gap-1.5">
        <span
          className="h-2 w-2 rounded-full shrink-0"
          style={{ backgroundColor: item.payload?.color }}
        />
        {item.payload?.name}
      </div>
      <div className="text-muted-foreground text-[11px] flex items-center justify-between gap-3">
        <span>Volume:</span>
        <span className="font-bold text-foreground font-mono">
          {Number(item.value).toLocaleString()}
        </span>
      </div>
    </div>
  );
}

export default function MetricsPage() {
  const [loading, setLoading] = useState(true);
  const [rawMetrics, setRawMetrics] = useState<string>("");
  const [parsedMetrics, setParsedMetrics] = useState<Record<string, number>>({});
  const [metricItems, setMetricItems] = useState<MetricItem[]>([]);
  const [history, setHistory] = useState<TelemetryPoint[]>([]);
  const [chartMode, setChartMode] = useState<"flows" | "memory">("flows");
  const [metricSearch, setMetricSearch] = useState("");
  const [showRaw, setShowRaw] = useState(false);

  const fetchMetrics = useCallback(async () => {
    try {
      setLoading(true);
      const res = await fetch("http://localhost:8000/metrics", {
        signal: AbortSignal.timeout(3000),
      });
      if (res.ok) {
        const text = await res.text();
        setRawMetrics(text);

        const parsed: Record<string, number> = {};
        const items: MetricItem[] = [];
        const lines = text.split("\n");

        let currentHelp = "";
        let currentType = "";

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed) continue;

          if (trimmed.startsWith("# HELP ")) {
            const parts = trimmed.slice(7).split(/\s+/);
            const name = parts[0];
            currentHelp = parts.slice(1).join(" ");
          } else if (trimmed.startsWith("# TYPE ")) {
            const parts = trimmed.slice(7).split(/\s+/);
            currentType = parts[1] || "gauge";
          } else {
            const parts = trimmed.split(/\s+/);
            if (parts.length >= 2) {
              const rawName = parts[0];
              const val = Number.parseFloat(parts[1]);
              if (!Number.isNaN(val)) {
                const cleanKey = rawName.replace(/\{.*\}/, "");
                parsed[cleanKey] = val;
                items.push({
                  name: rawName,
                  type: currentType || "gauge",
                  value: val,
                  help: currentHelp || "Firewall subsystem telemetry metric",
                });
              }
            }
          }
        }

        setParsedMetrics(parsed);
        setMetricItems(items);

        // Record historical snapshot for time-series chart
        const point: TelemetryPoint = {
          time: new Date().toLocaleTimeString(),
          flows: parsed.firewall_flows_ingested_total || 0,
          windows: parsed.firewall_windows_evaluated_total || 0,
          memMb: Math.round(((parsed.firewall_process_memory_bytes || 0) / (1024 * 1024)) * 10) / 10,
          logsProc: parsed.firewall_logs_processed_total || 0,
          logsConf: parsed.firewall_logs_webrtc_conferencing_total || 0,
          logsMal: parsed.firewall_logs_malformed_total || 0,
          logsIgn: parsed.firewall_logs_ignored_total || 0,
        };

        setHistory((prev) => {
          const next = [...prev, point];
          return next.slice(-15); // keep latest 15 points
        });
      }
    } catch {
      toast.error("Failed to scrape /metrics from backend server");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchMetrics();
    const interval = setInterval(fetchMetrics, 5000);
    return () => clearInterval(interval);
  }, [fetchMetrics]);

  const uptimeSec = parsedMetrics.firewall_uptime_seconds || 0;
  const uptimeMinutes = (uptimeSec / 60).toFixed(1);
  const memBytes = parsedMetrics.firewall_process_memory_bytes || 0;
  const memMb = (memBytes / (1024 * 1024)).toFixed(1);
  const flows = parsedMetrics.firewall_flows_ingested_total || 0;
  const windows = parsedMetrics.firewall_windows_evaluated_total || 0;
  const alertsTotal = parsedMetrics.firewall_alerts_generated_total || 0;
  const wsClients = parsedMetrics.firewall_active_ws_subscribers || 0;
  const activeLoggers = parsedMetrics.firewall_active_loggers_count || 0;
  const logsProc = parsedMetrics.firewall_logs_processed_total || 0;
  const logsConf = parsedMetrics.firewall_logs_webrtc_conferencing_total || 0;
  const logsMal = parsedMetrics.firewall_logs_malformed_total || 0;
  const logsIgn = parsedMetrics.firewall_logs_ignored_total || 0;

  // Key ratios & velocity calculations
  const flowVelocity = uptimeSec > 0 ? (flows / uptimeSec).toFixed(1) : "0.0";
  const windowVelocity = uptimeSec > 0 ? ((windows / uptimeSec) * 60).toFixed(1) : "0.0";
  const conferencingPct = logsProc > 0 ? ((logsConf / logsProc) * 100).toFixed(1) : "0.0";
  const malformedPct = logsProc > 0 ? ((logsMal / logsProc) * 100).toFixed(2) : "0.00";

  // Data for Breakdown Bar Chart
  const pipelineDistributionData = [
    { name: "Ingested Logs", count: logsProc, color: "#06b6d4" },
    { name: "WebRTC Filtered", count: logsConf, color: "#10b981" },
    { name: "Ignored/Dropped", count: logsIgn, color: "#f59e0b" },
    { name: "Malformed Traps", count: logsMal, color: "#ef4444" },
  ];

  const filteredItems = useMemo(() => {
    if (!metricSearch.trim()) return metricItems;
    const q = metricSearch.toLowerCase();
    return metricItems.filter(
      (m) => m.name.toLowerCase().includes(q) || m.help.toLowerCase().includes(q)
    );
  }, [metricItems, metricSearch]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-border">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2.5">
            <Gauge className="h-6 w-6 text-primary" />
            Prometheus Telemetry & System Visualisations
          </h1>
          <p className="text-xs text-muted-foreground mt-1">
            Real-time scraping from <span className="font-mono text-foreground font-semibold">GET /metrics</span> with time-series trends and Prometheus Prometheus exposition analytics.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={fetchMetrics}
            disabled={loading}
            className="h-8 text-xs text-muted-foreground hover:text-foreground"
          >
            <RefreshCw className={`h-3.5 w-3.5 mr-1.5 ${loading ? "animate-spin" : ""}`} />
            Scrape Now
          </Button>
          <a href="http://localhost:3001" target="_blank" rel="noopener noreferrer">
            <Button
              size="sm"
              className="h-8 text-xs font-semibold gap-1.5 bg-orange-600 hover:bg-orange-700 text-white shadow-sm"
            >
              <ExternalLink className="h-3.5 w-3.5" />
              <span>Launch Grafana (:3001)</span>
            </Button>
          </a>
        </div>
      </div>

      {/* 6 Vital Stat Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <Card className="border-border bg-card shadow-sm p-3.5">
          <div className="text-[10px] uppercase font-mono text-muted-foreground">Process Uptime</div>
          <div className="text-xl font-bold font-mono text-foreground mt-0.5">{uptimeMinutes}m</div>
          <div className="text-[10px] text-muted-foreground mt-0.5 font-mono">{uptimeSec.toFixed(0)}s total</div>
        </Card>

        <Card className="border-border bg-card shadow-sm p-3.5">
          <div className="text-[10px] uppercase font-mono text-muted-foreground">Resident Memory</div>
          <div className="text-xl font-bold font-mono text-foreground mt-0.5">{memMb} MB</div>
          <div className="text-[10px] text-muted-foreground mt-0.5 font-mono">Process RSS (ru_maxrss)</div>
        </Card>

        <Card className="border-border bg-card shadow-sm p-3.5">
          <div className="text-[10px] uppercase font-mono text-muted-foreground">Flows Ingested</div>
          <div className="text-xl font-bold font-mono text-cyan-500 mt-0.5">{flows}</div>
          <div className="text-[10px] text-muted-foreground mt-0.5 font-mono">{flowVelocity} flows/sec</div>
        </Card>

        <Card className="border-border bg-card shadow-sm p-3.5">
          <div className="text-[10px] uppercase font-mono text-muted-foreground">Windows Evaluated</div>
          <div className="text-xl font-bold font-mono text-purple-500 mt-0.5">{windows}</div>
          <div className="text-[10px] text-muted-foreground mt-0.5 font-mono">{windowVelocity} windows/min</div>
        </Card>

        <Card className="border-border bg-card shadow-sm p-3.5">
          <div className="text-[10px] uppercase font-mono text-muted-foreground">Active Sensors</div>
          <div className="text-xl font-bold font-mono text-emerald-500 mt-0.5">{activeLoggers}</div>
          <div className="text-[10px] text-muted-foreground mt-0.5 font-mono">Sensors registered</div>
        </Card>

        <Card className="border-border bg-card shadow-sm p-3.5">
          <div className="text-[10px] uppercase font-mono text-muted-foreground">WS Clients</div>
          <div className="text-xl font-bold font-mono text-primary mt-0.5">{wsClients}</div>
          <div className="text-[10px] text-muted-foreground mt-0.5 font-mono">Active dashboards</div>
        </Card>
      </div>

      {/* Visualisations Section (2 Rich Charts) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Chart 1: Time-Series Telemetry Trends (7 cols) */}
        <div className="lg:col-span-7">
          <Card className="border-border bg-card shadow-sm rounded-xl h-full flex flex-col">
            <CardHeader className="pb-2 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <div className="flex items-center gap-2">
                  <LineChartIcon className="h-4 w-4 text-cyan-500" />
                  <CardTitle className="text-sm font-semibold tracking-wide uppercase text-foreground">
                    Real-Time Telemetry Velocity
                  </CardTitle>
                </div>
                <CardDescription className="text-xs text-muted-foreground">
                  Rolling scrape horizon across recent evaluation intervals
                </CardDescription>
              </div>

              {/* Chart Mode Toggle */}
              <div className="flex items-center gap-1 p-0.5 bg-muted/50 rounded-lg border border-border text-xs">
                <button
                  type="button"
                  onClick={() => setChartMode("flows")}
                  className={`px-2.5 py-1 rounded text-xs transition-all cursor-pointer ${
                    chartMode === "flows"
                      ? "bg-card text-foreground font-semibold shadow-xs border border-border"
                      : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  Flows & Windows
                </button>
                <button
                  type="button"
                  onClick={() => setChartMode("memory")}
                  className={`px-2.5 py-1 rounded text-xs transition-all cursor-pointer ${
                    chartMode === "memory"
                      ? "bg-card text-foreground font-semibold shadow-xs border border-border"
                      : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  Memory RSS (MB)
                </button>
              </div>
            </CardHeader>

            <CardContent className="flex-1 pt-3 pb-3">
              <div className="h-[260px] w-full">
                <ResponsiveContainer width="100%" height="100%">
                  {chartMode === "flows" ? (
                    <AreaChart data={history.length > 0 ? history : [{ time: "Now", flows, windows, memMb: Number(memMb), logsProc, logsConf, logsMal, logsIgn }]}>
                      <defs>
                        <linearGradient id="flowGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                          <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                        </linearGradient>
                        <linearGradient id="windowGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#a855f7" stopOpacity={0.4} />
                          <stop offset="95%" stopColor="#a855f7" stopOpacity={0.0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(128,128,128,0.18)" />
                      <XAxis dataKey="time" stroke="#71717a" fontSize={10} tickLine={false} />
                      <YAxis stroke="#71717a" fontSize={10} tickLine={false} />
                      <Tooltip content={<ChartTooltip />} />
                      <Legend wrapperStyle={{ fontSize: "11px", paddingTop: "6px" }} />
                      <Area
                        type="monotone"
                        dataKey="flows"
                        name="Flows Ingested"
                        stroke="#06b6d4"
                        fillOpacity={1}
                        fill="url(#flowGrad)"
                        strokeWidth={2}
                      />
                      <Area
                        type="monotone"
                        dataKey="windows"
                        name="Windows Evaluated"
                        stroke="#a855f7"
                        fillOpacity={1}
                        fill="url(#windowGrad)"
                        strokeWidth={2}
                      />
                    </AreaChart>
                  ) : (
                    <AreaChart data={history.length > 0 ? history : [{ time: "Now", flows, windows, memMb: Number(memMb), logsProc, logsConf, logsMal, logsIgn }]}>
                      <defs>
                        <linearGradient id="memGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#10b981" stopOpacity={0.4} />
                          <stop offset="95%" stopColor="#10b981" stopOpacity={0.0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(128,128,128,0.18)" />
                      <XAxis dataKey="time" stroke="#71717a" fontSize={10} tickLine={false} />
                      <YAxis stroke="#71717a" fontSize={10} tickLine={false} />
                      <Tooltip content={<ChartTooltip />} />
                      <Legend wrapperStyle={{ fontSize: "11px", paddingTop: "6px" }} />
                      <Area
                        type="monotone"
                        dataKey="memMb"
                        name="Memory RSS (MB)"
                        stroke="#10b981"
                        fillOpacity={1}
                        fill="url(#memGrad)"
                        strokeWidth={2}
                      />
                    </AreaChart>
                  )}
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Chart 2: Pipeline Ingestion & Filtering Breakdown (5 cols) */}
        <div className="lg:col-span-5">
          <Card className="border-border bg-card shadow-sm rounded-xl h-full flex flex-col">
            <CardHeader className="pb-2">
              <div className="flex items-center gap-2">
                <BarChart2 className="h-4 w-4 text-emerald-500" />
                <CardTitle className="text-sm font-semibold tracking-wide uppercase text-foreground">
                  Ingestion Volume Breakdown
                </CardTitle>
              </div>
              <CardDescription className="text-xs text-muted-foreground">
                Distribution of processed, filtered, and malformed telemetry
              </CardDescription>
            </CardHeader>

            <CardContent className="flex-1 pt-3 pb-3">
              <div className="h-[260px] w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={pipelineDistributionData} layout="vertical" margin={{ left: 15, right: 20 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(128,128,128,0.18)" horizontal={false} />
                    <XAxis type="number" stroke="#71717a" fontSize={10} tickLine={false} />
                    <YAxis dataKey="name" type="category" stroke="#71717a" fontSize={10} tickLine={false} width={105} />
                    <Tooltip content={<BarChartTooltip />} />
                    <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                      {pipelineDistributionData.map((entry) => (
                        <Cell key={entry.name} fill={entry.color} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Deep Textual Telemetry & Key Performance Indicators */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        <Card className="border-border bg-card shadow-sm p-4">
          <div className="flex items-center justify-between pb-1">
            <span className="text-xs text-muted-foreground font-mono">WebRTC Filter Ratio</span>
            <ShieldCheck className="h-4 w-4 text-emerald-500" />
          </div>
          <div className="text-2xl font-bold font-mono text-foreground mt-1">{conferencingPct}%</div>
          <p className="text-[11px] text-muted-foreground mt-1">
            {logsConf} STUN/TURN media packets normalized to prevent false positives.
          </p>
        </Card>

        <Card className="border-border bg-card shadow-sm p-4">
          <div className="flex items-center justify-between pb-1">
            <span className="text-xs text-muted-foreground font-mono">Schema Error Rate</span>
            <ShieldAlert className="h-4 w-4 text-cyan-500" />
          </div>
          <div className="text-2xl font-bold font-mono text-foreground mt-1">{malformedPct}%</div>
          <p className="text-[11px] text-muted-foreground mt-1">
            {logsMal} malformed records safely trapped in Redis without server freeze.
          </p>
        </Card>

        <Card className="border-border bg-card shadow-sm p-4">
          <div className="flex items-center justify-between pb-1">
            <span className="text-xs text-muted-foreground font-mono">Simulation Thresholds</span>
            <Layers className="h-4 w-4 text-purple-500" />
          </div>
          <div className="text-sm font-bold font-mono text-foreground mt-1">
            Alert: {((parsedMetrics.firewall_threshold_alert || 0.4) * 100).toFixed(0)}% | Crit: {((parsedMetrics.firewall_threshold_critical || 0.7) * 100).toFixed(0)}%
          </div>
          <p className="text-[11px] text-muted-foreground mt-1">
            Autoregressive forward rollout threat classification barriers.
          </p>
        </Card>

        <Card className="border-border bg-card shadow-sm p-4">
          <div className="flex items-center justify-between pb-1">
            <span className="text-xs text-muted-foreground font-mono">Client Capacity</span>
            <Server className="h-4 w-4 text-primary" />
          </div>
          <div className="text-2xl font-bold font-mono text-foreground mt-1">
            {parsedMetrics.firewall_connected_clients_capacity || 1} Workstations
          </div>
          <p className="text-[11px] text-muted-foreground mt-1">
            Enterprise network scale factor applied to state vectors.
          </p>
        </Card>
      </div>

      {/* Filterable Prometheus Metrics Table */}
      <Card className="border-border bg-card shadow-sm rounded-xl">
        <CardHeader className="pb-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <Terminal className="h-4 w-4 text-primary" />
              <CardTitle className="text-sm font-semibold tracking-wide uppercase text-foreground">
                Exported Prometheus Metric Dictionary
              </CardTitle>
            </div>
            <CardDescription className="text-xs text-muted-foreground">
              Live gauge and counter exposition values available on :8000/metrics
            </CardDescription>
          </div>

          <div className="flex items-center gap-2">
            <div className="relative w-64">
              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
              <input
                type="text"
                placeholder="Search metrics..."
                value={metricSearch}
                onChange={(e) => setMetricSearch(e.target.value)}
                className="w-full pl-8 pr-3 py-1.5 text-xs bg-muted/40 rounded-lg border border-border focus:outline-hidden text-foreground font-mono"
              />
            </div>

            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowRaw(!showRaw)}
              className="text-xs h-8"
            >
              {showRaw ? "Hide Raw" : "Raw Text"}
            </Button>
          </div>
        </CardHeader>

        <CardContent>
          {showRaw ? (
            <pre className="text-[11px] font-mono p-4 bg-muted/40 rounded-lg max-h-[300px] overflow-y-auto text-foreground border border-border">
              {rawMetrics || "Scraping /metrics..."}
            </pre>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs font-mono">
                <thead>
                  <tr className="border-b border-border/80 text-muted-foreground text-left">
                    <th className="pb-2 font-medium">Metric Identifier</th>
                    <th className="pb-2 font-medium">Type</th>
                    <th className="pb-2 font-medium text-right">Live Value</th>
                    <th className="pb-2 font-medium pl-4">Description / Help</th>
                    <th className="pb-2 font-medium text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/40">
                  {filteredItems.map((item) => (
                    <tr key={item.name} className="hover:bg-muted/30 transition-colors">
                      <td className="py-2 text-foreground font-semibold flex items-center gap-2">
                        <span className="h-1.5 w-1.5 rounded-full bg-primary" />
                        <span>{item.name}</span>
                      </td>
                      <td className="py-2">
                        <Badge
                          variant="outline"
                          className="text-[10px] uppercase font-mono py-0 px-1.5 text-muted-foreground"
                        >
                          {item.type}
                        </Badge>
                      </td>
                      <td className="py-2 text-right font-bold text-cyan-400">
                        {typeof item.value === "number"
                          ? Number.isInteger(item.value)
                            ? item.value
                            : item.value.toFixed(2)
                          : item.value}
                      </td>
                      <td className="py-2 pl-4 text-muted-foreground text-[11px] max-w-xs truncate">
                        {item.help}
                      </td>
                      <td className="py-2 text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => {
                            navigator.clipboard.writeText(`${item.name} ${item.value}`);
                            toast.success(`Copied ${item.name}`);
                          }}
                          className="h-6 w-6 p-0 text-muted-foreground hover:text-foreground"
                        >
                          <Copy className="h-3 w-3" />
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
