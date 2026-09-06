"use client";

import {
  Activity,
  BarChart2,
  Copy,
  ExternalLink,
  Gauge,
  RefreshCw,
  Server,
  Terminal,
} from "lucide-react";
import { useCallback, useEffect, useState } from "react";
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

export default function MetricsPage() {
  const [loading, setLoading] = useState(true);
  const [rawMetrics, setRawMetrics] = useState<string>("");
  const [parsedMetrics, setParsedMetrics] = useState<Record<string, number>>(
    {},
  );
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

        // Parse prometheus key-value pairs
        const parsed: Record<string, number> = {};
        for (const line of text.split("\n")) {
          const trimmed = line.trim();
          if (trimmed && !trimmed.startsWith("#")) {
            const parts = trimmed.split(/\s+/);
            if (parts.length >= 2) {
              const key = parts[0];
              const val = Number.parseFloat(parts[1]);
              if (!Number.isNaN(val)) {
                // remove labels if any for simple display
                const cleanKey = key.replace(/\{.*\}/, "");
                parsed[cleanKey] = val;
              }
            }
          }
        }
        setParsedMetrics(parsed);
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
  const _alerts = parsedMetrics.firewall_alerts_generated_total || 0;
  const wsClients = parsedMetrics.firewall_active_ws_subscribers || 0;
  const activeLoggers = parsedMetrics.firewall_active_loggers_count || 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-border">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2.5">
            <Gauge className="h-6 w-6 text-primary" />
            Prometheus Metrics & Grafana Integration
          </h1>
          <p className="text-xs text-muted-foreground mt-1">
            Standardized Prometheus telemetry scraping from FastAPI backend with
            direct Grafana SOC operations link.
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
            <RefreshCw
              className={`h-3.5 w-3.5 mr-1.5 ${loading ? "animate-spin" : ""}`}
            />
            Scrape Now
          </Button>
          <a
            href="http://localhost:3001"
            target="_blank"
            rel="noopener noreferrer"
          >
            <Button
              size="sm"
              className="h-8 text-xs font-semibold gap-1.5 bg-orange-600 hover:bg-orange-700 text-white shadow-sm"
            >
              <ExternalLink className="h-3.5 w-3.5" />
              <span>Open Grafana Dashboard</span>
            </Button>
          </a>
        </div>
      </div>

      {/* Prominent Grafana SOC Launch Banner */}
      <Card className="border-orange-500/20 bg-orange-500/5 shadow-sm rounded-xl overflow-hidden">
        <div className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="h-12 w-12 rounded-xl bg-orange-500/10 border border-orange-500/20 flex items-center justify-center shrink-0">
              <BarChart2 className="h-6 w-6 text-orange-500" />
            </div>
            <div>
              <div className="text-xs uppercase font-mono tracking-wider text-orange-500 font-semibold">
                SOC Operations Visualization Hub
              </div>
              <div className="text-lg font-bold text-foreground mt-0.5">
                Grafana 11 Dashboard & Time-Series Analytics
              </div>
              <div className="text-xs text-muted-foreground mt-0.5">
                Pre-configured Prometheus data source on port 3001 with zero
                authentication required for presentations.
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <a
              href="http://localhost:9090"
              target="_blank"
              rel="noopener noreferrer"
            >
              <Button
                variant="outline"
                size="sm"
                className="text-xs h-9 gap-1.5 font-mono"
              >
                <Terminal className="h-3.5 w-3.5 text-muted-foreground" />
                <span>Prometheus UI (:9090)</span>
              </Button>
            </a>

            <a
              href="http://localhost:3001"
              target="_blank"
              rel="noopener noreferrer"
            >
              <Button
                size="sm"
                className="text-xs h-9 gap-1.5 bg-orange-600 hover:bg-orange-700 text-white font-semibold"
              >
                <ExternalLink className="h-3.5 w-3.5" />
                <span>Launch Grafana (:3001)</span>
              </Button>
            </a>
          </div>
        </div>
      </Card>

      {/* Metrics Overview Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <Card className="border-border bg-card shadow-sm p-3.5">
          <div className="text-[10px] uppercase font-mono text-muted-foreground">
            Uptime
          </div>
          <div className="text-xl font-bold font-mono text-foreground mt-0.5">
            {uptimeMinutes}m
          </div>
          <div className="text-[10px] text-muted-foreground mt-0.5 font-mono">
            {uptimeSec.toFixed(0)}s total
          </div>
        </Card>

        <Card className="border-border bg-card shadow-sm p-3.5">
          <div className="text-[10px] uppercase font-mono text-muted-foreground">
            Resident Memory
          </div>
          <div className="text-xl font-bold font-mono text-foreground mt-0.5">
            {memMb} MB
          </div>
          <div className="text-[10px] text-muted-foreground mt-0.5 font-mono">
            Process RSS
          </div>
        </Card>

        <Card className="border-border bg-card shadow-sm p-3.5">
          <div className="text-[10px] uppercase font-mono text-muted-foreground">
            Flows Ingested
          </div>
          <div className="text-xl font-bold font-mono text-cyan-500 mt-0.5">
            {flows}
          </div>
          <div className="text-[10px] text-muted-foreground mt-0.5 font-mono">
            Raw telemetry
          </div>
        </Card>

        <Card className="border-border bg-card shadow-sm p-3.5">
          <div className="text-[10px] uppercase font-mono text-muted-foreground">
            Windows Scanned
          </div>
          <div className="text-xl font-bold font-mono text-purple-500 mt-0.5">
            {windows}
          </div>
          <div className="text-[10px] text-muted-foreground mt-0.5 font-mono">
            15s aggregated
          </div>
        </Card>

        <Card className="border-border bg-card shadow-sm p-3.5">
          <div className="text-[10px] uppercase font-mono text-muted-foreground">
            Active Sensors
          </div>
          <div className="text-xl font-bold font-mono text-emerald-500 mt-0.5">
            {activeLoggers}
          </div>
          <div className="text-[10px] text-muted-foreground mt-0.5 font-mono">
            Loggers registered
          </div>
        </Card>

        <Card className="border-border bg-card shadow-sm p-3.5">
          <div className="text-[10px] uppercase font-mono text-muted-foreground">
            WS Clients
          </div>
          <div className="text-xl font-bold font-mono text-primary mt-0.5">
            {wsClients}
          </div>
          <div className="text-[10px] text-muted-foreground mt-0.5 font-mono">
            Live subscribers
          </div>
        </Card>
      </div>

      {/* Docker Compose Topology & Integration Guide */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Docker Compose Services Map (6 cols) */}
        <div className="lg:col-span-6">
          <Card className="border-border bg-card shadow-sm rounded-xl h-full flex flex-col">
            <CardHeader className="pb-3">
              <div className="flex items-center gap-2">
                <Server className="h-4 w-4 text-primary" />
                <CardTitle className="text-sm font-semibold tracking-wide uppercase text-foreground">
                  Docker Infrastructure Topology
                </CardTitle>
              </div>
              <CardDescription className="text-xs text-muted-foreground">
                Container services configured in docker-compose.yml
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-2.5 font-mono text-xs">
              {[
                {
                  name: "firewall_backend",
                  port: ":8000",
                  desc: "FastAPI World Model & /metrics exporter",
                  color: "text-purple-400",
                },
                {
                  name: "firewall_prometheus",
                  port: ":9090",
                  desc: "Scrapes backend:8000 every 5 seconds",
                  color: "text-red-400",
                },
                {
                  name: "firewall_grafana",
                  port: ":3001",
                  desc: "Operations dashboards with embedding",
                  color: "text-orange-400",
                },
                {
                  name: "firewall_kafka",
                  port: ":9092",
                  desc: "Apache Kafka KRaft message streaming broker",
                  color: "text-cyan-400",
                },
                {
                  name: "firewall_redis",
                  port: ":6379",
                  desc: "Real-time fault-tolerant telemetry store",
                  color: "text-emerald-400",
                },
              ].map((svc) => (
                <div
                  key={svc.name}
                  className="flex items-center justify-between p-2.5 rounded-lg border border-border bg-muted/20"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="h-1.5 w-1.5 rounded-full bg-primary shrink-0" />
                    <span className={`font-bold ${svc.color} truncate`}>
                      {svc.name}
                    </span>
                    <span className="text-[11px] text-muted-foreground">
                      {svc.port}
                    </span>
                  </div>
                  <span className="text-[11px] text-muted-foreground truncate ml-2">
                    {svc.desc}
                  </span>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>

        {/* Right: Prometheus Scrape Status & Endpoints (6 cols) */}
        <div className="lg:col-span-6">
          <Card className="border-border bg-card shadow-sm rounded-xl h-full flex flex-col">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Activity className="h-4 w-4 text-emerald-500" />
                  <CardTitle className="text-sm font-semibold tracking-wide uppercase text-foreground">
                    Scraping Configuration
                  </CardTitle>
                </div>
                <Badge
                  variant="outline"
                  className="text-[10px] font-mono border-emerald-500/30 text-emerald-500"
                >
                  Target Healthy
                </Badge>
              </div>
              <CardDescription className="text-xs text-muted-foreground">
                Configured scrape interval and target endpoints
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3 text-xs">
              <div className="p-3 rounded-lg bg-muted/40 border border-border font-mono space-y-1.5">
                <div className="text-muted-foreground">
                  <span className="text-foreground font-semibold">
                    Endpoint:
                  </span>{" "}
                  GET http://localhost:8000/metrics
                </div>
                <div className="text-muted-foreground">
                  <span className="text-foreground font-semibold">Format:</span>{" "}
                  Prometheus Text Exposition (v0.0.4)
                </div>
                <div className="text-muted-foreground">
                  <span className="text-foreground font-semibold">
                    Scrape Interval:
                  </span>{" "}
                  5 seconds
                </div>
                <div className="text-muted-foreground">
                  <span className="text-foreground font-semibold">
                    Metrics Exported:
                  </span>{" "}
                  15 custom firewall gauges & counters
                </div>
              </div>

              <div className="pt-1 flex items-center justify-between">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setShowRaw(!showRaw)}
                  className="text-xs h-8"
                >
                  <Terminal className="h-3.5 w-3.5 mr-1.5" />
                  {showRaw ? "Hide Raw Scrape" : "Inspect Raw /metrics Output"}
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    navigator.clipboard.writeText(rawMetrics);
                    toast.success("Raw Prometheus metrics copied");
                  }}
                  className="text-xs h-8"
                >
                  <Copy className="h-3.5 w-3.5 mr-1" />
                  Copy Output
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Raw Prometheus Text Output Viewer */}
      {showRaw && (
        <Card className="border-border bg-card shadow-sm rounded-xl">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-xs font-mono uppercase text-muted-foreground">
                Raw Prometheus Output (http://localhost:8000/metrics)
              </CardTitle>
              <Badge variant="outline" className="font-mono text-[10px]">
                {rawMetrics.split("\n").length} Lines
              </Badge>
            </div>
          </CardHeader>
          <CardContent>
            <pre className="text-[11px] font-mono p-4 bg-muted/40 rounded-lg max-h-[350px] overflow-y-auto text-foreground border border-border">
              {rawMetrics || "Scraping /metrics..."}
            </pre>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
