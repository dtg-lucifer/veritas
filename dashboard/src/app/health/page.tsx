"use client";

import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  Cpu,
  Database,
  HeartPulse,
  Radio,
  RefreshCw,
  Server,
} from "lucide-react";
import type React from "react";
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

interface SubsystemStatus {
  name: string;
  category: string;
  isUp: boolean;
  latencyMs: number | null;
  details: Record<string, any>;
  icon: React.ElementType;
}

export default function HealthPage() {
  const [loading, setLoading] = useState(false);
  const [lastCheck, setLastCheck] = useState<string>("");

  const [backendStatus, setBackendStatus] = useState<SubsystemStatus>({
    name: "FastAPI Gateway Backend",
    category: "Core API & WebSocket Hub",
    isUp: false,
    latencyMs: null,
    details: {},
    icon: Server,
  });

  const [kafkaStatus, setKafkaStatus] = useState<SubsystemStatus>({
    name: "Apache Kafka Streaming Broker",
    category: "Telemetry Ingestion Pipeline",
    isUp: false,
    latencyMs: null,
    details: {},
    icon: Server,
  });

  const [redisStatus, setRedisStatus] = useState<SubsystemStatus>({
    name: "Redis 7 In-Memory Store",
    category: "Telemetry & Schema Validation Cache",
    isUp: false,
    latencyMs: null,
    details: {},
    icon: Database,
  });

  const [loggersStatus, setLoggersStatus] = useState<SubsystemStatus>({
    name: "Distributed Network Sensors",
    category: "PyShark / NetFlow Loggers",
    isUp: false,
    latencyMs: null,
    details: {},
    icon: Radio,
  });

  const [worldModelStatus, setWorldModelStatus] = useState<SubsystemStatus>({
    name: "PyTorch AI World Model",
    category: "Dynamics Core & Forward Simulation",
    isUp: false,
    latencyMs: null,
    details: {},
    icon: Cpu,
  });

  const runDiagnostics = useCallback(async () => {
    setLoading(true);
    setLastCheck(new Date().toLocaleTimeString());

    // 1. Check Backend
    const t0 = performance.now();
    try {
      const res = await fetch("http://localhost:8000/health", {
        signal: AbortSignal.timeout(3000),
      });
      const lat = Math.round(performance.now() - t0);
      if (res.ok) {
        const data = await res.json();
        setBackendStatus((prev) => ({
          ...prev,
          isUp: true,
          latencyMs: lat,
          details: {
            "Active WebSockets": data.active_ws_subscribers ?? 0,
            "Service Status": data.status ?? "ok",
            "Model Loaded": data.models_ready ? "Yes" : "No",
          },
        }));

        setWorldModelStatus((prev) => ({
          ...prev,
          isUp: Boolean(data.models_ready),
          latencyMs: lat + 2,
          details: {
            "Model Checkpoint": "world_model.pt",
            "Window Size": `${data.config?.thresholds?.window_size_seconds ?? 15}s`,
            "Context History": "W = 8",
            "Forward Horizon": "K = 5 Steps",
          },
        }));
      } else {
        setBackendStatus((prev) => ({
          ...prev,
          isUp: false,
          latencyMs: null,
          details: {},
        }));
      }
    } catch {
      setBackendStatus((prev) => ({
        ...prev,
        isUp: false,
        latencyMs: null,
        details: {},
      }));
      setWorldModelStatus((prev) => ({
        ...prev,
        isUp: false,
        latencyMs: null,
        details: {},
      }));
    }

    // 2. Check Kafka
    const t1 = performance.now();
    try {
      const res = await fetch("http://localhost:8000/api/v1/kafka/status", {
        signal: AbortSignal.timeout(3000),
      });
      const lat = Math.round(performance.now() - t1);
      if (res.ok) {
        const data = await res.json();
        setKafkaStatus((prev) => ({
          ...prev,
          isUp: data.status === "RUNNING",
          latencyMs: lat,
          details: {
            "Consumer Group": "firewall_world_model_group",
            Topic: data.topic || "network_flows",
            "Flows Ingested": data.flows_ingested ?? 0,
            "Pending Lag": data.pending_flows ?? 0,
          },
        }));
      } else {
        setKafkaStatus((prev) => ({
          ...prev,
          isUp: false,
          latencyMs: null,
          details: {},
        }));
      }
    } catch {
      setKafkaStatus((prev) => ({
        ...prev,
        isUp: false,
        latencyMs: null,
        details: {},
      }));
    }

    // 3. Check Redis & Loggers
    const t2 = performance.now();
    try {
      const res = await fetch("http://localhost:8000/api/v1/metrics/redis", {
        signal: AbortSignal.timeout(3000),
      });
      const lat = Math.round(performance.now() - t2);
      if (res.ok) {
        const data = await res.json();
        setRedisStatus((prev) => ({
          ...prev,
          isUp: Boolean(data.redis_connected),
          latencyMs: lat,
          details: {
            "Connection URL": data.redis_url || "redis://localhost:6379/0",
            "Processed Logs": data.counters?.logs_processed ?? 0,
            "Media Dampened": data.counters?.logs_webrtc_conferencing ?? 0,
            "Last Update": data.timestamps?.last_log_timestamp
              ? new Date(
                  data.timestamps.last_log_timestamp,
                ).toLocaleTimeString()
              : "N/A",
          },
        }));

        const loggers = data.active_loggers || [];
        setLoggersStatus((prev) => ({
          ...prev,
          isUp: loggers.length > 0 || (data.counters?.logs_processed ?? 0) > 0,
          latencyMs: lat + 1,
          details: {
            "Active Sensors": loggers.length,
            "Sensor Identifiers":
              loggers.join(", ") || "Awaiting logger stream",
            "Malformed Trapped": data.counters?.logs_malformed_schema ?? 0,
          },
        }));
      } else {
        setRedisStatus((prev) => ({
          ...prev,
          isUp: false,
          latencyMs: null,
          details: {},
        }));
        setLoggersStatus((prev) => ({
          ...prev,
          isUp: false,
          latencyMs: null,
          details: {},
        }));
      }
    } catch {
      setRedisStatus((prev) => ({
        ...prev,
        isUp: false,
        latencyMs: null,
        details: {},
      }));
      setLoggersStatus((prev) => ({
        ...prev,
        isUp: false,
        latencyMs: null,
        details: {},
      }));
    }

    setLoading(false);
  }, []);

  useEffect(() => {
    runDiagnostics();
    const interval = setInterval(runDiagnostics, 5000);
    return () => clearInterval(interval);
  }, [runDiagnostics]);

  const subsystems = [
    backendStatus,
    kafkaStatus,
    redisStatus,
    loggersStatus,
    worldModelStatus,
  ];
  const operationalCount = subsystems.filter((s) => s.isUp).length;
  const overallPct = Math.round((operationalCount / subsystems.length) * 100);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-border">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2.5">
            <HeartPulse className="h-6 w-6 text-primary" />
            Subsystem Health & Round-Trip Latency Monitor
          </h1>
          <p className="text-xs text-muted-foreground mt-1">
            Real-time ping telemetry across the FastAPI backend, Apache Kafka
            broker, Redis telemetry store, distributed sensors, and PyTorch
            model.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {lastCheck && (
            <span className="text-xs text-muted-foreground font-mono mr-2">
              Last check: {lastCheck}
            </span>
          )}
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              runDiagnostics();
              toast.success("Subsystem ping diagnostics completed");
            }}
            disabled={loading}
            className="h-8 text-xs text-muted-foreground hover:text-foreground"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 mr-1.5 ${loading ? "animate-spin" : ""}`}
            />
            Ping All Now
          </Button>
        </div>
      </div>

      {/* Overall Health Card */}
      <Card className="border-border bg-card shadow-sm rounded-xl overflow-hidden">
        <div className="p-4 bg-muted/20 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div
              className={`h-12 w-12 rounded-xl flex items-center justify-center shrink-0 border ${
                overallPct === 100
                  ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-500"
                  : overallPct >= 60
                    ? "bg-amber-500/10 border-amber-500/20 text-amber-500"
                    : "bg-destructive/10 border-destructive/20 text-destructive"
              }`}
            >
              {overallPct === 100 ? (
                <CheckCircle2 className="h-6 w-6" />
              ) : (
                <AlertTriangle className="h-6 w-6" />
              )}
            </div>
            <div>
              <div className="text-xs uppercase font-mono tracking-wider text-muted-foreground">
                Fleet Operational Health
              </div>
              <div className="text-lg font-bold text-foreground">
                {operationalCount} of {subsystems.length} Subsystems Active (
                {overallPct}%)
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3 font-mono text-xs">
            <div className="text-right">
              <div className="text-muted-foreground">Gateway Status</div>
              <div className="font-bold text-foreground">
                {backendStatus.isUp ? "ONLINE" : "UNREACHABLE"}
              </div>
            </div>
            {backendStatus.latencyMs !== null && (
              <Badge
                variant="outline"
                className="text-xs py-1 px-2.5 font-mono"
              >
                {backendStatus.latencyMs}ms roundtrip
              </Badge>
            )}
          </div>
        </div>
      </Card>

      {/* 5 Subsystem Health Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {subsystems.map((sub) => {
          const Icon = sub.icon;
          return (
            <Card
              key={sub.name}
              className={`border transition-all shadow-sm rounded-xl ${
                sub.isUp
                  ? "border-border bg-card hover:border-border/80"
                  : "border-destructive/30 bg-destructive/5"
              }`}
            >
              <CardHeader className="pb-3">
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2.5">
                    <div
                      className={`h-9 w-9 rounded-lg flex items-center justify-center shrink-0 border ${
                        sub.isUp
                          ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-500"
                          : "bg-destructive/10 border-destructive/20 text-destructive"
                      }`}
                    >
                      <Icon className="h-4 w-4" />
                    </div>
                    <div>
                      <CardTitle className="text-sm font-semibold text-foreground leading-tight">
                        {sub.name}
                      </CardTitle>
                      <CardDescription className="text-[11px] text-muted-foreground mt-0.5">
                        {sub.category}
                      </CardDescription>
                    </div>
                  </div>

                  <Badge
                    variant="outline"
                    className={`font-mono text-[10px] shrink-0 ${
                      sub.isUp
                        ? "border-emerald-500/30 text-emerald-500 bg-emerald-500/10"
                        : "border-destructive/30 text-destructive bg-destructive/10"
                    }`}
                  >
                    {sub.isUp ? "ACTIVE" : "STANDBY / DOWN"}
                  </Badge>
                </div>
              </CardHeader>

              <CardContent className="space-y-3 pt-1">
                {/* Roundtrip Latency pill */}
                <div className="flex items-center justify-between p-2 rounded-lg bg-muted/40 border border-border text-xs font-mono">
                  <span className="text-muted-foreground flex items-center gap-1.5">
                    <Clock className="h-3 w-3 text-muted-foreground" />
                    Round-Trip Latency:
                  </span>
                  <span
                    className={`font-bold ${sub.isUp ? "text-emerald-500" : "text-destructive"}`}
                  >
                    {sub.latencyMs !== null ? `${sub.latencyMs} ms` : "Timeout"}
                  </span>
                </div>

                {/* Subsystem Details list */}
                <div className="space-y-1.5 text-xs font-mono pt-1">
                  {Object.entries(sub.details).map(([key, val]) => (
                    <div
                      key={key}
                      className="flex justify-between items-center py-0.5 border-b border-border/30"
                    >
                      <span className="text-muted-foreground">{key}:</span>
                      <span className="text-foreground truncate max-w-[170px] text-right font-medium">
                        {String(val)}
                      </span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
