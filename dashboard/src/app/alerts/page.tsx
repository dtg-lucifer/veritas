"use client";

import { AnimatePresence, motion } from "framer-motion";
import {
  Activity,
  AlertTriangle,
  ArrowDown,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Clock,
  Copy,
  Download,
  Filter,
  Layers,
  Pause,
  Play,
  Radio,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Target,
  Terminal,
  Trash2,
  Zap,
} from "lucide-react";
import type React from "react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
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
import { ScrollArea } from "@/components/ui/scroll-area";

export interface AlertLog {
  id: string;
  timestamp: string;
  target: string;
  risk_score: number;
  classification: "NORMAL" | "SUSPICIOUS" | "CRITICAL";
  mitre_stage: string;
  policy_action: string;
  soc_guidance?: string;
  top_attributions?: Array<{ feature: string; score: number; raw_value?: number }>;
  rollout_steps?: Array<{
    step: number;
    relative_seconds: number;
    infiltration_prob: number;
    mitre_stage: string;
    status: string;
    policy_action: string;
  }>;
  rawPayload?: any;
}

export default function AlertsStreamPage() {
  const [logs, setLogs] = useState<AlertLog[]>([]);
  const [wsConnected, setWsConnected] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<"ALL" | "CRITICAL" | "SUSPICIOUS" | "NORMAL">("ALL");
  const [selectedLog, setSelectedLog] = useState<AlertLog | null>(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const [isolatingIp, setIsolatingIp] = useState<string | null>(null);

  const scrollRef = useRef<HTMLDivElement>(null);
  const isPausedRef = useRef(isPaused);
  isPausedRef.current = isPaused;

  const wsUrl = useMemo(() => {
    if (typeof window === "undefined") return "ws://localhost:8000/ws/alerts";
    const host = window.location.hostname || "localhost";
    return process.env.NEXT_PUBLIC_WS_URL || `ws://${host}:8000/ws/alerts`;
  }, []);

  // Pre-populate historical alerts from REST endpoint
  const loadHistoricalAlerts = useCallback(async () => {
    try {
      const res = await fetch("http://localhost:8000/api/v1/alerts", {
        signal: AbortSignal.timeout(3000),
      });
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data.alerts)) {
          const mapped: AlertLog[] = data.alerts.map((a: any, i: number) => {
            const rep = a.report || {};
            const prob = a.max_infiltration_prob || rep.max_infiltration_prob || 0;
            const riskPct = prob > 1 ? prob : prob * 100;
            const sev =
              a.severity ||
              (riskPct >= 70 ? "CRITICAL" : riskPct >= 40 ? "SUSPICIOUS" : "NORMAL");

            return {
              id: `hist-${i}-${a.timestamp || Date.now()}`,
              timestamp: a.timestamp || new Date().toISOString(),
              target: a.target || a.target_ip || "10.0.4.21",
              risk_score: riskPct,
              classification: sev,
              mitre_stage: a.mitre_stage || rep.peak_stage || "Threat Escalation",
              policy_action: a.policy_action || rep.recommended_policy || "ALLOW",
              soc_guidance: rep.soc_guidance,
              top_attributions: rep.top_attributions,
              rollout_steps: rep.rollout_steps,
              rawPayload: a,
            };
          });
          setLogs(mapped.reverse());
        }
      }
    } catch {
      // offline fallback
    }
  }, []);

  // WebSocket Live Stream Connection
  useEffect(() => {
    loadHistoricalAlerts();

    let ws: WebSocket | null = null;
    let timer: any = null;
    let isDestroyed = false;

    const connect = () => {
      if (isDestroyed) return;
      try {
        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
          if (!isDestroyed) setWsConnected(true);
        };

        ws.onclose = () => {
          if (isDestroyed) return;
          setWsConnected(false);
          timer = setTimeout(connect, 3000);
        };

        ws.onerror = () => {
          if (isDestroyed) return;
          setWsConnected(false);
          ws?.close();
        };

        ws.onmessage = (event) => {
          if (isPausedRef.current || isDestroyed) return;
          try {
            const data = JSON.parse(event.data);
            if (data.type === "CONNECTION_ESTABLISHED") return;

            if (
              data.type === "WORLD_MODEL_PREDICTION_ALERT" ||
              data.type === "SECURITY_INCIDENT_ALERT"
            ) {
              const rep = data.report || data.alert || {};
              const prob = data.max_infiltration_prob || rep.max_infiltration_prob || 0;
              const riskPct = prob > 1 ? prob : prob * 100;
              const sev =
                data.severity ||
                (riskPct >= 70 ? "CRITICAL" : riskPct >= 40 ? "SUSPICIOUS" : "NORMAL");

              const newLog: AlertLog = {
                id: `ws-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
                timestamp: data.timestamp || new Date().toISOString(),
                target: data.target || "10.0.4.21",
                risk_score: riskPct,
                classification: sev,
                mitre_stage: data.mitre_stage || rep.peak_stage || "Threat Escalation",
                policy_action: data.policy_action || rep.recommended_policy || "ISOLATE_DEVICE",
                soc_guidance: rep.soc_guidance,
                top_attributions: rep.top_attributions,
                rollout_steps: rep.rollout_steps,
                rawPayload: data,
              };

              setLogs((prev) => [newLog, ...prev].slice(0, 500));
            } else if (data.type === "FIREWALL_POLICY_ENFORCED") {
              const enforceLog: AlertLog = {
                id: `policy-${Date.now()}`,
                timestamp: new Date().toISOString(),
                target: data.data?.ip || "Host",
                risk_score: 100,
                classification: "CRITICAL",
                mitre_stage: "Host Quarantine Enforced",
                policy_action: data.data?.action || "ISOLATE_DEVICE",
                soc_guidance: data.data?.reason || "Autonomous firewall enforcement rule triggered.",
                rawPayload: data,
              };
              setLogs((prev) => [enforceLog, ...prev].slice(0, 500));
            }
          } catch (e) {
            console.error("Alert log parse error:", e);
          }
        };
      } catch {
        if (!isDestroyed) setWsConnected(false);
      }
    };

    connect();

    return () => {
      isDestroyed = true;
      clearTimeout(timer);
      if (ws) {
        ws.onclose = null;
        ws.onerror = null;
        ws.close();
      }
    };
  }, [wsUrl, loadHistoricalAlerts]);

  // Filter logs by search & severity
  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      if (severityFilter !== "ALL" && log.classification !== severityFilter) {
        return false;
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchIp = log.target.toLowerCase().includes(q);
        const matchStage = log.mitre_stage.toLowerCase().includes(q);
        const matchPolicy = log.policy_action.toLowerCase().includes(q);
        const matchGuidance = (log.soc_guidance || "").toLowerCase().includes(q);
        return matchIp || matchStage || matchPolicy || matchGuidance;
      }
      return true;
    });
  }, [logs, severityFilter, searchQuery]);

  const handleIsolateHost = async (targetIp: string) => {
    try {
      setIsolatingIp(targetIp);
      const res = await fetch("http://localhost:8000/api/v1/policy/enforce", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_ip: targetIp,
          action: "ISOLATE_DEVICE",
          reason: "Manual operator quarantine triggered from /alerts log terminal",
        }),
      });
      if (res.ok) {
        toast.error(`Quarantine Policy Enforced: ${targetIp}`, {
          description: "Target traffic blocked across network gateway.",
        });
      } else {
        toast.error("Host isolation request failed");
      }
    } catch {
      toast.error("Failed to reach backend");
    } finally {
      setIsolatingIp(null);
    }
  };

  const handleExportJson = () => {
    const dataStr = JSON.stringify(logs, null, 2);
    const blob = new Blob([dataStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `firewall-websocket-alerts-${new Date().toISOString().slice(0, 19)}.json`;
    link.click();
    URL.revokeObjectURL(url);
    toast.success("Alert logs exported to JSON");
  };

  const criticalCount = logs.filter((l) => l.classification === "CRITICAL").length;
  const suspiciousCount = logs.filter((l) => l.classification === "SUSPICIOUS").length;
  const normalCount = logs.filter((l) => l.classification === "NORMAL").length;

  return (
    <div className="space-y-6">
      {/* Top Banner & Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-border">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2.5">
            <Radio className="h-6 w-6 text-primary" />
            Live WebSocket Alert Stream Terminal
          </h1>
          <p className="text-xs text-muted-foreground mt-1">
            Real-time feed streamed directly from <span className="font-mono text-foreground font-semibold">{wsUrl}</span>
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <Badge
            variant="outline"
            className={`font-mono text-xs py-1 px-3 flex items-center gap-2 ${
              wsConnected
                ? "border-emerald-500/30 text-emerald-500 bg-emerald-500/10"
                : "border-destructive/30 text-destructive bg-destructive/10"
            }`}
          >
            <span
              className={`h-2 w-2 rounded-full ${
                wsConnected ? "bg-emerald-500 animate-pulse" : "bg-destructive"
              }`}
            />
            <span>{wsConnected ? "STREAM LIVE" : "DISCONNECTED"}</span>
          </Badge>

          <Button
            variant="outline"
            size="sm"
            onClick={() => setIsPaused(!isPaused)}
            className="h-8 text-xs font-semibold gap-1.5"
          >
            {isPaused ? (
              <>
                <Play className="h-3.5 w-3.5 text-emerald-500 fill-emerald-500" />
                <span>Resume Stream</span>
              </>
            ) : (
              <>
                <Pause className="h-3.5 w-3.5 text-amber-500" />
                <span>Pause Stream</span>
              </>
            )}
          </Button>

          <Button
            variant="outline"
            size="sm"
            onClick={handleExportJson}
            disabled={logs.length === 0}
            className="h-8 text-xs font-medium gap-1.5"
          >
            <Download className="h-3.5 w-3.5" />
            <span>Export JSON</span>
          </Button>

          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setLogs([]);
              toast.info("Alert log buffer cleared");
            }}
            className="h-8 text-xs text-muted-foreground hover:text-destructive"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>

      {/* 4 Metric Counter Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Card className="border-border bg-card shadow-sm p-3.5">
          <div className="text-[10px] uppercase font-mono text-muted-foreground">Total Streamed</div>
          <div className="text-xl font-bold font-mono text-foreground mt-0.5">{logs.length}</div>
          <div className="text-[10px] text-muted-foreground mt-0.5 font-mono">In memory buffer</div>
        </Card>
        <Card className="border-border bg-card shadow-sm p-3.5">
          <div className="text-[10px] uppercase font-mono text-destructive">Critical Infiltration</div>
          <div className="text-xl font-bold font-mono text-destructive mt-0.5">{criticalCount}</div>
          <div className="text-[10px] text-muted-foreground mt-0.5 font-mono">Rollout risk &ge; 70%</div>
        </Card>
        <Card className="border-border bg-card shadow-sm p-3.5">
          <div className="text-[10px] uppercase font-mono text-amber-500">Suspicious Probes</div>
          <div className="text-xl font-bold font-mono text-amber-500 mt-0.5">{suspiciousCount}</div>
          <div className="text-[10px] text-muted-foreground mt-0.5 font-mono">Rollout risk 40–69%</div>
        </Card>
        <Card className="border-border bg-card shadow-sm p-3.5">
          <div className="text-[10px] uppercase font-mono text-emerald-500">Nominal Windows</div>
          <div className="text-xl font-bold font-mono text-emerald-500 mt-0.5">{normalCount}</div>
          <div className="text-[10px] text-muted-foreground mt-0.5 font-mono">Benign baselines</div>
        </Card>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 p-2 bg-card border border-border rounded-xl">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search IP, MITRE stage, or guidance notes..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-1.5 text-xs bg-muted/40 rounded-lg border border-border focus:outline-hidden focus:ring-1 focus:ring-primary text-foreground placeholder:text-muted-foreground font-mono"
          />
        </div>

        {/* Severity Filter Tabs */}
        <div className="flex items-center gap-1 p-0.5 bg-muted/40 rounded-lg border border-border text-xs">
          <button
            type="button"
            onClick={() => setSeverityFilter("ALL")}
            className={`px-3 py-1 rounded-md text-xs transition-all cursor-pointer font-medium ${
              severityFilter === "ALL"
                ? "bg-card text-foreground font-semibold shadow-xs border border-border"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            All ({logs.length})
          </button>
          <button
            type="button"
            onClick={() => setSeverityFilter("CRITICAL")}
            className={`px-3 py-1 rounded-md text-xs transition-all cursor-pointer font-medium flex items-center gap-1.5 ${
              severityFilter === "CRITICAL"
                ? "bg-destructive/15 text-destructive border border-destructive/30 font-semibold"
                : "text-muted-foreground hover:text-destructive"
            }`}
          >
            <span className="h-1.5 w-1.5 rounded-full bg-destructive" />
            Critical ({criticalCount})
          </button>
          <button
            type="button"
            onClick={() => setSeverityFilter("SUSPICIOUS")}
            className={`px-3 py-1 rounded-md text-xs transition-all cursor-pointer font-medium flex items-center gap-1.5 ${
              severityFilter === "SUSPICIOUS"
                ? "bg-amber-500/15 text-amber-500 border border-amber-500/30 font-semibold"
                : "text-muted-foreground hover:text-amber-500"
            }`}
          >
            <span className="h-1.5 w-1.5 rounded-full bg-amber-500" />
            Suspicious ({suspiciousCount})
          </button>
          <button
            type="button"
            onClick={() => setSeverityFilter("NORMAL")}
            className={`px-3 py-1 rounded-md text-xs transition-all cursor-pointer font-medium flex items-center gap-1.5 ${
              severityFilter === "NORMAL"
                ? "bg-emerald-500/15 text-emerald-500 border border-emerald-500/30 font-semibold"
                : "text-muted-foreground hover:text-emerald-500"
            }`}
          >
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
            Normal ({normalCount})
          </button>
        </div>
      </div>

      {/* Main Stream Area */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Live Stream List (7 cols) */}
        <div className="lg:col-span-7 space-y-2">
          <div className="flex items-center justify-between text-xs text-muted-foreground px-1">
            <span>Displaying {filteredLogs.length} matching events</span>
            {isPaused && (
              <span className="text-amber-500 font-mono flex items-center gap-1">
                <Pause className="h-3 w-3" /> Stream Paused
              </span>
            )}
          </div>

          <ScrollArea className="h-[620px] rounded-xl border border-border bg-card/60 p-2.5">
            <div className="space-y-2">
              <AnimatePresence initial={false}>
                {filteredLogs.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-20 text-center text-muted-foreground space-y-3">
                    <ShieldCheck className="h-10 w-10 text-emerald-500/60" />
                    <p className="text-sm font-medium text-foreground">No matching incidents in stream</p>
                    <p className="text-xs max-w-sm text-muted-foreground">
                      Events will populate automatically as network traffic flows through the Kafka pipeline and PyTorch forward simulation.
                    </p>
                  </div>
                ) : (
                  filteredLogs.map((log) => {
                    const isSelected = selectedLog?.id === log.id;
                    return (
                      <motion.div
                        key={log.id}
                        layout
                        initial={{ opacity: 0, y: -6 }}
                        animate={{ opacity: 1, y: 0 }}
                        onClick={() => setSelectedLog(log)}
                        className={`p-3 rounded-lg border transition-all cursor-pointer ${
                          isSelected
                            ? "border-primary bg-primary/5 shadow-xs"
                            : log.classification === "CRITICAL"
                              ? "border-destructive/30 bg-destructive/5 hover:bg-destructive/10"
                              : log.classification === "SUSPICIOUS"
                                ? "border-amber-500/30 bg-amber-500/5 hover:bg-amber-500/10"
                                : "border-border bg-card hover:bg-muted/30"
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <div className="flex items-center gap-2.5 min-w-0">
                            {log.classification === "CRITICAL" ? (
                              <ShieldAlert className="h-4 w-4 text-destructive shrink-0" />
                            ) : log.classification === "SUSPICIOUS" ? (
                              <AlertTriangle className="h-4 w-4 text-amber-500 shrink-0" />
                            ) : (
                              <ShieldCheck className="h-4 w-4 text-emerald-500 shrink-0" />
                            )}
                            <span className="font-semibold text-xs text-foreground truncate">
                              {log.mitre_stage}
                            </span>
                            <span className="font-mono text-[11px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground">
                              {log.target}
                            </span>
                          </div>

                          <div className="flex items-center gap-2 shrink-0">
                            <Badge
                              variant="outline"
                              className={`font-mono text-[10px] ${
                                log.classification === "CRITICAL"
                                  ? "text-destructive border-destructive/30 bg-destructive/10"
                                  : log.classification === "SUSPICIOUS"
                                    ? "text-amber-500 border-amber-500/30 bg-amber-500/10"
                                    : "text-emerald-500 border-emerald-500/30 bg-emerald-500/10"
                              }`}
                            >
                              {log.risk_score.toFixed(1)}% Risk
                            </Badge>
                            <span className="text-[10px] font-mono text-muted-foreground">
                              {new Date(log.timestamp).toLocaleTimeString()}
                            </span>
                          </div>
                        </div>

                        {log.soc_guidance && (
                          <p className="text-[11px] text-muted-foreground mt-1.5 line-clamp-1">
                            {log.soc_guidance}
                          </p>
                        )}
                      </motion.div>
                    );
                  })
                )}
              </AnimatePresence>
            </div>
          </ScrollArea>
        </div>

        {/* Right: Detailed Log Forensics Inspector (5 cols) */}
        <div className="lg:col-span-5">
          <Card className="border-border bg-card shadow-sm rounded-xl h-[660px] flex flex-col">
            <CardHeader className="pb-3 border-b border-border">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Terminal className="h-4 w-4 text-primary" />
                  <CardTitle className="text-sm font-semibold uppercase tracking-wider text-foreground">
                    Forensic Inspector
                  </CardTitle>
                </div>
                {selectedLog && (
                  <Badge
                    variant="outline"
                    className={`font-mono text-[10px] ${
                      selectedLog.classification === "CRITICAL"
                        ? "text-destructive border-destructive/30 bg-destructive/10"
                        : "text-amber-500 border-amber-500/30 bg-amber-500/10"
                    }`}
                  >
                    {selectedLog.classification}
                  </Badge>
                )}
              </div>
              <CardDescription className="text-xs text-muted-foreground">
                {selectedLog
                  ? `Inspection for incident: ${selectedLog.id}`
                  : "Click any event in the live stream to inspect deep rollout forensics."}
              </CardDescription>
            </CardHeader>

            <CardContent className="flex-1 overflow-y-auto p-4 space-y-4">
              {selectedLog ? (
                <>
                  {/* Target & Mitre details */}
                  <div className="p-3 bg-muted/40 rounded-lg border border-border font-mono text-xs space-y-1.5">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Target IP:</span>
                      <span className="font-bold text-foreground">{selectedLog.target}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">MITRE Stage:</span>
                      <span className="font-bold text-foreground">{selectedLog.mitre_stage}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Forecasted Risk:</span>
                      <span className="font-bold text-destructive">{selectedLog.risk_score.toFixed(1)}%</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Recommended Policy:</span>
                      <span className="font-bold text-primary">{selectedLog.policy_action}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Timestamp:</span>
                      <span className="text-foreground">{selectedLog.timestamp}</span>
                    </div>
                  </div>

                  {/* SOC Analyst Guidance */}
                  {selectedLog.soc_guidance && (
                    <div className="space-y-1">
                      <div className="text-[11px] uppercase font-mono text-muted-foreground font-semibold">
                        Analyst Action Guidance
                      </div>
                      <p className="text-xs p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400">
                        {selectedLog.soc_guidance}
                      </p>
                    </div>
                  )}

                  {/* K-step forward simulation rollout */}
                  {selectedLog.rollout_steps && selectedLog.rollout_steps.length > 0 && (
                    <div className="space-y-1.5">
                      <div className="text-[11px] uppercase font-mono text-muted-foreground font-semibold">
                        Forward Horizon Forecast (+75s)
                      </div>
                      <div className="grid grid-cols-5 gap-1.5 text-center">
                        {selectedLog.rollout_steps.map((step) => (
                          <div
                            key={step.step}
                            className="p-2 rounded-md bg-muted/40 border border-border"
                          >
                            <div className="text-[9px] font-mono text-muted-foreground">
                              +{step.relative_seconds}s
                            </div>
                            <div
                              className={`text-xs font-bold font-mono mt-0.5 ${
                                step.infiltration_prob >= 0.7
                                  ? "text-destructive"
                                  : step.infiltration_prob >= 0.4
                                    ? "text-amber-500"
                                    : "text-emerald-500"
                              }`}
                            >
                              {(step.infiltration_prob * 100).toFixed(0)}%
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Top Driving Attribution Features */}
                  {selectedLog.top_attributions && selectedLog.top_attributions.length > 0 && (
                    <div className="space-y-1.5">
                      <div className="text-[11px] uppercase font-mono text-muted-foreground font-semibold">
                        Top Driving Attribution Features (XAI)
                      </div>
                      <div className="space-y-1">
                        {selectedLog.top_attributions.map((attr) => (
                          <div
                            key={attr.feature}
                            className="flex justify-between items-center p-1.5 rounded bg-muted/30 text-xs font-mono border border-border/40"
                          >
                            <span className="text-muted-foreground truncate">{attr.feature}</span>
                            <span className="text-foreground font-bold">
                              {(attr.score * 100).toFixed(1)}%
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Quarantine Action Trigger */}
                  <div className="pt-2 flex items-center justify-between border-t border-border">
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() => handleIsolateHost(selectedLog.target)}
                      disabled={isolatingIp === selectedLog.target}
                      className="text-xs font-semibold gap-1.5 h-8"
                    >
                      <Target className="h-3.5 w-3.5" />
                      <span>
                        {isolatingIp === selectedLog.target
                          ? "Isolating Host..."
                          : `Quarantine Host ${selectedLog.target}`}
                      </span>
                    </Button>

                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        navigator.clipboard.writeText(JSON.stringify(selectedLog.rawPayload || selectedLog, null, 2));
                        toast.success("JSON copied to clipboard");
                      }}
                      className="text-xs h-8 gap-1.5"
                    >
                      <Copy className="h-3.5 w-3.5" />
                      <span>Copy Payload</span>
                    </Button>
                  </div>
                </>
              ) : (
                <div className="flex flex-col items-center justify-center h-full text-center text-muted-foreground py-16 space-y-2">
                  <Terminal className="h-8 w-8 text-muted-foreground/50" />
                  <p className="text-xs">Select any incident on the left to inspect raw forecast attributions.</p>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
