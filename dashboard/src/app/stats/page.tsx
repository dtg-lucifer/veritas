"use client";

import {
  Activity,
  BarChart3,
  CheckCircle2,
  Copy,
  Database,
  FileWarning,
  Radio,
  RefreshCw,
  Search,
  ShieldAlert,
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

export default function StatsPage() {
  const [loading, setLoading] = useState(true);
  const [redisData, setRedisData] = useState<any>(null);
  const [simStatus, setSimStatus] = useState<any>(null);
  const [alertsList, setAlertsList] = useState<any[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");

  const fetchStats = useCallback(async () => {
    try {
      setLoading(true);
      const [rRes, sRes, aRes] = await Promise.allSettled([
        fetch("http://localhost:8000/api/v1/metrics/redis"),
        fetch("http://localhost:8000/api/v1/simulation/status"),
        fetch("http://localhost:8000/api/v1/alerts"),
      ]);

      if (rRes.status === "fulfilled" && rRes.value.ok) {
        setRedisData(await rRes.value.json());
      }
      if (sRes.status === "fulfilled" && sRes.value.ok) {
        setSimStatus(await sRes.value.json());
      }
      if (aRes.status === "fulfilled" && aRes.value.ok) {
        const aData = await aRes.value.json();
        setAlertsList(aData.alerts || []);
      }
    } catch {
      toast.error("Failed to refresh statistics");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 5000);
    return () => clearInterval(interval);
  }, [fetchStats]);

  const counters = redisData?.counters || {};
  const activeLoggers = redisData?.active_loggers || [];
  const malformedSamples = redisData?.recent_malformed_samples || [];
  const recentEvaluations = redisData?.recent_evaluations || [];

  // Filter alerts
  const filteredAlerts = alertsList.filter((alert) => {
    const rep = alert.report || {};
    const severity = (
      alert.severity ||
      (alert.max_infiltration_prob >= 0.7
        ? "CRITICAL"
        : alert.max_infiltration_prob >= 0.4
          ? "SUSPICIOUS"
          : "NORMAL")
    ).toUpperCase();
    const target = alert.target || alert.target_ip || "10.0.4.21";
    const stage = alert.mitre_stage || rep.peak_stage || "";

    const matchesSeverity =
      severityFilter === "ALL" || severity === severityFilter;
    const matchesSearch =
      target.toLowerCase().includes(searchQuery.toLowerCase()) ||
      stage.toLowerCase().includes(searchQuery.toLowerCase());

    return matchesSeverity && matchesSearch;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-border">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2.5">
            <BarChart3 className="h-6 w-6 text-primary" />
            Complete SOC Statistics & Ingestion Forensics
          </h1>
          <p className="text-xs text-muted-foreground mt-1">
            Deep-dive metrics across Redis telemetry buffers, sensor heartbeats,
            malformed flow samples, and historical 15s evaluation cycles.
          </p>
        </div>

        <Button
          variant="outline"
          size="sm"
          onClick={() => {
            fetchStats();
            toast.success("All statistics refreshed");
          }}
          disabled={loading}
          className="h-8 text-xs text-muted-foreground hover:text-foreground"
        >
          <RefreshCw
            className={`h-3.5 w-3.5 mr-1.5 ${loading ? "animate-spin" : ""}`}
          />
          Refresh Stats
        </Button>
      </div>

      {/* Row 1: Key Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <Card className="border-border bg-card shadow-sm">
          <CardContent className="pt-4 pb-3">
            <div className="text-[11px] uppercase font-mono text-muted-foreground">
              Total Ingested
            </div>
            <div className="text-2xl font-bold font-mono text-foreground mt-0.5">
              {counters.logs_processed || simStatus?.flows_ingested || 0}
            </div>
            <div className="text-[10px] text-muted-foreground mt-1">
              Flow records processed
            </div>
          </CardContent>
        </Card>

        <Card className="border-border bg-card shadow-sm">
          <CardContent className="pt-4 pb-3">
            <div className="text-[11px] uppercase font-mono text-muted-foreground">
              15s Windows
            </div>
            <div className="text-2xl font-bold font-mono text-foreground mt-0.5">
              {counters.windows_evaluated || simStatus?.windows_evaluated || 0}
            </div>
            <div className="text-[10px] text-muted-foreground mt-1">
              Evaluations executed
            </div>
          </CardContent>
        </Card>

        <Card className="border-border bg-card shadow-sm">
          <CardContent className="pt-4 pb-3">
            <div className="text-[11px] uppercase font-mono text-muted-foreground">
              Media Dampened
            </div>
            <div className="text-2xl font-bold font-mono text-emerald-500 mt-0.5">
              {counters.logs_webrtc_conferencing || 0}
            </div>
            <div className="text-[10px] text-muted-foreground mt-1">
              Video call packets normalized
            </div>
          </CardContent>
        </Card>

        <Card className="border-border bg-card shadow-sm">
          <CardContent className="pt-4 pb-3">
            <div className="text-[11px] uppercase font-mono text-muted-foreground">
              Schema Rejections
            </div>
            <div className="text-2xl font-bold font-mono text-destructive mt-0.5">
              {counters.logs_malformed_schema || counters.logs_ignored || 0}
            </div>
            <div className="text-[10px] text-muted-foreground mt-1">
              Malformed packet traps
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Row 2: Active Sensors & Malformed Packet Samples */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Active Distributed Sensors Directory (5 cols) */}
        <div className="lg:col-span-5 space-y-6">
          <Card className="border-border bg-card shadow-sm rounded-xl">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Radio className="h-4 w-4 text-emerald-500" />
                  <CardTitle className="text-sm font-semibold tracking-wide uppercase text-foreground">
                    Sensor Directory
                  </CardTitle>
                </div>
                <Badge
                  variant="outline"
                  className="text-[10px] font-mono border-emerald-500/30 text-emerald-500"
                >
                  {activeLoggers.length} Connected
                </Badge>
              </div>
              <CardDescription className="text-xs text-muted-foreground">
                Registered packet sniffers, replayers, and gateway agents
              </CardDescription>
            </CardHeader>
            <CardContent>
              {activeLoggers.length === 0 ? (
                <div className="text-xs text-muted-foreground text-center py-6 border border-dashed border-border rounded-lg">
                  No active loggers registered in Redis yet.
                </div>
              ) : (
                <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1">
                  {activeLoggers.map((loggerId: string) => (
                    <div
                      key={loggerId}
                      className="flex items-center justify-between p-2.5 rounded-lg border border-border bg-muted/30 text-xs"
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="h-2 w-2 rounded-full bg-emerald-500 shrink-0 animate-pulse" />
                        <span className="font-mono text-foreground truncate font-medium">
                          {loggerId}
                        </span>
                      </div>
                      <Badge
                        variant="outline"
                        className="text-[10px] font-mono shrink-0"
                      >
                        Online
                      </Badge>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Redis Telemetry Health Info */}
          <Card className="border-border bg-card shadow-sm rounded-xl">
            <CardHeader className="pb-3">
              <div className="flex items-center gap-2">
                <Database className="h-4 w-4 text-red-500" />
                <CardTitle className="text-sm font-semibold tracking-wide uppercase text-foreground">
                  Redis Buffer Health
                </CardTitle>
              </div>
            </CardHeader>
            <CardContent className="space-y-2 text-xs font-mono">
              <div className="flex justify-between py-1 border-b border-border/40">
                <span className="text-muted-foreground">
                  Connection Status:
                </span>
                <span className="text-emerald-500 font-bold">
                  {redisData?.redis_connected ? "Connected" : "Standby"}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-border/40">
                <span className="text-muted-foreground">Target URL:</span>
                <span className="text-foreground truncate max-w-[200px]">
                  {redisData?.redis_url || "redis://localhost:6379/0"}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-border/40">
                <span className="text-muted-foreground">Last Log Arrival:</span>
                <span className="text-foreground">
                  {redisData?.timestamps?.last_log_timestamp
                    ? new Date(
                        redisData.timestamps.last_log_timestamp,
                      ).toLocaleTimeString()
                    : "N/A"}
                </span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-muted-foreground">Last Evaluation:</span>
                <span className="text-foreground">
                  {redisData?.timestamps?.last_evaluation_timestamp
                    ? new Date(
                        redisData.timestamps.last_evaluation_timestamp,
                      ).toLocaleTimeString()
                    : "N/A"}
                </span>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Right: Rogue Logger & Malformed Packet Samples (7 cols) */}
        <div className="lg:col-span-7">
          <Card className="border-border bg-card shadow-sm rounded-xl h-full flex flex-col">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FileWarning className="h-4 w-4 text-destructive" />
                  <CardTitle className="text-sm font-semibold tracking-wide uppercase text-foreground">
                    Malformed Schema & Rogue Logger Traps
                  </CardTitle>
                </div>
                <Badge
                  variant="outline"
                  className="text-[10px] font-mono border-destructive/30 text-destructive"
                >
                  {malformedSamples.length} Samples Caught
                </Badge>
              </div>
              <CardDescription className="text-xs text-muted-foreground">
                Fail-open audit log: Corrupted, missing key, or unparseable
                packets safely quarantined without crashing the pipeline.
              </CardDescription>
            </CardHeader>
            <CardContent className="flex-1">
              {malformedSamples.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-48 text-center text-muted-foreground border border-dashed border-border rounded-xl">
                  <CheckCircle2 className="h-8 w-8 text-emerald-500/50 mb-2" />
                  <p className="text-xs">
                    No corrupted or malformed packets captured.
                  </p>
                  <p className="text-[11px] text-muted-foreground/70">
                    All ingested telemetry satisfies the 32-D flow schema.
                  </p>
                </div>
              ) : (
                <div className="space-y-3 max-h-[420px] overflow-y-auto pr-1">
                  {malformedSamples.map((sample: any, i: number) => (
                    <div
                      key={`malformed-${sample.logger_id || "unknown"}-${sample.timestamp || i}`}
                      className="p-3 rounded-lg border border-destructive/20 bg-destructive/5 text-xs space-y-2"
                    >
                      <div className="flex items-center justify-between font-mono text-[11px]">
                        <span className="text-destructive font-semibold">
                          Logger: {sample.logger_id || "unknown"}
                        </span>
                        <span className="text-muted-foreground">
                          {sample.timestamp
                            ? new Date(sample.timestamp).toLocaleTimeString()
                            : ""}
                        </span>
                      </div>
                      <div className="text-xs font-medium text-foreground">
                        Reason:{" "}
                        <span className="text-amber-500 font-mono">
                          {sample.reason}
                        </span>
                      </div>
                      <div className="relative">
                        <pre className="p-2 rounded bg-muted/60 text-[10px] font-mono overflow-x-auto text-muted-foreground border border-border">
                          {sample.sample}
                        </pre>
                        <Button
                          variant="ghost"
                          size="icon-xs"
                          onClick={() => {
                            navigator.clipboard.writeText(sample.sample);
                            toast.success("Payload sample copied");
                          }}
                          className="absolute right-1 top-1 h-6 w-6 text-muted-foreground hover:text-foreground"
                          title="Copy payload sample"
                        >
                          <Copy className="h-3 w-3" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Row 3: Historical 15s Window Evaluations Table */}
      <Card className="border-border bg-card shadow-sm rounded-xl">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-primary" />
              <CardTitle className="text-sm font-semibold tracking-wide uppercase text-foreground">
                Recent 15-Second Window Evaluation Cycles
              </CardTitle>
            </div>
            <span className="text-xs text-muted-foreground font-mono">
              Last {recentEvaluations.length} Cycles
            </span>
          </div>
        </CardHeader>
        <CardContent>
          {recentEvaluations.length === 0 ? (
            <div className="text-xs text-muted-foreground text-center py-6 border border-dashed border-border rounded-lg">
              No evaluation windows recorded in Redis yet. Run the logger to
              stream telemetry.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left border-collapse">
                <thead>
                  <tr className="border-b border-border text-muted-foreground font-mono text-[11px] uppercase">
                    <th className="py-2.5 px-3">Timestamp</th>
                    <th className="py-2.5 px-3">Risk %</th>
                    <th className="py-2.5 px-3">MITRE Stage</th>
                    <th className="py-2.5 px-3">Policy Action</th>
                    <th className="py-2.5 px-3">Flow Count</th>
                    <th className="py-2.5 px-3">Severity</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/40 font-mono">
                  {recentEvaluations.map((ev: any, idx: number) => {
                    const isCritical = ev.risk_pct >= 70;
                    const isSuspicious = ev.risk_pct >= 40 && ev.risk_pct < 70;
                    return (
                      <tr
                        key={`eval-${ev.timestamp || idx}`}
                        className="hover:bg-muted/30 transition-colors"
                      >
                        <td className="py-2.5 px-3 text-muted-foreground">
                          {new Date(ev.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="py-2.5 px-3 font-bold">
                          <span
                            className={
                              isCritical
                                ? "text-destructive"
                                : isSuspicious
                                  ? "text-amber-500"
                                  : "text-emerald-500"
                            }
                          >
                            {ev.risk_pct.toFixed(1)}%
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-foreground">
                          {ev.stage}
                        </td>
                        <td className="py-2.5 px-3">
                          <Badge
                            variant="outline"
                            className={`text-[10px] ${
                              ev.policy === "ISOLATE_DEVICE"
                                ? "border-destructive/30 text-destructive bg-destructive/10"
                                : ev.policy === "ALERT_ADMIN"
                                  ? "border-amber-500/30 text-amber-500 bg-amber-500/10"
                                  : "border-emerald-500/30 text-emerald-500 bg-emerald-500/10"
                            }`}
                          >
                            {ev.policy}
                          </Badge>
                        </td>
                        <td className="py-2.5 px-3 text-muted-foreground">
                          {ev.flow_count}
                        </td>
                        <td className="py-2.5 px-3">
                          <span className="text-[10px] font-semibold uppercase text-muted-foreground">
                            {ev.severity || "NORMAL"}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Row 4: Historical Session Incident Archive */}
      <Card className="border-border bg-card shadow-sm rounded-xl">
        <CardHeader className="pb-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-destructive" />
              <CardTitle className="text-sm font-semibold tracking-wide uppercase text-foreground">
                Session Incident Archive ({alertsList.length})
              </CardTitle>
            </div>

            {/* Filter and Search Bar */}
            <div className="flex items-center gap-2">
              <div className="relative">
                <Search className="h-3 w-3 text-muted-foreground absolute left-2.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  placeholder="Filter by target / stage..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-7 pr-2.5 py-1 text-xs bg-muted/50 border border-border rounded-lg text-foreground font-mono focus:outline-none"
                />
              </div>

              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                aria-label="Filter incidents by severity level"
                className="text-xs bg-muted/50 border border-border rounded-lg px-2 py-1 text-foreground font-mono focus:outline-none"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical Only</option>
                <option value="SUSPICIOUS">Suspicious Only</option>
                <option value="NORMAL">Normal Only</option>
              </select>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {filteredAlerts.length === 0 ? (
            <div className="text-xs text-muted-foreground text-center py-6 border border-dashed border-border rounded-lg">
              No incidents match the selected filter criteria.
            </div>
          ) : (
            <div className="overflow-x-auto max-h-[350px]">
              <table className="w-full text-xs text-left border-collapse">
                <thead>
                  <tr className="border-b border-border text-muted-foreground font-mono text-[11px] uppercase sticky top-0 bg-card">
                    <th className="py-2.5 px-3">Timestamp</th>
                    <th className="py-2.5 px-3">Target</th>
                    <th className="py-2.5 px-3">Severity</th>
                    <th className="py-2.5 px-3">Risk Prob</th>
                    <th className="py-2.5 px-3">MITRE Stage</th>
                    <th className="py-2.5 px-3">Policy Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/40 font-mono">
                  {filteredAlerts.map((a: any, idx: number) => {
                    const prob =
                      a.max_infiltration_prob ||
                      a.report?.max_infiltration_prob ||
                      0;
                    const sev =
                      a.severity ||
                      (prob >= 0.7
                        ? "CRITICAL"
                        : prob >= 0.4
                          ? "SUSPICIOUS"
                          : "NORMAL");
                    return (
                      <tr
                        key={`alert-${a.id || a.timestamp || idx}`}
                        className="hover:bg-muted/30 transition-colors"
                      >
                        <td className="py-2 px-3 text-muted-foreground">
                          {new Date(a.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="py-2 px-3 text-foreground font-semibold">
                          {a.target || a.target_ip || "10.0.4.21"}
                        </td>
                        <td className="py-2 px-3">
                          <Badge
                            variant="outline"
                            className={`text-[10px] ${
                              sev === "CRITICAL"
                                ? "border-destructive/30 text-destructive bg-destructive/10"
                                : sev === "SUSPICIOUS"
                                  ? "border-amber-500/30 text-amber-500 bg-amber-500/10"
                                  : "border-emerald-500/30 text-emerald-500 bg-emerald-500/10"
                            }`}
                          >
                            {sev}
                          </Badge>
                        </td>
                        <td className="py-2 px-3 font-bold">
                          {(prob * 100).toFixed(1)}%
                        </td>
                        <td className="py-2 px-3 text-muted-foreground">
                          {a.mitre_stage || a.report?.peak_stage || "Discovery"}
                        </td>
                        <td className="py-2 px-3">
                          <span className="text-[11px] font-semibold">
                            {a.policy_action ||
                              a.report?.recommended_policy ||
                              "ALLOW"}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
