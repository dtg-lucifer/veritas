"use client";

import {
  Activity,
  Cpu,
  Radio,
  RefreshCw,
  Server,
  ShieldAlert,
  ShieldCheck,
  Target,
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
import { type Alert, LiveAlertFeed } from "./alerts/LiveAlertFeed";
import {
  type RiskData,
  RiskDistributionChart,
} from "./charts/RiskDistributionChart";

export function Dashboard() {
  const [healthData, setHealthData] = useState<any>(null);
  const [kafkaStatus, setKafkaStatus] = useState<any>(null);
  const [redisMetrics, setRedisMetrics] = useState<any>(null);
  const [latestSim, setLatestSim] = useState<any>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [_wsConnected, setWsConnected] = useState(false);
  const [quarantineIp, setQuarantineIp] = useState("");
  const [isolating, setIsolating] = useState(false);

  // Distribution chart counts
  const [riskStats, setRiskStats] = useState({
    normal: 40,
    suspicious: 0,
    critical: 0,
  });

  const fetchVitalTelemetry = useCallback(async () => {
    try {
      const [hRes, kRes, rRes, sRes] = await Promise.allSettled([
        fetch("http://localhost:8000/health", {
          signal: AbortSignal.timeout(3000),
        }),
        fetch("http://localhost:8000/api/v1/kafka/status", {
          signal: AbortSignal.timeout(3000),
        }),
        fetch("http://localhost:8000/api/v1/metrics/redis", {
          signal: AbortSignal.timeout(3000),
        }),
        fetch("http://localhost:8000/api/v1/simulation/latest", {
          signal: AbortSignal.timeout(3000),
        }),
      ]);

      if (hRes.status === "fulfilled" && hRes.value.ok) {
        setHealthData(await hRes.value.json());
      }
      if (kRes.status === "fulfilled" && kRes.value.ok) {
        setKafkaStatus(await kRes.value.json());
      }
      if (rRes.status === "fulfilled" && rRes.value.ok) {
        const rData = await rRes.value.json();
        setRedisMetrics(rData);
        if (rData.counters) {
          setRiskStats({
            normal: rData.counters.alerts_normal || 40,
            suspicious: rData.counters.alerts_suspicious || 0,
            critical: rData.counters.alerts_critical || 0,
          });
        }
      }
      if (sRes.status === "fulfilled" && sRes.value.ok) {
        const sData = await sRes.value.json();
        if (sData.simulation) {
          setLatestSim(sData.simulation);
        }
      }
    } catch (err) {
      console.error("Telemetry fetch error:", err);
    }
  }, []);

  const fetchAlerts = useCallback(async () => {
    try {
      const res = await fetch("http://localhost:8000/api/v1/alerts", {
        signal: AbortSignal.timeout(3000),
      });
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data.alerts)) {
          const mapped: Alert[] = data.alerts.map((a: any, i: number) => {
            const rep = a.report || {};
            const prob =
              a.max_infiltration_prob || rep.max_infiltration_prob || 0;
            return {
              id: `hist-${i}-${a.timestamp || Date.now()}`,
              timestamp: a.timestamp || new Date().toISOString(),
              target: a.target || a.target_ip || "10.0.4.21",
              risk_score: prob > 1 ? prob : prob * 100,
              classification:
                a.severity ||
                (prob >= 0.7
                  ? "CRITICAL"
                  : prob >= 0.4
                    ? "SUSPICIOUS"
                    : "NORMAL"),
              mitre_stage: a.mitre_stage || rep.peak_stage || "Discovery",
              policy_action:
                a.policy_action || rep.recommended_policy || "ALLOW",
              soc_guidance: rep.soc_guidance,
              top_attributions: rep.top_attributions,
              rollout_steps: rep.rollout_steps,
            };
          });
          setAlerts(mapped.reverse());
        }
      }
    } catch {
      // fallback if offline
    }
  }, []);

  useEffect(() => {
    fetchVitalTelemetry();
    fetchAlerts();
    const interval = setInterval(fetchVitalTelemetry, 4000);
    return () => clearInterval(interval);
  }, [fetchVitalTelemetry, fetchAlerts]);

  // WebSocket Live Incident Feed
  useEffect(() => {
    const wsUrl =
      process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000/ws/alerts";
    let ws: WebSocket | null = null;
    let timer: NodeJS.Timeout;

    const connect = () => {
      try {
        ws = new WebSocket(wsUrl);
        ws.onopen = () => setWsConnected(true);
        ws.onclose = () => {
          setWsConnected(false);
          timer = setTimeout(connect, 4000);
        };
        ws.onerror = () => {
          setWsConnected(false);
          ws?.close();
        };
        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type === "CONNECTION_ESTABLISHED") return;

            if (
              data.type === "WORLD_MODEL_PREDICTION_ALERT" ||
              data.type === "SECURITY_INCIDENT_ALERT"
            ) {
              const rep = data.report || data.alert || {};
              const prob =
                data.max_infiltration_prob || rep.max_infiltration_prob || 0;
              const riskPct = prob > 1 ? prob : prob * 100;
              const severity =
                data.severity ||
                (riskPct >= 70
                  ? "CRITICAL"
                  : riskPct >= 40
                    ? "SUSPICIOUS"
                    : "NORMAL");

              const newAlert: Alert = {
                id: `ws-${Date.now()}`,
                timestamp: data.timestamp || new Date().toISOString(),
                target: data.target || "10.0.4.21",
                risk_score: riskPct,
                classification: severity,
                mitre_stage:
                  data.mitre_stage || rep.peak_stage || "Threat Escalation",
                policy_action:
                  data.policy_action ||
                  rep.recommended_policy ||
                  "ISOLATE_DEVICE",
                soc_guidance: rep.soc_guidance,
                top_attributions: rep.top_attributions,
                rollout_steps: rep.rollout_steps,
              };

              setAlerts((prev) => [newAlert, ...prev].slice(0, 50));

              // Update live stats
              setRiskStats((prev) => ({
                ...prev,
                [severity.toLowerCase()]:
                  (prev[severity.toLowerCase() as keyof typeof prev] || 0) + 1,
              }));

              // Sonner Toast Notification
              if (severity === "CRITICAL") {
                toast.error(`Critical Infiltration: ${newAlert.mitre_stage}`, {
                  description: `Risk: ${riskPct.toFixed(1)}% | Policy: ${newAlert.policy_action}`,
                  duration: 8000,
                });
              } else if (severity === "SUSPICIOUS") {
                toast.warning(`Suspicious Behavior: ${newAlert.mitre_stage}`, {
                  description: `Risk: ${riskPct.toFixed(1)}% | Policy: ${newAlert.policy_action}`,
                  duration: 6000,
                });
              }
            } else if (data.type === "FIREWALL_POLICY_ENFORCED") {
              toast.info(`Firewall Policy Enforced`, {
                description: `Target ${data.data?.ip} isolated: ${data.data?.reason}`,
              });
            }
          } catch (e) {
            console.error("WS Parse error:", e);
          }
        };
      } catch {
        setWsConnected(false);
      }
    };

    connect();

    return () => {
      clearTimeout(timer);
      if (ws) ws.close();
    };
  }, []);

  const handleManualIsolation = async () => {
    if (!quarantineIp) {
      toast.warning("Please specify an IP address or hostname to isolate");
      return;
    }
    try {
      setIsolating(true);
      const res = await fetch("http://localhost:8000/api/v1/policy/enforce", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_ip: quarantineIp,
          action: "ISOLATE_DEVICE",
          reason: "Manual SOC operator trigger from Main Dashboard",
        }),
      });
      if (res.ok) {
        toast.error(`Host Quarantine Applied: ${quarantineIp}`, {
          description: "Target traffic blocked across firewall gateway.",
        });
        setQuarantineIp("");
      } else {
        toast.error("Quarantine failed to apply");
      }
    } catch {
      toast.error("Network error executing quarantine");
    } finally {
      setIsolating(false);
    }
  };

  const chartData: RiskData[] = [
    { name: "Nominal Baseline", value: riskStats.normal, color: "#10b981" },
    {
      name: "Suspicious Probes",
      value: riskStats.suspicious,
      color: "#f59e0b",
    },
    { name: "Critical Attack", value: riskStats.critical, color: "#ef4444" },
  ];

  const activeLoggersCount = redisMetrics?.active_loggers?.length || 0;
  const processedLogsCount = redisMetrics?.counters?.logs_processed || 0;
  const webrtcCount = redisMetrics?.counters?.logs_webrtc_conferencing || 0;
  const peakRisk = latestSim
    ? (latestSim.max_infiltration_prob * 100).toFixed(1)
    : "0.0";
  const peakStage = latestSim?.peak_stage || "Nominal Baseline";
  const recommendedPolicy = latestSim?.recommended_policy || "ALLOW";

  return (
    <div className="space-y-6">
      {/* Top Banner: Status & Quick Telemetry Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-border">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2.5">
            <Radio className="h-6 w-6 text-primary" />
            Security Operations Center (SOC) Console
          </h1>
          <p className="text-xs text-muted-foreground mt-1">
            Real-time streaming ingestion, 15-second state aggregation, and AI
            World Model forward simulation.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Badge
            variant="outline"
            className="font-mono text-xs px-2.5 py-1 bg-card text-muted-foreground border-border"
          >
            Window: 15s (W=8)
          </Badge>
          <Badge
            variant="outline"
            className="font-mono text-xs px-2.5 py-1 bg-card text-muted-foreground border-border"
          >
            Horizon: 5 Steps (+75s)
          </Badge>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              fetchVitalTelemetry();
              fetchAlerts();
              toast.success("Telemetry Refreshed");
            }}
            className="h-8 text-xs text-muted-foreground hover:text-foreground"
          >
            <RefreshCw className="h-3.5 w-3.5 mr-1" />
            Refresh
          </Button>
        </div>
      </div>

      {/* 4 Vital Executive Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Kafka Streaming Broker */}
        <Card className="border-border bg-card shadow-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
            <CardTitle className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
              Streaming Broker
            </CardTitle>
            <Server className="h-4 w-4 text-cyan-500" />
          </CardHeader>
          <CardContent>
            <div className="flex items-baseline justify-between">
              <span className="text-2xl font-bold text-foreground font-mono">
                {kafkaStatus?.flows_ingested || processedLogsCount}
              </span>
              <Badge
                variant="outline"
                className={`text-[10px] font-mono ${
                  kafkaStatus?.status === "RUNNING"
                    ? "text-emerald-500 bg-emerald-500/10 border-emerald-500/20"
                    : "text-muted-foreground bg-muted border-border"
                }`}
              >
                {kafkaStatus?.status === "RUNNING"
                  ? "KAFKA LIVE"
                  : "BROKER READY"}
              </Badge>
            </div>
            <p className="text-[11px] text-muted-foreground mt-1 flex items-center justify-between font-mono">
              <span>Topic: {kafkaStatus?.topic || "network_flows"}</span>
              <span>Lag: {kafkaStatus?.pending_flows || 0}</span>
            </p>
          </CardContent>
        </Card>

        {/* Card 2: Distributed Sensors & Loggers */}
        <Card className="border-border bg-card shadow-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
            <CardTitle className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
              Distributed Loggers
            </CardTitle>
            <Activity className="h-4 w-4 text-emerald-500" />
          </CardHeader>
          <CardContent>
            <div className="flex items-baseline justify-between">
              <span className="text-2xl font-bold text-foreground font-mono">
                {activeLoggersCount}
              </span>
              <span className="text-xs text-muted-foreground font-mono">
                Sensors Active
              </span>
            </div>
            <p className="text-[11px] text-muted-foreground mt-1 flex items-center justify-between font-mono">
              <span>Media Filter: {webrtcCount}</span>
              <span>Ignored: {redisMetrics?.counters?.logs_ignored || 0}</span>
            </p>
          </CardContent>
        </Card>

        {/* Card 3: AI Network World Model */}
        <Card className="border-border bg-card shadow-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
            <CardTitle className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
              World Model State
            </CardTitle>
            <Cpu className="h-4 w-4 text-purple-500" />
          </CardHeader>
          <CardContent>
            <div className="flex items-baseline justify-between">
              <span className="text-2xl font-bold text-foreground font-mono">
                {healthData?.models_ready !== false ? "ONLINE" : "STANDBY"}
              </span>
              <Badge
                variant="outline"
                className="text-[10px] font-mono text-purple-400 bg-purple-500/10 border-purple-500/20"
              >
                LSTM + XAI
              </Badge>
            </div>
            <p className="text-[11px] text-muted-foreground mt-1 flex items-center justify-between font-mono">
              <span>
                Clients:{" "}
                {healthData?.config?.network?.connected_clients_count || 1}
              </span>
              <span>Subscribers: {healthData?.active_ws_subscribers || 0}</span>
            </p>
          </CardContent>
        </Card>

        {/* Card 4: Forecasted Threat Escalation */}
        <Card className="border-border bg-card shadow-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
            <CardTitle className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
              Peak Forecasted Risk
            </CardTitle>
            {Number(peakRisk) >= 70 ? (
              <ShieldAlert className="h-4 w-4 text-destructive" />
            ) : (
              <ShieldCheck className="h-4 w-4 text-emerald-500" />
            )}
          </CardHeader>
          <CardContent>
            <div className="flex items-baseline justify-between">
              <span
                className={`text-2xl font-bold font-mono ${
                  Number(peakRisk) >= 70
                    ? "text-destructive"
                    : Number(peakRisk) >= 40
                      ? "text-amber-500"
                      : "text-emerald-500"
                }`}
              >
                {peakRisk}%
              </span>
              <Badge
                variant="outline"
                className={`text-[10px] font-mono ${
                  recommendedPolicy === "ISOLATE_DEVICE"
                    ? "text-destructive bg-destructive/10 border-destructive/20"
                    : recommendedPolicy === "ALERT_ADMIN"
                      ? "text-amber-500 bg-amber-500/10 border-amber-500/20"
                      : "text-emerald-500 bg-emerald-500/10 border-emerald-500/20"
                }`}
              >
                {recommendedPolicy}
              </Badge>
            </div>
            <p className="text-[11px] text-muted-foreground mt-1 truncate font-mono">
              Stage: {peakStage}
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Main Split Grid: Left (Radar & Quick Actions) | Right (Live Incident Feed) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: 5 Cols */}
        <div className="lg:col-span-5 space-y-6">
          {/* Risk Distribution Radar */}
          <div className="h-[340px]">
            <RiskDistributionChart data={chartData} />
          </div>

          {/* Quick SOC Actions Card */}
          <Card className="border-border bg-card shadow-sm rounded-xl">
            <CardHeader className="pb-3">
              <div className="flex items-center gap-2">
                <Target className="h-4 w-4 text-primary" />
                <CardTitle className="text-sm font-semibold tracking-wide uppercase text-foreground">
                  Proactive Quarantine Control
                </CardTitle>
              </div>
              <CardDescription className="text-xs text-muted-foreground">
                One-click firewall isolation for compromised endpoints
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex items-center gap-2">
                <div className="relative flex-1">
                  <Terminal className="h-3.5 w-3.5 text-muted-foreground absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    placeholder="Enter Host IP (e.g. 10.0.4.21)"
                    value={quarantineIp}
                    onChange={(e) => setQuarantineIp(e.target.value)}
                    className="w-full pl-9 pr-3 py-1.5 text-xs bg-muted/50 border border-border rounded-lg text-foreground font-mono focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                </div>
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={handleManualIsolation}
                  disabled={isolating}
                  className="text-xs font-semibold h-8 shrink-0"
                >
                  {isolating ? "Isolating..." : "Isolate"}
                </Button>
              </div>

              {/* Quick suggestion buttons */}
              <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-muted-foreground">
                <span>Targets:</span>
                {["10.0.4.21", "192.168.1.105", "172.16.0.4"].map((ip) => (
                  <button
                    key={ip}
                    type="button"
                    onClick={() => setQuarantineIp(ip)}
                    className="font-mono bg-muted px-2 py-0.5 rounded border border-border hover:bg-muted/80 text-foreground transition-colors cursor-pointer"
                  >
                    {ip}
                  </button>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Right Column: 7 Cols (Live Incident Feed) */}
        <div className="lg:col-span-7">
          <Card className="border-border bg-card shadow-sm rounded-xl p-4 h-full flex flex-col min-h-[500px]">
            <LiveAlertFeed
              alerts={alerts}
              onIsolateDevice={(ip) => setQuarantineIp(ip)}
            />
          </Card>
        </div>
      </div>
    </div>
  );
}
