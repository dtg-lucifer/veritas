"use client";

import {
  Cpu,
  GitBranch,
  Layers,
  RefreshCw,
  Target,
  TrendingUp,
  Zap,
} from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  ReferenceLine,
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

export default function SimulationPage() {
  const [loading, setLoading] = useState(true);
  const [simulation, setSimulation] = useState<any>(null);
  const [resetting, setResetting] = useState(false);

  const fetchSimulation = useCallback(async () => {
    try {
      setLoading(true);
      const res = await fetch("http://localhost:8000/api/v1/simulation/latest");
      if (res.ok) {
        const data = await res.json();
        if (data.simulation) {
          setSimulation(data.simulation);
        }
      }
    } catch {
      toast.error("Failed to fetch simulation rollout report");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSimulation();
    const interval = setInterval(fetchSimulation, 4000);
    return () => clearInterval(interval);
  }, [fetchSimulation]);

  const handleReset = async () => {
    try {
      setResetting(true);
      const res = await fetch("http://localhost:8000/api/v1/simulation/reset", {
        method: "POST",
      });
      if (res.ok) {
        toast.success("Simulation History Flushed", {
          description: "All flow buffers, state context, and alerts cleared.",
        });
        fetchSimulation();
      }
    } catch {
      toast.error("Network error resetting simulation");
    } finally {
      setResetting(false);
    }
  };

  // Format Rollout steps for Recharts LineChart
  const rolloutSteps = simulation?.rollout_steps || [];
  const chartData = [
    {
      time: "T=0 (Now)",
      seconds: 0,
      risk: simulation
        ? Number((simulation.max_infiltration_prob * 100).toFixed(1))
        : 0,
      stage: simulation?.peak_stage || "Nominal",
      policy: simulation?.recommended_policy || "ALLOW",
    },
    ...rolloutSteps.map((step: any) => ({
      time: `+${step.relative_seconds}s`,
      seconds: step.relative_seconds,
      risk: Number((step.infiltration_prob * 100).toFixed(1)),
      stage: step.mitre_stage || "Nominal",
      policy: step.policy_action || "ALLOW",
      predicted_flow_count: step.predicted_flow_count,
      predicted_syn_ratio: step.predicted_syn_ratio,
    })),
  ];

  // Feature attributions for BarChart
  const topAttributions = simulation?.top_attributions || [];
  const attributionData = topAttributions.map((attr: any) => ({
    name: attr.feature.replace(/_/g, " "),
    score: Number((attr.score * 100).toFixed(1)),
    raw: attr.raw_value,
  }));

  const maxRisk = simulation
    ? (simulation.max_infiltration_prob * 100).toFixed(1)
    : "0.0";
  const peakStage = simulation?.peak_stage || "Nominal Operation";
  const recommendedPolicy = simulation?.recommended_policy || "ALLOW";

  const mitrePhases = [
    { id: 0, name: "Reconnaissance", desc: "Port scans & stealthy probes" },
    { id: 1, name: "Initial Access", desc: "Brute force & exploit attempts" },
    { id: 2, name: "Infiltration", desc: "Lateral movement & pivoting" },
    { id: 3, name: "Command & Control", desc: "Botnet beaconing & C2 sync" },
    { id: 4, name: "Exfiltration / Impact", desc: "Data siphon & DDoS flood" },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-border">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2.5">
            <GitBranch className="h-6 w-6 text-primary" />
            AI World Model Forward Simulation & Attribution
          </h1>
          <p className="text-xs text-muted-foreground mt-1">
            Autoregressive K-step rollout: Simulating future network environment
            physics P(S_t+1 | S_t) up to 75 seconds ahead.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={fetchSimulation}
            disabled={loading}
            className="h-8 text-xs text-muted-foreground hover:text-foreground"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 mr-1.5 ${loading ? "animate-spin" : ""}`}
            />
            Refresh Horizon
          </Button>
          <Button
            variant="destructive"
            size="sm"
            onClick={handleReset}
            disabled={resetting}
            className="h-8 text-xs font-medium"
          >
            {resetting ? "Resetting..." : "Reset Sequence Context"}
          </Button>
        </div>
      </div>

      {/* Top Banner: Forecast Summary & SOC Guidance */}
      <Card className="border-border bg-card shadow-sm rounded-xl overflow-hidden">
        <div className="p-4 bg-primary/5 border-b border-border flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center shrink-0">
              <Cpu className="h-5 w-5 text-primary" />
            </div>
            <div>
              <div className="text-xs uppercase font-mono tracking-wider text-muted-foreground">
                Current Horizon Escalation Forecast
              </div>
              <div className="text-base font-bold text-foreground flex items-center gap-2 mt-0.5">
                <span>Anticipated Phase: {peakStage}</span>
                <span className="text-xs text-muted-foreground font-normal">
                  (Peak Risk: {maxRisk}%)
                </span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Badge
              variant="outline"
              className={`font-mono text-xs px-3 py-1 ${
                recommendedPolicy === "ISOLATE_DEVICE"
                  ? "border-destructive text-destructive bg-destructive/10"
                  : recommendedPolicy === "ALERT_ADMIN"
                    ? "border-amber-500 text-amber-500 bg-amber-500/10"
                    : "border-emerald-500 text-emerald-500 bg-emerald-500/10"
              }`}
            >
              Policy: {recommendedPolicy}
            </Badge>
          </div>
        </div>

        {/* SOC Guidance */}
        {simulation?.soc_guidance && (
          <div className="p-4 text-xs font-mono bg-muted/30 text-foreground flex items-start gap-2.5">
            <Zap className="h-4 w-4 text-amber-500 shrink-0 mt-0.5" />
            <div className="leading-relaxed">
              <span className="font-semibold text-foreground mr-1">
                SOC Recommendation:
              </span>
              {simulation.soc_guidance}
            </div>
          </div>
        )}
      </Card>

      {/* Main Grid: Left Rollout Line Chart (7 cols) | Right Attributions Bar Chart (5 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Rollout Horizon Line Chart */}
        <div className="lg:col-span-7">
          <Card className="border-border bg-card shadow-sm rounded-xl h-full flex flex-col">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <TrendingUp className="h-4 w-4 text-primary" />
                  <CardTitle className="text-sm font-semibold tracking-wide uppercase text-foreground">
                    Autoregressive Risk Trajectory Horizon
                  </CardTitle>
                </div>
                <Badge
                  variant="outline"
                  className="font-mono text-[10px] text-muted-foreground"
                >
                  K = 5 Steps (15s Window)
                </Badge>
              </div>
              <CardDescription className="text-xs text-muted-foreground">
                Infiltration probability forecast across consecutive forward
                simulation time steps
              </CardDescription>
            </CardHeader>
            <CardContent className="flex-1 pt-2 pb-4">
              <div className="h-[280px] w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart
                    data={chartData}
                    margin={{ top: 10, right: 20, left: -20, bottom: 0 }}
                  >
                    <CartesianGrid
                      strokeDasharray="3 3"
                      stroke="rgba(120, 120, 120, 0.15)"
                    />
                    <XAxis
                      dataKey="time"
                      stroke="var(--muted-foreground)"
                      fontSize={11}
                      tickLine={false}
                    />
                    <YAxis
                      domain={[0, 100]}
                      stroke="var(--muted-foreground)"
                      fontSize={11}
                      tickFormatter={(v) => `${v}%`}
                      tickLine={false}
                    />
                    <ReferenceLine
                      y={40}
                      stroke="#f59e0b"
                      strokeDasharray="4 4"
                      label={{
                        value: "Warning (40%)",
                        fill: "#f59e0b",
                        fontSize: 10,
                        position: "insideTopRight",
                      }}
                    />
                    <ReferenceLine
                      y={70}
                      stroke="#ef4444"
                      strokeDasharray="4 4"
                      label={{
                        value: "Critical (70%)",
                        fill: "#ef4444",
                        fontSize: 10,
                        position: "insideTopRight",
                      }}
                    />
                    <Tooltip
                      content={({ active, payload }) => {
                        if (active && payload && payload.length) {
                          const data = payload[0].payload;
                          return (
                            <div className="rounded-lg border border-border bg-popover/95 p-3 shadow-md backdrop-blur-sm text-xs font-mono space-y-1">
                              <div className="font-semibold text-popover-foreground">
                                {data.time}
                              </div>
                              <div className="text-muted-foreground">
                                Infiltration Risk:{" "}
                                <span
                                  className={`font-bold ${
                                    data.risk >= 70
                                      ? "text-destructive"
                                      : data.risk >= 40
                                        ? "text-amber-500"
                                        : "text-emerald-500"
                                  }`}
                                >
                                  {data.risk}%
                                </span>
                              </div>
                              <div className="text-muted-foreground">
                                Predicted Phase:{" "}
                                <span className="text-foreground">
                                  {data.stage}
                                </span>
                              </div>
                              <div className="text-muted-foreground">
                                Policy Action:{" "}
                                <span className="text-foreground">
                                  {data.policy}
                                </span>
                              </div>
                            </div>
                          );
                        }
                        return null;
                      }}
                    />
                    <Line
                      type="monotone"
                      dataKey="risk"
                      stroke="var(--primary)"
                      strokeWidth={3}
                      dot={{ r: 4, fill: "var(--primary)" }}
                      activeDot={{ r: 6 }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Right Column: Explainable AI Attribution Bar Chart */}
        <div className="lg:col-span-5">
          <Card className="border-border bg-card shadow-sm rounded-xl h-full flex flex-col">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Layers className="h-4 w-4 text-primary" />
                  <CardTitle className="text-sm font-semibold tracking-wide uppercase text-foreground">
                    Driving Feature Attribution (XAI)
                  </CardTitle>
                </div>
                <Badge
                  variant="outline"
                  className="font-mono text-[10px] text-muted-foreground"
                >
                  Self-Attention
                </Badge>
              </div>
              <CardDescription className="text-xs text-muted-foreground">
                Top signals driving the current transition dynamics prediction
              </CardDescription>
            </CardHeader>
            <CardContent className="flex-1 pt-2 pb-4">
              {attributionData.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-[280px] text-center text-muted-foreground border border-dashed border-border rounded-xl">
                  <p className="text-xs">
                    No active feature attribution weights calculated yet.
                  </p>
                </div>
              ) : (
                <div className="h-[280px] w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                      data={attributionData}
                      layout="vertical"
                      margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
                    >
                      <CartesianGrid
                        strokeDasharray="3 3"
                        stroke="rgba(120, 120, 120, 0.1)"
                        horizontal={false}
                      />
                      <XAxis
                        type="number"
                        domain={[0, 100]}
                        stroke="var(--muted-foreground)"
                        fontSize={11}
                        tickFormatter={(v) => `${v}%`}
                        tickLine={false}
                      />
                      <YAxis
                        type="category"
                        dataKey="name"
                        stroke="var(--muted-foreground)"
                        fontSize={11}
                        tickLine={false}
                        width={90}
                      />
                      <Tooltip
                        content={({ active, payload }) => {
                          if (active && payload && payload.length) {
                            const d = payload[0].payload;
                            return (
                              <div className="rounded-lg border border-border bg-popover/95 p-2.5 shadow-md backdrop-blur-sm text-xs font-mono">
                                <div className="font-semibold text-popover-foreground">
                                  {d.name}
                                </div>
                                <div className="text-muted-foreground">
                                  Attribution Contribution:{" "}
                                  <span className="text-foreground font-bold">
                                    {d.score}%
                                  </span>
                                </div>
                                {d.raw !== undefined && (
                                  <div className="text-muted-foreground">
                                    Observed Value:{" "}
                                    <span className="text-foreground font-mono">
                                      {d.raw}
                                    </span>
                                  </div>
                                )}
                              </div>
                            );
                          }
                          return null;
                        }}
                      />
                      <Bar dataKey="score" radius={[0, 4, 4, 0]}>
                        {attributionData.map(
                          (
                            _item: {
                              name: string;
                              score: number;
                              raw?: number;
                            },
                            index: number,
                          ) => (
                            <Cell
                              key={_item.name}
                              fill={
                                index === 0
                                  ? "#ef4444"
                                  : index === 1
                                    ? "#f59e0b"
                                    : "#3b82f6"
                              }
                            />
                          ),
                        )}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Row 3: MITRE ATT&CK Kill-Chain Progression Path */}
      <Card className="border-border bg-card shadow-sm rounded-xl">
        <CardHeader className="pb-3">
          <div className="flex items-center gap-2">
            <Target className="h-4 w-4 text-primary" />
            <CardTitle className="text-sm font-semibold tracking-wide uppercase text-foreground">
              Canonical MITRE ATT&CK Tactical Progression Mapping
            </CardTitle>
          </div>
          <CardDescription className="text-xs text-muted-foreground">
            The World Model evaluates state trajectory transitions across
            canonical cyber kill-chain stages.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 sm:grid-cols-5 gap-3">
            {mitrePhases.map((phase) => {
              const isCurrent = peakStage
                .toLowerCase()
                .includes(phase.name.toLowerCase());
              return (
                <div
                  key={phase.id}
                  className={`p-3 rounded-xl border text-xs transition-all relative ${
                    isCurrent
                      ? "border-primary bg-primary/10 shadow-sm shadow-primary/20 ring-1 ring-primary"
                      : "border-border bg-muted/20 opacity-80"
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5 font-mono text-[10px]">
                    <span
                      className={
                        isCurrent
                          ? "text-primary font-bold"
                          : "text-muted-foreground"
                      }
                    >
                      Phase {phase.id}
                    </span>
                    {isCurrent && (
                      <span className="h-2 w-2 rounded-full bg-primary animate-pulse" />
                    )}
                  </div>
                  <div
                    className={`font-semibold text-xs ${isCurrent ? "text-primary" : "text-foreground"}`}
                  >
                    {phase.name}
                  </div>
                  <div className="text-[11px] text-muted-foreground mt-1 leading-snug">
                    {phase.desc}
                  </div>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
