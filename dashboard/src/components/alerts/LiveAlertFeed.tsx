"use client";

import { AnimatePresence, motion } from "framer-motion";
import {
  Activity,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Clock,
  Layers,
  ShieldAlert,
  ShieldCheck,
  Target,
  Zap,
} from "lucide-react";
import type React from "react";
import { useState } from "react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";

export interface Alert {
  id: string;
  timestamp: string;
  target?: string;
  risk_score: number; // 0 to 100 percentage
  classification: "NORMAL" | "SUSPICIOUS" | "CRITICAL";
  mitre_stage?: string;
  policy_action?: string;
  message?: string;
  soc_guidance?: string;
  top_attributions?: Array<{
    feature: string;
    score: number;
    raw_value?: number;
  }>;
  rollout_steps?: Array<{
    step: number;
    relative_seconds: number;
    infiltration_prob: number;
    mitre_stage: string;
    status: string;
    policy_action: string;
  }>;
}

interface LiveAlertFeedProps {
  alerts: Alert[];
  onIsolateDevice?: (target: string) => void;
}

function AlertCard({
  alert,
  onIsolate,
}: {
  alert: Alert;
  onIsolate?: (ip: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const [isolating, setIsolating] = useState(false);

  const getIcon = (classification: string) => {
    switch (classification) {
      case "CRITICAL":
        return <ShieldAlert className="h-5 w-5 text-red-500 shrink-0" />;
      case "SUSPICIOUS":
        return <AlertTriangle className="h-5 w-5 text-amber-500 shrink-0" />;
      default:
        return <ShieldCheck className="h-5 w-5 text-emerald-500 shrink-0" />;
    }
  };

  const getCardStyle = (classification: string) => {
    switch (classification) {
      case "CRITICAL":
        return "border-destructive/30 bg-destructive/5 hover:bg-destructive/10";
      case "SUSPICIOUS":
        return "border-amber-500/30 bg-amber-500/5 hover:bg-amber-500/10";
      default:
        return "border-border bg-card/80 hover:bg-muted/40";
    }
  };

  const getBadgeVariant = (classification: string) => {
    switch (classification) {
      case "CRITICAL":
        return "bg-destructive/15 text-destructive border-destructive/30";
      case "SUSPICIOUS":
        return "bg-amber-500/15 text-amber-500 border-amber-500/30";
      default:
        return "bg-emerald-500/15 text-emerald-500 border-emerald-500/30";
    }
  };

  const handleIsolate = async (e: React.MouseEvent) => {
    e.stopPropagation();
    const targetIp = alert.target || "10.0.4.21";
    try {
      setIsolating(true);
      const res = await fetch("http://localhost:8000/api/v1/policy/enforce", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_ip: targetIp,
          action: "ISOLATE_DEVICE",
          reason: `Autonomous trigger: World Model forecasted ${alert.risk_score.toFixed(1)}% threat at ${alert.mitre_stage || "Kill-Chain Escalation"}`,
        }),
      });

      if (res.ok) {
        toast.error(`Device Isolated: ${targetIp}`, {
          description:
            "Quarantine firewall policy enforced across network gateway.",
        });
        if (onIsolate) onIsolate(targetIp);
      } else {
        toast.error("Policy Enforcement Failed");
      }
    } catch {
      toast.error("Network Error: Could not reach backend");
    } finally {
      setIsolating(false);
    }
  };

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: -10, scale: 0.98 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      className={`flex flex-col gap-2.5 rounded-xl border p-4 transition-colors cursor-pointer ${getCardStyle(
        alert.classification,
      )}`}
      onClick={() => setExpanded(!expanded)}
    >
      {/* Top row: Status, Target/Stage, Risk Score */}
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-3 min-w-0">
          {getIcon(alert.classification)}
          <div className="flex flex-col min-w-0">
            <div className="flex items-center gap-2">
              <span className="font-semibold text-foreground text-sm truncate">
                {alert.mitre_stage || alert.target || "Security Incident"}
              </span>
              {alert.target && (
                <span className="text-[11px] font-mono text-muted-foreground bg-muted px-1.5 py-0.5 rounded">
                  {alert.target}
                </span>
              )}
            </div>
            <span className="text-[11px] text-muted-foreground truncate font-mono">
              Action: {alert.policy_action || "ALLOW"}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <Badge
            variant="outline"
            className={`text-xs font-semibold ${getBadgeVariant(alert.classification)}`}
          >
            {alert.classification}
          </Badge>

          <Badge
            variant="outline"
            className="bg-muted/80 border-border font-mono text-xs text-foreground"
          >
            Risk:{" "}
            <span
              className={`ml-1 font-bold ${
                alert.risk_score >= 70
                  ? "text-destructive"
                  : alert.risk_score >= 40
                    ? "text-amber-500"
                    : "text-emerald-500"
              }`}
            >
              {alert.risk_score.toFixed(1)}%
            </span>
          </Badge>

          {expanded ? (
            <ChevronUp className="h-4 w-4 text-muted-foreground" />
          ) : (
            <ChevronDown className="h-4 w-4 text-muted-foreground" />
          )}
        </div>
      </div>

      {/* Expandable Forensic Details */}
      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            className="overflow-hidden"
          >
            <div className="pt-3 pb-1 space-y-3 border-t border-border/60 mt-1">
              {/* Guidance message */}
              {alert.soc_guidance && (
                <div className="text-xs p-3 rounded-lg bg-muted/60 border border-border text-foreground font-mono leading-relaxed">
                  <div className="text-[10px] uppercase font-bold text-muted-foreground mb-1 flex items-center gap-1.5">
                    <Zap className="h-3 w-3 text-primary" />
                    SOC Guidance
                  </div>
                  {alert.soc_guidance}
                </div>
              )}

              {/* Driving Features / Attributions */}
              {alert.top_attributions && alert.top_attributions.length > 0 && (
                <div className="space-y-1.5">
                  <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                    <Layers className="h-3 w-3 text-primary" />
                    Top Attributed Features
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                    {alert.top_attributions.map((attr) => (
                      <div
                        key={attr.feature}
                        className="bg-card/90 p-2 rounded-md border border-border text-xs flex items-center justify-between"
                      >
                        <span className="font-mono text-muted-foreground truncate mr-2">
                          {attr.feature.replace(/_/g, " ")}
                        </span>
                        <div className="flex items-center gap-2">
                          {attr.raw_value !== undefined && (
                            <span className="text-[10px] text-muted-foreground font-mono">
                              ({attr.raw_value})
                            </span>
                          )}
                          <span className="font-bold text-foreground font-mono">
                            {(attr.score * 100).toFixed(1)}%
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Forward Simulation Trajectory */}
              {alert.rollout_steps && alert.rollout_steps.length > 0 && (
                <div className="space-y-1.5">
                  <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                    <Activity className="h-3 w-3 text-primary" />
                    Autoregressive Rollout Horizon
                  </div>
                  <div className="flex items-center gap-2 overflow-x-auto pb-1">
                    {alert.rollout_steps.map((step) => (
                      <div
                        key={`step-${step.step}-${step.relative_seconds}`}
                        className="bg-card p-2 rounded-lg border border-border min-w-[110px] text-center shrink-0"
                      >
                        <div className="text-[10px] text-muted-foreground font-mono">
                          +{step.relative_seconds}s
                        </div>
                        <div
                          className={`text-sm font-bold font-mono ${
                            step.infiltration_prob >= 0.7
                              ? "text-destructive"
                              : step.infiltration_prob >= 0.4
                                ? "text-amber-500"
                                : "text-emerald-500"
                          }`}
                        >
                          {(step.infiltration_prob * 100).toFixed(0)}%
                        </div>
                        <div className="text-[10px] truncate text-muted-foreground mt-0.5">
                          {step.mitre_stage}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Isolate Device Trigger */}
              <div className="pt-2 flex justify-end">
                <Button
                  variant={
                    alert.classification === "CRITICAL"
                      ? "destructive"
                      : "outline"
                  }
                  size="sm"
                  onClick={handleIsolate}
                  disabled={isolating}
                  className="text-xs font-semibold gap-1.5 h-8"
                >
                  <Target className="h-3.5 w-3.5" />
                  <span>
                    {isolating ? "Isolating..." : "Enforce Host Isolation"}
                  </span>
                </Button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Card Footer: Timestamp */}
      <div className="flex items-center justify-between text-[11px] text-muted-foreground pt-1.5 border-t border-border/40">
        <div className="flex items-center gap-1.5 font-mono">
          <Clock className="h-3 w-3" />
          {new Date(alert.timestamp).toLocaleTimeString()}
        </div>
        <div className="text-[10px] text-muted-foreground">
          Click to inspect forensic attribution
        </div>
      </div>
    </motion.div>
  );
}

export function LiveAlertFeed({ alerts, onIsolateDevice }: LiveAlertFeedProps) {
  const [severityFilter, setSeverityFilter] = useState<"ALL" | "SUSPICIOUS" | "CRITICAL">("ALL");

  const totalCount = alerts.length;
  const suspiciousCount = alerts.filter((a) => a.classification === "SUSPICIOUS").length;
  const criticalCount = alerts.filter((a) => a.classification === "CRITICAL").length;

  const filteredAlerts = alerts.filter((alert) => {
    if (severityFilter === "ALL") return true;
    return alert.classification === severityFilter;
  });

  return (
    <div className="flex flex-1 h-full min-h-0 flex-col space-y-3">
      {/* Header and Filter Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
        <div className="flex items-center gap-2">
          <Activity className="h-4 w-4 text-primary" />
          <h3 className="text-sm font-semibold text-foreground tracking-wide uppercase">
            Live Incident Stream
          </h3>
          <Badge
            variant="outline"
            className="border-emerald-500/30 text-emerald-500 bg-emerald-500/10 font-mono text-[10px] ml-1"
          >
            <span className="mr-1 h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse inline-block" />
            Live
          </Badge>
        </div>

        {/* Severity Filter Tabs */}
        <div className="flex items-center gap-1 p-0.5 bg-muted/50 rounded-lg border border-border text-xs">
          <button
            type="button"
            onClick={() => setSeverityFilter("ALL")}
            className={`px-2.5 py-1 rounded-md text-[11px] transition-all flex items-center gap-1.5 cursor-pointer ${
              severityFilter === "ALL"
                ? "bg-card text-foreground font-semibold shadow-xs border border-border"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            <span>All</span>
            <span className="text-[10px] font-mono px-1 py-0.2 rounded bg-muted text-muted-foreground">
              {totalCount}
            </span>
          </button>
          <button
            type="button"
            onClick={() => setSeverityFilter("SUSPICIOUS")}
            className={`px-2.5 py-1 rounded-md text-[11px] transition-all flex items-center gap-1.5 cursor-pointer ${
              severityFilter === "SUSPICIOUS"
                ? "bg-amber-500/15 text-amber-500 font-semibold shadow-xs border border-amber-500/30"
                : "text-muted-foreground hover:text-amber-500"
            }`}
          >
            <span className="h-1.5 w-1.5 rounded-full bg-amber-500 inline-block" />
            <span>Suspicious</span>
            <span className="text-[10px] font-mono px-1 py-0.2 rounded bg-muted text-muted-foreground">
              {suspiciousCount}
            </span>
          </button>
          <button
            type="button"
            onClick={() => setSeverityFilter("CRITICAL")}
            className={`px-2.5 py-1 rounded-md text-[11px] transition-all flex items-center gap-1.5 cursor-pointer ${
              severityFilter === "CRITICAL"
                ? "bg-destructive/15 text-destructive font-semibold shadow-xs border border-destructive/30"
                : "text-muted-foreground hover:text-destructive"
            }`}
          >
            <span className="h-1.5 w-1.5 rounded-full bg-destructive inline-block" />
            <span>Critical</span>
            <span className="text-[10px] font-mono px-1 py-0.2 rounded bg-muted text-muted-foreground">
              {criticalCount}
            </span>
          </button>
        </div>
      </div>

      <ScrollArea className="flex-1 pr-2 max-h-[500px]">
        <div className="space-y-2.5">
          <AnimatePresence initial={false}>
            {filteredAlerts.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-center text-muted-foreground space-y-2.5 border border-dashed border-border rounded-xl bg-card/40">
                <ShieldCheck className="h-8 w-8 text-emerald-500/60" />
                <p className="text-sm font-medium">
                  {severityFilter === "ALL"
                    ? "Nominal Traffic Baseline"
                    : `No ${severityFilter.toLowerCase()} incidents in current feed`}
                </p>
                <p className="text-xs max-w-xs text-muted-foreground">
                  {severityFilter === "ALL"
                    ? "No active threat escalation detected in recent 15-second state windows."
                    : `Switch filter to 'All' or wait for live threat evaluation.`}
                </p>
              </div>
            ) : (
              filteredAlerts.map((alert) => (
                <AlertCard
                  key={alert.id}
                  alert={alert}
                  onIsolate={onIsolateDevice}
                />
              ))
            )}
          </AnimatePresence>
        </div>
      </ScrollArea>
    </div>
  );
}
