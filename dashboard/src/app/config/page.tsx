"use client";

import {
  Code,
  Copy,
  Database,
  RotateCcw,
  Save,
  Settings2,
  ShieldAlert,
  Users,
  Video,
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

export default function ConfigPage() {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [showJson, setShowJson] = useState(false);

  // Configuration state
  const [connectedClients, setConnectedClients] = useState(1);
  const [baselineCapacity, setBaselineCapacity] = useState(1);
  const [autoScale, setAutoScale] = useState(true);

  const [allowWebRtc, setAllowWebRtc] = useState(true);
  const [conferencingPorts, setConferencingPorts] = useState(
    "3478, 19302, 19303, 19304, 19305, 19306, 19307, 19308, 19309",
  );
  const [whitelistedPorts, setWhitelistedPorts] = useState(
    "53, 80, 443, 3478, 8080, 8443",
  );

  const [alertThreshold, setAlertThreshold] = useState(0.4);
  const [criticalThreshold, setCriticalThreshold] = useState(0.7);
  const [windowSize, setWindowSize] = useState(15);
  const [warmupWindows, setWarmupWindows] = useState(4);

  const [redisUrl, setRedisUrl] = useState("redis://localhost:6379/0");
  const [redisEnabled, setRedisEnabled] = useState(true);

  const fetchConfig = useCallback(async () => {
    try {
      setLoading(true);
      const res = await fetch("http://localhost:8000/api/v1/config");
      if (res.ok) {
        const data = await res.json();
        const cfg = data.config || {};
        if (cfg.network) {
          setConnectedClients(cfg.network.connected_clients_count ?? 1);
          setBaselineCapacity(cfg.network.baseline_clients_capacity ?? 1);
          setAutoScale(cfg.network.auto_scale_volumetric_thresholds ?? true);
        }
        if (cfg.traffic_policy) {
          setAllowWebRtc(cfg.traffic_policy.allow_webrtc_conferencing ?? true);
          if (Array.isArray(cfg.traffic_policy.conferencing_ports)) {
            setConferencingPorts(
              cfg.traffic_policy.conferencing_ports.join(", "),
            );
          }
          if (Array.isArray(cfg.traffic_policy.whitelisted_ports)) {
            setWhitelistedPorts(
              cfg.traffic_policy.whitelisted_ports.join(", "),
            );
          }
        }
        if (cfg.thresholds) {
          setAlertThreshold(cfg.thresholds.alert_threshold ?? 0.4);
          setCriticalThreshold(cfg.thresholds.critical_threshold ?? 0.7);
          setWindowSize(cfg.thresholds.window_size_seconds ?? 15);
          setWarmupWindows(cfg.thresholds.min_warmup_windows ?? 4);
        }
        if (cfg.redis) {
          setRedisUrl(cfg.redis.url ?? "redis://localhost:6379/0");
          setRedisEnabled(cfg.redis.enabled ?? true);
        }
      }
    } catch {
      toast.error("Failed to load active configuration from backend");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchConfig();
  }, [fetchConfig]);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);

    const parsePortList = (str: string) =>
      str
        .split(",")
        .map((p) => Number.parseInt(p.trim(), 10))
        .filter((p) => !Number.isNaN(p));

    const payload = {
      network: {
        connected_clients_count: Number(connectedClients),
        baseline_clients_capacity: Number(baselineCapacity),
        auto_scale_volumetric_thresholds: Boolean(autoScale),
      },
      traffic_policy: {
        allow_webrtc_conferencing: Boolean(allowWebRtc),
        conferencing_ports: parsePortList(conferencingPorts),
        whitelisted_ports: parsePortList(whitelistedPorts),
        whitelisted_ips: [],
      },
      thresholds: {
        alert_threshold: Number(alertThreshold),
        critical_threshold: Number(criticalThreshold),
        window_size_seconds: Number(windowSize),
        min_warmup_windows: Number(warmupWindows),
      },
      redis: {
        url: redisUrl,
        key_prefix: "firewall:",
        enabled: Boolean(redisEnabled),
        metrics_ttl_seconds: 86400,
      },
    };

    try {
      const res = await fetch("http://localhost:8000/api/v1/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (res.ok) {
        toast.success("Configuration Persisted", {
          description:
            "Runtime network scaling & thresholds updated without restart.",
        });
      } else {
        const err = await res.json();
        toast.error("Update Failed", {
          description: err.detail || "Server error",
        });
      }
    } catch {
      toast.error("Network Error: Could not connect to backend");
    } finally {
      setSaving(false);
    }
  };

  const currentPayloadJson = JSON.stringify(
    {
      network: {
        connected_clients_count: Number(connectedClients),
        baseline_clients_capacity: Number(baselineCapacity),
        auto_scale_volumetric_thresholds: Boolean(autoScale),
      },
      traffic_policy: {
        allow_webrtc_conferencing: Boolean(allowWebRtc),
        conferencing_ports: conferencingPorts
          .split(",")
          .map((p) => Number(p.trim())),
        whitelisted_ports: whitelistedPorts
          .split(",")
          .map((p) => Number(p.trim())),
      },
      thresholds: {
        alert_threshold: Number(alertThreshold),
        critical_threshold: Number(criticalThreshold),
        window_size_seconds: Number(windowSize),
        min_warmup_windows: Number(warmupWindows),
      },
      redis: {
        url: redisUrl,
        enabled: Boolean(redisEnabled),
      },
    },
    null,
    2,
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-border">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2.5">
            <Settings2 className="h-6 w-6 text-primary" />
            Admin Configuration & Policy Orchestration
          </h1>
          <p className="text-xs text-muted-foreground mt-1">
            Dynamically adjust client volumetric normalization, video call
            dampening, and ML forward simulation thresholds.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={fetchConfig}
            disabled={loading}
            className="h-8 text-xs text-muted-foreground hover:text-foreground"
          >
            <RotateCcw className="h-3.5 w-3.5 mr-1" />
            Reload
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setShowJson(!showJson)}
            className="h-8 text-xs text-muted-foreground hover:text-foreground"
          >
            <Code className="h-3.5 w-3.5 mr-1" />
            {showJson ? "Hide JSON" : "View JSON"}
          </Button>
        </div>
      </div>

      <form onSubmit={handleSave} className="space-y-6">
        {/* Section 1: Network Client Scaling */}
        <Card className="border-border bg-card shadow-sm rounded-xl">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Users className="h-4 w-4 text-cyan-500" />
                <CardTitle className="text-sm font-semibold tracking-wide uppercase text-foreground">
                  Workstation & Client Volumetric Scaling
                </CardTitle>
              </div>
              <Badge
                variant="outline"
                className="font-mono text-[10px] text-cyan-400 border-cyan-500/30"
              >
                Scale Factor: {connectedClients}x
              </Badge>
            </div>
            <CardDescription className="text-xs text-muted-foreground">
              Normalizes byte rates and packet volumes as more users join the
              local network, preventing false positives from legitimate traffic
              spikes.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <div className="flex justify-between items-center text-xs">
                <label
                  htmlFor="clients-count"
                  className="font-medium text-foreground"
                >
                  Connected Workstations ({connectedClients})
                </label>
                <span className="text-muted-foreground font-mono text-[11px]">
                  Range: 1 – 500 devices
                </span>
              </div>
              <input
                id="clients-count"
                type="range"
                min="1"
                max="500"
                step="1"
                value={connectedClients}
                onChange={(e) => setConnectedClients(Number(e.target.value))}
                className="w-full h-1.5 bg-muted rounded-lg appearance-none cursor-pointer accent-primary"
              />
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-1">
              <div className="space-y-1.5">
                <label
                  htmlFor="baseline-cap"
                  className="text-xs font-medium text-muted-foreground"
                >
                  Baseline Capacity Benchmark (Workstations)
                </label>
                <input
                  id="baseline-cap"
                  type="number"
                  min="1"
                  value={baselineCapacity}
                  onChange={(e) => setBaselineCapacity(Number(e.target.value))}
                  className="w-full px-3 py-1.5 text-xs bg-muted/40 border border-border rounded-lg text-foreground font-mono"
                />
              </div>

              <div className="flex items-center gap-3 pt-4">
                <input
                  type="checkbox"
                  id="autoScale"
                  checked={autoScale}
                  onChange={(e) => setAutoScale(e.target.checked)}
                  className="h-4 w-4 rounded border-border text-primary focus:ring-primary accent-primary"
                />
                <label
                  htmlFor="autoScale"
                  className="text-xs text-foreground font-medium cursor-pointer"
                >
                  Auto-scale Volumetric State Normalization
                </label>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Section 2: Traffic Policy & WebRTC Filtering */}
        <Card className="border-border bg-card shadow-sm rounded-xl">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Video className="h-4 w-4 text-emerald-500" />
                <CardTitle className="text-sm font-semibold tracking-wide uppercase text-foreground">
                  Media & Real-Time Conferencing Policy (WebRTC)
                </CardTitle>
              </div>
              <Badge
                variant="outline"
                className={`font-mono text-[10px] ${
                  allowWebRtc
                    ? "text-emerald-500 border-emerald-500/30 bg-emerald-500/10"
                    : "text-muted-foreground border-border"
                }`}
              >
                {allowWebRtc ? "DAMPENING ACTIVE" : "FILTER DISABLED"}
              </Badge>
            </div>
            <CardDescription className="text-xs text-muted-foreground">
              Suppresses UDP flood false-alarms generated by Google Meet, Zoom,
              WebRTC, and STUN/TURN port 3478 traffic.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between p-3 rounded-lg bg-muted/30 border border-border">
              <div>
                <div className="text-xs font-semibold text-foreground">
                  Allow Video Conferencing & Google Meet Traffic
                </div>
                <div className="text-[11px] text-muted-foreground mt-0.5">
                  Flags UDP media streams on recognized STUN/TURN ports as
                  legitimate conferencing baselines.
                </div>
              </div>
              <input
                type="checkbox"
                id="allowWebRtc"
                checked={allowWebRtc}
                onChange={(e) => setAllowWebRtc(e.target.checked)}
                className="h-5 w-5 rounded border-border text-primary focus:ring-primary accent-primary cursor-pointer"
              />
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor="conf-ports"
                className="text-xs font-medium text-muted-foreground"
              >
                Conferencing Ports (comma-separated UDP ports)
              </label>
              <input
                id="conf-ports"
                type="text"
                value={conferencingPorts}
                onChange={(e) => setConferencingPorts(e.target.value)}
                className="w-full px-3 py-1.5 text-xs bg-muted/40 border border-border rounded-lg text-foreground font-mono"
              />
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor="white-ports"
                className="text-xs font-medium text-muted-foreground"
              >
                Whitelisted Standard Ports
              </label>
              <input
                id="white-ports"
                type="text"
                value={whitelistedPorts}
                onChange={(e) => setWhitelistedPorts(e.target.value)}
                className="w-full px-3 py-1.5 text-xs bg-muted/40 border border-border rounded-lg text-foreground font-mono"
              />
            </div>
          </CardContent>
        </Card>

        {/* Section 3: World Model Thresholds */}
        <Card className="border-border bg-card shadow-sm rounded-xl">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-amber-500" />
                <CardTitle className="text-sm font-semibold tracking-wide uppercase text-foreground">
                  World Model Risk & Horizon Thresholds
                </CardTitle>
              </div>
              <Badge
                variant="outline"
                className="font-mono text-[10px] text-amber-400 border-amber-500/30"
              >
                Auto-Mitigation Active
              </Badge>
            </div>
            <CardDescription className="text-xs text-muted-foreground">
              Define the probability cutoffs for alerting administrators or
              automatically triggering device quarantine.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-2">
                <div className="flex justify-between items-center text-xs">
                  <label
                    htmlFor="alert-slider"
                    className="font-medium text-foreground"
                  >
                    Warning Alert Threshold ({(alertThreshold * 100).toFixed(0)}
                    %)
                  </label>
                  <span className="text-amber-500 font-mono text-[11px]">
                    ALERT_ADMIN
                  </span>
                </div>
                <input
                  id="alert-slider"
                  type="range"
                  min="0.1"
                  max="0.9"
                  step="0.05"
                  value={alertThreshold}
                  onChange={(e) => setAlertThreshold(Number(e.target.value))}
                  className="w-full h-1.5 bg-muted rounded-lg appearance-none cursor-pointer accent-amber-500"
                />
              </div>

              <div className="space-y-2">
                <div className="flex justify-between items-center text-xs">
                  <label
                    htmlFor="crit-slider"
                    className="font-medium text-foreground"
                  >
                    Critical Quarantine Threshold (
                    {(criticalThreshold * 100).toFixed(0)}%)
                  </label>
                  <span className="text-destructive font-mono text-[11px]">
                    ISOLATE_DEVICE
                  </span>
                </div>
                <input
                  id="crit-slider"
                  type="range"
                  min="0.4"
                  max="0.95"
                  step="0.05"
                  value={criticalThreshold}
                  onChange={(e) => setCriticalThreshold(Number(e.target.value))}
                  className="w-full h-1.5 bg-muted rounded-lg appearance-none cursor-pointer accent-destructive"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-1">
              <div className="space-y-1.5">
                <label
                  htmlFor="window-dur"
                  className="text-xs font-medium text-muted-foreground"
                >
                  Window Duration (Seconds)
                </label>
                <input
                  id="window-dur"
                  type="number"
                  value={windowSize}
                  disabled
                  className="w-full px-3 py-1.5 text-xs bg-muted/40 border border-border rounded-lg text-muted-foreground font-mono"
                />
                <span className="text-[10px] text-muted-foreground">
                  Fixed to 15s aggregation standard
                </span>
              </div>

              <div className="space-y-1.5">
                <label
                  htmlFor="warmup-win"
                  className="text-xs font-medium text-muted-foreground"
                >
                  Minimum Warmup Windows
                </label>
                <input
                  id="warmup-win"
                  type="number"
                  min="1"
                  max="8"
                  value={warmupWindows}
                  onChange={(e) => setWarmupWindows(Number(e.target.value))}
                  className="w-full px-3 py-1.5 text-xs bg-muted/40 border border-border rounded-lg text-foreground font-mono"
                />
                <span className="text-[10px] text-muted-foreground">
                  {warmupWindows * 15}s buffer before alerts trigger
                </span>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Section 4: Redis Telemetry Cache */}
        <Card className="border-border bg-card shadow-sm rounded-xl">
          <CardHeader className="pb-3">
            <div className="flex items-center gap-2">
              <Database className="h-4 w-4 text-red-500" />
              <CardTitle className="text-sm font-semibold tracking-wide uppercase text-foreground">
                Redis Telemetry & Malformed Schema Cache
              </CardTitle>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="sm:col-span-2 space-y-1.5">
                <label
                  htmlFor="redis-url"
                  className="text-xs font-medium text-muted-foreground"
                >
                  Redis URL Connection String
                </label>
                <input
                  id="redis-url"
                  type="text"
                  value={redisUrl}
                  onChange={(e) => setRedisUrl(e.target.value)}
                  className="w-full px-3 py-1.5 text-xs bg-muted/40 border border-border rounded-lg text-foreground font-mono"
                />
              </div>
              <div className="flex items-center gap-3 pt-5">
                <input
                  type="checkbox"
                  id="redisEnabled"
                  checked={redisEnabled}
                  onChange={(e) => setRedisEnabled(e.target.checked)}
                  className="h-4 w-4 rounded border-border text-primary focus:ring-primary accent-primary"
                />
                <label
                  htmlFor="redisEnabled"
                  className="text-xs text-foreground font-medium cursor-pointer"
                >
                  Telemetry Active
                </label>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Action Button Bar */}
        <div className="flex items-center justify-end gap-3 pt-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={fetchConfig}
            disabled={loading || saving}
            className="h-9 px-4 text-xs"
          >
            Cancel
          </Button>
          <Button
            type="submit"
            disabled={saving}
            className="h-9 px-5 text-xs font-semibold gap-2 shadow-sm"
          >
            <Save className="h-4 w-4" />
            <span>
              {saving ? "Applying Updates..." : "Save & Apply Configuration"}
            </span>
          </Button>
        </div>
      </form>

      {/* Optional Collapsible JSON Viewer */}
      {showJson && (
        <Card className="border-border bg-card shadow-sm rounded-xl">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-xs font-mono uppercase text-muted-foreground">
                Active Payload Preview
              </CardTitle>
              <Button
                variant="ghost"
                size="icon-xs"
                onClick={() => {
                  navigator.clipboard.writeText(currentPayloadJson);
                  toast.success("JSON copied to clipboard");
                }}
              >
                <Copy className="h-3.5 w-3.5" />
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <pre className="text-[11px] font-mono p-3 bg-muted/50 rounded-lg overflow-x-auto text-foreground">
              {currentPayloadJson}
            </pre>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
