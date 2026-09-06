"use client";

import { Radio, RefreshCw } from "lucide-react";
import type React from "react";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Sidebar } from "./Sidebar";

interface AppShellProps {
  children: React.ReactNode;
}

export function AppShell({ children }: AppShellProps) {
  const [collapsed, setCollapsed] = useState(false);
  const [wsOnline, setWsOnline] = useState(false);
  const [resetting, setResetting] = useState(false);

  useEffect(() => {
    // Check WebSocket status periodically or connect a shared ping
    const wsUrl =
      process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000/api/v1/ws/alerts";
    let ws: WebSocket | null = null;
    let reconnectTimeout: NodeJS.Timeout;

    const connectWs = () => {
      try {
        ws = new WebSocket(wsUrl);
        ws.onopen = () => setWsOnline(true);
        ws.onclose = () => {
          setWsOnline(false);
          reconnectTimeout = setTimeout(connectWs, 5000);
        };
        ws.onerror = () => {
          setWsOnline(false);
          ws?.close();
        };
      } catch {
        setWsOnline(false);
      }
    };

    connectWs();

    return () => {
      clearTimeout(reconnectTimeout);
      if (ws) ws.close();
    };
  }, []);

  const handleGlobalReset = async () => {
    try {
      setResetting(true);
      const res = await fetch("http://localhost:8000/api/v1/simulation/reset", {
        method: "POST",
      });
      if (res.ok) {
        toast.success("Simulation & State Reset", {
          description:
            "All flow buffers, state history, and temporary alerts cleared.",
        });
      } else {
        toast.error("Reset Failed", {
          description: "Backend returned an error while resetting state.",
        });
      }
    } catch {
      toast.error("Network Error", {
        description: "Could not reach backend to reset simulation.",
      });
    } finally {
      setResetting(false);
    }
  };

  return (
    <div className="min-h-screen bg-background text-foreground flex">
      {/* Collapsible Sidebar */}
      <Sidebar collapsed={collapsed} setCollapsed={setCollapsed} />

      {/* Main Content Area */}
      <div
        className={`flex-1 flex flex-col min-w-0 transition-all duration-300 ${
          collapsed ? "ml-16" : "ml-64"
        }`}
      >
        {/* Top Operational Header */}
        <header className="h-16 border-b border-border bg-card/60 backdrop-blur-md sticky top-0 z-30 px-6 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-xs uppercase font-mono tracking-wider text-muted-foreground">
              Smart India Hackathon 2026
            </span>
            <span className="text-muted-foreground/40">/</span>
            <span className="text-xs font-semibold text-foreground">
              Network Threat Prediction & Autonomous Defense
            </span>
          </div>

          <div className="flex items-center gap-3">
            {/* Live WebSocket Status Badge */}
            <Badge
              variant="outline"
              className={`flex items-center gap-1.5 px-2.5 py-1 text-xs font-mono font-medium transition-colors ${
                wsOnline
                  ? "bg-emerald-500/10 text-emerald-500 border-emerald-500/30"
                  : "bg-amber-500/10 text-amber-500 border-amber-500/30"
              }`}
            >
              <Radio className={`h-3 w-3 ${wsOnline ? "animate-pulse" : ""}`} />
              <span>{wsOnline ? "WS FEED LIVE" : "WS RECONNECTING"}</span>
            </Badge>

            {/* Quick Reset State Button */}
            <Button
              variant="outline"
              size="sm"
              onClick={handleGlobalReset}
              disabled={resetting}
              className="text-xs text-muted-foreground hover:text-foreground h-8"
              title="Flush flow buffers and reset World Model sequence history"
            >
              <RefreshCw
                className={`h-3.5 w-3.5 mr-1.5 ${resetting ? "animate-spin" : ""}`}
              />
              <span>Reset State</span>
            </Button>
          </div>
        </header>

        {/* Page Viewport */}
        <main className="flex-1 p-6 overflow-y-auto max-w-7xl w-full mx-auto">
          {children}
        </main>
      </div>
    </div>
  );
}
