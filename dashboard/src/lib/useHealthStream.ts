"use client";

import { useEffect, useState, useCallback } from "react";

export interface HealthSnapshot {
  type: string;
  status: string;
  service: string;
  timestamp: string;
  server_uptime_seconds: number;
  model_ready: boolean;
  models_ready: boolean;
  active_ws_subscribers: number;
  active_health_subscribers: number;
  kafka: {
    status: "RUNNING" | "STOPPED";
    is_running: boolean;
    topic: string;
    bootstrap_servers: string;
    flows_ingested: number;
    pending_flows: number;
    windows_evaluated: number;
  };
  kafka_worker: {
    status: "RUNNING" | "STOPPED";
    is_running: boolean;
    topic: string;
    bootstrap_servers: string;
  };
  redis: {
    status?: string;
    redis_connected?: boolean;
    redis_url?: string;
    counters?: Record<string, number>;
    active_loggers?: string[];
    timestamps?: Record<string, string>;
    [key: string]: any;
  };
  world_model: {
    model_ready: boolean;
    models_ready?: boolean;
    model_path?: string;
    window_size_seconds: number;
    rollout_steps: number;
    alert_threshold: number;
    flows_ingested: number;
    windows_evaluated: number;
    simulations_completed: number;
    alerts_generated: number;
    peak_risk_observed: number;
    active_history_states?: number;
  };
  network_config: {
    connected_clients_count: number;
    allow_webrtc_conferencing: boolean;
    alert_threshold: number;
    critical_threshold: number;
  };
  config?: any;
  simulation?: {
    status: string;
    latest?: any;
  };
}

// Module-level singleton manager for a single shared WebSocket connection
type Listener = (data: HealthSnapshot | null, isConnected: boolean, latency: number | null) => void;

class HealthStreamManager {
  private ws: WebSocket | null = null;
  private listeners: Set<Listener> = new Set();
  private lastSnapshot: HealthSnapshot | null = null;
  private isConnected = false;
  private latencyMs: number | null = null;
  private reconnectTimer: any = null;
  private pingTimer: any = null;
  private retryDelay = 2000;

  public subscribe(listener: Listener): () => void {
    this.listeners.add(listener);
    // Immediately inform subscriber of current state
    listener(this.lastSnapshot, this.isConnected, this.latencyMs);

    if (this.listeners.size === 1) {
      this.connect();
    }

    return () => {
      this.listeners.delete(listener);
      if (this.listeners.size === 0) {
        this.cleanup();
      }
    };
  }

  private getWsUrl(): string {
    if (typeof window === "undefined") return "ws://localhost:8000/ws/health";
    const host = window.location.hostname || "localhost";
    return (
      process.env.NEXT_PUBLIC_WS_HEALTH_URL ||
      `ws://${host}:8000/ws/health`
    );
  }

  private connect() {
    if (typeof window === "undefined") return;
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    try {
      const url = this.getWsUrl();
      this.ws = new WebSocket(url);

      this.ws.onopen = () => {
        this.isConnected = true;
        this.retryDelay = 2000;
        this.notify();
        this.startPing();
      };

      this.ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload.type === "HEALTH_SNAPSHOT") {
            this.lastSnapshot = payload;
            if (payload.echo_ts) {
              this.latencyMs = Math.max(1, Math.round(performance.now() - payload.echo_ts));
            }
            this.notify();
          }
        } catch (e) {
          console.error("HealthStream parse error:", e);
        }
      };

      this.ws.onclose = () => {
        this.isConnected = false;
        this.stopPing();
        this.notify();
        this.scheduleReconnect();
      };

      this.ws.onerror = () => {
        this.isConnected = false;
        this.notify();
      };
    } catch {
      this.scheduleReconnect();
    }
  }

  private scheduleReconnect() {
    clearTimeout(this.reconnectTimer);
    if (this.listeners.size > 0) {
      this.reconnectTimer = setTimeout(() => {
        this.connect();
      }, this.retryDelay);
      this.retryDelay = Math.min(this.retryDelay * 1.5, 10000);
    }
  }

  private startPing() {
    this.stopPing();
    this.pingTimer = setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({ action: "ping", ts: performance.now() }));
      }
    }, 5000);
  }

  private stopPing() {
    clearInterval(this.pingTimer);
  }

  public refresh() {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ action: "refresh", ts: performance.now() }));
    } else {
      this.connect();
    }
  }

  private notify() {
    for (const listener of this.listeners) {
      listener(this.lastSnapshot, this.isConnected, this.latencyMs);
    }
  }

  private cleanup() {
    this.stopPing();
    clearTimeout(this.reconnectTimer);
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.isConnected = false;
  }
}

const manager = new HealthStreamManager();

export function useHealthStream() {
  const [snapshot, setSnapshot] = useState<HealthSnapshot | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [latencyMs, setLatencyMs] = useState<number | null>(null);

  useEffect(() => {
    const unsubscribe = manager.subscribe((data, connected, latency) => {
      setSnapshot(data);
      setIsConnected(connected);
      setLatencyMs(latency);
    });
    return unsubscribe;
  }, []);

  const refresh = useCallback(() => {
    manager.refresh();
  }, []);

  return {
    snapshot,
    healthData: snapshot,
    kafkaStatus: snapshot?.kafka || null,
    redisMetrics: snapshot?.redis || null,
    worldModel: snapshot?.world_model || null,
    latestSim: snapshot?.simulation?.latest || null,
    isConnected,
    latencyMs,
    refresh,
  };
}
