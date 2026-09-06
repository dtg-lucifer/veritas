"use client";

import {
  BarChart3,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  Gauge,
  GitBranch,
  HeartPulse,
  LayoutDashboard,
  Radio,
  Settings2,
  Shield,
  ShieldAlert,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import type React from "react";
import { ThemeToggle } from "@/components/theme/ThemeToggle";
import { Button } from "@/components/ui/button";
import { useHealthStream } from "@/lib/useHealthStream";

interface NavItem {
  name: string;
  href: string;
  icon: React.ElementType;
  badge?: string;
}

const navItems: NavItem[] = [
  { name: "Overview", href: "/", icon: LayoutDashboard },
  {
    name: "Live Alert Feed",
    href: "/alerts",
    icon: ShieldAlert,
    badge: "LIVE",
  },
  { name: "Admin Config", href: "/config", icon: Settings2 },
  { name: "Full Statistics", href: "/stats", icon: BarChart3 },
  {
    name: "Forward Simulation",
    href: "/simulation",
    icon: GitBranch,
    badge: "AI",
  },
  { name: "Subsystem Health", href: "/health", icon: HeartPulse },
  { name: "Metrics & Grafana", href: "/metrics", icon: Gauge },
];

export function Sidebar({
  collapsed,
  setCollapsed,
}: {
  collapsed: boolean;
  setCollapsed: (c: boolean | ((prev: boolean) => boolean)) => void;
}) {
  const pathname = usePathname();
  const { isConnected, latencyMs } = useHealthStream();
  const backendAlive = isConnected;
  const backendLatency = latencyMs ?? 2;

  return (
    <aside
      className={`fixed top-0 left-0 z-40 h-screen border-r border-border bg-card transition-all duration-300 flex flex-col justify-between select-none ${collapsed ? "w-16" : "w-64"
        }`}
    >
      {/* Top Brand Header */}
      <div>
        <div className="h-16 flex items-center justify-between px-3 border-b border-border">
          {!collapsed && (
            <Link
              href="/"
              className="flex items-center gap-2.5 overflow-hidden"
            >
              <div className="h-9 w-9 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center shrink-0">
                <Shield className="h-5 w-5 text-primary" />
              </div>
              <div className="flex flex-col">
                <span className="font-bold text-sm tracking-wide text-foreground leading-tight">
                  Veritas XAI
                </span>
                <span className="text-[10px] text-muted-foreground font-mono">
                  AI World Model SOC
                </span>
              </div>
            </Link>
          )}

          {collapsed && (
            <Link href="/" className="mx-auto" title="Veritas SOC">
              <div className="h-9 w-9 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center">
                <Shield className="h-5 w-5 text-primary" />
              </div>
            </Link>
          )}

          <Button
            variant="ghost"
            size="icon-xs"
            onClick={() => setCollapsed((prev) => !prev)}
            className="text-muted-foreground hover:text-foreground shrink-0"
            title={collapsed ? "Expand Sidebar" : "Collapse Sidebar"}
          >
            {collapsed ? (
              <ChevronRight className="h-4 w-4" />
            ) : (
              <ChevronLeft className="h-4 w-4" />
            )}
          </Button>
        </div>

        {/* Navigation Items */}
        <nav className="p-2 space-y-1 mt-2">
          {navItems.map((item) => {
            const isActive = pathname === item.href;
            const Icon = item.icon;

            return (
              <Link
                key={item.href}
                href={item.href}
                className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-all group relative ${isActive
                  ? "bg-primary text-primary-foreground shadow-sm shadow-primary/20 font-semibold"
                  : "text-muted-foreground hover:text-foreground hover:bg-muted"
                  } ${collapsed ? "justify-center px-0 h-10" : ""}`}
                title={collapsed ? item.name : undefined}
              >
                <Icon
                  className={`h-4 w-4 shrink-0 transition-transform group-hover:scale-110 ${isActive
                    ? "text-primary-foreground"
                    : "text-muted-foreground group-hover:text-foreground"
                    }`}
                />
                {!collapsed && (
                  <span className="truncate flex-1">{item.name}</span>
                )}
                {!collapsed && item.badge && (
                  <span
                    className={`text-[10px] uppercase font-mono px-1.5 py-0.5 rounded font-bold ${isActive
                      ? "bg-primary-foreground/20 text-primary-foreground"
                      : "bg-primary/10 text-primary border border-primary/20"
                      }`}
                  >
                    {item.badge}
                  </span>
                )}
                {/* Collapsed Tooltip Indicator */}
                {collapsed && isActive && (
                  <span className="absolute right-1 w-1.5 h-1.5 rounded-full bg-primary-foreground" />
                )}
              </Link>
            );
          })}
        </nav>
      </div>

      {/* Bottom Area: Health Indicator, Quick Links & Theme Switcher */}
      <div className="p-2 border-t border-border space-y-2 bg-muted/20">
        {/* Subsystem Health Indicator Pill */}
        <Link
          href="/health"
          className={`block rounded-lg p-2 transition-all border ${backendAlive === true
            ? "bg-emerald-500/5 hover:bg-emerald-500/10 border-emerald-500/20 text-emerald-500"
            : backendAlive === false
              ? "bg-destructive/5 hover:bg-destructive/10 border-destructive/20 text-destructive"
              : "bg-muted border-border text-muted-foreground"
            } ${collapsed ? "text-center py-2 px-0" : ""}`}
          title={
            backendAlive === true
              ? `Backend Online (${backendLatency}ms) - View Health`
              : backendAlive === false
                ? "Backend Offline - Click to Inspect"
                : "Connecting..."
          }
        >
          {collapsed ? (
            <div className="flex flex-col items-center justify-center">
              <span
                className={`relative flex h-2.5 w-2.5 ${backendAlive === true
                  ? "text-emerald-500"
                  : "text-destructive"
                  }`}
              >
                {backendAlive === true && (
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                )}
                <span
                  className={`relative inline-flex rounded-full h-2.5 w-2.5 ${backendAlive === true
                    ? "bg-emerald-500"
                    : backendAlive === false
                      ? "bg-destructive"
                      : "bg-yellow-500"
                    }`}
                />
              </span>
            </div>
          ) : (
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="relative flex h-2 w-2 shrink-0">
                  {backendAlive === true && (
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                  )}
                  <span
                    className={`relative inline-flex rounded-full h-2 w-2 ${backendAlive === true
                      ? "bg-emerald-500"
                      : backendAlive === false
                        ? "bg-destructive"
                        : "bg-yellow-500"
                      }`}
                  />
                </span>
                <span className="text-xs font-medium">
                  {backendAlive === true
                    ? "Backend Active"
                    : backendAlive === false
                      ? "Backend Offline"
                      : "Checking..."}
                </span>
              </div>
              {backendAlive === true && backendLatency !== null && (
                <span className="text-[10px] font-mono opacity-80">
                  {backendLatency}ms
                </span>
              )}
            </div>
          )}
        </Link>

        {/* Grafana External Link Shortcut */}
        {!collapsed && (
          <a
            href="http://localhost:3001"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center justify-between px-3 py-1.5 rounded-lg text-xs text-muted-foreground hover:text-foreground hover:bg-muted transition-colors font-medium"
          >
            <span className="flex items-center gap-2">
              <Radio className="h-3.5 w-3.5 text-orange-400" />
              <span>Grafana SOC</span>
            </span>
            <ExternalLink className="h-3 w-3 opacity-60" />
          </a>
        )}

        {/* Theme Toggle */}
        <ThemeToggle collapsed={collapsed} />
      </div>
    </aside>
  );
}
