"use client";

import { useState } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { ShieldAlert, AlertTriangle, ShieldCheck, Clock, Hash, ChevronDown, ChevronUp, Activity } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

export interface Alert {
  id: string;
  timestamp: string;
  user: string;
  risk_score: number;
  classification: "NORMAL" | "SUSPICIOUS" | "CRITICAL";
  features?: Record<string, any>;
  message?: string;
  top_deviations?: string[];
}

interface LiveAlertFeedProps {
  alerts: Alert[];
}

function AlertCard({ alert }: { alert: Alert }) {
  const [expanded, setExpanded] = useState(false);

  const getIcon = (classification: string) => {
    switch (classification) {
      case "CRITICAL":
        return <ShieldAlert className="h-5 w-5 text-red-500" />;
      case "SUSPICIOUS":
        return <AlertTriangle className="h-5 w-5 text-orange-500" />;
      default:
        return <ShieldCheck className="h-5 w-5 text-green-500" />;
    }
  };

  const getCardStyle = (classification: string) => {
    switch (classification) {
      case "CRITICAL":
        return "border-red-200 bg-red-50 hover:bg-red-100";
      case "SUSPICIOUS":
        return "border-yellow-200 bg-yellow-50 hover:bg-yellow-100";
      default:
        return "border-gray-200 bg-white hover:bg-gray-50 shadow-sm";
    }
  };

  const getBadgeVariant = (classification: string) => {
    switch (classification) {
      case "CRITICAL":
        return "bg-red-100 text-red-600 hover:bg-red-200 border-red-200";
      case "SUSPICIOUS":
        return "bg-orange-100 text-orange-600 hover:bg-orange-200 border-orange-200";
      default:
        return "bg-green-100 text-green-600 hover:bg-green-200 border-green-200";
    }
  };

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: -20, scale: 0.95 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      className={`flex flex-col gap-2 rounded-lg border p-4 backdrop-blur-sm transition-colors cursor-pointer h-fit ${getCardStyle(alert.classification)}`}
      onClick={() => setExpanded(!expanded)}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          {getIcon(alert.classification)}
          <span className="font-bold text-slate-900 text-base tracking-wide">
            {alert.user}
          </span>
        </div>
        <div className="flex items-center gap-3">
          <Badge variant="outline" className={getBadgeVariant(alert.classification)}>
            {alert.classification}
          </Badge>
          <Badge variant="outline" className="bg-gray-100 border-gray-200 font-mono text-xs text-slate-700">
            Score: <span className={alert.risk_score > 75 ? "text-red-500 ml-1 font-bold" : alert.risk_score >= 35 ? "text-yellow-600 ml-1 font-bold" : "text-green-600 ml-1 font-bold"}>{alert.risk_score.toFixed(1)}</span>
          </Badge>
          {expanded ? <ChevronUp className="h-4 w-4 text-slate-400" /> : <ChevronDown className="h-4 w-4 text-slate-400" />}
        </div>
      </div>

      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            className="overflow-hidden"
          >
            <div className="pt-3 pb-1 space-y-3 border-t border-gray-200 mt-2">
              {alert.message && (
                <div className="text-sm text-slate-700 bg-gray-50 p-3 rounded-md border border-gray-200">
                  {alert.message}
                </div>
              )}

              {alert.top_deviations && alert.top_deviations.length > 0 && (
                <div className="space-y-2">
                  <div className="text-xs font-semibold uppercase tracking-wider text-slate-500 flex items-center gap-1">
                    <Activity className="h-3 w-3" />
                    Top Deviations
                  </div>
                  <ul className="space-y-1.5">
                    {alert.top_deviations.map((dev, i) => (
                      <li key={i} className="bg-gray-50 p-2 rounded border border-gray-200 text-xs text-slate-700 flex items-start gap-2 shadow-sm">
                        <span className="text-yellow-500 font-bold mt-0.5">•</span>
                        <span>{dev}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              
              {alert.features && (
                <div className="space-y-2 mt-3">
                   <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">Raw Features Snapshot</div>
                   <div className="bg-gray-50 p-2 rounded border border-gray-200 text-[10px] font-mono text-slate-600 max-h-40 overflow-y-auto custom-scrollbar shadow-sm">
                     <pre>{JSON.stringify(alert.features, null, 2)}</pre>
                   </div>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="flex flex-wrap items-center justify-between text-xs text-slate-500 mt-2 pt-2 border-t border-gray-200">
        <div className="flex items-center gap-1.5">
          <Clock className="h-3.5 w-3.5" />
          {new Date(alert.timestamp).toLocaleTimeString()}
        </div>
        {alert.features && alert.features.dns_query_count !== undefined && (
          <div className="flex items-center gap-1.5">
            <Hash className="h-3.5 w-3.5" />
            {alert.features.dns_query_count} DNS queries
          </div>
        )}
      </div>
    </motion.div>
  );
}

export function LiveAlertFeed({ alerts }: LiveAlertFeedProps) {
  return (
    <div className="flex h-full flex-col space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-medium text-slate-900 flex items-center gap-2">
          <Activity className="h-5 w-5 text-blue-500" />
          Live Incident Stream
        </h3>
        <Badge variant="outline" className="border-green-200 text-green-700 bg-green-100 shadow-sm">
          <div className="mr-2 h-2 w-2 rounded-full bg-green-500 animate-pulse"></div>
          Live
        </Badge>
      </div>

      <ScrollArea className="flex-1 pr-4">
        <div className="space-y-3">
          <AnimatePresence initial={false}>
            {alerts.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-40 text-center text-slate-500 space-y-3 border border-dashed border-gray-300 rounded-lg bg-gray-50">
                 <ShieldCheck className="h-8 w-8 text-green-500/50" />
                 <p>No recent incidents detected.</p>
              </div>
            ) : (
              alerts.map((alert) => (
                <AlertCard key={alert.id} alert={alert} />
              ))
            )}
          </AnimatePresence>
        </div>
      </ScrollArea>
    </div>
  );
}
