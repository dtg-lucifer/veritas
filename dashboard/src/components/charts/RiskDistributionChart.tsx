"use client";

import { PieChart as PieIcon } from "lucide-react";
import {
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
} from "recharts";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export interface RiskData {
  name: string;
  value: number;
  color: string;
}

interface RiskDistributionChartProps {
  data: RiskData[];
}

export function RiskDistributionChart({ data }: RiskDistributionChartProps) {
  const total = data.reduce((acc, curr) => acc + curr.value, 0);

  return (
    <Card className="flex flex-col border-border bg-card shadow-sm rounded-xl h-full">
      <CardHeader className="items-start pb-2">
        <div className="flex items-center gap-2">
          <PieIcon className="h-4 w-4 text-primary" />
          <CardTitle className="text-sm font-semibold tracking-wide uppercase text-foreground">
            Threat Distribution Radar
          </CardTitle>
        </div>
        <CardDescription className="text-xs text-muted-foreground">
          Evaluation breakdown across continuous 15-second state windows
        </CardDescription>
      </CardHeader>
      <CardContent className="flex-1 pb-2">
        <div className="h-[240px] w-full">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                cx="50%"
                cy="50%"
                innerRadius={55}
                outerRadius={80}
                paddingAngle={4}
                dataKey="value"
                stroke="none"
              >
                {data.map((entry) => (
                  <Cell key={entry.name} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                content={({ active, payload }) => {
                  if (active && payload && payload.length) {
                    const item = payload[0];
                    const val = Number(item.value) || 0;
                    const pct =
                      total > 0 ? ((val / total) * 100).toFixed(1) : "0.0";
                    return (
                      <div className="rounded-lg border border-border bg-popover/95 p-2.5 shadow-md backdrop-blur-sm text-xs font-mono">
                        <div className="font-semibold text-popover-foreground mb-0.5">
                          {item.name}
                        </div>
                        <div className="text-muted-foreground">
                          Count:{" "}
                          <span className="text-foreground font-bold">
                            {val}
                          </span>{" "}
                          ({pct}%)
                        </div>
                      </div>
                    );
                  }
                  return null;
                }}
              />
              <Legend
                verticalAlign="bottom"
                height={32}
                formatter={(value) => (
                  <span className="text-xs text-muted-foreground font-mono">
                    {value}
                  </span>
                )}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}
