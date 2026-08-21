"use client";

import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from "recharts";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";

interface RiskData {
  name: string;
  value: number;
  color: string;
}

interface RiskDistributionChartProps {
  data: RiskData[];
}

export function RiskDistributionChart({ data }: RiskDistributionChartProps) {
  return (
    <Card className="flex flex-col bg-white border-gray-100 shadow-sm rounded-xl h-full">
      <CardHeader className="items-center pb-2">
        <CardTitle className="text-lg font-semibold tracking-tight text-slate-800">
          Ensemble ML Risk Distribution
        </CardTitle>
        <CardDescription className="text-slate-500">
          Real-time risk classification of 5-minute behavioral windows
        </CardDescription>
      </CardHeader>
      <CardContent className="flex-1 pb-0">
        <div className="h-[250px] w-full">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={90}
                paddingAngle={5}
                dataKey="value"
                stroke="none"
              >
                {data.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: 'rgba(255, 255, 255, 0.95)', 
                  border: '1px solid #f1f5f9',
                  borderRadius: '8px',
                  color: '#1e293b',
                  boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)'
                }}
                itemStyle={{ color: '#0f172a' }}
              />
              <Legend verticalAlign="bottom" height={36}/>
            </PieChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}
