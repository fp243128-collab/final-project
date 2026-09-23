"use client";

import { useEffect, useState } from "react";
import { BarChart2 } from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
  PieChart,
  Pie,
  Cell
} from "recharts";

interface AnalyticsData {
  trend: {
    date: string;
    critical: number;
    high: number;
    medium: number;
  }[];
  severity_distribution: {
    name: string;
    value: number;
  }[];
}

const COLORS = {
  Critical: '#ef4444',
  High: '#f97316',
  Medium: '#eab308',
  Low: '#3b82f6'
};

export default function AnalyticsPage() {
  const [data, setData] = useState<AnalyticsData | null>(null);

  useEffect(() => {
    fetch("http://localhost:8000/api/analytics")
      .then((res) => res.json())
      .then((json) => setData(json))
      .catch(console.error);
  }, []);

  if (!data) return <div className="p-8 text-center text-muted">Loading analytics data...</div>;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 mb-6">
        <BarChart2 className="w-7 h-7 text-primary" />
        <h1 className="text-2xl font-bold text-foreground">Security Analytics</h1>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Trend Chart */}
        <div className="col-span-1 lg:col-span-2 bg-surface border-sentinel p-5 rounded-lg shadow-sm">
          <h2 className="text-lg font-semibold mb-4 text-foreground">Threat Trend (30 Days)</h2>
          <div className="h-[400px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data.trend}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" vertical={false} />
                <XAxis dataKey="date" stroke="#9ca3af" fontSize={12} tickMargin={10} minTickGap={30} />
                <YAxis stroke="#9ca3af" fontSize={12} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#ffffff', borderRadius: '8px', border: '1px solid #e5e7eb' }}
                />
                <Legend />
                <Area type="monotone" dataKey="critical" stackId="1" stroke={COLORS.Critical} fill={COLORS.Critical} fillOpacity={0.6} />
                <Area type="monotone" dataKey="high" stackId="1" stroke={COLORS.High} fill={COLORS.High} fillOpacity={0.6} />
                <Area type="monotone" dataKey="medium" stackId="1" stroke={COLORS.Medium} fill={COLORS.Medium} fillOpacity={0.6} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Distribution Chart */}
        <div className="bg-surface border-sentinel p-5 rounded-lg shadow-sm">
          <h2 className="text-lg font-semibold mb-4 text-foreground">Severity Distribution</h2>
          <div className="h-[300px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={data.severity_distribution}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={100}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {data.severity_distribution.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[entry.name as keyof typeof COLORS]} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ backgroundColor: '#ffffff', borderRadius: '8px', border: '1px solid #e5e7eb' }}
                />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
          
          <div className="mt-6 pt-6 border-t border-border">
            <h3 className="text-sm font-semibold mb-3">Summary</h3>
            <div className="space-y-2">
              {data.severity_distribution.map((item, i) => (
                <div key={i} className="flex justify-between items-center text-sm">
                  <span className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full" style={{ backgroundColor: COLORS[item.name as keyof typeof COLORS] }}></div>
                    {item.name}
                  </span>
                  <span className="font-semibold">{item.value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
