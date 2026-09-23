"use client";

import { useEffect, useState } from "react";
import { Shield, AlertTriangle, Activity, Cloud } from "lucide-react";
import {
  BarChart,
  Bar,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

interface OverviewData {
  stats: {
    threats: number;
    critical: number;
    risk_score: number;
    cloud_security_score: number;
  };
  trends: {
    threats: { direction: string; value: string };
    critical: { direction: string; value: string };
    cloud_security_score: { direction: string; value: string };
  };
  threat_distribution: { label: string; count: number }[];
  risk_trend: { date: string; score: number }[];
  recent_events: {
    id: string;
    time: string;
    type: string;
    source: string;
    severity: string;
    status: string;
  }[];
}

export default function OverviewPage() {
  const [data, setData] = useState<OverviewData | null>(null);

  useEffect(() => {
    fetch("http://localhost:8000/api/overview")
      .then((res) => res.json())
      .then((json) => setData(json))
      .catch(console.error);
  }, []);

  if (!data || !data.stats) {
    return <div className="p-8 text-center text-muted">Loading overview data...</div>;
  }

  const getRiskColor = (score: number) => {
    if (score >= 80) return "text-red-600";
    if (score >= 60) return "text-orange-500";
    if (score >= 30) return "text-yellow-500";
    return "text-green-500";
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 mb-6">
        <Activity className="w-7 h-7 text-primary" />
        <h1 className="text-2xl font-bold text-foreground">Security Overview</h1>
      </div>

      {/* Top Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard 
          title="Total Threats" 
          value={data.stats.threats} 
          trend={data.trends.threats?.value} 
          icon={<Shield className="w-5 h-5 text-blue-500" />} 
        />
        <StatCard 
          title="Critical Events" 
          value={data.stats.critical} 
          trend={data.trends.critical?.value} 
          icon={<AlertTriangle className="w-5 h-5 text-red-500" />} 
        />
        <StatCard 
          title="Overall Risk Score" 
          value={`${data.stats.risk_score}/100`} 
          trend=""
          valueColor={getRiskColor(data.stats.risk_score)}
          icon={<Activity className="w-5 h-5 text-purple-500" />} 
        />
        <StatCard 
          title="Cloud Security" 
          value={`${data.stats.cloud_security_score}%`} 
          trend={data.trends.cloud_security_score?.value} 
          icon={<Cloud className="w-5 h-5 text-green-500" />} 
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Threat Distribution */}
        <div className="bg-surface border-sentinel p-5 rounded-lg shadow-sm">
          <h2 className="text-lg font-semibold mb-4 text-foreground">Threat Distribution</h2>
          <div className="h-[300px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.threat_distribution} layout="vertical" margin={{ left: 20 }}>
                <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#e5e7eb" />
                <XAxis type="number" stroke="#9ca3af" fontSize={12} />
                <YAxis dataKey="label" type="category" stroke="#9ca3af" fontSize={12} width={100} />
                <Tooltip cursor={{ fill: '#f3f4f6' }} contentStyle={{ borderRadius: '8px' }} />
                <Bar dataKey="count" fill="#2563EB" radius={[0, 4, 4, 0]} barSize={24} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Risk Trend */}
        <div className="bg-surface border-sentinel p-5 rounded-lg shadow-sm">
          <h2 className="text-lg font-semibold mb-4 text-foreground">Security Risk Trend</h2>
          <div className="h-[300px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data.risk_trend}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e5e7eb" />
                <XAxis dataKey="date" stroke="#9ca3af" fontSize={12} />
                <YAxis stroke="#9ca3af" fontSize={12} domain={[0, 100]} />
                <Tooltip contentStyle={{ borderRadius: '8px' }} />
                <Area type="monotone" dataKey="score" stroke="#ef4444" fill="#ef4444" fillOpacity={0.2} strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent Events Table */}
      <div className="bg-surface border-sentinel rounded-lg shadow-sm overflow-hidden">
        <div className="p-5 border-b border-border">
          <h2 className="text-lg font-semibold text-foreground">Recent Critical Events</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead className="text-xs text-muted uppercase bg-gray-50 border-b border-border">
              <tr>
                <th className="px-6 py-3 font-medium">Time</th>
                <th className="px-6 py-3 font-medium">Type</th>
                <th className="px-6 py-3 font-medium">Source</th>
                <th className="px-6 py-3 font-medium">Severity</th>
                <th className="px-6 py-3 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {data.recent_events.length === 0 ? (
                <tr><td colSpan={5} className="px-6 py-4 text-center text-muted">No recent events found.</td></tr>
              ) : (
                data.recent_events.map((event) => (
                  <tr key={event.id} className="border-b border-border hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">{event.time}</td>
                    <td className="px-6 py-4 font-medium text-foreground">{event.type}</td>
                    <td className="px-6 py-4 text-muted font-mono">{event.source}</td>
                    <td className="px-6 py-4">
                      <span className={`px-2 py-1 rounded text-xs font-semibold ${
                        event.severity === "CRITICAL" ? "bg-red-100 text-red-700" :
                        event.severity === "HIGH" ? "bg-orange-100 text-orange-700" :
                        "bg-yellow-100 text-yellow-700"
                      }`}>
                        {event.severity}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <span className={`px-2 py-1 rounded text-xs font-semibold ${
                        event.status === "Open" ? "border border-red-200 text-red-600 bg-red-50" : "border border-gray-200 text-gray-600 bg-gray-50"
                      }`}>
                        {event.status}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

interface StatCardProps {
  title: string;
  value: string | number;
  trend?: string;
  icon: React.ReactNode;
  valueColor?: string;
}

function StatCard({ title, value, trend, icon, valueColor = "text-foreground" }: StatCardProps) {
  return (
    <div className="bg-surface border-sentinel p-5 rounded-lg shadow-sm">
      <div className="flex justify-between items-start mb-2">
        <h3 className="text-sm font-medium text-muted uppercase tracking-wider">{title}</h3>
        {icon}
      </div>
      <div className={`text-3xl font-bold ${valueColor}`}>{value}</div>
      {trend && (
        <div className="mt-2 text-sm text-muted">
          <span className={trend.startsWith("+") || trend.startsWith("Up") ? "text-red-500 font-medium" : "text-green-500 font-medium"}>
            {trend}
          </span>{" "}
          from last week
        </div>
      )}
    </div>
  );
}
