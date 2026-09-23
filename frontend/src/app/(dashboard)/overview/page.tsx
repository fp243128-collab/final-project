"use client";

import { useEffect, useState } from "react";
import { StatCard } from "@/components/ui/StatCard";
import { RiskScoreCard } from "@/components/ui/RiskScoreCard";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { DataTable } from "@/components/ui/DataTable";
import { ShieldAlert, AlertTriangle, ShieldCheck } from "lucide-react";

export interface ThreatEventData {
  id: string;
  time: string;
  type: string;
  source: string;
  severity: string;
  status: string;
}

export interface DashboardData {
  stats: {
    threats: number;
    critical: number;
    risk_score: number;
    cloud_security_score: number;
  };
  trends: {
    threats?: { direction: "up" | "down"; value: string };
    critical?: { direction: "up" | "down"; value: string };
    cloud_security_score?: { direction: "up" | "down"; value: string };
  };
  recent_events: ThreatEventData[];
  threat_distribution: { label: string; count: number }[];
}

export default function OverviewPage() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await fetch("http://localhost:8000/api/overview");
        const result = await response.json();
        setData(result);
      } catch (error) {
        console.error("Error fetching overview data:", error);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  if (loading) {
    return (
      <div className="flex h-[50vh] items-center justify-center text-muted">
        Loading Security Overview...
      </div>
    );
  }

  if (!data || !data.stats) {
    return (
      <div className="flex h-[50vh] items-center justify-center text-critical">
        Error loading data. Make sure backend is running on port 8000.
      </div>
    );
  }

  const { stats, trends, recent_events, threat_distribution } = data;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-foreground">Security Overview</h1>
          <p className="text-sm text-muted mt-1">Command center for your environment.</p>
        </div>
        <div suppressHydrationWarning className="text-sm text-muted font-mono bg-surface border-sentinel px-3 py-1.5 rounded-md shadow-sm">
          Last updated: {new Date().toLocaleTimeString()}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard title="Threats" value={stats.threats} subtitle="Last 24 hours" icon={<ShieldAlert />} trend={trends.threats?.direction} trendValue={trends.threats?.value} />
        <StatCard title="Critical" value={stats.critical} subtitle="Needs immediate attention" icon={<AlertTriangle />} trend={trends.critical?.direction} trendValue={trends.critical?.value} />
        <RiskScoreCard score={stats.risk_score} />
        <StatCard title="Cloud Security" value={`${stats.cloud_security_score}%`} subtitle="Posture Score" icon={<ShieldCheck />} trend={trends.cloud_security_score?.direction} trendValue={trends.cloud_security_score?.value} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1 bg-surface border-sentinel rounded-lg p-5 shadow-sm">
          <h3 className="text-sm font-semibold text-muted uppercase tracking-wider mb-4">Threat Distribution</h3>
          <div className="space-y-3">
            {threat_distribution?.map((item) => (
              <div key={item.label} className="flex justify-between items-center text-sm">
                <span className="font-medium text-foreground">{item.label}</span>
                <span className="font-mono text-muted">{item.count}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="lg:col-span-2 bg-surface border-sentinel rounded-lg p-5 shadow-sm">
           <div className="flex justify-between items-center mb-4">
            <h3 className="text-sm font-semibold text-muted uppercase tracking-wider">Recent Critical Events</h3>
            <button className="text-primary text-xs font-medium hover:underline">View All</button>
           </div>
           <DataTable
            data={recent_events}
            keyExtractor={(row: ThreatEventData) => row.id}
            columns={[
              { header: "Time", accessor: (row: ThreatEventData) => <span className="font-mono">{row.time}</span> },
              { header: "Type", accessor: "type", className: "font-medium" },
              { header: "Source", accessor: (row: ThreatEventData) => <span className="font-mono">{row.source}</span> },
              { header: "Severity", accessor: (row: ThreatEventData) => <SeverityBadge severity={row.severity as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"} /> },
              { header: "Status", accessor: "status", className: "text-muted" },
            ]}
           />
        </div>
      </div>
    </div>
  );
}
