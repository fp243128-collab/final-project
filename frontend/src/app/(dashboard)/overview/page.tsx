"use client";

import { API_URL, WS_URL } from "@/lib/api";

import { useEffect, useState, useRef, useCallback } from "react";
import { Shield, AlertTriangle, Activity, Cloud, RefreshCw, Zap, Radio, Loader2 } from "lucide-react";
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
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [wsConnected, setWsConnected] = useState(false);
  const [simulating, setSimulating] = useState(false);
  const [simAlert, setSimAlert] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  const fetchOverview = useCallback(async () => {
    try {
      const res = await fetch(`${API_URL}/api/overview`);
      if (res.ok) {
        const json = await res.json();
        setData(json);
      }
    } catch (err) {
      console.error("Failed to load overview data:", err);
    }
  }, []);

  const handleManualRefresh = async () => {
    setIsRefreshing(true);
    await fetchOverview();
    setIsRefreshing(false);
  };

  const handleSimulateAttack = async () => {
    setSimulating(true);
    setSimAlert(null);
    try {
      const res = await fetch(`${API_URL}/api/threats/simulate`, { method: "POST" });
      const result = await res.json();
      if (result.status === "success") {
        setSimAlert(`🚨 Injected Traffic Vector: ${result.scenario} -> ${result.analysis.prediction} (${result.analysis.severity})`);
        await fetchOverview();
      }
    } catch (e) {
      console.error("Simulation error:", e);
    } finally {
      setSimulating(false);
    }
  };

  useEffect(() => {
    let isCancelled = false;

    fetch(`${API_URL}/api/overview`)
      .then((res) => res.json())
      .then((json) => {
        if (!isCancelled) setData(json);
      })
      .catch((err) => console.error("Failed to load overview data:", err));

    // Setup live WebSocket stream
    const connectWs = () => {
      try {
        const ws = new WebSocket(WS_URL);
        wsRef.current = ws;

        ws.onopen = () => {
          setWsConnected(true);
        };

        ws.onmessage = (event) => {
          try {
            const msg = JSON.parse(event.data);
            if (msg.type === "NEW_THREAT" || msg.type === "CSPM_REMEDIATED" || msg.type === "NEW_PIPELINE_RUN") {
              fetchOverview();
            }
          } catch {
            // Ignore malformed WS packets
          }
        };

        ws.onclose = () => {
          setWsConnected(false);
        };

        ws.onerror = () => {
          setWsConnected(false);
        };
      } catch {
        setWsConnected(false);
      }
    };

    connectWs();

    // Fallback periodic polling every 10 seconds to keep charts and telemetry in sync
    const interval = setInterval(fetchOverview, 10000);

    return () => {
      isCancelled = true;
      clearInterval(interval);
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [fetchOverview]);

  if (!data || !data.stats) {
    return (
      <div className="p-12 text-center text-muted flex flex-col items-center justify-center gap-3">
        <Loader2 className="w-8 h-8 text-primary animate-spin" />
        <p className="font-medium text-sm">Aggregating real-time security posture & telemetry...</p>
      </div>
    );
  }

  const getRiskColor = (score: number) => {
    if (score >= 80) return "text-red-600";
    if (score >= 60) return "text-orange-500";
    if (score >= 30) return "text-yellow-500";
    return "text-green-500";
  };

  return (
    <div className="space-y-6">
      {/* Top Header & Real-time Controls */}
      <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-4 mb-2">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-primary/10 rounded-lg border border-primary/20 text-primary">
            <Activity className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="text-2xl font-bold text-foreground">Security Overview</h1>
              <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold border ${
                wsConnected 
                  ? 'bg-emerald-50 text-emerald-700 border-emerald-200' 
                  : 'bg-amber-50 text-amber-700 border-amber-200'
              }`}>
                <Radio className={`w-3 h-3 ${wsConnected ? 'animate-pulse text-emerald-500' : 'text-amber-500'}`} />
                {wsConnected ? 'Live Stream Active' : 'Polling (10s)'}
              </span>
            </div>
            <p className="text-xs text-muted">
              Live threat telemetry, cloud posture analytics, and risk assessments
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleSimulateAttack}
            disabled={simulating}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold bg-red-600 hover:bg-red-700 text-white rounded-md transition-all shadow-xs disabled:opacity-50"
            title="Inject simulated traffic vector to test real-time IDS ML classification"
          >
            {simulating ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5" />}
            <span>{simulating ? "Injecting..." : "Simulate Attack Traffic"}</span>
          </button>

          <button
            onClick={handleManualRefresh}
            disabled={isRefreshing}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium border border-border bg-surface hover:bg-gray-50 text-foreground rounded-md transition-all shadow-xs disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-primary' : 'text-muted'}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {simAlert && (
        <div className="p-3 bg-red-50 border border-red-200 text-red-800 text-xs font-medium rounded-lg flex items-center justify-between animate-fadeIn">
          <span>{simAlert}</span>
          <button onClick={() => setSimAlert(null)} className="text-red-500 hover:text-red-700 font-bold ml-2">✕</button>
        </div>
      )}

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
