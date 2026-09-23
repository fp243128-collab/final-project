"use client";

import { useEffect, useState } from "react";
import { Activity, Cpu, HardDrive, Network, Server, Zap } from "lucide-react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";

interface SystemMetric {
  time: string;
  cpu_usage: number;
  memory_usage: number;
  network_rx: number;
  network_tx: number;
  api_latency: number;
}

interface SystemHealth {
  uptime: string;
  active_containers: number;
  error_rate: string;
  status: string;
}

export default function MonitoringPage() {
  const [metrics, setMetrics] = useState<SystemMetric[]>([]);
  const [health, setHealth] = useState<SystemHealth | null>(null);

  useEffect(() => {
    const fetchData = () => {
      fetch("http://localhost:8000/api/monitoring/metrics")
        .then((res) => res.json())
        .then((data) => {
          // Format time for chart display
          const formatted = data.metrics.map((m: SystemMetric) => ({
            ...m,
            timeLabel: new Date(m.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
          }));
          setMetrics(formatted);
        })
        .catch(console.error);

      fetch("http://localhost:8000/api/monitoring/health")
        .then((res) => res.json())
        .then((data) => setHealth(data))
        .catch(console.error);
    };

    fetchData();
    const interval = setInterval(fetchData, 5000); // Poll every 5s for the live effect
    return () => clearInterval(interval);
  }, []);

  if (!metrics.length || !health) {
    return <div className="p-8 text-center text-muted">Loading monitoring telemetry...</div>;
  }

  const latest = metrics[metrics.length - 1];

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-foreground">Infrastructure Monitoring</h1>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse"></div>
          <span className="text-sm font-medium text-muted uppercase tracking-wider">Live</span>
        </div>
      </div>

      {/* Top Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard 
          title="System Status" 
          value={health.status} 
          icon={<Server className="w-5 h-5 text-primary" />} 
          subtitle={`Uptime: ${health.uptime}`} 
        />
        <StatCard 
          title="API Latency" 
          value={`${latest.api_latency}ms`} 
          icon={<Zap className="w-5 h-5 text-yellow-500" />} 
          subtitle="Avg Response Time" 
        />
        <StatCard 
          title="Active Containers" 
          value={health.active_containers.toString()} 
          icon={<HardDrive className="w-5 h-5 text-blue-500" />} 
          subtitle="Docker Services" 
        />
        <StatCard 
          title="Error Rate" 
          value={health.error_rate} 
          icon={<Activity className="w-5 h-5 text-red-500" />} 
          subtitle="Last 5 minutes" 
        />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* CPU & Memory */}
        <div className="bg-surface border-sentinel p-5 rounded-lg shadow-sm">
          <h2 className="text-lg font-semibold flex items-center gap-2 mb-4">
            <Cpu className="w-5 h-5" /> Resource Usage
          </h2>
          <div className="h-[300px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={metrics}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" vertical={false} />
                <XAxis dataKey="timeLabel" stroke="#9ca3af" fontSize={12} tickMargin={10} minTickGap={30} />
                <YAxis stroke="#9ca3af" fontSize={12} domain={[0, 100]} tickFormatter={(val) => `${val}%`} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#ffffff', borderRadius: '8px', border: '1px solid #e5e7eb' }}
                  itemStyle={{ fontSize: '14px' }}
                />
                <Legend />
                <Line type="monotone" name="CPU Usage (%)" dataKey="cpu_usage" stroke="#0ea5e9" strokeWidth={2} dot={false} activeDot={{ r: 6 }} />
                <Line type="monotone" name="Memory Usage (%)" dataKey="memory_usage" stroke="#8b5cf6" strokeWidth={2} dot={false} activeDot={{ r: 6 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Network */}
        <div className="bg-surface border-sentinel p-5 rounded-lg shadow-sm">
          <h2 className="text-lg font-semibold flex items-center gap-2 mb-4">
            <Network className="w-5 h-5" /> Network Traffic
          </h2>
          <div className="h-[300px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={metrics}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" vertical={false} />
                <XAxis dataKey="timeLabel" stroke="#9ca3af" fontSize={12} tickMargin={10} minTickGap={30} />
                <YAxis stroke="#9ca3af" fontSize={12} tickFormatter={(val) => `${val} MB/s`} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#ffffff', borderRadius: '8px', border: '1px solid #e5e7eb' }}
                  itemStyle={{ fontSize: '14px' }}
                />
                <Legend />
                <Line type="monotone" name="Network RX (MB/s)" dataKey="network_rx" stroke="#10b981" strokeWidth={2} dot={false} activeDot={{ r: 6 }} />
                <Line type="monotone" name="Network TX (MB/s)" dataKey="network_tx" stroke="#f59e0b" strokeWidth={2} dot={false} activeDot={{ r: 6 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
}

function StatCard({ title, value, icon, subtitle }: { title: string; value: string; icon: React.ReactNode; subtitle: string }) {
  return (
    <div className="bg-surface border-sentinel p-5 rounded-lg shadow-sm flex items-start justify-between">
      <div>
        <h3 className="text-sm font-medium text-muted mb-1">{title}</h3>
        <p className="text-2xl font-bold text-foreground">{value}</p>
        <p className="text-xs text-muted mt-1">{subtitle}</p>
      </div>
      <div className="bg-background p-2 rounded-md">
        {icon}
      </div>
    </div>
  );
}
