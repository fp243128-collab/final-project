"use client";

import { useEffect, useState, useRef } from "react";
import { Bell, CheckCircle, Clock, Radio, ShieldAlert } from "lucide-react";

interface AlertData {
  id: string;
  time: string;
  title: string;
  severity: string;
  source: string;
  message: string;
  status: string;
}

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<AlertData[]>([]);
  const [loading, setLoading] = useState(true);
  const [wsConnected, setWsConnected] = useState(false);
  const [lastNotification, setLastNotification] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  const fetchAlerts = () => {
    fetch("http://localhost:8000/api/alerts")
      .then((res) => res.json())
      .then((data) => {
        setAlerts(data.alerts);
        setLoading(false);
      })
      .catch(console.error);
  };

  useEffect(() => {
    fetchAlerts();

    // Setup live WebSocket connection to SentinelX
    const connectWs = () => {
      try {
        const ws = new WebSocket("ws://localhost:8000/ws/live");
        wsRef.current = ws;

        ws.onopen = () => {
          setWsConnected(true);
        };

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type === "NEW_THREAT") {
              setLastNotification(`🚨 Real-time alert: ${data.threat.type} detected from ${data.threat.source}`);
              fetchAlerts();
            } else if (data.type === "ALERT_RESOLVED") {
              setAlerts(prev => prev.map(a => a.id === data.alert_id ? { ...a, status: "Resolved" } : a));
            } else if (data.type === "CSPM_REMEDIATED") {
              setLastNotification(`🛡️ Policy resolved for resource: ${data.finding_id}`);
              fetchAlerts();
            }
          } catch (e) {
            console.error("Failed to parse ws event:", e);
          }
        };

        ws.onclose = () => {
          setWsConnected(false);
          // Auto-reconnect after 3 seconds
          setTimeout(connectWs, 3000);
        };

        ws.onerror = () => {
          setWsConnected(false);
        };
      } catch (err) {
        console.error("WS error:", err);
      }
    };

    connectWs();

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  const resolveAlert = (id: string) => {
    fetch(`http://localhost:8000/api/alerts/resolve/${id}`, { method: "POST" })
      .then(() => {
        setAlerts(prev => prev.map(a => a.id === id ? { ...a, status: "Resolved" } : a));
      })
      .catch(console.error);
  };

  if (loading) return <div className="p-8 text-center text-muted">Loading alert center...</div>;

  const activeAlerts = alerts.filter(a => a.status === "Active");
  const criticalCount = activeAlerts.filter(a => a.severity.toLowerCase() === "critical").length;
  const highCount = activeAlerts.filter(a => a.severity.toLowerCase() === "high").length;

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <Bell className="w-6 h-6 text-primary" /> Alert & Notification Stream
          </h1>
          <p className="text-xs text-muted mt-1">Real-time event-driven incident broadcast & SOC notifications</p>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold border bg-surface">
            <Radio className={`w-3.5 h-3.5 ${wsConnected ? "text-emerald-500 animate-pulse" : "text-gray-400"}`} />
            <span className={wsConnected ? "text-emerald-600" : "text-gray-500"}>
              {wsConnected ? "Live WebSocket Stream" : "Connecting Stream..."}
            </span>
          </div>

          <div className="flex gap-2">
            <span className="bg-red-50 text-red-700 border border-red-200 px-3 py-1 rounded text-xs font-bold">
              {criticalCount} Critical
            </span>
            <span className="bg-amber-50 text-amber-700 border border-amber-200 px-3 py-1 rounded text-xs font-bold">
              {highCount} High
            </span>
          </div>
        </div>
      </div>

      {lastNotification && (
        <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-xs text-red-800 flex items-center justify-between shadow-xs">
          <div className="flex items-center gap-2 font-medium">
            <ShieldAlert className="w-4 h-4 text-red-600 shrink-0" />
            <span>{lastNotification}</span>
          </div>
          <button 
            onClick={() => setLastNotification(null)}
            className="text-[11px] underline text-red-700 hover:text-red-900"
          >
            Dismiss
          </button>
        </div>
      )}

      <div className="bg-surface border border-sentinel rounded-xl shadow-xs overflow-hidden">
        {alerts.length === 0 ? (
          <div className="p-8 text-center text-muted">No security alerts logged.</div>
        ) : (
          <div className="divide-y divide-border">
            {alerts.map((alert) => (
              <div key={alert.id} className={`p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 transition-colors ${alert.status === "Resolved" ? 'opacity-60 bg-gray-50/70' : 'hover:bg-gray-50'}`}>
                <div className="flex items-start gap-3">
                  <div className="mt-1">
                    {alert.severity.toLowerCase() === "critical" && <div className="w-3 h-3 rounded-full bg-red-500 animate-pulse"></div>}
                    {alert.severity.toLowerCase() === "high" && <div className="w-3 h-3 rounded-full bg-amber-500"></div>}
                    {alert.severity.toLowerCase() === "medium" && <div className="w-3 h-3 rounded-full bg-blue-500"></div>}
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="text-sm font-semibold text-foreground">{alert.title}</h3>
                      <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded ${
                        alert.severity.toLowerCase() === 'critical' ? 'bg-red-100 text-red-700' : 'bg-amber-100 text-amber-700'
                      }`}>
                        {alert.severity}
                      </span>
                    </div>
                    <p className="text-xs text-muted mt-1 max-w-2xl leading-relaxed">{alert.message}</p>
                    <div className="flex items-center gap-4 mt-2 text-[11px] text-muted font-medium">
                      <span className="flex items-center gap-1 font-mono"><Clock className="w-3 h-3"/> {new Date(alert.time).toLocaleTimeString()}</span>
                      <span className="uppercase tracking-wider font-mono">Source: {alert.source}</span>
                      <span className="uppercase tracking-wider font-mono text-gray-400">ID: {alert.id}</span>
                    </div>
                  </div>
                </div>
                <div>
                  {alert.status === "Active" ? (
                    <button 
                      onClick={() => resolveAlert(alert.id)}
                      className="px-3.5 py-1.5 bg-white border border-gray-300 rounded-md text-xs font-semibold text-gray-700 hover:bg-gray-100 transition-colors shadow-xs"
                    >
                      Resolve Incident
                    </button>
                  ) : (
                    <span className="flex items-center gap-1 text-emerald-600 text-xs font-semibold bg-emerald-50 px-2.5 py-1 rounded-md border border-emerald-200">
                      <CheckCircle className="w-3.5 h-3.5"/> Resolved
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
