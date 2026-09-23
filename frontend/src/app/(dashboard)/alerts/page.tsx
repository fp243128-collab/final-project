"use client";

import { useEffect, useState } from "react";
import { Bell, CheckCircle, Clock } from "lucide-react";

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
    const interval = setInterval(fetchAlerts, 10000); // Poll every 10s
    return () => clearInterval(interval);
  }, []);

  const resolveAlert = (id: string) => {
    fetch(`http://localhost:8000/api/alerts/resolve/${id}`, { method: "POST" })
      .then(() => fetchAlerts())
      .catch(console.error);
  };

  if (loading) return <div className="p-8 text-center text-muted">Loading alerts...</div>;

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
          <Bell className="w-6 h-6 text-primary" /> Alert Center
        </h1>
        <div className="flex gap-2">
          <span className="bg-red-100 text-red-700 px-3 py-1 rounded text-sm font-semibold">
            {alerts.filter(a => a.severity === "Critical" && a.status === "Active").length} Critical
          </span>
          <span className="bg-yellow-100 text-yellow-700 px-3 py-1 rounded text-sm font-semibold">
            {alerts.filter(a => a.severity === "High" && a.status === "Active").length} High
          </span>
        </div>
      </div>

      <div className="bg-surface border-sentinel rounded-lg shadow-sm">
        {alerts.length === 0 ? (
          <div className="p-8 text-center text-muted">No alerts found.</div>
        ) : (
          <div className="divide-y divide-border">
            {alerts.map((alert) => (
              <div key={alert.id} className={`p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 ${alert.status === "Resolved" ? 'opacity-60 bg-gray-50' : 'hover:bg-gray-50'}`}>
                <div className="flex items-start gap-3">
                  <div className="mt-1">
                    {alert.severity === "Critical" && <div className="w-3 h-3 rounded-full bg-red-500 animate-pulse"></div>}
                    {alert.severity === "High" && <div className="w-3 h-3 rounded-full bg-orange-500"></div>}
                    {alert.severity === "Medium" && <div className="w-3 h-3 rounded-full bg-yellow-500"></div>}
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-foreground">{alert.title}</h3>
                    <p className="text-sm text-muted mt-1 max-w-2xl">{alert.message}</p>
                    <div className="flex items-center gap-4 mt-2 text-xs text-muted font-medium">
                      <span className="flex items-center gap-1"><Clock className="w-3 h-3"/> {new Date(alert.time).toLocaleString()}</span>
                      <span className="uppercase tracking-wider">Source: {alert.source}</span>
                      <span className="uppercase tracking-wider">ID: {alert.id}</span>
                    </div>
                  </div>
                </div>
                <div>
                  {alert.status === "Active" ? (
                    <button 
                      onClick={() => resolveAlert(alert.id)}
                      className="px-4 py-2 bg-white border border-gray-300 rounded text-sm font-medium hover:bg-gray-50 transition-colors"
                    >
                      Resolve
                    </button>
                  ) : (
                    <span className="flex items-center gap-1 text-green-600 text-sm font-semibold bg-green-50 px-3 py-1 rounded border border-green-200">
                      <CheckCircle className="w-4 h-4"/> Resolved
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
