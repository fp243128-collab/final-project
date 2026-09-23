"use client";

import { useEffect, useState } from "react";
import { Settings, Cloud, Key, CheckCircle, XCircle } from "lucide-react";

interface Integration {
  name: string;
  status: string;
  last_sync: string;
}

export default function SettingsPage() {
  const [integrations, setIntegrations] = useState<Integration[]>([]);

  useEffect(() => {
    fetch("http://localhost:8000/api/settings")
      .then(res => res.json())
      .then(data => setIntegrations(data.integrations))
      .catch(console.error);
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 mb-6">
        <Settings className="w-7 h-7 text-primary" />
        <h1 className="text-2xl font-bold text-foreground">Platform Settings</h1>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Cloud Accounts Panel */}
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-surface border-sentinel rounded-xl shadow-sm overflow-hidden">
            <div className="p-4 border-b border-border bg-gray-50 flex items-center gap-2">
              <Cloud className="w-5 h-5 text-muted" />
              <h2 className="font-semibold text-foreground">Cloud Integrations</h2>
            </div>
            <div className="p-0">
              <ul className="divide-y divide-border">
                {integrations.map((int, i) => (
                  <li key={i} className="p-4 flex items-center justify-between hover:bg-gray-50">
                    <div>
                      <h3 className="font-medium text-foreground">{int.name}</h3>
                      <p className="text-xs text-muted">Last sync: {int.last_sync}</p>
                    </div>
                    <div className="flex items-center gap-4">
                      {int.status === "Connected" ? (
                        <span className="flex items-center gap-1 text-green-600 text-sm font-medium">
                          <CheckCircle className="w-4 h-4" /> Connected
                        </span>
                      ) : (
                        <span className="flex items-center gap-1 text-gray-500 text-sm font-medium">
                          <XCircle className="w-4 h-4" /> Disconnected
                        </span>
                      )}
                      <button className={`px-3 py-1.5 text-xs font-semibold rounded border ${
                        int.status === "Connected" 
                          ? "border-red-200 text-red-600 hover:bg-red-50" 
                          : "border-blue-200 text-blue-600 hover:bg-blue-50"
                      }`}>
                        {int.status === "Connected" ? "Disconnect" : "Connect"}
                      </button>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          <div className="bg-surface border-sentinel rounded-xl shadow-sm p-6">
             <div className="flex items-center gap-2 mb-4 border-b border-border pb-3">
              <Key className="w-5 h-5 text-muted" />
              <h2 className="font-semibold text-foreground">API Keys</h2>
            </div>
            <p className="text-sm text-muted mb-4">Manage API keys used for external CI/CD tool integrations.</p>
            <button className="bg-primary hover:bg-blue-700 text-white px-4 py-2 rounded text-sm font-medium transition-colors">
              Generate New API Key
            </button>
          </div>
        </div>

        {/* Profile / Preferences Panel */}
        <div className="space-y-6">
           <div className="bg-surface border-sentinel rounded-xl shadow-sm p-6">
            <h2 className="font-semibold text-foreground mb-4">User Profile</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-xs text-muted mb-1 uppercase font-semibold">Email</label>
                <input type="email" disabled value="admin@sentinelx.io" className="w-full bg-gray-100 border border-gray-200 rounded px-3 py-2 text-sm text-gray-500" />
              </div>
              <div>
                <label className="block text-xs text-muted mb-1 uppercase font-semibold">Role</label>
                <input type="text" disabled value="Super Admin" className="w-full bg-gray-100 border border-gray-200 rounded px-3 py-2 text-sm text-gray-500" />
              </div>
            </div>
          </div>

          <div className="bg-surface border-sentinel rounded-xl shadow-sm p-6">
            <h2 className="font-semibold text-foreground mb-4">Notification Preferences</h2>
            <div className="space-y-3">
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" defaultChecked className="rounded text-primary focus:ring-primary" />
                Email Alerts (High & Critical)
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" defaultChecked className="rounded text-primary focus:ring-primary" />
                Slack Notifications
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" className="rounded text-primary focus:ring-primary" />
                Weekly Summary Report
              </label>
            </div>
            <button className="mt-4 w-full border border-border hover:bg-gray-50 font-medium text-sm px-4 py-2 rounded transition-colors">
              Save Preferences
            </button>
          </div>
        </div>

      </div>
    </div>
  );
}
