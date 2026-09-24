"use client";

import { API_URL, WS_URL } from "@/lib/api";

import { useEffect, useState } from "react";
import { History, Search, Download } from "lucide-react";

interface AuditLog {
  id: string;
  time: string;
  user: string;
  action: string;
  status: string;
}

export default function AuditLogsPage() {
  const [logs, setLogs] = useState<AuditLog[]>([]);

  useEffect(() => {
    fetch(`${API_URL}/api/audit-logs`)
      .then(res => res.json())
      .then(data => setLogs(data.logs))
      .catch(console.error);
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 mb-6">
        <History className="w-7 h-7 text-primary" />
        <h1 className="text-2xl font-bold text-foreground">Audit Logs</h1>
      </div>

      <div className="bg-surface border-sentinel rounded-lg shadow-sm overflow-hidden">
        <div className="p-4 border-b border-border flex justify-between items-center bg-gray-50">
          <div className="relative">
            <Search className="w-4 h-4 text-muted absolute left-3 top-1/2 -translate-y-1/2" />
            <input 
              type="text" 
              placeholder="Search logs..." 
              className="pl-9 pr-4 py-2 border border-gray-300 rounded text-sm w-64 focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </div>
          <button className="border border-border text-foreground hover:bg-gray-100 px-3 py-1.5 rounded text-sm font-medium flex items-center gap-2 transition-colors">
            <Download className="w-4 h-4" /> Export CSV
          </button>
        </div>
        
        <table className="w-full text-sm text-left">
          <thead className="text-xs text-muted uppercase border-b border-border">
            <tr>
              <th className="px-6 py-3">Timestamp</th>
              <th className="px-6 py-3">User / Identity</th>
              <th className="px-6 py-3">Action</th>
              <th className="px-6 py-3">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {logs.map((log) => (
              <tr key={log.id} className="hover:bg-gray-50">
                <td className="px-6 py-4 text-muted whitespace-nowrap">{log.time}</td>
                <td className="px-6 py-4 font-mono text-sm text-foreground">{log.user}</td>
                <td className="px-6 py-4 font-medium">{log.action}</td>
                <td className="px-6 py-4">
                  <span className={`px-2 py-1 rounded text-xs font-semibold ${
                    log.status === "Success" ? "bg-green-100 text-green-700" : "bg-red-100 text-red-700"
                  }`}>
                    {log.status}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
