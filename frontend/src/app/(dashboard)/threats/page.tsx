"use client";

import { useEffect, useState } from "react";
import { DataTable } from "@/components/ui/DataTable";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { ShieldAlert, Activity, Filter, Download } from "lucide-react";

interface ThreatData {
  id: string;
  time: string;
  type: string;
  source: string;
  destination: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  status: string;
  confidence: number;
}

export default function ThreatDetectionPage() {
  const [threats, setThreats] = useState<ThreatData[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("http://localhost:8000/api/threats")
      .then((res) => res.json())
      .then((data) => {
        setThreats(data);
        setLoading(false);
      })
      .catch((error) => {
        console.error("Failed to fetch threats:", error);
        setLoading(false);
      });
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-foreground">Threat Detection</h1>
        <div className="flex items-center gap-3">
          <button className="flex items-center gap-2 px-3 py-1.5 text-sm font-medium border border-border rounded text-muted hover:text-foreground hover:bg-surface-hover transition-colors">
            <Filter className="w-4 h-4" /> Filter
          </button>
          <button className="flex items-center gap-2 px-3 py-1.5 text-sm font-medium border border-border rounded text-muted hover:text-foreground hover:bg-surface-hover transition-colors">
            <Download className="w-4 h-4" /> Export
          </button>
        </div>
      </div>

      {/* Model Status Card */}
      <div className="bg-surface border-sentinel rounded-lg p-5 shadow-sm flex items-center justify-between">
        <div className="flex items-center gap-8">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-full bg-green-50 flex items-center justify-center border border-green-100">
              <Activity className="w-5 h-5 text-green-600" />
            </div>
            <div>
              <div className="text-sm font-medium text-muted">AI Detection Status</div>
              <div className="text-sm font-semibold text-green-600 flex items-center gap-1">
                <div className="w-2 h-2 rounded-full bg-green-600"></div> ACTIVE
              </div>
            </div>
          </div>
          
          <div className="h-10 w-px bg-border"></div>
          
          <div>
            <div className="text-sm font-medium text-muted">Model</div>
            <div className="text-sm font-semibold text-foreground flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-primary" /> Random Forest v1.0
            </div>
          </div>

          <div className="h-10 w-px bg-border"></div>

          <div>
            <div className="text-sm font-medium text-muted">Accuracy</div>
            <div className="text-sm font-semibold text-foreground">94.2%</div>
          </div>
        </div>
        
        <div>
           <button className="text-sm font-medium text-primary hover:underline">View Model Details</button>
        </div>
      </div>

      {/* Threat Data Table */}
      <div className="bg-surface border-sentinel rounded-lg shadow-sm overflow-hidden">
        <div className="p-5 border-b border-border flex justify-between items-center">
          <h3 className="text-sm font-semibold text-foreground uppercase tracking-wider">Detected Threats</h3>
          <span className="text-xs font-medium text-muted">{threats.length} total events</span>
        </div>
        
        {loading ? (
          <div className="p-8 text-center text-muted">Loading threats...</div>
        ) : (
          <DataTable
            data={threats}
            keyExtractor={(row) => row.id}
            columns={[
              { header: "ID", accessor: (row) => <span className="font-mono text-muted text-xs">{row.id}</span> },
              { header: "Attack", accessor: "type", className: "font-medium" },
              { header: "Source", accessor: (row) => <span className="font-mono text-xs">{row.source}</span> },
              { header: "Destination", accessor: (row) => <span className="font-mono text-xs">{row.destination}</span> },
              { header: "Confidence", accessor: (row) => (
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs">{row.confidence.toFixed(1)}%</span>
                  <div className="w-16 h-1.5 bg-gray-100 rounded-full overflow-hidden">
                    <div 
                      className={`h-full ${row.confidence > 90 ? 'bg-green-500' : row.confidence > 70 ? 'bg-yellow-500' : 'bg-red-500'}`}
                      style={{ width: `${row.confidence}%` }}
                    ></div>
                  </div>
                </div>
              ) },
              { header: "Severity", accessor: (row) => <SeverityBadge severity={row.severity} /> },
              { header: "Time", accessor: (row) => <span className="font-mono text-muted text-xs">{row.time}</span> },
            ]}
          />
        )}
      </div>
    </div>
  );
}
