"use client";

import { useEffect, useState } from "react";
import { DataTable } from "@/components/ui/DataTable";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { RefreshCw, Download, Server } from "lucide-react";

interface CSPMFindingData {
  id: string;
  finding: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  resource: string;
  rule_id: string;
  status: string;
}

interface CSPMData {
  score: number;
  counts: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
  };
  findings: CSPMFindingData[];
}

export default function CSPMPage() {
  const [data, setData] = useState<CSPMData | null>(null);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);

  const fetchCSPM = () => {
    fetch("http://localhost:8000/api/cspm")
      .then((res) => res.json())
      .then((json) => {
        setData(json);
        setLoading(false);
      })
      .catch((error) => {
        console.error("Failed to fetch CSPM:", error);
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchCSPM();
  }, []);

  const handleScan = () => {
    setScanning(true);
    fetch("http://localhost:8000/api/cspm/scan", { method: "POST" })
      .then(() => {
        fetchCSPM();
        setScanning(false);
      })
      .catch((error) => {
        console.error("Failed to run scan:", error);
        setScanning(false);
      });
  };

  if (loading || !data) {
    return <div className="p-8 text-center text-muted">Loading CSPM data...</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-foreground">Cloud Security Posture</h1>
        <div className="flex items-center gap-3">
          <button className="flex items-center gap-2 px-3 py-1.5 text-sm font-medium border border-border rounded text-muted hover:text-foreground hover:bg-surface-hover transition-colors">
            <Server className="w-4 h-4" /> AWS
          </button>
          <button className="flex items-center gap-2 px-3 py-1.5 text-sm font-medium border border-border rounded text-muted hover:text-foreground hover:bg-surface-hover transition-colors">
            <Download className="w-4 h-4" /> Export Report
          </button>
          <button 
            onClick={handleScan}
            disabled={scanning}
            className="flex items-center gap-2 px-3 py-1.5 text-sm font-medium bg-primary text-white rounded hover:bg-primary/90 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${scanning ? "animate-spin" : ""}`} /> 
            {scanning ? "Scanning..." : "Run Full Scan"}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        <div className="lg:col-span-1 bg-surface border-sentinel rounded-lg p-5 shadow-sm flex flex-col items-center justify-center">
          <div className="text-sm font-medium text-muted uppercase tracking-wider mb-2">Overall Score</div>
          <div className="text-4xl font-bold text-foreground">{data.score}/100</div>
          <div className="mt-2 text-xs font-medium text-green-600 bg-green-50 px-2 py-1 rounded">Healthy</div>
        </div>
        
        <div className="lg:col-span-4 grid grid-cols-4 gap-4">
          <SeverityCard label="Critical" count={data.counts.CRITICAL} color="red" />
          <SeverityCard label="High" count={data.counts.HIGH} color="yellow" />
          <SeverityCard label="Medium" count={data.counts.MEDIUM} color="blue" />
          <SeverityCard label="Low" count={data.counts.LOW} color="slate" />
        </div>
      </div>

      <div className="bg-surface border-sentinel rounded-lg shadow-sm overflow-hidden">
        <div className="p-5 border-b border-border">
          <h3 className="text-sm font-semibold text-foreground uppercase tracking-wider">Misconfigurations</h3>
        </div>
        
        <DataTable
          data={data.findings}
          keyExtractor={(row) => row.id}
          columns={[
            { header: "Finding", accessor: (row) => <span className="font-medium text-foreground">{row.finding}</span> },
            { header: "Severity", accessor: (row) => <SeverityBadge severity={row.severity} /> },
            { header: "Resource", accessor: (row) => <span className="font-mono text-xs">{row.resource}</span> },
            { header: "Rule ID", accessor: (row) => <span className="font-mono text-xs text-muted">{row.rule_id}</span> },
          ]}
        />
      </div>
    </div>
  );
}

function SeverityCard({ label, count, color }: { label: string; count: number; color: string }) {
  const bgColors = {
    red: "bg-red-50",
    yellow: "bg-yellow-50",
    blue: "bg-blue-50",
    slate: "bg-slate-50"
  };
  
  const textColors = {
    red: "text-red-700",
    yellow: "text-yellow-700",
    blue: "text-blue-700",
    slate: "text-slate-700"
  };

  return (
    <div className={`border-sentinel rounded-lg p-5 shadow-sm flex flex-col justify-between ${bgColors[color as keyof typeof bgColors]}`}>
      <div className={`text-sm font-semibold uppercase tracking-wider ${textColors[color as keyof typeof textColors]}`}>{label}</div>
      <div className={`text-3xl font-bold mt-2 ${textColors[color as keyof typeof textColors]}`}>{count}</div>
    </div>
  );
}
