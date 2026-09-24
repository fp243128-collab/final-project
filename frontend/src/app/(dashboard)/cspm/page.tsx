"use client";

import { useEffect, useState } from "react";
import { DataTable } from "@/components/ui/DataTable";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { RefreshCw, Download, Server, Wrench, CheckCircle2, ShieldCheck, AlertCircle, Terminal } from "lucide-react";

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
  const [remediatingId, setRemediatingId] = useState<string | null>(null);
  const [lastAction, setLastAction] = useState<string | null>(null);

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
    setLastAction(null);
    fetch("http://localhost:8000/api/cspm/scan", { method: "POST" })
      .then(() => {
        fetchCSPM();
        setScanning(false);
        setLastAction("Full CIS compliance scan completed across all cloud assets.");
      })
      .catch((error) => {
        console.error("Failed to run scan:", error);
        setScanning(false);
      });
  };

  const handleRemediate = (findingId: string) => {
    setRemediatingId(findingId);
    fetch("http://localhost:8000/api/cspm/remediate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ finding_id: findingId }),
    })
      .then((res) => res.json())
      .then((res) => {
        setRemediatingId(null);
        if (res.status === "success") {
          setLastAction(`Remediation applied to ${findingId}. Command executed: ${res.executed_command}`);
          fetchCSPM();
        }
      })
      .catch((err) => {
        console.error(err);
        setRemediatingId(null);
      });
  };

  if (loading || !data) {
    return <div className="p-8 text-center text-muted">Loading CSPM data...</div>;
  }

  const getScoreBadge = (score: number) => {
    if (score >= 80) return { text: "Compliant", color: "bg-emerald-50 text-emerald-700 border-emerald-200" };
    if (score >= 60) return { text: "Needs Attention", color: "bg-amber-50 text-amber-700 border-amber-200" };
    return { text: "Critical Drift", color: "bg-red-50 text-red-700 border-red-200" };
  };

  const badge = getScoreBadge(data.score);

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Cloud Security Posture Management</h1>
          <p className="text-xs text-muted mt-1">Continuous CIS benchmark verification & automated cloud misconfiguration remediation</p>
        </div>
        <div className="flex items-center gap-3">
          <button className="flex items-center gap-2 px-3 py-1.5 text-xs font-semibold border border-border rounded-md text-muted hover:text-foreground hover:bg-surface-hover transition-colors">
            <Server className="w-3.5 h-3.5 text-orange-500" /> AWS (Production)
          </button>
          <button 
            onClick={handleScan}
            disabled={scanning}
            className="flex items-center gap-2 px-3 py-1.5 text-xs font-semibold bg-primary text-white rounded-md hover:bg-blue-700 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${scanning ? "animate-spin" : ""}`} /> 
            {scanning ? "Evaluating Rules..." : "Run Compliance Scan"}
          </button>
        </div>
      </div>

      {lastAction && (
        <div className="p-3 bg-blue-50 border border-blue-200 text-blue-900 rounded-lg text-xs flex items-start gap-2">
          <Terminal className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
          <div className="flex-1 font-mono break-all">{lastAction}</div>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        <div className="lg:col-span-1 bg-surface border border-sentinel rounded-xl p-5 shadow-xs flex flex-col items-center justify-center text-center">
          <div className="text-xs font-semibold text-muted uppercase tracking-wider mb-2">Posture Score</div>
          <div className="text-4xl font-extrabold text-foreground">{data.score}<span className="text-lg text-muted font-normal">/100</span></div>
          <div className={`mt-2 text-xs font-semibold px-2.5 py-0.5 rounded-full border ${badge.color}`}>
            {badge.text}
          </div>
        </div>
        
        <div className="lg:col-span-4 grid grid-cols-2 md:grid-cols-4 gap-4">
          <SeverityCard label="Critical" count={data.counts.CRITICAL} color="red" />
          <SeverityCard label="High" count={data.counts.HIGH} color="yellow" />
          <SeverityCard label="Medium" count={data.counts.MEDIUM} color="blue" />
          <SeverityCard label="Low" count={data.counts.LOW} color="slate" />
        </div>
      </div>

      {/* Findings Table */}
      <div className="bg-surface border border-sentinel rounded-xl shadow-xs overflow-hidden">
        <div className="px-5 py-4 border-b border-border flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-primary" />
            <h3 className="text-sm font-semibold text-foreground uppercase tracking-wider">Active Policy Violations & Misconfigurations</h3>
          </div>
          <span className="text-xs text-muted font-medium">Showing {data.findings.length} findings</span>
        </div>
        
        <DataTable
          data={data.findings}
          keyExtractor={(row) => row.id}
          columns={[
            { 
              header: "Finding & Rule", 
              accessor: (row) => (
                <div>
                  <div className="font-semibold text-sm text-foreground">{row.finding}</div>
                  <div className="text-[11px] font-mono text-muted">{row.rule_id}</div>
                </div>
              )
            },
            { header: "Severity", accessor: (row) => <SeverityBadge severity={row.severity} /> },
            { 
              header: "Resource Target", 
              accessor: (row) => (
                <span className="font-mono text-xs px-2 py-0.5 rounded bg-gray-100 border border-gray-200 text-gray-800">
                  {row.resource}
                </span>
              ) 
            },
            { 
              header: "Status", 
              accessor: (row) => (
                row.status === "Resolved" ? (
                  <span className="inline-flex items-center gap-1 text-xs font-semibold text-emerald-600 bg-emerald-50 px-2.5 py-0.5 rounded-full border border-emerald-200">
                    <CheckCircle2 className="w-3.5 h-3.5" /> Resolved
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 text-xs font-semibold text-rose-600 bg-rose-50 px-2.5 py-0.5 rounded-full border border-rose-200">
                    <AlertCircle className="w-3.5 h-3.5" /> Open
                  </span>
                )
              ) 
            },
            {
              header: "Remediation",
              accessor: (row) => (
                row.status === "Resolved" ? (
                  <span className="text-xs text-muted font-medium">Remediated</span>
                ) : (
                  <button
                    onClick={() => handleRemediate(row.id)}
                    disabled={remediatingId === row.id}
                    className="flex items-center gap-1.5 px-3 py-1 text-xs font-semibold bg-emerald-600 hover:bg-emerald-700 text-white rounded-md transition-colors disabled:opacity-50"
                  >
                    <Wrench className={`w-3 h-3 ${remediatingId === row.id ? "animate-spin" : ""}`} />
                    {remediatingId === row.id ? "Applying..." : "Auto-Fix"}
                  </button>
                )
              )
            }
          ]}
        />
      </div>
    </div>
  );
}

function SeverityCard({ label, count, color }: { label: string; count: number; color: string }) {
  const styles = {
    red: "bg-red-50/70 border-red-200 text-red-700",
    yellow: "bg-amber-50/70 border-amber-200 text-amber-700",
    blue: "bg-blue-50/70 border-blue-200 text-blue-700",
    slate: "bg-slate-50 border-slate-200 text-slate-700"
  };

  return (
    <div className={`border rounded-xl p-4 shadow-xs flex flex-col justify-between ${styles[color as keyof typeof styles]}`}>
      <div className="text-xs font-bold uppercase tracking-wider">{label}</div>
      <div className="text-3xl font-black mt-2">{count}</div>
    </div>
  );
}
