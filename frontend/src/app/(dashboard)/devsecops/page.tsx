"use client";

import { API_URL, WS_URL } from "@/lib/api";

import { useEffect, useState } from "react";
import { DataTable } from "@/components/ui/DataTable";
import { Play, GitBranch, GitCommit, User, GitMerge } from "lucide-react";

interface PipelineRunData {
  id: string;
  time: string;
  commit_sha: string;
  branch: string;
  developer: string;
  status: string;
  sast_status: string;
  secret_status: string;
  dependency_status: string;
  container_status: string;
}

export default function DevSecOpsPage() {
  const [runs, setRuns] = useState<PipelineRunData[]>([]);
  const [loading, setLoading] = useState(true);
  const [triggering, setTriggering] = useState(false);

  const fetchRuns = () => {
    fetch(`${API_URL}/api/devsecops/runs`)
      .then((res) => res.json())
      .then((json) => {
        setRuns(json.runs || []);
        setLoading(false);
      })
      .catch((error) => {
        console.error("Failed to fetch devsecops runs:", error);
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchRuns();

    // Listen to real-time CI/CD pipeline scans via WebSocket
    try {
      const ws = new WebSocket(WS_URL);
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === "NEW_PIPELINE_RUN") {
            setRuns((prev) => [data.run, ...prev]);
          }
        } catch (e) {
          // Ignore
        }
      };
      return () => ws.close();
    } catch (e) {
      // Ignore
    }
  }, []);


  const triggerWebhook = () => {
    setTriggering(true);
    fetch(`${API_URL}/api/devsecops/webhook`, { method: "POST" })
      .then(() => {
        fetchRuns();
        setTriggering(false);
      })
      .catch((error) => {
        console.error("Failed to trigger webhook:", error);
        setTriggering(false);
      });
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "PASSED":
        return <span className="bg-green-100 text-green-700 text-xs font-semibold px-2 py-1 rounded">PASSED</span>;
      case "PASSED WITH WARNINGS":
        return <span className="bg-yellow-100 text-yellow-700 text-xs font-semibold px-2 py-1 rounded">WARNINGS</span>;
      case "FAILED":
        return <span className="bg-red-100 text-red-700 text-xs font-semibold px-2 py-1 rounded">FAILED</span>;
      default:
        return <span className="bg-gray-100 text-gray-700 text-xs font-semibold px-2 py-1 rounded">{status}</span>;
    }
  };

  const getStepIcon = (status: string) => {
    if (status === "PASSED") return <span className="text-green-500">✓</span>;
    if (status === "WARNING") return <span className="text-yellow-500">⚠</span>;
    if (status === "FAILED") return <span className="text-red-500">✗</span>;
    return <span className="text-gray-400">-</span>;
  };

  if (loading) {
    return <div className="p-8 text-center text-muted">Loading DevSecOps pipeline runs...</div>;
  }

  const latestRun = runs.length > 0 ? runs[0] : null;

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground">DevSecOps Center</h1>
          <p className="text-xs text-muted mt-1">Real-time Git push CI/CD monitoring, SAST security audit & automated gates</p>
        </div>
        <div className="flex items-center gap-2.5">
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs font-semibold">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span>Live Webhook Listener Active</span>
          </div>
          <button 
            onClick={triggerWebhook}
            disabled={triggering}
            className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium bg-primary text-white rounded hover:bg-primary/90 transition-colors disabled:opacity-50 shadow-xs cursor-pointer"
          >
            <Play className="w-3.5 h-3.5" /> 
            {triggering ? "Scanning Code..." : "Test Push Webhook"}
          </button>
        </div>
      </div>

      {/* GitHub Webhook Info Banner */}
      <div className="p-4 rounded-lg bg-surface border border-border flex flex-col md:flex-row items-start md:items-center justify-between gap-3 text-xs">
        <div className="space-y-1">
          <div className="font-semibold text-foreground flex items-center gap-1.5">
            <GitBranch className="w-4 h-4 text-primary" />
            <span>Connect Live GitHub Repository Webhook</span>
          </div>
          <p className="text-muted">
            Receive instant security audit scans whenever you or team members push commits to GitHub:
          </p>
        </div>
        <div className="flex items-center gap-2 bg-gray-100 dark:bg-gray-800 px-3 py-2 rounded-md font-mono text-[11px] text-gray-700 dark:text-gray-200 border border-gray-300 dark:border-gray-700">
          <span>{API_URL}/api/devsecops/webhook</span>
        </div>
      </div>


      {latestRun && (
        <div className="bg-surface border-sentinel rounded-lg shadow-sm p-6 mb-8">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-lg font-semibold flex items-center gap-2">
              <GitMerge className="w-5 h-5" /> Latest Pipeline Execution
            </h2>
            {getStatusBadge(latestRun.status)}
          </div>
          
          <div className="flex gap-4 mb-8 text-sm text-muted">
            <span className="flex items-center gap-1"><GitCommit className="w-4 h-4"/> {latestRun.commit_sha}</span>
            <span className="flex items-center gap-1"><GitBranch className="w-4 h-4"/> {latestRun.branch}</span>
            <span className="flex items-center gap-1"><User className="w-4 h-4"/> {latestRun.developer}</span>
          </div>

          <div className="flex justify-between items-center w-full max-w-4xl mx-auto text-sm">
            <PipelineStep name="Build" status="PASSED" icon={getStepIcon("PASSED")} />
            <PipelineDivider />
            <PipelineStep name="SAST" status={latestRun.sast_status} icon={getStepIcon(latestRun.sast_status)} />
            <PipelineDivider />
            <PipelineStep name="Secrets" status={latestRun.secret_status} icon={getStepIcon(latestRun.secret_status)} />
            <PipelineDivider />
            <PipelineStep name="Deps" status={latestRun.dependency_status} icon={getStepIcon(latestRun.dependency_status)} />
            <PipelineDivider />
            <PipelineStep name="Container" status={latestRun.container_status} icon={getStepIcon(latestRun.container_status)} />
            <PipelineDivider />
            <PipelineStep name="Deploy" status={latestRun.status === "FAILED" ? "SKIPPED" : "PASSED"} icon={latestRun.status === "FAILED" ? getStepIcon("SKIPPED") : getStepIcon("PASSED")} />
          </div>
        </div>
      )}

      <div className="bg-surface border-sentinel rounded-lg shadow-sm overflow-hidden">
        <div className="p-5 border-b border-border">
          <h3 className="text-sm font-semibold text-foreground uppercase tracking-wider">Pipeline History</h3>
        </div>
        
        <DataTable
          data={runs}
          keyExtractor={(row) => row.id}
          columns={[
            { header: "Run ID", accessor: (row) => <span className="font-mono text-xs">{row.id}</span> },
            { header: "Branch", accessor: (row) => <span className="flex items-center gap-1 font-medium"><GitBranch className="w-3 h-3"/> {row.branch}</span> },
            { header: "Commit", accessor: (row) => <span className="font-mono text-xs text-muted">{row.commit_sha}</span> },
            { header: "Developer", accessor: (row) => <span>{row.developer}</span> },
            { header: "Status", accessor: (row) => getStatusBadge(row.status) },
            { header: "Time", accessor: (row) => <span className="text-muted">{new Date(row.time).toLocaleString()}</span> },
          ]}
        />
      </div>
    </div>
  );
}

function PipelineStep({ name, status, icon }: { name: string, status: string, icon: React.ReactNode }) {
  let colorClass = "border-gray-200 text-gray-500";
  if (status === "PASSED") colorClass = "border-green-200 text-green-700 bg-green-50";
  if (status === "WARNING") colorClass = "border-yellow-200 text-yellow-700 bg-yellow-50";
  if (status === "FAILED") colorClass = "border-red-200 text-red-700 bg-red-50";

  return (
    <div className={`flex flex-col items-center justify-center p-3 rounded-lg border ${colorClass} w-24 text-center`}>
      <div className="mb-1 text-lg">{icon}</div>
      <div className="font-medium text-xs">{name}</div>
    </div>
  );
}

function PipelineDivider() {
  return (
    <div className="flex-1 h-px bg-gray-300 mx-2"></div>
  );
}
