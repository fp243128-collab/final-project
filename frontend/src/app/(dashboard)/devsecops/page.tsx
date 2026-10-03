"use client";

import { useEffect, useState, useRef, useCallback } from "react";
import { API_URL } from "@/lib/api";
import {
  Shield,
  Activity,
  Play,
  Pause,
  ArrowRight,
  Download,
  CheckCircle2,
  Layers,
  RefreshCw,
  Lock,
  Globe,
  AlertTriangle
} from "lucide-react";

interface PipelineStage {
  title: string;
  detail: string;
  agent: string;
}

interface ToolItem {
  stage: number;
  title: string;
  detail: string;
}

interface AuditState {
  status: "idle" | "queued" | "running" | "complete" | "stopped" | "failed";
  completed: number;
  total_stages: number;
  active: string;
  stage_index: number;
  mode: "guided" | "all";
  target: string;
  provider: string;
  events: { time: string; label: string; status: string }[];
  report: string;
  reports: Record<string, string>;
  counts: { Critical: number; High: number; Medium: number; Low: number };
  error: string | null;
  started: string | null;
  pipeline: PipelineStage[];
  tools: ToolItem[];
}

export default function DevSecOpsPage() {
  const [audit, setAudit] = useState<AuditState | null>(null);
  const [target, setTarget] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [mode, setMode] = useState<"guided" | "all">("guided");
  const [provider, setProvider] = useState("gemini");
  const [loading, setLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<string>("Overview");
  const pollIntervalRef = useRef<NodeJS.Timeout | null>(null);

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch(`${API_URL}/api/devsecops/audit/status`);
      if (res.ok) {
        const data = await res.json();
        setAudit(data);
        if (data.target) {
          setTarget((prev) => (prev ? prev : data.target));
        }
      }
    } catch (err) {
      console.error("Failed to fetch audit status:", err);
    }
  }, []);

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchStatus();
    }, 0);
    pollIntervalRef.current = setInterval(fetchStatus, 2000);
    return () => {
      clearTimeout(timer);
      if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
    };
  }, [fetchStatus]);

  const handleLaunch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) {
      alert("Please enter a valid target URL or domain.");
      return;
    }
    if (!authorized) {
      alert("You must verify authorization to test this target.");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/api/devsecops/audit/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: target.trim(),
          authorized,
          mode,
          provider,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.detail || "Failed to start audit");
      } else {
        setAudit(data);
      }
    } catch (err) {
      console.error("Audit start error:", err);
      alert("Failed to communicate with backend server.");
    } finally {
      setLoading(false);
    }
  };

  const handleNextStage = async () => {
    setActionLoading(true);
    try {
      const res = await fetch(`${API_URL}/api/devsecops/audit/next`, { method: "POST" });
      const data = await res.json();
      setAudit(data);
    } catch (err) {
      console.error(err);
    } finally {
      setActionLoading(false);
    }
  };

  const handleRunAll = async () => {
    setActionLoading(true);
    try {
      const res = await fetch(`${API_URL}/api/devsecops/audit/run-all`, { method: "POST" });
      const data = await res.json();
      setAudit(data);
    } catch (err) {
      console.error(err);
    } finally {
      setActionLoading(false);
    }
  };

  const handleStop = async () => {
    setActionLoading(true);
    try {
      const res = await fetch(`${API_URL}/api/devsecops/audit/stop`, { method: "POST" });
      const data = await res.json();
      setAudit(data);
    } catch (err) {
      console.error(err);
    } finally {
      setActionLoading(false);
    }
  };

  const downloadReport = () => {
    if (!audit?.report) return;
    const blob = new Blob([audit.report], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `security-audit-${audit.target.replace(/[^a-zA-Z0-9]/g, "_") || "report"}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Structured Markdown Sections Parser
  const parseReportSections = (text: string) => {
    if (!text) return [];
    const cleaned = text.replace(/^```(?:markdown|md|text)?\s*/i, "").replace(/\s*```$/, "").trim();
    const parts = cleaned.split(/(?=^##\s+)/m).filter(Boolean);
    if (parts.length <= 1) {
      return [{ title: "Overview", content: cleaned }];
    }
    return parts.map((part) => {
      const match = part.match(/^##\s+(.+?)$/m);
      const title = match ? match[1].replace(/[*_~`]/g, "").trim().slice(0, 36) : "Section";
      const content = part.replace(/^##\s+.+?$/m, "").trim();
      return { title, content };
    });
  };

  const reportSections = audit?.report ? parseReportSections(audit.report) : [];
  const maxRiskCount = audit?.counts ? Math.max(...Object.values(audit.counts), 1) : 1;
  const isRunning = audit?.status === "running" || audit?.status === "queued";

  return (
    <div className="space-y-8 max-w-7xl mx-auto pb-16">
      {/* Hero Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-6 border-b border-border/40 pb-6">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-600 dark:text-cyan-400 tracking-wider uppercase mb-1">
            <Shield className="w-4 h-4 text-cyan-500" />
            <span>DevSecOps AI Security Audit Tool // Multi-Agent Engine</span>
          </div>
          <h1 className="text-3xl font-extrabold tracking-tight text-foreground">
            See the attack surface before attackers do.
          </h1>
          <p className="text-sm text-muted mt-1 max-w-2xl leading-relaxed">
            A calm, evidence-first interface for turning any target into a prioritized, actionable security brief.
            Execute the 8-stage CrewAI pipeline or run step-by-step guided assessments.
          </p>
        </div>

        {/* Live Status indicator */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-border/80 bg-surface text-xs font-medium shadow-xs">
            <span
              className={`w-2 h-2 rounded-full ${
                isRunning
                  ? "bg-amber-500 animate-ping"
                  : audit?.status === "complete"
                  ? "bg-emerald-500"
                  : audit?.status === "failed"
                  ? "bg-red-500"
                  : "bg-muted"
              }`}
            />
            <span className="font-mono uppercase font-semibold text-foreground">
              {audit?.status || "IDLE"}
            </span>
            {audit?.status === "running" && (
              <span className="text-muted border-l border-border/60 pl-2">
                Stage {audit.completed + 1} of {audit.total_stages}
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Error Banner if Audit Failed or Errored */}
      {audit?.error && (
        <div className="p-4 rounded-xl border border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 flex-shrink-0 text-red-500" />
            <div className="text-sm">
              <span className="font-semibold">Assessment Notice:</span> {audit.error}
            </div>
          </div>
          <button
            type="button"
            onClick={async () => {
              try {
                await fetch(`${API_URL}/api/devsecops/audit/stop`, { method: "POST" });
                fetchStatus();
              } catch (e) {
                console.error(e);
              }
            }}
            className="px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white rounded-lg text-xs font-semibold whitespace-nowrap transition-colors"
          >
            Reset Scanner
          </button>
        </div>
      )}

      {/* Main Grid: Control Form & Configuration */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Form: Target Setup */}
        <div className="lg:col-span-2 bg-surface border border-border rounded-xl p-6 shadow-xs space-y-5">
          <div className="flex items-center justify-between border-b border-border/40 pb-3">
            <h2 className="text-base font-semibold text-foreground flex items-center gap-2">
              <Globe className="w-4 h-4 text-primary" /> Audit Target Configuration
            </h2>
            <span className="text-xs text-muted font-mono">OWASP & CVE Intelligence</span>
          </div>

          <form onSubmit={handleLaunch} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-foreground/80 uppercase tracking-wider mb-1.5">
                Target Domain, IP, or URL
              </label>
              <div className="relative">
                <input
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="https://app.example.com or 192.168.1.1"
                  className="w-full bg-background border border-border rounded-lg px-3.5 py-2.5 text-sm text-foreground placeholder:text-muted focus:outline-none focus:ring-2 focus:ring-primary/30"
                  disabled={isRunning}
                  required
                />
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-semibold text-foreground/80 uppercase tracking-wider mb-1.5">
                  AI Provider
                </label>
                <select
                  value={provider}
                  onChange={(e) => setProvider(e.target.value)}
                  disabled={isRunning}
                  className="w-full bg-background border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/30"
                >
                  <option value="gemini">Google Gemini (gemini-3.8-flash)</option>
                  <option value="grok">xAI Grok (grok-3-mini)</option>
                  <option value="openai">OpenAI (gpt-4o-mini)</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-foreground/80 uppercase tracking-wider mb-1.5">
                  Assessment Mode
                </label>
                <div className="flex gap-4 pt-1">
                  <label className="flex items-center gap-2 text-xs font-medium text-foreground cursor-pointer">
                    <input
                      type="radio"
                      name="mode"
                      value="guided"
                      checked={mode === "guided"}
                      onChange={() => setMode("guided")}
                      disabled={isRunning}
                      className="accent-primary"
                    />
                    One-by-one Guided
                  </label>
                  <label className="flex items-center gap-2 text-xs font-medium text-foreground cursor-pointer">
                    <input
                      type="radio"
                      name="mode"
                      value="all"
                      checked={mode === "all"}
                      onChange={() => setMode("all")}
                      disabled={isRunning}
                      className="accent-primary"
                    />
                    Run All Stages
                  </label>
                </div>
              </div>
            </div>

            <div className="pt-2">
              <label className="flex items-start gap-2.5 text-xs text-muted cursor-pointer">
                <input
                  type="checkbox"
                  checked={authorized}
                  onChange={(e) => setAuthorized(e.target.checked)}
                  disabled={isRunning}
                  className="mt-0.5 accent-primary"
                  required
                />
                <span>
                  I have explicit authorization to test this target. Active probes may generate network traffic and simulate intrusion vectors.
                </span>
              </label>
            </div>

            <div className="pt-3 flex flex-wrap items-center gap-3">
              <button
                type="submit"
                disabled={loading || isRunning || !target.trim()}
                className="flex items-center justify-center gap-2 px-5 py-2.5 bg-primary text-white font-semibold text-sm rounded-lg hover:bg-primary/90 transition-all shadow-xs disabled:opacity-50 cursor-pointer"
              >
                {loading || isRunning ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Executing Audit...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 fill-current" />
                    <span>Launch Assessment</span>
                  </>
                )}
              </button>

              {audit && audit.status !== "idle" && (
                <button
                  type="button"
                  onClick={fetchStatus}
                  className="p-2.5 text-muted hover:text-foreground border border-border rounded-lg bg-surface transition-colors"
                  title="Refresh Status"
                >
                  <RefreshCw className="w-4 h-4" />
                </button>
              )}
            </div>
          </form>
        </div>

        {/* Right Info: Live Pulse Metrics */}
        <div className="bg-surface border border-border rounded-xl p-6 shadow-xs flex flex-col justify-between">
          <div>
            <div className="text-xs font-mono uppercase tracking-wider text-muted mb-2">
              Assessment Pulse
            </div>
            <div className="grid grid-cols-2 gap-3 mb-4">
              <div className="p-3 rounded-lg border border-border bg-background">
                <div className="text-[11px] font-mono text-muted uppercase">Status</div>
                <div className="text-lg font-bold text-foreground capitalize mt-0.5">
                  {audit?.status || "Idle"}
                </div>
                <div className="text-[10px] text-muted truncate mt-0.5">{audit?.active || "Ready"}</div>
              </div>

              <div className="p-3 rounded-lg border border-border bg-background">
                <div className="text-[11px] font-mono text-muted uppercase">Completed</div>
                <div className="text-lg font-bold text-foreground mt-0.5">
                  {audit?.completed || 0} / {audit?.total_stages || 8}
                </div>
                <div className="text-[10px] text-muted mt-0.5">Pipeline Stages</div>
              </div>

              <div className="p-3 rounded-lg border border-border bg-background">
                <div className="text-[11px] font-mono text-muted uppercase">Critical / High</div>
                <div className="text-lg font-bold text-red-500 mt-0.5">
                  {(audit?.counts?.Critical || 0) + (audit?.counts?.High || 0)}
                </div>
                <div className="text-[10px] text-muted mt-0.5">High Priority Items</div>
              </div>

              <div className="p-3 rounded-lg border border-border bg-background">
                <div className="text-[11px] font-mono text-muted uppercase">Last Run</div>
                <div className="text-xs font-mono font-medium text-foreground mt-1 truncate">
                  {audit?.started || "--:--"}
                </div>
                <div className="text-[10px] text-muted mt-0.5">Session Timestamp</div>
              </div>
            </div>
          </div>

          <div className="border-t border-border/50 pt-3 text-[11px] text-muted">
            <span className="font-semibold text-foreground">Multi-Agent Roster:</span> DNS Recon, Port Inspector, Header Analyzer, TLS/SSL, Injection Tester, Auth Auditor & Report Synthesizer.
          </div>
        </div>
      </div>

      {/* Live Session Progress Bar & Pipeline Steps */}
      {audit && audit.status !== "idle" && (
        <div className="bg-surface border border-border rounded-xl p-6 shadow-xs space-y-6">
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
            <div>
              <h2 className="text-base font-semibold text-foreground flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan-500" />
                Live Assessment Execution Pipeline
              </h2>
              <p className="text-xs text-muted mt-0.5">
                Active Target: <span className="font-mono text-foreground font-semibold">{audit.target}</span>
              </p>
            </div>

            {/* Guided Controls */}
            {(audit.status === "stopped" || (audit.status === "complete" && audit.mode === "guided")) && (
              <div className="flex items-center gap-2">
                {audit.completed < audit.total_stages ? (
                  <>
                    <button
                      onClick={handleNextStage}
                      disabled={actionLoading}
                      className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors cursor-pointer"
                    >
                      <ArrowRight className="w-3.5 h-3.5" /> Next Stage ({audit.completed + 1})
                    </button>
                    <button
                      onClick={handleRunAll}
                      disabled={actionLoading}
                      className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold bg-primary hover:bg-primary/90 text-white rounded-lg transition-colors cursor-pointer"
                    >
                      <Play className="w-3.5 h-3.5" /> Run All Remaining
                    </button>
                  </>
                ) : (
                  <div className="flex items-center gap-1.5 text-xs text-emerald-600 font-semibold bg-emerald-50 dark:bg-emerald-950/40 px-3 py-1.5 rounded-lg border border-emerald-200 dark:border-emerald-800">
                    <CheckCircle2 className="w-4 h-4" /> All Stages Complete
                  </div>
                )}
                {isRunning && (
                  <button
                    onClick={handleStop}
                    disabled={actionLoading}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors cursor-pointer"
                  >
                    <Pause className="w-3.5 h-3.5" /> Pause
                  </button>
                )}
              </div>
            )}
          </div>

          {/* Progress Bar */}
          <div className="space-y-1.5">
            <div className="flex justify-between text-xs font-mono text-muted">
              <span>{audit.active}</span>
              <span>{Math.round((audit.completed / (audit.total_stages || 8)) * 100)}%</span>
            </div>
            <div className="w-full bg-border/60 h-2 rounded-full overflow-hidden">
              <div
                className="bg-primary h-full transition-all duration-500 rounded-full"
                style={{ width: `${(audit.completed / (audit.total_stages || 8)) * 100}%` }}
              />
            </div>
          </div>

          {/* Pipeline Step Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2.5 pt-2">
            {audit.pipeline?.map((item, idx) => {
              const isDone = idx < audit.completed;
              const isCurrent = idx === audit.completed && isRunning;
              return (
                <div
                  key={idx}
                  className={`p-3 rounded-lg border text-center transition-all ${
                    isDone
                      ? "border-emerald-300 dark:border-emerald-800 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                      : isCurrent
                      ? "border-amber-400 bg-amber-500/15 text-amber-700 dark:text-amber-300 ring-2 ring-amber-400/30"
                      : "border-border bg-background text-muted"
                  }`}
                >
                  <div className="text-[10px] font-mono uppercase mb-1">Stage {idx + 1}</div>
                  <div className="font-semibold text-xs truncate" title={item.title}>
                    {item.title}
                  </div>
                  <div className="mt-1.5 flex justify-center">
                    {isDone ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                    ) : isCurrent ? (
                      <RefreshCw className="w-4 h-4 text-amber-500 animate-spin" />
                    ) : (
                      <span className="w-2 h-2 rounded-full bg-border mt-1" />
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Tools & Events Live Activity */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
            <div className="border border-border/80 rounded-lg p-4 bg-background/50">
              <div className="text-xs font-mono uppercase text-muted mb-2">Live Agent Activities</div>
              <div className="space-y-1.5 max-h-48 overflow-y-auto pr-2">
                {audit.events && audit.events.length > 0 ? (
                  audit.events.map((evt, idx) => (
                    <div key={idx} className="flex items-center justify-between text-xs py-1 border-b border-border/40 font-mono">
                      <span className="text-foreground">{evt.label}</span>
                      <span className="text-muted text-[11px]">{evt.time}</span>
                    </div>
                  ))
                ) : (
                  <div className="text-xs text-muted py-2">Waiting for first agent event...</div>
                )}
              </div>
            </div>

            <div className="border border-border/80 rounded-lg p-4 bg-background/50">
              <div className="text-xs font-mono uppercase text-muted mb-2">Security Tool Instrumentation</div>
              <div className="grid grid-cols-2 gap-2 text-xs max-h-48 overflow-y-auto pr-1">
                {audit.tools?.map((tool, idx) => {
                  const done = tool.stage < audit.completed;
                  const active = tool.stage === audit.completed && isRunning;
                  return (
                    <div key={idx} className="p-2 border border-border/50 rounded bg-surface/50">
                      <div className="font-semibold text-[11px] text-foreground truncate">{tool.title}</div>
                      <div className="text-[10px] text-muted truncate">{tool.detail}</div>
                      <span
                        className={`text-[9px] font-mono uppercase mt-1 inline-block ${
                          done ? "text-emerald-500" : active ? "text-amber-500 animate-pulse" : "text-muted"
                        }`}
                      >
                        {done ? "Complete" : active ? "Running" : "Queued"}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Findings Desk & Risk Breakdown */}
      {audit?.report ? (
        <div className="space-y-6">
          {/* Severity Strip & Download Bar */}
          <div className="bg-surface border border-border rounded-xl p-6 shadow-xs space-y-6">
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-border/40 pb-4">
              <div>
                <h2 className="text-lg font-bold text-foreground">Findings Desk & Risk Distribution</h2>
                <p className="text-xs text-muted mt-0.5">Automated triage categorized by CVSS and OWASP standards</p>
              </div>

              <button
                onClick={downloadReport}
                className="flex items-center gap-2 px-4 py-2 bg-foreground text-background font-semibold text-xs rounded-lg hover:opacity-90 transition-opacity cursor-pointer shadow-xs"
              >
                <Download className="w-3.5 h-3.5" /> Download Executive Report (.md)
              </button>
            </div>

            {/* Severity Cards */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <div className="p-4 rounded-xl border border-red-500/20 bg-red-500/10">
                <span className="text-xs font-mono font-bold text-red-500 uppercase">Critical</span>
                <div className="text-2xl font-extrabold text-red-600 dark:text-red-400 mt-1">
                  {audit.counts?.Critical || 0}
                </div>
                <div className="text-[11px] text-muted mt-0.5">Immediate exploit risk</div>
              </div>

              <div className="p-4 rounded-xl border border-amber-500/20 bg-amber-500/10">
                <span className="text-xs font-mono font-bold text-amber-500 uppercase">High</span>
                <div className="text-2xl font-extrabold text-amber-600 dark:text-amber-400 mt-1">
                  {audit.counts?.High || 0}
                </div>
                <div className="text-[11px] text-muted mt-0.5">Priority remediation</div>
              </div>

              <div className="p-4 rounded-xl border border-cyan-500/20 bg-cyan-500/10">
                <span className="text-xs font-mono font-bold text-cyan-500 uppercase">Medium</span>
                <div className="text-2xl font-extrabold text-cyan-600 dark:text-cyan-400 mt-1">
                  {audit.counts?.Medium || 0}
                </div>
                <div className="text-[11px] text-muted mt-0.5">Configuration defects</div>
              </div>

              <div className="p-4 rounded-xl border border-slate-500/20 bg-slate-500/10">
                <span className="text-xs font-mono font-bold text-slate-500 uppercase">Low</span>
                <div className="text-2xl font-extrabold text-slate-600 dark:text-slate-400 mt-1">
                  {audit.counts?.Low || 0}
                </div>
                <div className="text-[11px] text-muted mt-0.5">Best practice & info</div>
              </div>
            </div>

            {/* Risk Graph Track */}
            <div className="p-4 border border-border rounded-lg bg-background space-y-3">
              <div className="text-xs font-mono uppercase text-muted">Risk Profile Graph</div>
              <div className="space-y-2.5">
                {[
                  { label: "Critical", count: audit.counts?.Critical || 0, color: "bg-red-500" },
                  { label: "High", count: audit.counts?.High || 0, color: "bg-amber-500" },
                  { label: "Medium", count: audit.counts?.Medium || 0, color: "bg-cyan-500" },
                  { label: "Low", count: audit.counts?.Low || 0, color: "bg-slate-400" },
                ].map((item) => (
                  <div key={item.label} className="flex items-center gap-3 text-xs font-mono">
                    <span className="w-16 font-semibold text-foreground">{item.label}</span>
                    <div className="flex-1 bg-border/40 h-2.5 rounded-full overflow-hidden">
                      <div
                        className={`${item.color} h-full rounded-full transition-all duration-500`}
                        style={{ width: `${(item.count / maxRiskCount) * 100}%` }}
                      />
                    </div>
                    <span className="w-8 text-right font-bold text-foreground">{item.count}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Structured Report Tabs */}
          <div className="bg-surface border border-border rounded-xl p-6 shadow-xs space-y-6">
            <div className="border-b border-border/60 pb-3 flex items-center justify-between">
              <h3 className="text-base font-bold text-foreground flex items-center gap-2">
                <Layers className="w-4 h-4 text-primary" /> Structured Executive Findings
              </h3>
              <span className="text-xs text-muted font-mono">Interactive Tabs</span>
            </div>

            {/* Tabs Header */}
            <div className="flex flex-wrap gap-2 border-b border-border/40 pb-2">
              {reportSections.map((sec, idx) => (
                <button
                  key={idx}
                  onClick={() => setActiveTab(sec.title)}
                  className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer ${
                    activeTab === sec.title || (activeTab === "Overview" && idx === 0)
                      ? "bg-cyan-500/15 text-cyan-600 dark:text-cyan-400 border border-cyan-500/30"
                      : "text-muted hover:text-foreground hover:bg-surface"
                  }`}
                >
                  {sec.title}
                </button>
              ))}
            </div>

            {/* Tab Body */}
            <div className="p-4 rounded-lg bg-background border border-border/80 text-foreground leading-relaxed text-sm whitespace-pre-wrap font-sans max-h-[600px] overflow-y-auto">
              {reportSections.find((s) => s.title === activeTab)?.content ||
                reportSections[0]?.content ||
                audit.report}
            </div>

            {/* Guided Individual Stage Reports if Available */}
            {audit.reports && Object.keys(audit.reports).length > 0 && (
              <div className="pt-4 border-t border-border/40 space-y-3">
                <div className="text-xs font-mono uppercase text-muted">
                  Completed Stage Logs ({Object.keys(audit.reports).length} stages)
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {Object.entries(audit.reports).map(([stageName, stageContent], idx) => (
                    <details key={idx} className="border border-border rounded-lg p-3 bg-background group">
                      <summary className="text-xs font-semibold text-foreground cursor-pointer flex items-center justify-between">
                        <span>{stageName}</span>
                        <span className="text-primary text-[11px] group-open:rotate-90 transition-transform">
                          ▶
                        </span>
                      </summary>
                      <div className="mt-2 text-xs text-muted font-mono bg-surface p-2.5 rounded border border-border/60 max-h-40 overflow-y-auto whitespace-pre-wrap">
                        {stageContent}
                      </div>
                    </details>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="bg-surface border border-dashed border-border rounded-xl p-10 text-center space-y-3">
          <div className="w-12 h-12 rounded-full bg-primary/10 text-primary flex items-center justify-center mx-auto">
            <Lock className="w-6 h-6" />
          </div>
          <h3 className="text-base font-semibold text-foreground">No Assessment Active</h3>
          <p className="text-xs text-muted max-w-md mx-auto">
            Enter an authorized domain, URL, or IP address in the configuration panel above to kick off the multi-agent AI security audit.
          </p>
        </div>
      )}
    </div>
  );
}
