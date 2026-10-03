"use client";

import React from "react";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  AlertCircle,
  Info,
  CheckCircle2,
  XCircle,
  Search,
  Globe,
  Lock,
  Key,
  Layers,
  Mail,
  Tag,
  FileText,
  ArrowRightLeft,
  Zap,
  Activity,
  Compass,
  Terminal,
  Server,
  Code2,
  Check,
} from "lucide-react";

// Severity Badges with real Lucide Icons
export function SeverityBadge({ level }: { level: string }) {
  const key = level.toLowerCase().trim();
  if (key.includes("crit") || key.includes("red") || key.includes("🔴")) {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-[11px] font-semibold bg-rose-500/10 text-rose-500 border border-rose-500/20 whitespace-nowrap shadow-xs">
        <ShieldAlert className="w-3.5 h-3.5 flex-shrink-0 text-rose-500" />
        Critical
      </span>
    );
  }
  if (key.includes("high") || key.includes("orange") || key.includes("🟠")) {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-[11px] font-semibold bg-amber-500/10 text-amber-500 border border-amber-500/20 whitespace-nowrap shadow-xs">
        <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 text-amber-500" />
        High
      </span>
    );
  }
  if (key.includes("med") || key.includes("yellow") || key.includes("🟡")) {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-[11px] font-semibold bg-yellow-500/10 text-yellow-500 border border-yellow-500/20 whitespace-nowrap shadow-xs">
        <AlertCircle className="w-3.5 h-3.5 flex-shrink-0 text-yellow-500" />
        Medium
      </span>
    );
  }
  if (key.includes("low") || key.includes("blue") || key.includes("🔵") || key.includes("info")) {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-[11px] font-semibold bg-blue-500/10 text-blue-500 border border-blue-500/20 whitespace-nowrap shadow-xs">
        <Info className="w-3.5 h-3.5 flex-shrink-0 text-blue-500" />
        Low
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-[11px] font-semibold bg-muted/10 text-muted-foreground border border-muted/20 whitespace-nowrap">
      <Info className="w-3.5 h-3.5 flex-shrink-0" />
      {level}
    </span>
  );
}

// Status Badges with real Lucide Icons
export function StatusBadge({ status }: { status: string }) {
  const s = status.toLowerCase().trim();
  if (
    s === "passed" ||
    s === "pass" ||
    s === "present" ||
    s === "active" ||
    s === "compliant" ||
    s === "protected" ||
    s === "controlled" ||
    s === "yes" ||
    s === "valid" ||
    s === "validated" ||
    s.includes("✅")
  ) {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[11px] font-semibold bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 whitespace-nowrap">
        <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0 text-emerald-500" />
        {status.replace(/^[✅\s]+/, "") || "Passed"}
      </span>
    );
  }
  if (
    s === "failed" ||
    s === "fail" ||
    s === "missing" ||
    s === "no" ||
    s === "error" ||
    s === "critical" ||
    s.includes("❌")
  ) {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[11px] font-semibold bg-rose-500/10 text-rose-500 border border-rose-500/20 whitespace-nowrap">
        <XCircle className="w-3.5 h-3.5 flex-shrink-0 text-rose-500" />
        {status.replace(/^[❌\s]+/, "") || "Missing"}
      </span>
    );
  }
  if (s === "warning" || s === "recommended" || s === "review" || s.includes("⚠️")) {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[11px] font-semibold bg-amber-500/10 text-amber-500 border border-amber-500/20 whitespace-nowrap">
        <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 text-amber-500" />
        {status.replace(/^[⚠️\s]+/, "") || "Warning"}
      </span>
    );
  }
  if (s === "monitored" || s === "info") {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[11px] font-semibold bg-sky-500/10 text-sky-500 border border-sky-500/20 whitespace-nowrap">
        <Activity className="w-3.5 h-3.5 flex-shrink-0 text-sky-500" />
        {status}
      </span>
    );
  }
  return <span>{status}</span>;
}

// Icon Mapping table replacing raw emojis with Lucide React Icons
function renderIconForEmoji(emoji: string, key: number) {
  switch (emoji) {
    case "🔍":
      return <Search key={key} className="w-3.5 h-3.5 inline-block text-primary mx-0.5 align-middle" />;
    case "🌐":
    case "📡":
      return <Globe key={key} className="w-3.5 h-3.5 inline-block text-cyan-500 mx-0.5 align-middle" />;
    case "🔐":
    case "🔒":
      return <Lock key={key} className="w-3.5 h-3.5 inline-block text-primary mx-0.5 align-middle" />;
    case "🔑":
    case "🗝️":
      return <Key key={key} className="w-3.5 h-3.5 inline-block text-amber-500 mx-0.5 align-middle" />;
    case "🛡️":
      return <ShieldCheck key={key} className="w-3.5 h-3.5 inline-block text-emerald-500 mx-0.5 align-middle" />;
    case "⚠️":
      return <AlertTriangle key={key} className="w-3.5 h-3.5 inline-block text-amber-500 mx-0.5 align-middle" />;
    case "🚨":
      return <ShieldAlert key={key} className="w-3.5 h-3.5 inline-block text-rose-500 mx-0.5 align-middle" />;
    case "🔴":
      return <ShieldAlert key={key} className="w-3.5 h-3.5 inline-block text-rose-500 mx-0.5 align-middle" />;
    case "🟠":
      return <AlertTriangle key={key} className="w-3.5 h-3.5 inline-block text-amber-500 mx-0.5 align-middle" />;
    case "🟡":
      return <AlertCircle key={key} className="w-3.5 h-3.5 inline-block text-yellow-500 mx-0.5 align-middle" />;
    case "🔵":
      return <Info key={key} className="w-3.5 h-3.5 inline-block text-blue-500 mx-0.5 align-middle" />;
    case "✅":
      return <CheckCircle2 key={key} className="w-3.5 h-3.5 inline-block text-emerald-500 mx-0.5 align-middle" />;
    case "❌":
      return <XCircle key={key} className="w-3.5 h-3.5 inline-block text-rose-500 mx-0.5 align-middle" />;
    case "🅰️":
      return <Layers key={key} className="w-3.5 h-3.5 inline-block text-primary mx-0.5 align-middle" />;
    case "📧":
      return <Mail key={key} className="w-3.5 h-3.5 inline-block text-indigo-400 mx-0.5 align-middle" />;
    case "🏷️":
      return <Tag key={key} className="w-3.5 h-3.5 inline-block text-violet-400 mx-0.5 align-middle" />;
    case "📋":
      return <FileText key={key} className="w-3.5 h-3.5 inline-block text-primary mx-0.5 align-middle" />;
    case "🔀":
      return <ArrowRightLeft key={key} className="w-3.5 h-3.5 inline-block text-cyan-400 mx-0.5 align-middle" />;
    case "⚡":
    case "🚀":
      return <Zap key={key} className="w-3.5 h-3.5 inline-block text-amber-400 mx-0.5 align-middle" />;
    case "📊":
      return <Activity key={key} className="w-3.5 h-3.5 inline-block text-primary mx-0.5 align-middle" />;
    case "🧭":
      return <Compass key={key} className="w-3.5 h-3.5 inline-block text-primary mx-0.5 align-middle" />;
    default:
      return null;
  }
}

// Inline token renderer with smart emoji & markdown replacement
function Inline({ text, cell = false }: { text: string; cell?: boolean }) {
  const trimmed = text.trim();
  const plain = trimmed.replace(/\*/g, "").trim();

  // If cell is exact severity keyword
  if (cell && /^(critical|high|medium|low|info|🔴 critical|🟠 high|🟡 medium|🔵 low)$/i.test(plain)) {
    return <SeverityBadge level={plain} />;
  }

  // If cell is exact status keyword
  if (
    cell &&
    /^(present|missing|passed|failed|active|compliant|protected|controlled|monitored|recommended|yes|no|valid|error|✅ passed|❌ missing|❌ failed)$/i.test(
      plain
    )
  ) {
    return <StatusBadge status={plain} />;
  }

  const parts = trimmed.split(/(\*\*[^*]+\*\*|`[^`]+`|[🔍🌐🔐🔒⚠️🚨🔴🟠🟡🔵⚪🔑🗝️📊🛡️✅❌📡🧭🅰️📧🏷️📋🔀⚡🚀])/gu).filter(Boolean);

  return (
    <span>
      {parts.map((p, i) => {
        if (p.startsWith("**") && p.endsWith("**") && p.length > 4) {
          return (
            <strong key={i} className="font-semibold text-foreground">
              <Inline text={p.slice(2, -2)} />
            </strong>
          );
        }
        if (p.startsWith("`") && p.endsWith("`") && p.length > 2) {
          return (
            <code
              key={i}
              className="px-1.5 py-0.5 rounded-md bg-primary/10 text-primary font-mono text-[12px] break-all border border-primary/20"
            >
              {p.slice(1, -1)}
            </code>
          );
        }
        const icon = renderIconForEmoji(p, i);
        if (icon) return icon;

        return <React.Fragment key={i}>{p}</React.Fragment>;
      })}
    </span>
  );
}

const splitRow = (line: string) =>
  line.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((c) => c.trim());

function Table({ rows }: { rows: string[] }) {
  const header = splitRow(rows[0]);
  const body = rows.slice(2).map(splitRow);
  return (
    <div className="my-4 overflow-x-auto rounded-xl border border-border/80 bg-surface/50 shadow-xs">
      <table className="w-full text-sm border-collapse">
        <thead>
          <tr className="bg-surface border-b border-border/80">
            {header.map((h, i) => (
              <th
                key={i}
                className="text-left px-4 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-muted whitespace-nowrap"
              >
                <Inline text={h.replace(/\*/g, "")} />
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {body.map((r, ri) => (
            <tr
              key={ri}
              className="border-b border-border/40 last:border-0 hover:bg-primary/[0.04] transition-colors"
            >
              {r.map((c, ci) => (
                <td
                  key={ci}
                  className={`px-4 py-2.5 align-middle text-foreground/90 ${
                    ci === 0 ? "font-medium text-foreground" : ""
                  }`}
                >
                  <Inline text={c} cell />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function MarkdownReport({ content, compact = false }: { content: string; compact?: boolean }) {
  const lines = (content || "")
    .replace(/^```(?:markdown|md|text)?\s*/i, "")
    .replace(/\s*```$/, "")
    .split("\n");

  const blocks: React.ReactNode[] = [];
  let kv: { k: string; v: string }[] = [];

  const flushKv = () => {
    if (!kv.length) return;
    const items = kv;
    kv = [];
    blocks.push(
      <div key={`kv-${blocks.length}`} className="my-3 grid grid-cols-1 sm:grid-cols-2 gap-2.5">
        {items.map((it, idx) => (
          <div key={idx} className="px-3.5 py-2.5 rounded-lg border border-border/70 bg-surface/80 shadow-2xs">
            <div className="text-[10px] font-mono uppercase tracking-wider text-muted font-semibold flex items-center gap-1.5">
              <Server className="w-3 h-3 text-primary/70" />
              <Inline text={it.k} />
            </div>
            <div className="text-sm text-foreground mt-1 break-words font-medium">
              <Inline text={it.v} />
            </div>
          </div>
        ))}
      </div>
    );
  };

  let i = 0;
  while (i < lines.length) {
    const t = lines[i].trim();

    // **Key:** value  → metadata card
    const kvm = t.match(/^\*\*([^*]+?):\*\*\s*(.+)$/);
    if (kvm) {
      kv.push({ k: kvm[1], v: kvm[2] });
      i++;
      continue;
    }
    flushKv();

    if (!t) {
      i++;
      continue;
    }

    // Code blocks
    if (t.startsWith("```")) {
      const lang = t.replace(/^```/, "").trim();
      const codeLines: string[] = [];
      i++;
      while (i < lines.length && !lines[i].trim().startsWith("```")) {
        codeLines.push(lines[i]);
        i++;
      }
      i++; // skip closing ```
      blocks.push(
        <div key={`code-${i}`} className="my-3 rounded-lg overflow-hidden border border-border/70 bg-black/40">
          {lang && (
            <div className="px-3 py-1 bg-surface text-[10px] font-mono uppercase text-muted border-b border-border/60 flex items-center gap-1.5">
              <Code2 className="w-3 h-3 text-primary" />
              {lang}
            </div>
          )}
          <pre className="p-3.5 text-xs font-mono text-foreground/90 overflow-x-auto">
            <code>{codeLines.join("\n")}</code>
          </pre>
        </div>
      );
      continue;
    }

    // Table
    if (t.startsWith("|") && lines[i + 1]?.trim().match(/^\|?\s*:?-{2,}/)) {
      const rows: string[] = [];
      while (i < lines.length && lines[i].trim().startsWith("|")) rows.push(lines[i++]);
      blocks.push(<Table key={`t-${i}`} rows={rows} />);
      continue;
    }

    // Headings
    const h = t.match(/^(#{1,4})\s+(.+)$/);
    if (h) {
      const level = h[1].length;
      const rawText = h[2];
      blocks.push(
        level <= 2 ? (
          <h3 key={`h-${i}`} className="text-base font-bold text-foreground mt-4 mb-2 pb-2 border-b border-border/60 flex items-center gap-2">
            <Shield className="w-4 h-4 text-primary flex-shrink-0" />
            <Inline text={rawText} />
          </h3>
        ) : (
          <h4
            key={`h-${i}`}
            className="flex items-center gap-2 text-sm font-semibold text-foreground mt-4 mb-1.5"
          >
            <span className="w-1.5 h-3.5 rounded-full bg-primary flex-shrink-0" />
            <Inline text={rawText.replace(/^\d+\.\s*/, "")} />
          </h4>
        )
      );
      i++;
      continue;
    }

    // Horizontal rule
    if (/^-{3,}$/.test(t)) {
      blocks.push(<hr key={`hr-${i}`} className="my-4 border-border/50" />);
      i++;
      continue;
    }

    // Lists (bullets or numbered)
    if (/^([-*]|\d+\.)\s+/.test(t)) {
      const ordered = /^\d+\./.test(t);
      const items: { text: string; nested: boolean }[] = [];
      while (i < lines.length && /^\s*([-*]|\d+\.)\s+/.test(lines[i])) {
        const raw = lines[i];
        items.push({ text: raw.trim().replace(/^([-*]|\d+\.)\s+/, ""), nested: /^\s{2,}/.test(raw) });
        i++;
      }
      blocks.push(
        <ul key={`l-${i}`} className="my-2.5 space-y-2">
          {items.map((it, idx) => (
            <li key={idx} className={`flex gap-2.5 text-sm text-foreground/85 leading-relaxed ${it.nested ? "ml-6" : ""}`}>
              {ordered && !it.nested ? (
                <span className="flex-shrink-0 w-5 h-5 mt-0.5 rounded-md bg-primary/10 text-primary text-[11px] font-bold flex items-center justify-center border border-primary/20">
                  {items.slice(0, idx + 1).filter((x) => !x.nested).length}
                </span>
              ) : (
                <span className="flex-shrink-0 w-1.5 h-1.5 mt-2 rounded-full bg-primary/70" />
              )}
              <span className="flex-1">
                <Inline text={it.text} />
              </span>
            </li>
          ))}
        </ul>
      );
      continue;
    }

    // Paragraph
    blocks.push(
      <p key={`p-${i}`} className="my-2 text-sm text-foreground/85 leading-relaxed">
        <Inline text={t} />
      </p>
    );
    i++;
  }
  flushKv();

  return <div className={`space-y-1 ${compact ? "text-xs [&_table]:text-xs" : ""}`}>{blocks}</div>;
}
