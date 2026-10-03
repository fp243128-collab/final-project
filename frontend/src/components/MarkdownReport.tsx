"use client";

import React from "react";
import {
  Shield,
  ShieldAlert,
  AlertTriangle,
  AlertCircle,
  Info,
  CheckCircle2,
  XCircle,
  Globe,
  Lock,
  Key,
  Layers,
  FileText,
  Zap,
  Activity,
  Compass,
  Server,
  Code2,
  Radio,
  FileCode,
} from "lucide-react";

// Strip any residual unicode emojis or raw symbols
export function stripEmojis(str: string): string {
  if (!str) return "";
  return str
    .replace(
      /[\u{1F600}-\u{1F64F}\u{1F300}-\u{1F5FF}\u{1F680}-\u{1F6FF}\u{1F1E0}-\u{1F1FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}\u{FE00}-\u{FE0F}\u{1F900}-\u{1F9FF}\u{1FA70}-\u{1FAFF}\u{200D}\u{2B50}\u{20E3}\u{2190}-\u{21FF}]/gu,
      ""
    )
    .replace(/\s{2,}/g, " ")
    .trim();
}

// Severity Badges with real Lucide Icons
export function SeverityBadge({ level }: { level: string }) {
  const clean = stripEmojis(level).toLowerCase().trim();
  if (clean.includes("crit") || clean.includes("red")) {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-[11px] font-semibold bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20 whitespace-nowrap shadow-xs">
        <ShieldAlert className="w-3.5 h-3.5 flex-shrink-0 text-rose-500" />
        Critical
      </span>
    );
  }
  if (clean.includes("high") || clean.includes("orange")) {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-[11px] font-semibold bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20 whitespace-nowrap shadow-xs">
        <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 text-amber-500" />
        High
      </span>
    );
  }
  if (clean.includes("med") || clean.includes("yellow")) {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-[11px] font-semibold bg-yellow-500/10 text-yellow-600 dark:text-yellow-400 border border-yellow-500/20 whitespace-nowrap shadow-xs">
        <AlertCircle className="w-3.5 h-3.5 flex-shrink-0 text-yellow-500" />
        Medium
      </span>
    );
  }
  if (clean.includes("low") || clean.includes("blue") || clean.includes("info")) {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-[11px] font-semibold bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20 whitespace-nowrap shadow-xs">
        <Info className="w-3.5 h-3.5 flex-shrink-0 text-blue-500" />
        Low
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-[11px] font-semibold bg-muted/15 text-muted-foreground border border-muted/25 whitespace-nowrap">
      <Info className="w-3.5 h-3.5 flex-shrink-0" />
      {stripEmojis(level)}
    </span>
  );
}

// Status Badges with real Lucide Icons
export function StatusBadge({ status }: { status: string }) {
  const clean = stripEmojis(status).toLowerCase().trim();
  if (
    clean === "passed" ||
    clean === "pass" ||
    clean === "present" ||
    clean === "active" ||
    clean === "compliant" ||
    clean === "protected" ||
    clean === "controlled" ||
    clean === "yes" ||
    clean === "valid" ||
    clean === "validated" ||
    clean === "clean"
  ) {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[11px] font-semibold bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20 whitespace-nowrap">
        <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0 text-emerald-500" />
        {stripEmojis(status) || "Passed"}
      </span>
    );
  }
  if (
    clean === "failed" ||
    clean === "fail" ||
    clean === "missing" ||
    clean === "no" ||
    clean === "error" ||
    clean === "critical" ||
    clean === "exposed"
  ) {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[11px] font-semibold bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20 whitespace-nowrap">
        <XCircle className="w-3.5 h-3.5 flex-shrink-0 text-rose-500" />
        {stripEmojis(status) || "Missing"}
      </span>
    );
  }
  if (
    clean === "warning" ||
    clean === "recommended" ||
    clean === "review" ||
    clean === "redirected" ||
    clean === "forbidden"
  ) {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[11px] font-semibold bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20 whitespace-nowrap">
        <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 text-amber-500" />
        {stripEmojis(status) || "Warning"}
      </span>
    );
  }
  if (clean === "monitored" || clean === "info") {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[11px] font-semibold bg-sky-500/10 text-sky-600 dark:text-sky-400 border border-sky-500/20 whitespace-nowrap">
        <Activity className="w-3.5 h-3.5 flex-shrink-0 text-sky-500" />
        {stripEmojis(status)}
      </span>
    );
  }
  return <span>{stripEmojis(status)}</span>;
}

// Helper to choose a contextual icon for headings
function getHeadingIcon(title: string) {
  const t = title.toLowerCase();
  if (t.includes("dns") || t.includes("ip") || t.includes("network") || t.includes("topology") || t.includes("asn")) {
    return <Globe className="w-4 h-4 text-cyan-500 flex-shrink-0" />;
  }
  if (t.includes("record") || t.includes("mx") || t.includes("ns") || t.includes("cname") || t.includes("txt")) {
    return <Layers className="w-4 h-4 text-primary flex-shrink-0" />;
  }
  if (t.includes("shodan") || t.includes("port") || t.includes("service") || t.includes("attack surface")) {
    return <Radio className="w-4 h-4 text-amber-500 flex-shrink-0" />;
  }
  if (t.includes("header") || t.includes("cookie") || t.includes("ssl") || t.includes("tls") || t.includes("cert")) {
    return <Lock className="w-4 h-4 text-emerald-500 flex-shrink-0" />;
  }
  if (t.includes("endpoint") || t.includes("path") || t.includes("discovery") || t.includes("probe")) {
    return <Compass className="w-4 h-4 text-primary flex-shrink-0" />;
  }
  if (t.includes("dos") || t.includes("rate limit") || t.includes("resilience") || t.includes("load")) {
    return <Zap className="w-4 h-4 text-amber-500 flex-shrink-0" />;
  }
  if (t.includes("injection") || t.includes("sql") || t.includes("xss") || t.includes("payload")) {
    return <Code2 className="w-4 h-4 text-rose-500 flex-shrink-0" />;
  }
  if (t.includes("auth") || t.includes("login") || t.includes("session") || t.includes("token")) {
    return <Key className="w-4 h-4 text-violet-500 flex-shrink-0" />;
  }
  if (t.includes("cve") || t.includes("owasp") || t.includes("vulnerab") || t.includes("threat")) {
    return <ShieldAlert className="w-4 h-4 text-rose-500 flex-shrink-0" />;
  }
  if (t.includes("warning") || t.includes("alert")) {
    return <AlertTriangle className="w-4 h-4 text-amber-500 flex-shrink-0" />;
  }
  if (t.includes("remediation") || t.includes("roadmap") || t.includes("action") || t.includes("recommend")) {
    return <CheckCircle2 className="w-4 h-4 text-emerald-500 flex-shrink-0" />;
  }
  if (t.includes("summary") || t.includes("brief") || t.includes("report") || t.includes("matrix")) {
    return <FileText className="w-4 h-4 text-primary flex-shrink-0" />;
  }
  return <Shield className="w-4 h-4 text-primary flex-shrink-0" />;
}

// Inline token renderer with smart emoji stripping & code formatting
function Inline({ text, cell = false }: { text: string; cell?: boolean }) {
  const cleanStr = stripEmojis(text);
  const plain = cleanStr.replace(/\*/g, "").trim();

  // If cell is exact severity keyword
  if (cell && /^(critical|high|medium|low|info)$/i.test(plain)) {
    return <SeverityBadge level={plain} />;
  }

  // If cell is exact status keyword
  if (
    cell &&
    /^(present|missing|passed|failed|active|compliant|protected|controlled|monitored|recommended|yes|no|valid|error|clean|exposed|forbidden|redirected)$/i.test(
      plain
    )
  ) {
    return <StatusBadge status={plain} />;
  }

  const parts = cleanStr.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).filter(Boolean);

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
        return <React.Fragment key={i}>{p}</React.Fragment>;
      })}
    </span>
  );
}

const splitRow = (line: string) =>
  line.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((c) => stripEmojis(c.trim()));

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
  const rawClean = stripEmojis(content || "")
    .replace(/^```(?:markdown|md|text)?\s*/i, "")
    .replace(/\s*```$/, "");

  const lines = rawClean.split("\n");
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
      i++;
      blocks.push(
        <div key={`code-${i}`} className="my-3 rounded-lg overflow-hidden border border-border/70 bg-black/40">
          {lang && (
            <div className="px-3 py-1 bg-surface text-[10px] font-mono uppercase text-muted border-b border-border/60 flex items-center gap-1.5">
              <FileCode className="w-3 h-3 text-primary" />
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

    // Blockquotes
    if (t.startsWith(">")) {
      const quoteText = t.replace(/^>\s*/, "");
      blocks.push(
        <div key={`bq-${i}`} className="my-3 px-4 py-2.5 rounded-lg border-l-4 border-amber-500 bg-amber-500/10 text-sm text-foreground flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-amber-500 flex-shrink-0" />
          <span><Inline text={quoteText} /></span>
        </div>
      );
      i++;
      continue;
    }

    // Headings
    const h = t.match(/^(#{1,4})\s+(.+)$/);
    if (h) {
      const level = h[1].length;
      const cleanTitle = stripEmojis(h[2]).replace(/\*/g, "");
      const icon = getHeadingIcon(cleanTitle);

      blocks.push(
        level <= 2 ? (
          <h3 key={`h-${i}`} className="text-base font-bold text-foreground mt-4 mb-2 pb-2 border-b border-border/60 flex items-center gap-2">
            {icon}
            <span>{cleanTitle}</span>
          </h3>
        ) : (
          <h4
            key={`h-${i}`}
            className="flex items-center gap-2 text-sm font-semibold text-foreground mt-4 mb-1.5"
          >
            {icon}
            <span>{cleanTitle.replace(/^\d+\.\s*/, "")}</span>
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
        items.push({ text: stripEmojis(raw.trim().replace(/^([-*]|\d+\.)\s+/, "")), nested: /^\s{2,}/.test(raw) });
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
