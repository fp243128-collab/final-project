"use client";

import React from "react";

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-red-500/15 text-red-600 dark:text-red-400 ring-red-500/30",
  high: "bg-orange-500/15 text-orange-600 dark:text-orange-400 ring-orange-500/30",
  medium: "bg-amber-500/15 text-amber-600 dark:text-amber-400 ring-amber-500/30",
  low: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 ring-emerald-500/30",
  info: "bg-sky-500/15 text-sky-600 dark:text-sky-400 ring-sky-500/30",
};

const STATUS_STYLES: Record<string, string> = {
  missing: "text-red-600 dark:text-red-400",
  present: "text-emerald-600 dark:text-emerald-400",
  active: "text-emerald-600 dark:text-emerald-400",
  compliant: "text-emerald-600 dark:text-emerald-400",
  passed: "text-emerald-600 dark:text-emerald-400",
  protected: "text-emerald-600 dark:text-emerald-400",
  controlled: "text-emerald-600 dark:text-emerald-400",
  monitored: "text-sky-600 dark:text-sky-400",
  recommended: "text-amber-600 dark:text-amber-400",
};

function SeverityBadge({ level }: { level: string }) {
  const key = level.toLowerCase();
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-semibold ring-1 ring-inset whitespace-nowrap ${SEVERITY_STYLES[key]}`}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current" />
      {key.charAt(0).toUpperCase() + key.slice(1)}
    </span>
  );
}

/** Inline markdown: **bold**, `code`; severity/status words get badges/colors inside table cells. */
function Inline({ text, cell = false }: { text: string; cell?: boolean }) {
  const trimmed = text.trim();
  const plain = trimmed.replace(/\*/g, "");
  const sev = plain.match(/^(critical|high|medium|low|info)$/i);
  if (cell && sev) return <SeverityBadge level={sev[1]} />;

  const statusClass = cell ? STATUS_STYLES[plain.toLowerCase()] : undefined;
  const parts = trimmed.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).filter(Boolean);

  return (
    <span className={statusClass ? `font-semibold ${statusClass}` : undefined}>
      {parts.map((p, i) => {
        if (p.startsWith("**") && p.endsWith("**") && p.length > 4)
          return (
            <strong key={i} className="font-semibold text-foreground">
              {p.slice(2, -2)}
            </strong>
          );
        if (p.startsWith("`") && p.endsWith("`") && p.length > 2)
          return (
            <code
              key={i}
              className="px-1.5 py-0.5 rounded-md bg-primary/10 text-primary font-mono text-[12px] break-all"
            >
              {p.slice(1, -1)}
            </code>
          );
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
    <div className="my-4 overflow-x-auto rounded-xl border border-border/80 shadow-xs">
      <table className="w-full text-sm border-collapse">
        <thead>
          <tr className="bg-surface">
            {header.map((h, i) => (
              <th
                key={i}
                className="text-left px-4 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-muted border-b border-border/80 whitespace-nowrap"
              >
                {h.replace(/\*/g, "")}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {body.map((r, ri) => (
            <tr
              key={ri}
              className="border-b border-border/50 last:border-0 hover:bg-primary/[0.04] transition-colors"
            >
              {r.map((c, ci) => (
                <td
                  key={ci}
                  className={`px-4 py-2.5 align-middle text-foreground/85 ${ci === 0 ? "font-medium text-foreground" : ""}`}
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
      <div key={`kv-${blocks.length}`} className="my-3 grid grid-cols-1 sm:grid-cols-2 gap-2">
        {items.map((it, idx) => (
          <div key={idx} className="px-3 py-2 rounded-lg border border-border/70 bg-surface">
            <div className="text-[10px] font-mono uppercase tracking-wider text-muted">{it.k}</div>
            <div className="text-sm text-foreground mt-0.5 break-words">
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
      const text = h[2].replace(/\*/g, "");
      blocks.push(
        level <= 2 ? (
          <h3 key={`h-${i}`} className="text-base font-bold text-foreground mt-2 mb-2 pb-2 border-b border-border/60">
            {text}
          </h3>
        ) : (
          <h4
            key={`h-${i}`}
            className="flex items-center gap-2 text-sm font-semibold text-foreground mt-5 mb-1"
          >
            <span className="w-1 h-4 rounded-full bg-primary" />
            {text.replace(/^\d+\.\s*/, "")}
          </h4>
        )
      );
      i++;
      continue;
    }

    // Horizontal rule
    if (/^-{3,}$/.test(t)) {
      blocks.push(<hr key={`hr-${i}`} className="my-4 border-border/60" />);
      i++;
      continue;
    }

    // Lists (bullets or numbered, with nested indents)
    if (/^([-*]|\d+\.)\s+/.test(t)) {
      const ordered = /^\d+\./.test(t);
      const items: { text: string; nested: boolean }[] = [];
      while (i < lines.length && /^\s*([-*]|\d+\.)\s+/.test(lines[i])) {
        const raw = lines[i];
        items.push({ text: raw.trim().replace(/^([-*]|\d+\.)\s+/, ""), nested: /^\s{2,}/.test(raw) });
        i++;
      }
      blocks.push(
        <ul key={`l-${i}`} className="my-2 space-y-1.5">
          {items.map((it, idx) => (
            <li key={idx} className={`flex gap-2.5 text-sm text-foreground/85 leading-relaxed ${it.nested ? "ml-6" : ""}`}>
              {ordered && !it.nested ? (
                <span className="flex-shrink-0 w-5 h-5 mt-0.5 rounded-md bg-primary/10 text-primary text-[11px] font-bold flex items-center justify-center">
                  {items.slice(0, idx + 1).filter((x) => !x.nested).length}
                </span>
              ) : (
                <span className="flex-shrink-0 w-1.5 h-1.5 mt-2 rounded-full bg-primary/60" />
              )}
              <span>
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

  return <div className={compact ? "text-xs [&_table]:text-xs" : ""}>{blocks}</div>;
}
