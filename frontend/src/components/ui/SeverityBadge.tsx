import { cn } from "@/lib/utils";

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

interface SeverityBadgeProps {
  severity: Severity;
}

export function SeverityBadge({ severity }: SeverityBadgeProps) {
  const styles = {
    CRITICAL: "bg-critical/10 text-critical border-critical/20",
    HIGH: "bg-warning/10 text-warning border-warning/20",
    MEDIUM: "bg-info/10 text-info border-info/20",
    LOW: "bg-success/10 text-success border-success/20",
  };

  return (
    <span className={cn("px-2.5 py-0.5 rounded-full text-xs font-semibold border", styles[severity])}>
      {severity}
    </span>
  );
}
