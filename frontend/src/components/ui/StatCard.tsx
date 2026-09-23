import { cn } from "@/lib/utils";

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon?: React.ReactNode;
  trend?: "up" | "down" | "neutral";
  trendValue?: string;
}

export function StatCard({ title, value, subtitle, icon, trend, trendValue }: StatCardProps) {
  return (
    <div className="bg-surface border-sentinel rounded-lg p-5 shadow-sm flex flex-col justify-between hover:shadow-md hover:-translate-y-0.5 transition-all duration-200">
      <div className="flex justify-between items-start mb-4">
        <h3 className="text-sm font-semibold text-muted uppercase tracking-wider">{title}</h3>
        {icon && <div className="text-muted/50 w-5 h-5">{icon}</div>}
      </div>
      <div>
        <div className="text-3xl font-bold text-foreground font-mono">{value}</div>
        {(subtitle || trendValue) && (
          <div className="mt-2 flex items-center gap-2 text-sm">
            {trendValue && (
              <span
                className={cn(
                  "font-medium",
                  trend === "up" ? "text-critical" : trend === "down" ? "text-success" : "text-muted"
                )}
              >
                {trend === "up" ? "↑" : trend === "down" ? "↓" : "−"} {trendValue}
              </span>
            )}
            {subtitle && <span className="text-muted">{subtitle}</span>}
          </div>
        )}
      </div>
    </div>
  );
}
