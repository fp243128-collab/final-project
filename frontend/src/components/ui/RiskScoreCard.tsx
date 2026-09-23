import { cn } from "@/lib/utils";

interface RiskScoreCardProps {
  score: number;
}

export function RiskScoreCard({ score }: RiskScoreCardProps) {
  let colorClass = "text-success";
  if (score >= 80) colorClass = "text-critical";
  else if (score >= 60) colorClass = "text-warning";
  else if (score >= 30) colorClass = "text-info"; // using info for medium

  return (
    <div className="bg-surface border-sentinel rounded-lg p-5 shadow-sm flex flex-col justify-center items-center h-full">
      <div className="text-sm font-semibold text-muted uppercase tracking-wider mb-2">Overall Risk Score</div>
      <div className={cn("text-5xl font-bold font-mono tracking-tighter", colorClass)}>
        {score}<span className="text-2xl text-muted/50">/100</span>
      </div>
    </div>
  );
}
