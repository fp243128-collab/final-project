"use client";

import { API_URL, WS_URL } from "@/lib/api";

import { useEffect, useState } from "react";
import { AlertTriangle, Server, Shield, Lock, Cloud } from "lucide-react";

interface RiskData {
  overall_risk: number;
  breakdown: {
    threat_risk: number;
    cloud_risk: number;
    iam_risk: number;
    infra_risk: number;
  };
  top_assets: { name: string; score: number }[];
}

export default function RiskPage() {
  const [data, setData] = useState<RiskData | null>(null);

  useEffect(() => {
    fetch(`${API_URL}/api/risk`)
      .then((res) => res.json())
      .then((json) => setData(json))
      .catch(console.error);
  }, []);

  if (!data) return <div className="p-8 text-center text-muted">Loading risk data...</div>;

  const getRiskColor = (score: number) => {
    if (score >= 80) return "text-red-600";
    if (score >= 60) return "text-orange-500";
    if (score >= 30) return "text-yellow-500";
    return "text-green-500";
  };

  const getRiskBg = (score: number) => {
    if (score >= 80) return "bg-red-50";
    if (score >= 60) return "bg-orange-50";
    if (score >= 30) return "bg-yellow-50";
    return "bg-green-50";
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      <div className="flex items-center gap-2 mb-8">
        <AlertTriangle className="w-7 h-7 text-primary" />
        <h1 className="text-2xl font-bold text-foreground">Risk Center</h1>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Overall Score */}
        <div className={`col-span-1 border border-border rounded-xl p-8 flex flex-col items-center justify-center text-center shadow-sm ${getRiskBg(data.overall_risk)}`}>
          <h2 className="text-lg font-medium text-muted uppercase tracking-wider mb-2">Overall Risk</h2>
          <div className={`text-6xl font-bold ${getRiskColor(data.overall_risk)} mb-2`}>
            {data.overall_risk}
          </div>
          <p className="text-sm text-muted">Out of 100 (Lower is better)</p>
        </div>

        {/* Breakdown */}
        <div className="col-span-1 lg:col-span-2 bg-surface border-sentinel rounded-xl p-6 shadow-sm">
          <h3 className="text-lg font-semibold mb-6">Risk Factor Breakdown</h3>
          <div className="space-y-5">
            <RiskBar label="Threat Risk" score={data.breakdown.threat_risk} icon={<Shield className="w-4 h-4"/>} />
            <RiskBar label="Cloud Risk" score={data.breakdown.cloud_risk} icon={<Cloud className="w-4 h-4"/>} />
            <RiskBar label="IAM Risk" score={data.breakdown.iam_risk} icon={<Lock className="w-4 h-4"/>} />
            <RiskBar label="Infrastructure Risk" score={data.breakdown.infra_risk} icon={<Server className="w-4 h-4"/>} />
          </div>
        </div>
      </div>

      {/* Top Assets */}
      <div className="bg-surface border-sentinel rounded-xl shadow-sm overflow-hidden mt-8">
        <div className="p-5 border-b border-border">
          <h3 className="text-sm font-semibold uppercase tracking-wider">Top Risk Assets</h3>
        </div>
        <div className="divide-y divide-border">
          {data.top_assets.map((asset, i) => (
            <div key={i} className="p-4 flex items-center justify-between hover:bg-gray-50">
              <div className="flex items-center gap-3">
                <span className="text-muted font-mono">{i + 1}.</span>
                <span className="font-semibold text-foreground">{asset.name}</span>
              </div>
              <div className="flex items-center gap-3">
                <div className="w-32 h-2 bg-gray-200 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-red-500 rounded-full"
                    style={{ width: `${asset.score}%` }}
                  ></div>
                </div>
                <span className={`font-bold w-8 text-right ${getRiskColor(asset.score)}`}>{asset.score}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function RiskBar({ label, score, icon }: { label: string, score: number, icon: React.ReactNode }) {
  return (
    <div>
      <div className="flex justify-between items-center mb-1">
        <span className="text-sm font-medium flex items-center gap-2 text-foreground">
          {icon} {label}
        </span>
        <span className="text-sm font-bold">{score}</span>
      </div>
      <div className="w-full h-2 bg-gray-100 rounded-full overflow-hidden">
        <div 
          className="h-full bg-primary rounded-full transition-all duration-500" 
          style={{ width: `${score}%` }}
        ></div>
      </div>
    </div>
  );
}
