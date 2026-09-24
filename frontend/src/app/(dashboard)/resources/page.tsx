"use client";

import { API_URL, WS_URL } from "@/lib/api";

import { useEffect, useState } from "react";
import { Server, CheckCircle, Cloud, AlertCircle } from "lucide-react";

interface Resource {
  id: string;
  provider: string;
  type: string;
  compliance: string;
  risk: string;
}

export default function ResourcesPage() {
  const [resources, setResources] = useState<Resource[]>([]);

  useEffect(() => {
    fetch(`${API_URL}/api/resources`)
      .then(res => res.json())
      .then(data => setResources(data.resources))
      .catch(console.error);
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 mb-6">
        <Server className="w-7 h-7 text-primary" />
        <h1 className="text-2xl font-bold text-foreground">Cloud Resources</h1>
      </div>

      <div className="bg-surface border-sentinel rounded-lg shadow-sm overflow-hidden">
        <div className="p-4 border-b border-border flex justify-between items-center">
          <h2 className="font-semibold text-foreground">Asset Inventory</h2>
          <span className="text-sm text-muted">{resources.length} Resources Scanned</span>
        </div>
        
        <table className="w-full text-sm text-left">
          <thead className="text-xs text-muted uppercase bg-gray-50 border-b border-border">
            <tr>
              <th className="px-6 py-3">Resource ID</th>
              <th className="px-6 py-3">Provider</th>
              <th className="px-6 py-3">Type</th>
              <th className="px-6 py-3">Compliance</th>
              <th className="px-6 py-3">Risk Level</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {resources.map((res) => (
              <tr key={res.id} className="hover:bg-gray-50">
                <td className="px-6 py-4 font-mono font-medium text-foreground">{res.id}</td>
                <td className="px-6 py-4 flex items-center gap-2">
                  <Cloud className="w-4 h-4 text-muted" /> {res.provider}
                </td>
                <td className="px-6 py-4">{res.type}</td>
                <td className="px-6 py-4">
                  {res.compliance === "Compliant" ? (
                    <span className="flex items-center gap-1 text-green-600 text-xs font-semibold bg-green-50 px-2 py-1 rounded border border-green-200 w-fit">
                      <CheckCircle className="w-3 h-3" /> Compliant
                    </span>
                  ) : (
                    <span className="flex items-center gap-1 text-red-600 text-xs font-semibold bg-red-50 px-2 py-1 rounded border border-red-200 w-fit">
                      <AlertCircle className="w-3 h-3" /> Non-Compliant
                    </span>
                  )}
                </td>
                <td className="px-6 py-4">
                  <span className={`px-2 py-1 rounded text-xs font-semibold ${
                    res.risk === "High" ? "bg-red-100 text-red-700" :
                    res.risk === "Medium" ? "bg-yellow-100 text-yellow-700" :
                    "bg-green-100 text-green-700"
                  }`}>
                    {res.risk}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
