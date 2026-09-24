"use client";

import { API_URL, WS_URL } from "@/lib/api";

import { useEffect, useState } from "react";
import { FileText, Download, Plus } from "lucide-react";

interface Report {
  id: string;
  name: string;
  date: string;
  type: string;
}

export default function ReportsPage() {
  const [reports, setReports] = useState<Report[]>([]);

  useEffect(() => {
    fetch(`${API_URL}/api/reports`)
      .then(res => res.json())
      .then(data => setReports(data.reports))
      .catch(console.error);
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center mb-6">
        <div className="flex items-center gap-2">
          <FileText className="w-7 h-7 text-primary" />
          <h1 className="text-2xl font-bold text-foreground">Reports</h1>
        </div>
        <button className="bg-primary hover:bg-blue-700 text-white px-4 py-2 rounded-lg font-medium transition-colors flex items-center gap-2 text-sm">
          <Plus className="w-4 h-4" /> Generate Report
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {reports.map(report => (
          <div key={report.id} className="bg-surface border-sentinel p-6 rounded-xl shadow-sm hover:shadow transition-shadow">
            <div className="flex justify-between items-start mb-4">
              <div className="w-10 h-10 bg-blue-50 text-blue-600 rounded flex items-center justify-center">
                <FileText className="w-5 h-5" />
              </div>
              <span className="text-xs font-semibold bg-gray-100 text-gray-600 px-2 py-1 rounded">
                {report.type}
              </span>
            </div>
            <h3 className="font-bold text-foreground mb-1">{report.name}</h3>
            <p className="text-sm text-muted mb-6">Generated on {report.date}</p>
            
            <button className="w-full border border-border text-foreground hover:bg-gray-50 font-medium text-sm px-4 py-2 rounded flex justify-center items-center gap-2 transition-colors">
              <Download className="w-4 h-4" /> Download PDF
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
