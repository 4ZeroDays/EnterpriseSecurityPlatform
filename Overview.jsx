import React from "react";
import { Activity } from "lucide-react";

export default function Overview() {
  return (
    <div className="bg-gradient-to-br from-slate-800 to-slate-900 rounded-xl p-6 shadow-xl border border-slate-700 hover:border-blue-500 transition-all duration-300">
      <div className="flex items-center gap-3 mb-3">
        <div className="p-2 bg-blue-500 bg-opacity-20 rounded-lg">
          <Activity className="w-6 h-6 text-blue-400" />
        </div>
        <h2 className="text-xl font-semibold text-slate-100">Overview</h2>
      </div>
      <p className="text-slate-400 leading-relaxed">
        Centralized log aggregation and monitoring overview. Real-time system insights at your fingertips.
      </p>
    </div>
  );
}
