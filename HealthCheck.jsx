import React, { useEffect, useState } from "react";
import { fetchHealth } from "../api";
import { Server } from "lucide-react";

export default function HealthCheck() {
  const [health, setHealth] = useState({ 
    cpu: "0%", 
    memory: "0%", 
    disk: "0%",
    status: "unknown"
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadHealth = async () => {
      try {
        const data = await fetchHealth();
        setHealth(data);
      } catch (error) {
        console.error("Failed to load health:", error);
      } finally {
        setLoading(false);
      }
    };

    loadHealth();
    // Refresh health every 10 seconds
    const interval = setInterval(loadHealth, 10000);
    return () => clearInterval(interval);
  }, []);

  const getColorForValue = (value) => {
    const numValue = parseInt(value);
    if (numValue < 50) return "green";
    if (numValue < 75) return "yellow";
    return "red";
  };

  const healthMetrics = [
    { 
      label: "CPU Usage", 
      value: health.cpu, 
      color: getColorForValue(health.cpu)
    },
    { 
      label: "Memory", 
      value: health.memory, 
      color: getColorForValue(health.memory)
    },
    { 
      label: "Disk Space", 
      value: health.disk, 
      color: getColorForValue(health.disk)
    },
  ];

  if (loading) {
    return (
      <div className="bg-gradient-to-br from-slate-800 to-slate-900 rounded-xl p-6 shadow-xl border border-slate-700 animate-pulse">
        <div className="h-40"></div>
      </div>
    );
  }

  return (
    <div className="bg-gradient-to-br from-slate-800 to-slate-900 rounded-xl p-6 shadow-xl border border-slate-700">
      <div className="flex items-center justify-between mb-5">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-green-500 bg-opacity-20 rounded-lg">
            <Server className="w-6 h-6 text-green-400" />
          </div>
          <h2 className="text-xl font-semibold text-slate-100">System Health</h2>
        </div>
        <div className={`px-3 py-1 rounded-full text-xs font-semibold ${
          health.status === 'healthy' 
            ? 'bg-green-500 bg-opacity-20 text-green-400' 
            : 'bg-yellow-500 bg-opacity-20 text-yellow-400'
        }`}>
          {health.status?.toUpperCase() || 'UNKNOWN'}
        </div>
      </div>
      <div className="space-y-4">
        {healthMetrics.map((metric, idx) => (
          <div key={idx}>
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium text-slate-300">{metric.label}</span>
              <span className={`text-sm font-bold text-${metric.color}-400`}>{metric.value}</span>
            </div>
            <div className="w-full bg-slate-700 rounded-full h-2 overflow-hidden">
              <div
                className={`h-full bg-gradient-to-r from-${metric.color}-400 to-${metric.color}-500 rounded-full transition-all duration-500`}
                style={{ width: metric.value }}
              ></div>
            </div>
          </div>
        ))}
      </div>
      
      {health.components && (
        <div className="mt-4 pt-4 border-t border-slate-700">
          <p className="text-xs text-slate-500 mb-2">Component Status</p>
          <div className="grid grid-cols-3 gap-2">
            {Object.entries(health.components).map(([key, status]) => (
              <div key={key} className="flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${
                  status === 'healthy' ? 'bg-green-400' : 'bg-red-400'
                }`}></div>
                <span className="text-xs text-slate-400 capitalize">{key}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
