import React, { useEffect, useState } from "react";
import { fetchLogs } from "../api";
import { Eye, RefreshCw } from "lucide-react";

export default function LogViewer() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const loadLogs = async () => {
    try {
      setRefreshing(true);
      const data = await fetchLogs(20, 0);
      setLogs(data);
    } catch (error) {
      console.error("Failed to load logs:", error);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadLogs();
    // Auto-refresh logs every 20 seconds
    const interval = setInterval(loadLogs, 20000);
    return () => clearInterval(interval);
  }, []);

  const getSeverityColor = (severity) => {
    const severityLower = severity?.toLowerCase() || 'low';
    switch (severityLower) {
      case 'critical':
      case 'high':
        return 'border-red-500';
      case 'medium':
        return 'border-yellow-500';
      default:
        return 'border-cyan-500';
    }
  };

  if (loading) {
    return (
      <div className="bg-gradient-to-br from-slate-800 to-slate-900 rounded-xl p-6 shadow-xl border border-slate-700 h-full animate-pulse">
        <div className="h-48"></div>
      </div>
    );
  }

  return (
    <div className="bg-gradient-to-br from-slate-800 to-slate-900 rounded-xl p-6 shadow-xl border border-slate-700 h-full flex flex-col">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-cyan-500 bg-opacity-20 rounded-lg">
            <Eye className="w-6 h-6 text-cyan-400" />
          </div>
          <h2 className="text-xl font-semibold text-slate-100">System Logs</h2>
        </div>
        <button
          onClick={loadLogs}
          disabled={refreshing}
          className="p-2 hover:bg-slate-700 rounded-lg transition-colors duration-200"
          title="Refresh logs"
        >
          <RefreshCw className={`w-4 h-4 text-slate-400 ${refreshing ? 'animate-spin' : ''}`} />
        </button>
      </div>
      
      <div className="flex-1 overflow-y-auto space-y-2 pr-2" style={{ maxHeight: "300px" }}>
        {logs.length === 0 ? (
          <div className="bg-slate-700 bg-opacity-30 rounded-lg p-4 text-center">
            <p className="text-sm text-slate-400">No logs available</p>
          </div>
        ) : (
          logs.map((log) => (
            <div
              key={log.id}
              className={`bg-slate-700 bg-opacity-30 rounded-lg p-3 border ${getSeverityColor(log.severity)} hover:border-cyan-400 transition-all duration-200`}
            >
              <div className="flex items-start justify-between gap-3 mb-1">
                <span className="text-xs text-slate-400 font-mono whitespace-nowrap">
                  {log.time}
                </span>
                {log.severity && (
                  <span className={`px-2 py-0.5 text-xs font-bold rounded uppercase ${
                    log.severity === 'high' || log.severity === 'critical' 
                      ? 'bg-red-500 bg-opacity-20 text-red-400' 
                      : log.severity === 'medium'
                      ? 'bg-yellow-500 bg-opacity-20 text-yellow-400'
                      : 'bg-blue-500 bg-opacity-20 text-blue-400'
                  }`}>
                    {log.severity}
                  </span>
                )}
              </div>
              <p className="text-sm text-slate-200">{log.message}</p>
              {log.risk_score !== undefined && (
                <div className="mt-2 flex items-center gap-2">
                  <span className="text-xs text-slate-500">Risk:</span>
                  <div className="flex-1 bg-slate-800 rounded-full h-1.5 overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-500 ${
                        log.risk_score > 70 ? 'bg-red-500' :
                        log.risk_score > 40 ? 'bg-yellow-500' : 'bg-green-500'
                      }`}
                      style={{ width: `${log.risk_score}%` }}
                    ></div>
                  </div>
                  <span className="text-xs text-slate-400 font-mono">
                    {log.risk_score.toFixed(1)}
                  </span>
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
