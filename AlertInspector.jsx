import React, { useEffect, useState } from "react";
import { fetchThreats, fetchLogs } from "../api";
import { Search, Filter, Download, AlertTriangle, TrendingUp, TrendingDown, Activity, Calendar, Shield } from "lucide-react";

export default function AlertInspector() {
  const [alerts, setAlerts] = useState([]);
  const [filteredAlerts, setFilteredAlerts] = useState([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [sortBy, setSortBy] = useState("newest");
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState({ total: 0, critical: 0, high: 0, medium: 0, low: 0 });

  useEffect(() => {
    const loadAlerts = async () => {
      try {
        const [threats, logs] = await Promise.all([fetchThreats(), fetchLogs(50, 0)]);
        
        // Combine threats and logs into alerts
        const combinedAlerts = [
          ...threats.map(t => ({
            ...t,
            type: 'threat',
            timestamp: t.created_at || new Date().toISOString()
          })),
          ...logs.map(l => ({
            ...l,
            name: l.message,
            type: 'log',
            timestamp: l.time
          }))
        ];

        setAlerts(combinedAlerts);
        calculateStats(combinedAlerts);
      } catch (error) {
        console.error("Failed to load alerts:", error);
      } finally {
        setLoading(false);
      }
    };

    loadAlerts();
    const interval = setInterval(loadAlerts, 20000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    applyFilters();
  }, [searchTerm, severityFilter, sortBy, alerts]);

  const calculateStats = (data) => {
    const stats = {
      total: data.length,
      critical: data.filter(a => a.severity?.toLowerCase() === 'critical').length,
      high: data.filter(a => a.severity?.toLowerCase() === 'high').length,
      medium: data.filter(a => a.severity?.toLowerCase() === 'medium').length,
      low: data.filter(a => a.severity?.toLowerCase() === 'low').length,
    };
    setStats(stats);
  };

  const applyFilters = () => {
    let filtered = [...alerts];

    // Search filter
    if (searchTerm) {
      filtered = filtered.filter(alert =>
        alert.name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        alert.message?.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    // Severity filter
    if (severityFilter !== 'all') {
      filtered = filtered.filter(alert => alert.severity?.toLowerCase() === severityFilter);
    }

    // Sort
    if (sortBy === 'newest') {
      filtered.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    } else if (sortBy === 'oldest') {
      filtered.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    } else if (sortBy === 'severity') {
      const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
      filtered.sort((a, b) => 
        (severityOrder[b.severity?.toLowerCase()] || 0) - (severityOrder[a.severity?.toLowerCase()] || 0)
      );
    } else if (sortBy === 'risk') {
      filtered.sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));
    }

    setFilteredAlerts(filtered);
  };

  const getSeverityColor = (severity) => {
    const severityLower = severity?.toLowerCase() || 'low';
    switch (severityLower) {
      case 'critical': return 'bg-red-500';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      default: return 'bg-blue-500';
    }
  };

  const exportData = () => {
    const dataStr = JSON.stringify(filteredAlerts, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `alerts-${new Date().toISOString()}.json`;
    link.click();
  };

  if (loading) {
    return (
      <div className="bg-gradient-to-br from-slate-800 to-slate-900 rounded-xl p-6 shadow-xl border border-slate-700 animate-pulse">
        <div className="h-96"></div>
      </div>
    );
  }

  return (
    <div className="bg-gradient-to-br from-slate-800 to-slate-900 rounded-xl shadow-xl border border-slate-700 flex flex-col h-full">
      {/* Header */}
      <div className="p-6 border-b border-slate-700">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-500 bg-opacity-20 rounded-lg">
              <Activity className="w-6 h-6 text-purple-400" />
            </div>
            <h2 className="text-xl font-semibold text-slate-100">Alert Inspector</h2>
          </div>
          <button
            onClick={exportData}
            className="flex items-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors text-sm font-medium text-slate-200"
          >
            <Download className="w-4 h-4" />
            Export
          </button>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-5 gap-3 mb-6">
          <div className="bg-slate-700 bg-opacity-30 rounded-lg p-3 text-center">
            <p className="text-2xl font-bold text-slate-100">{stats.total}</p>
            <p className="text-xs text-slate-400 mt-1">Total</p>
          </div>
          <div className="bg-red-500 bg-opacity-10 rounded-lg p-3 text-center border border-red-500">
            <p className="text-2xl font-bold text-red-400">{stats.critical}</p>
            <p className="text-xs text-red-400 mt-1">Critical</p>
          </div>
          <div className="bg-orange-500 bg-opacity-10 rounded-lg p-3 text-center border border-orange-500">
            <p className="text-2xl font-bold text-orange-400">{stats.high}</p>
            <p className="text-xs text-orange-400 mt-1">High</p>
          </div>
          <div className="bg-yellow-500 bg-opacity-10 rounded-lg p-3 text-center border border-yellow-500">
            <p className="text-2xl font-bold text-yellow-400">{stats.medium}</p>
            <p className="text-xs text-yellow-400 mt-1">Medium</p>
          </div>
          <div className="bg-blue-500 bg-opacity-10 rounded-lg p-3 text-center border border-blue-500">
            <p className="text-2xl font-bold text-blue-400">{stats.low}</p>
            <p className="text-xs text-blue-400 mt-1">Low</p>
          </div>
        </div>

        {/* Search and Filters */}
        <div className="flex gap-3">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search alerts..."
              className="w-full pl-10 pr-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-slate-100 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent text-sm"
            />
          </div>
          
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-slate-100 focus:outline-none focus:ring-2 focus:ring-purple-500 text-sm"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
            className="px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-slate-100 focus:outline-none focus:ring-2 focus:ring-purple-500 text-sm"
          >
            <option value="newest">Newest First</option>
            <option value="oldest">Oldest First</option>
            <option value="severity">By Severity</option>
            <option value="risk">By Risk Score</option>
          </select>
        </div>
      </div>

      {/* Alert List */}
      <div className="flex-1 overflow-y-auto p-6 space-y-3">
        {filteredAlerts.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-center">
            <Shield className="w-16 h-16 text-slate-600 mb-4" />
            <p className="text-slate-400">No alerts match your filters</p>
          </div>
        ) : (
          filteredAlerts.map((alert, index) => (
            <div
              key={`${alert.id}-${index}`}
              className="bg-slate-700 bg-opacity-30 rounded-lg p-4 border border-slate-600 hover:border-purple-500 transition-all duration-200 hover:shadow-lg"
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <span className={`w-2 h-2 rounded-full ${getSeverityColor(alert.severity)}`}></span>
                    <h3 className="font-semibold text-slate-100 capitalize">
                      {alert.name || alert.message}
                    </h3>
                    {alert.type && (
                      <span className="px-2 py-0.5 text-xs bg-slate-600 text-slate-300 rounded">
                        {alert.type}
                      </span>
                    )}
                  </div>
                  
                  <div className="flex items-center gap-4 text-xs text-slate-400">
                    <div className="flex items-center gap-1">
                      <Calendar className="w-3 h-3" />
                      {new Date(alert.timestamp).toLocaleString()}
                    </div>
                    {alert.risk_score !== undefined && (
                      <div className="flex items-center gap-1">
                        <TrendingUp className="w-3 h-3" />
                        Risk: {alert.risk_score.toFixed(1)}
                      </div>
                    )}
                    {alert.confidence !== undefined && (
                      <div className="flex items-center gap-1">
                        <Activity className="w-3 h-3" />
                        Confidence: {(alert.confidence * 100).toFixed(0)}%
                      </div>
                    )}
                  </div>
                </div>

                <span className={`px-3 py-1 text-xs font-bold rounded uppercase ${getSeverityColor(alert.severity)} bg-opacity-20 border ${getSeverityColor(alert.severity).replace('bg-', 'border-')}`}>
                  {alert.severity || 'low'}
                </span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
