import React, { useEffect, useState } from "react";
import { fetchStats } from "../api";
import { Users, AlertTriangle, TrendingUp } from "lucide-react";

export default function Stats() {
  const [stats, setStats] = useState({ users: 0, threats: 0, alerts: 0 });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadStats = async () => {
      try {
        const data = await fetchStats();
        setStats(data);
      } catch (error) {
        console.error("Failed to load stats:", error);
      } finally {
        setLoading(false);
      }
    };

    loadStats();
    // Refresh stats every 30 seconds
    const interval = setInterval(loadStats, 30000);
    return () => clearInterval(interval);
  }, []);

  const statCards = [
    { 
      label: "Active Users", 
      value: stats.users, 
      icon: Users, 
      color: "blue",
      gradient: "from-blue-500 to-blue-600" 
    },
    { 
      label: "Threats Detected", 
      value: stats.threats, 
      icon: AlertTriangle, 
      color: "red",
      gradient: "from-red-500 to-red-600" 
    },
    { 
      label: "Active Alerts", 
      value: stats.alerts, 
      icon: TrendingUp, 
      color: "yellow",
      gradient: "from-yellow-500 to-yellow-600" 
    },
  ];

  if (loading) {
    return (
      <div className="grid grid-cols-3 gap-4">
        {[1, 2, 3].map((i) => (
          <div key={i} className="bg-gradient-to-br from-slate-800 to-slate-900 rounded-xl p-5 shadow-xl border border-slate-700 animate-pulse">
            <div className="h-12"></div>
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="grid grid-cols-3 gap-4">
      {statCards.map((stat, idx) => (
        <div
          key={idx}
          className="bg-gradient-to-br from-slate-800 to-slate-900 rounded-xl p-5 shadow-xl border border-slate-700 hover:border-slate-600 hover:scale-105 transition-all duration-300"
        >
          <div className="flex items-center justify-between mb-3">
            <div className={`p-2 bg-gradient-to-br ${stat.gradient} bg-opacity-20 rounded-lg`}>
              <stat.icon className={`w-5 h-5 text-${stat.color}-400`} />
            </div>
            <span className={`text-3xl font-bold text-${stat.color}-400`}>
              {stat.value}
            </span>
          </div>
          <p className="text-sm text-slate-400 font-medium">{stat.label}</p>
        </div>
      ))}
    </div>
  );
}
