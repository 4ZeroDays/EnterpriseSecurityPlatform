import React, { useEffect, useState } from "react";
import { fetchStats } from "../api";

export default function StatsPanel() {
  const [stats, setStats] = useState(null);

  useEffect(() => {
    fetchStats().then(setStats);
  }, []);

  if (!stats) return <div>Loading stats...</div>;

  return (
    <div className="panel stats-panel">
      <h3>Stats</h3>
      <ul>
        {Object.entries(stats).map(([key, value]) => (
          <li key={key}>{key}: {value}</li>
        ))}
      </ul>
    </div>
  );
}
