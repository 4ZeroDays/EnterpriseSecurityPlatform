import React, { useState } from "react";
import Header from "./components/Header";
import Overview from "./components/Overview";
import Stats from "./components/Stats";
import HealthCheck from "./components/HealthCheck";
import ThreatAnalyzer from "./components/ThreatAnalyzer";
import Alerts from "./components/Alerts";
import LogViewer from "./components/LogViewer";
import ThreatMap from "./components/ThreatMap";
import AlertInspector from "./components/AlertInspector";
import { Layers, List } from "lucide-react";

export default function App() {
  const [viewMode, setViewMode] = useState("dashboard"); 

  return (
    <div className="min-h-screen w-full bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 flex flex-col">
      <Header />
      
      {/* View Toggle */}
      <div className="px-6 pt-6">
        <div className="flex gap-2 bg-slate-800 bg-opacity-50 p-1 rounded-lg w-fit">
          <button
            onClick={() => setViewMode("dashboard")}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
              viewMode === "dashboard"
                ? "bg-blue-500 text-white shadow-lg shadow-blue-500/30"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-700"
            }`}
          >
            <Layers className="w-4 h-4" />
            Dashboard
          </button>
          <button
            onClick={() => setViewMode("threatmap")}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
              viewMode === "threatmap"
                ? "bg-blue-500 text-white shadow-lg shadow-blue-500/30"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-700"
            }`}
          >
            <Layers className="w-4 h-4" />
            Threat Map
          </button>
          <button
            onClick={() => setViewMode("inspector")}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
              viewMode === "inspector"
                ? "bg-blue-500 text-white shadow-lg shadow-blue-500/30"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-700"
            }`}
          >
            <List className="w-4 h-4" />
            Alert Inspector
          </button>
        </div>
      </div>

      <div className="flex-1 p-6">
        {viewMode === "dashboard" && (
          <div className="grid grid-cols-3 gap-6 h-full">
            <div className="col-span-2 flex flex-col gap-6">
              <Overview />
              <Stats />
              <HealthCheck />
            </div>
            <div className="col-span-1 flex flex-col gap-6">
              <ThreatAnalyzer />
              <Alerts />
              <LogViewer />
            </div>
          </div>
        )}

        {viewMode === "threatmap" && (
          <div className="h-full">
            <ThreatMap />
          </div>
        )}

        {viewMode === "inspector" && (
          <div className="h-full">
            <AlertInspector />
          </div>
        )}
      </div>
    </div>
  );
}
