import React, { useState } from "react";
import { analyzeThreat } from "../api";
import { Shield, Loader } from "lucide-react";

export default function ThreatAnalyzer() {
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const runAnalysis = async () => {
    setAnalyzing(true);
    setError(null);
    setResult(null);

    try {
      // Sample threat analysis - you can customize these values
      const response = await analyzeThreat(
        "Sample log entry with suspicious activity",
        "192.168.1.100",
        { source: "manual_analysis" }
      );
      
      setResult(response);
    } catch (err) {
      setError("Failed to analyze threat. Please check your authentication.");
      console.error("Analysis error:", err);
    } finally {
      setAnalyzing(false);
    }
  };

  return (
    <div className="bg-gradient-to-br from-slate-800 to-slate-900 rounded-xl p-6 shadow-xl border border-slate-700 h-full flex flex-col">
      <div className="flex items-center gap-3 mb-4">
        <div className="p-2 bg-red-500 bg-opacity-20 rounded-lg">
          <Shield className="w-6 h-6 text-red-400" />
        </div>
        <h2 className="text-xl font-semibold text-slate-100">Threat Analyzer</h2>
      </div>
      
      <p className="text-slate-400 mb-4 text-sm">
        Analyze potential threats and vulnerabilities in your system.
      </p>

      {result && (
        <div className="mb-4 p-4 bg-slate-700 bg-opacity-30 rounded-lg border border-slate-600">
          <div className="grid grid-cols-2 gap-3 text-sm">
            <div>
              <span className="text-slate-500">Risk Score:</span>
              <span className={`ml-2 font-bold ${
                result.risk_score > 70 ? 'text-red-400' : 
                result.risk_score > 40 ? 'text-yellow-400' : 'text-green-400'
              }`}>
                {result.risk_score.toFixed(1)}
              </span>
            </div>
            <div>
              <span className="text-slate-500">Severity:</span>
              <span className="ml-2 font-bold text-slate-200 capitalize">
                {result.severity}
              </span>
            </div>
            <div>
              <span className="text-slate-500">Type:</span>
              <span className="ml-2 font-bold text-slate-200 capitalize">
                {result.threat_type}
              </span>
            </div>
            <div>
              <span className="text-slate-500">Confidence:</span>
              <span className="ml-2 font-bold text-slate-200">
                {(result.confidence * 100).toFixed(0)}%
              </span>
            </div>
          </div>
        </div>
      )}

      {error && (
        <div className="mb-4 p-3 bg-red-500 bg-opacity-10 border border-red-500 rounded-lg">
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}

      <button
        onClick={runAnalysis}
        disabled={analyzing}
        className="w-full bg-gradient-to-r from-red-500 to-red-600 hover:from-red-600 hover:to-red-700 text-white font-semibold py-3 px-6 rounded-lg transition-all duration-300 shadow-lg hover:shadow-red-500/50 hover:scale-105 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100 flex items-center justify-center gap-2"
      >
        {analyzing ? (
          <>
            <Loader className="w-5 h-5 animate-spin" />
            Analyzing...
          </>
        ) : (
          "Run Full Analysis"
        )}
      </button>
    </div>
  );
}
