cat > src/components/Login.jsx << 'EOF'
import React, { useState } from "react";
import { createAuthToken } from "../api";
import { Shield, Loader } from "lucide-react";

export default function Login({ onLoginSuccess }) {
  const [userId, setUserId] = useState("admin");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const response = await createAuthToken(userId, ["read", "write", "admin"]);
      console.log("Login successful:", response);
      onLoginSuccess();
    } catch (err) {
      setError("Failed to authenticate. Please try again.");
      console.error("Login error:", err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen w-full bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 flex items-center justify-center p-6">
      <div className="bg-gradient-to-br from-slate-800 to-slate-900 rounded-2xl p-8 shadow-2xl border border-slate-700 max-w-md w-full">
        <div className="flex items-center justify-center mb-6">
          <div className="p-4 bg-blue-500 bg-opacity-20 rounded-full">
            <Shield className="w-12 h-12 text-blue-400" />
          </div>
        </div>
        
        <h1 className="text-3xl font-bold text-center mb-2 bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent">
          Security Dashboard
        </h1>
        <p className="text-center text-slate-400 mb-8">
          Enter your credentials to access the dashboard
        </p>

        <form onSubmit={handleLogin} className="space-y-4">
          <div>
            <label htmlFor="userId" className="block text-sm font-medium text-slate-300 mb-2">
              User ID
            </label>
            <input
              id="userId"
              type="text"
              value={userId}
              onChange={(e) => setUserId(e.target.value)}
              className="w-full px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-slate-100 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
              placeholder="Enter user ID"
              required
            />
          </div>

          {error && (
            <div className="p-3 bg-red-500 bg-opacity-10 border border-red-500 rounded-lg">
              <p className="text-sm text-red-400">{error}</p>
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-gradient-to-r from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700 text-white font-semibold py-3 px-6 rounded-lg transition-all duration-300 shadow-lg hover:shadow-blue-500/50 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <Loader className="w-5 h-5 animate-spin" />
                Authenticating...
              </>
            ) : (
              "Login"
            )}
          </button>
        </form>

        <div className="mt-6 p-4 bg-slate-700 bg-opacity-30 rounded-lg">
          <p className="text-xs text-slate-400 text-center">
            Default credentials: <span className="text-slate-200 font-mono">admin</span>
          </p>
        </div>
      </div>
    </div>
  );
}
EOF
