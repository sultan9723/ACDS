import React, { useState } from "react";
import { useDashboard } from "../../context/DashboardContext";
import {
  PlayIcon,
  ArrowPathIcon,
  ShieldExclamationIcon,
  CheckCircleIcon,
  XCircleIcon,
  BoltIcon,
  DocumentTextIcon,
} from "@heroicons/react/24/outline";

const LiveTestingPanel = () => {
  const dashboardData = useDashboard() || {};
  const {
    testRunning = false,
    runBatch = async () => ({ success: false }),
    testResults = [],
    liveThreats = [],
    responseActions = [],
    currentTestSession = null,
    simulationMeta = null,
  } = dashboardData;

  const [testCount, setTestCount] = useState(2);
  const [selectedModule, setSelectedModule] = useState("all");
  const [lastTestSummary, setLastTestSummary] = useState(null);
  const [error, setError] = useState(null);

  const handleRunTest = async () => {
    setError(null);
    try {
      const result = await runBatch(testCount, selectedModule);
      setLastTestSummary(result?.summary || null);
    } catch (err) {
      console.error("Test failed:", err);
      setError(err?.detail || err?.message || "Simulation failed. Please try again.");
    }
  };

  // Calculate stats from results - with safe access
  const safeResults = Array.isArray(testResults) ? testResults : [];
  const correctPredictions = safeResults.filter((r) => r && r.correct).length;
  const accuracy =
    safeResults.length > 0
      ? Math.round((correctPredictions / safeResults.length) * 100)
      : 0;
  const isRansomwareView =
    selectedModule === "ransomware" ||
    (simulationMeta?.module === "ransomware" && safeResults.some((result) => result.module === "ransomware"));

  const formatConfidence = (value) => {
    if (value === null || value === undefined) return "N/A";
    const numeric = Number(value);
    if (Number.isNaN(numeric)) return "N/A";
    return `${Math.round((numeric > 1 ? numeric : numeric * 100))}%`;
  };

  const getSeverityClass = (severity) => {
    switch (String(severity || "").toUpperCase()) {
      case "CRITICAL":
        return "border-red-500/30 bg-red-500/15 text-red-200";
      case "HIGH":
        return "border-rose-500/30 bg-rose-500/15 text-rose-200";
      case "MEDIUM":
        return "border-amber-500/30 bg-amber-500/15 text-amber-200";
      default:
        return "border-emerald-500/30 bg-emerald-500/10 text-emerald-200";
    }
  };

  return (
    <div className="relative bg-slate-900/70 backdrop-blur-sm border border-slate-800/80 hover:border-emerald-500/30 rounded-xl p-5 sm:p-6 transition-all duration-300 group overflow-hidden">
      {/* Decorative corner accent */}
      <div className="absolute top-0 right-0 w-24 h-24 bg-gradient-to-bl from-emerald-500/10 to-transparent rounded-bl-full opacity-0 group-hover:opacity-100 transition-opacity duration-500" />

      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between mb-6 relative">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-gradient-to-br from-emerald-500/30 to-emerald-600/20 rounded-lg border border-emerald-500/20">
            <BoltIcon className="h-6 w-6 text-emerald-400" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-slate-100">
              Live Threat Detection Simulation
            </h2>
            <p className="text-sm text-slate-400">
              Run controlled detection batches across ACDS modules
            </p>
          </div>
        </div>
        {currentTestSession && (
          <span className="text-xs text-slate-500 bg-slate-700/50 px-2 py-1 rounded">
            Session: {currentTestSession}
          </span>
        )}
      </div>

      {/* Controls */}
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:gap-4 mb-6">
        <div className="flex items-center gap-2">
          <label className="text-sm text-slate-400">Module:</label>
          <select
            value={selectedModule}
            onChange={(e) => setSelectedModule(e.target.value)}
            disabled={testRunning}
            className="bg-slate-950/60 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-emerald-500/40"
          >
            <option value="all">All Modules</option>
            <option value="email_phishing">Email Phishing</option>
            <option value="malware">Malware</option>
            <option value="ransomware">Ransomware</option>
            <option value="credential_stuffing">Credential Stuffing</option>
          </select>
        </div>

        <div className="flex items-center gap-2">
          <label className="text-sm text-slate-400">Batch size:</label>
          <select
            value={testCount}
            onChange={(e) => setTestCount(Number(e.target.value))}
            disabled={testRunning}
            className="bg-slate-950/60 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-emerald-500/40"
          >
            <option value={2}>2</option>
            <option value={5}>5</option>
            <option value={10}>10</option>
          </select>
        </div>

        <button
          onClick={handleRunTest}
          disabled={testRunning}
          className={`flex items-center justify-center gap-2 px-4 py-2 rounded-lg font-medium transition-all ${
            testRunning
              ? "bg-slate-700 text-slate-400 cursor-not-allowed"
              : "border border-emerald-500/30 bg-emerald-500/20 text-emerald-100 hover:bg-emerald-500/30"
          }`}
        >
          {testRunning ? (
            <>
              <ArrowPathIcon className="h-5 w-5 animate-spin" />
              <span>Running Simulation...</span>
            </>
          ) : (
            <>
              <PlayIcon className="h-5 w-5" />
              <span>Run Simulation</span>
            </>
          )}
        </button>
      </div>

      {simulationMeta?.model_loaded === false && (
        <div className="mb-5 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-100">
          Static PE analysis completed. ML model artifact is not loaded, so confidence may remain low.
        </div>
      )}

      {/* Stats Cards */}
      {safeResults.length > 0 && !isRansomwareView && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <div className="bg-gradient-to-br from-slate-800/60 to-slate-800/30 rounded-lg p-4 border border-slate-700/50 hover:border-slate-600/70 transition-colors">
            <div className="flex items-center space-x-2 text-slate-400 mb-1">
              <DocumentTextIcon className="h-4 w-4" />
              <span className="text-xs uppercase tracking-wider">
                Processed
              </span>
            </div>
            <p className="text-2xl font-bold bg-gradient-to-r from-slate-100 to-slate-300 bg-clip-text text-transparent">
              {safeResults.length}
            </p>
          </div>

          <div className="bg-gradient-to-br from-red-900/20 to-slate-800/30 rounded-lg p-4 border border-red-500/20 hover:border-red-500/40 transition-colors">
            <div className="flex items-center space-x-2 text-red-400 mb-1">
              <ShieldExclamationIcon className="h-4 w-4" />
              <span className="text-xs uppercase tracking-wider">
                Threats Found
              </span>
            </div>
            <p className="text-2xl font-bold text-red-400">
              {(Array.isArray(liveThreats) ? liveThreats : []).length}
            </p>
          </div>

          <div className="bg-gradient-to-br from-green-900/20 to-slate-800/30 rounded-lg p-4 border border-green-500/20 hover:border-green-500/40 transition-colors">
            <div className="flex items-center space-x-2 text-green-400 mb-1">
              <CheckCircleIcon className="h-4 w-4" />
              <span className="text-xs uppercase tracking-wider">
                Auto-Resolved
              </span>
            </div>
            <p className="text-2xl font-bold text-green-400">
              {(Array.isArray(responseActions) ? responseActions : []).length}
            </p>
          </div>

          <div className="bg-gradient-to-br from-emerald-900/20 to-slate-800/30 rounded-lg p-4 border border-emerald-500/20 hover:border-emerald-500/40 transition-colors">
            <div className="flex items-center space-x-2 text-emerald-400 mb-1">
              <CheckCircleIcon className="h-4 w-4" />
              <span className="text-xs uppercase tracking-wider">Accuracy</span>
            </div>
            <p className="text-2xl font-bold text-emerald-400">{accuracy}%</p>
          </div>
        </div>
      )}

      {/* Realtime Results */}
      {safeResults.length > 0 && isRansomwareView && (
        <div className="overflow-x-auto rounded-lg border border-slate-800/80">
          <table className="w-full min-w-[760px] text-left text-sm">
            <thead className="border-b border-slate-800 bg-slate-950/50 text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <th className="px-4 py-3">Filename</th>
                <th className="px-4 py-3">Prediction</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Confidence</th>
                <th className="px-4 py-3">Lifecycle State</th>
                <th className="px-4 py-3">Evidence Count</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {safeResults
                .filter((result) => result.module === "ransomware")
                .map((result) => (
                  <tr key={result.id} className="bg-slate-900/40 hover:bg-slate-800/40">
                    <td className="px-4 py-3 font-mono text-xs text-slate-200">
                      {result.filename || "unknown.exe"}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`rounded-full border px-2.5 py-1 text-xs font-semibold ${
                          result.prediction === "RANSOMWARE"
                            ? "border-red-500/30 bg-red-500/15 text-red-200"
                            : "border-emerald-500/30 bg-emerald-500/10 text-emerald-200"
                        }`}
                      >
                        {result.prediction || "SAFE"}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`rounded-full border px-2.5 py-1 text-xs font-semibold ${getSeverityClass(result.severity)}`}>
                        {result.severity || "LOW"}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-300">
                      {formatConfidence(result.confidence)}
                    </td>
                    <td className="px-4 py-3 text-slate-300">
                      {String(result.lifecycle_state || "closed").replaceAll("_", " ")}
                    </td>
                    <td className="px-4 py-3 text-slate-300">
                      {result.evidence_count || 0}
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      )}

      {safeResults.length > 0 && !isRansomwareView && (
        <div className="space-y-3 max-h-[300px] overflow-y-auto custom-scrollbar">
          <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider sticky top-0 bg-slate-800/90 py-2">
            Detection Results
          </h3>
          {safeResults.slice(0, 10).map((result, idx) => (
            <div
              key={idx}
              className={`flex items-center justify-between p-3 rounded-lg border ${
                result && result.is_phishing
                  ? "bg-red-500/10 border-red-500/30"
                  : "bg-green-500/10 border-green-500/30"
              }`}
            >
              <div className="flex items-center space-x-3">
                {result && result.is_phishing ? (
                  <ShieldExclamationIcon className="h-5 w-5 text-red-400" />
                ) : (
                  <CheckCircleIcon className="h-5 w-5 text-green-400" />
                )}
                <div>
                  <p className="text-sm font-medium text-slate-100 truncate max-w-[200px]">
                    {(result && result.subject) || `Email #${idx + 1}`}
                  </p>
                  <p className="text-xs text-slate-400">
                    {result.sender || "Unknown sender"}
                  </p>
                </div>
              </div>

              <div className="flex items-center space-x-4">
                <div className="text-right">
                  <p
                    className={`text-sm font-semibold ${
                      result.is_phishing ? "text-red-400" : "text-green-400"
                    }`}
                  >
                    {result.prediction || (result.is_phishing ? "PHISHING" : "SAFE")}
                  </p>
                  <p className="text-xs text-slate-500">
                    {formatConfidence((result && result.confidence) || 0)} confidence
                  </p>
                </div>

                {/* Prediction correctness */}
                <div
                  className={`p-1 rounded ${
                    result && result.correct
                      ? "bg-green-500/20"
                      : "bg-red-500/20"
                  }`}
                >
                  {result && result.correct ? (
                    <CheckCircleIcon className="h-4 w-4 text-green-400" />
                  ) : (
                    <XCircleIcon className="h-4 w-4 text-red-400" />
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Empty State */}
      {safeResults.length === 0 && !testRunning && (
        <div className="text-center py-8 text-slate-500">
          <BoltIcon className="h-12 w-12 mx-auto mb-3 opacity-50 text-emerald-500/50" />
          <p>Click "Run Simulation" to start controlled threat detection</p>
          <p className="text-sm mt-1">Select a module and batch size before running.</p>
        </div>
      )}
    </div>
  );
};

export default LiveTestingPanel;
