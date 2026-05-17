import React, { useEffect, useMemo, useState } from "react";
import { RefreshCw } from "lucide-react";
import { fetchSocLogs } from "../utils/api";

const MODULES = ["all", "ransomware", "malware", "phishing", "credential_stuffing"];

const Logs = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [moduleFilter, setModuleFilter] = useState("all");

  const loadLogs = async () => {
    setLoading(true);
    setError(null);
    try {
      const params = { limit: 300 };
      if (moduleFilter !== "all") {
        params.module = moduleFilter;
      }
      const data = await fetchSocLogs(params);
      setLogs(data.logs || []);
    } catch (err) {
      setError(err.message || "Failed to load SOC audit logs");
      setLogs([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadLogs();
  }, [moduleFilter]);

  const filteredLogs = useMemo(() => logs, [logs]);

  const formatTime = (value) => {
    if (!value || value === "Unknown") return "Unknown";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleString();
  };

  const severityClass = (severity) => {
    switch (String(severity || "").toUpperCase()) {
      case "CRITICAL":
        return "border-red-500/30 bg-red-500/15 text-red-200";
      case "HIGH":
        return "border-rose-500/30 bg-rose-500/15 text-rose-200";
      case "MEDIUM":
        return "border-amber-500/30 bg-amber-500/15 text-amber-200";
      case "LOW":
        return "border-emerald-500/30 bg-emerald-500/10 text-emerald-200";
      default:
        return "border-slate-700 bg-slate-800/70 text-slate-300";
    }
  };

  return (
    <div className="space-y-5 pb-6">
      <div className="rounded-xl border border-slate-800/80 bg-slate-900/70 p-5 shadow-[0_18px_45px_rgba(2,6,23,0.18)]">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300/80">
              Audit Workspace
            </p>
            <h1 className="mt-1 text-2xl font-semibold tracking-tight text-slate-100">
              System Logs
            </h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
              SOC audit trail built from incident actions, detection events, and response activity.
            </p>
          </div>
          <button
            onClick={loadLogs}
            disabled={loading}
            className="inline-flex items-center justify-center gap-2 rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-4 py-2 text-sm font-semibold text-cyan-200 transition-colors hover:bg-cyan-500/20 disabled:cursor-not-allowed disabled:opacity-60"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      <div className="rounded-xl border border-slate-800/80 bg-slate-900/70 shadow-[0_18px_45px_rgba(2,6,23,0.18)]">
        <div className="flex flex-col gap-3 border-b border-slate-800 p-5 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
              SOC Audit Logs
            </p>
            <h2 className="mt-1 text-lg font-semibold text-slate-100">
              Incident Action Timeline
            </h2>
          </div>
          <select
            value={moduleFilter}
            onChange={(event) => setModuleFilter(event.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-cyan-500/40"
          >
            {MODULES.map((module) => (
              <option key={module} value={module}>
                {module === "all" ? "All Modules" : module.replace("_", " ")}
              </option>
            ))}
          </select>
        </div>

        {error && (
          <div className="m-5 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
            {error}
          </div>
        )}

        <div className="overflow-x-auto">
          <table className="w-full min-w-[980px] text-left text-sm">
            <thead className="border-b border-slate-800 bg-slate-950/50 text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <th className="px-5 py-3">Time</th>
                <th className="px-5 py-3">Incident ID</th>
                <th className="px-5 py-3">Module</th>
                <th className="px-5 py-3">Agent</th>
                <th className="px-5 py-3">Action</th>
                <th className="px-5 py-3">Severity</th>
                <th className="px-5 py-3">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {loading ? (
                <tr>
                  <td colSpan="7" className="px-5 py-10 text-center text-slate-400">
                    Loading SOC audit logs...
                  </td>
                </tr>
              ) : filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan="7" className="px-5 py-10 text-center text-slate-400">
                    No SOC audit logs found.
                  </td>
                </tr>
              ) : (
                filteredLogs.map((log) => (
                  <tr key={log.id} className="bg-slate-900/40 hover:bg-slate-800/40">
                    <td className="whitespace-nowrap px-5 py-3 text-slate-300">
                      {formatTime(log.timestamp || log.created_at)}
                    </td>
                    <td className="px-5 py-3 font-mono text-xs text-cyan-200">
                      {log.incident_id || "Unknown"}
                    </td>
                    <td className="px-5 py-3 capitalize text-slate-300">
                      {(log.module || "Unknown").replace("_", " ")}
                    </td>
                    <td className="px-5 py-3 text-slate-300">
                      {log.agent || "Unknown"}
                    </td>
                    <td className="max-w-[360px] px-5 py-3 text-slate-300">
                      {log.action || "Unknown"}
                    </td>
                    <td className="px-5 py-3">
                      <span className={`rounded-full border px-2.5 py-1 text-xs font-semibold ${severityClass(log.severity)}`}>
                        {log.severity || "Unknown"}
                      </span>
                    </td>
                    <td className="px-5 py-3 capitalize text-slate-300">
                      {(log.status || log.lifecycle_state || "Unknown").replace("_", " ")}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default Logs;
