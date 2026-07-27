import React from "react";
import { useDashboard } from "../../context/DashboardContext";
import { fetchIncidentDetails } from "../../utils/api";

const ThreatMonitoringTable = () => {
  const dashboardData = useDashboard() || {};
  const { threats = [], setSelectedIncident = () => {} } = dashboardData;

  const safeThreats = Array.isArray(threats) ? threats : [];

  const formatTime = (timestamp) => {
    if (!timestamp) return "N/A";
    const date = new Date(timestamp);
    if (Number.isNaN(date.getTime())) return String(timestamp);

    return date.toLocaleString("en-US", {
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  const formatConfidence = (confidence) => {
    const numeric = Number(confidence);
    if (!Number.isFinite(numeric)) return "N/A";
    return `${Math.round(numeric > 1 ? numeric : numeric * 100)}%`;
  };

  const getThreatType = (threat) =>
    threat?.type ||
    threat?.module ||
    (threat?.is_malware ? "Malware" : "Phishing");

  const getSeverityTone = (severity = "") => {
    switch (String(severity).toUpperCase()) {
      case "CRITICAL":
      case "HIGH":
        return "border-red-500/30 bg-red-500/10 text-red-300";
      case "MEDIUM":
        return "border-amber-500/30 bg-amber-500/10 text-amber-300";
      case "LOW":
        return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
      default:
        return "border-slate-700 bg-slate-800/50 text-slate-300";
    }
  };

  const getStatusTone = (status = "") => {
    const normalized = String(status).toLowerCase();
    if (normalized.includes("resolved") || normalized.includes("blocked")) {
      return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
    }
    if (normalized.includes("active") || normalized.includes("detected")) {
      return "border-red-500/30 bg-red-500/10 text-red-300";
    }
    return "border-slate-700 bg-slate-800/50 text-slate-300";
  };

  const handleRowClick = async (id) => {
    try {
      const details = await fetchIncidentDetails(id);
      setSelectedIncident(details);
    } catch (error) {
      console.error("Failed to fetch incident details:", error);
    }
  };

  return (
    <div className="bg-slate-900/70 backdrop-blur-sm border border-slate-800/80 rounded-xl h-full">
      <div className="p-4 border-b border-slate-800/80">
        <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
          Investigation Queue
        </p>
        <h3 className="mt-1 text-sm font-semibold text-slate-100">
          Threat Monitoring
        </h3>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm text-left">
          <thead className="text-xs text-slate-500 uppercase bg-slate-900/30">
            <tr>
              <th className="px-4 py-3">Time</th>
              <th className="px-4 py-3">Type</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Source</th>
              <th className="px-4 py-3">Confidence</th>
              <th className="px-4 py-3">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/50">
            {safeThreats.length > 0 ? (
              safeThreats.map((threat, index) => {
                const status = threat?.status || threat?.state || "Detected";
                const severity = threat?.severity || "MEDIUM";
                const source =
                  threat?.sender ||
                  threat?.source ||
                  threat?.filename ||
                  threat?.file_name ||
                  "Unknown";
                const timestamp =
                  threat?.detected_at || threat?.timestamp || threat?.time;

                return (
                  <tr
                    key={threat?.id || `${source}-${timestamp || index}`}
                    onClick={() => threat?.id && handleRowClick(threat.id)}
                    className={`transition-colors hover:bg-emerald-500/5 ${
                      threat?.id ? "cursor-pointer" : ""
                    }`}
                  >
                    <td className="px-4 py-3 text-slate-400 font-mono text-xs">
                      {formatTime(timestamp)}
                    </td>
                    <td className="px-4 py-3">
                      <p className="text-sm font-medium text-slate-200 capitalize">
                        {String(getThreatType(threat)).replace(/_/g, " ")}
                      </p>
                      <p className="mt-1 max-w-[280px] truncate text-xs text-slate-500">
                        {threat?.subject || threat?.description || "No summary"}
                      </p>
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`inline-flex rounded-md border px-2 py-1 text-xs font-semibold uppercase ${getSeverityTone(
                          severity
                        )}`}
                      >
                        {severity}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-300">
                      <span className="block max-w-[220px] truncate">
                        {source}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-300">
                      {formatConfidence(threat?.confidence)}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`inline-flex rounded-md border px-2 py-1 text-xs font-semibold uppercase ${getStatusTone(
                          status
                        )}`}
                      >
                        {String(status).replace(/_/g, " ")}
                      </span>
                    </td>
                  </tr>
                );
              })
            ) : (
              <tr>
                <td colSpan={6} className="px-4 py-10 text-center">
                  <p className="text-sm font-medium text-slate-300">
                    No incidents are waiting for review
                  </p>
                  <p className="mt-1 text-xs text-slate-500">
                    New detections will populate this investigation queue for
                    analyst triage.
                  </p>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default ThreatMonitoringTable;
