import React from "react";
import { useDashboard } from "../../context/DashboardContext";
import { fetchIncidentDetails } from "../../utils/api";

const ThreatMonitoringTable = () => {
  const dashboardData = useDashboard() || {};
  const {
    threats = [],
    liveThreats = [],
    activityLogs = [],
    setSelectedIncident = () => {},
  } = dashboardData;

  const sourceRows = [
    ...(Array.isArray(threats) ? threats : []),
    ...(Array.isArray(liveThreats) ? liveThreats : []),
    ...(Array.isArray(activityLogs) ? activityLogs : []),
  ];

  const seen = new Set();
  const safeThreats = sourceRows
    .map((item, index) => {
      const id = item.id || item.threat_id || item.incident_id || `incident-${index}`;
      const module = item.module || item.threat_type || item.type || "Unknown";
      const subject =
        item.subject ||
        item.filename ||
        item.description ||
        item.message ||
        "Security incident";
      return {
        id,
        time: item.time || item.detected_at || item.timestamp || item.created_at || "Unknown",
        module,
        incident_id: item.incident_id || item.threat_id || item.id || id,
        prediction: item.prediction || item.type || item.event || "Unknown",
        subject,
        severity: item.severity || "Unknown",
        status: item.status || item.lifecycle_state || "Unknown",
        confidence: item.confidence ?? item.details?.confidence ?? 0,
        action_taken: item.action_taken || item.actions?.[0] || item.details?.action_taken || "No recent action",
      };
    })
    .filter((item) => {
      if (seen.has(item.id)) return false;
      seen.add(item.id);
      return true;
    })
    .slice(0, 12);

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
              <th className="px-4 py-3">Module</th>
              <th className="px-4 py-3">Incident ID</th>
              <th className="px-4 py-3">Prediction</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Confidence (%)</th>
              <th className="px-4 py-3">Action Taken</th>
              <th className="px-4 py-3">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/50">
            {safeThreats.length > 0 ? (
              safeThreats.map((threat) => (
                <tr
                  key={threat?.id || Math.random()}
                  onClick={() => threat?.id && handleRowClick(threat.id)}
                  className="hover:bg-emerald-500/5 transition-colors cursor-pointer"
                >
                  <td className="px-4 py-3 text-slate-300 capitalize">
                    {String(threat.module || "Unknown").replace("_", " ")}
                  </td>
                  <td className="px-4 py-3 text-slate-400 font-mono text-xs">
                    {threat.incident_id || "Unknown"}
                  </td>
                  <td className="px-4 py-3 text-slate-300 max-w-[180px] truncate">
                    {String(threat.prediction || "Unknown").replace("_", " ")}
                  </td>
                  <td className="px-4 py-3 text-slate-300">
                    {threat.severity || "Unknown"}
                  </td>
                  <td className="px-4 py-3 text-slate-300">
                    {Number(threat.confidence || 0) > 1
                      ? Math.round(Number(threat.confidence || 0))
                      : Math.round(Number(threat.confidence || 0) * 100)}
                  </td>
                  <td className="px-4 py-3 text-slate-300 max-w-[220px] truncate">
                    {String(threat.action_taken || "No recent action").replace("_", " ")}
                  </td>
                  <td className="px-4 py-3 text-slate-400 capitalize">
                    {String(threat.status || "Unknown").replace("_", " ")}
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={7} className="px-4 py-10 text-center">
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
