import React from "react";
import { useDashboard } from "../../context/DashboardContext";

const IncidentDetails = ({
  incident: providedIncident,
  emptyTitle = "No incident selected",
  emptyDescription = "Select a row from Threat Monitoring to review evidence, confidence, automated action, and analyst feedback.",
}) => {
  const dashboardData = useDashboard() || {};
  const selectedIncident =
    providedIncident !== undefined
      ? providedIncident
      : dashboardData.selectedIncident;
  const incident = selectedIncident?.threat || selectedIncident;
  const actions =
    incident?.actions_taken ||
    incident?.actions ||
    (incident?.action_taken ? [incident.action_taken] : []);

  const formatConfidence = (value) => {
    if (value === null || value === undefined || value === "") return "N/A";
    const numeric = Number(value);
    if (Number.isNaN(numeric)) return value;
    return `${Math.round(numeric > 1 ? numeric : numeric * 100)}%`;
  };

  const explanation =
    incident?.explanation ||
    incident?.description ||
    incident?.content_preview ||
    (Array.isArray(incident?.evidence) && incident.evidence.length > 0
      ? incident.evidence.join(" ")
      : "No detailed explanation is available for this incident.");
  const isThreat =
    incident?.prediction === "Phishing" ||
    String(incident?.type || "").toLowerCase().includes("phishing") ||
    Boolean(incident?.threat_id || incident?.action_taken);

  if (!selectedIncident) {
    return (
      <div className="bg-slate-900/70 backdrop-blur-sm border border-slate-800/80 rounded-xl p-6 h-full flex items-center justify-center">
        <div className="max-w-sm text-center">
          <p className="text-sm font-medium text-slate-300">
            {emptyTitle}
          </p>
          <p className="mt-2 text-xs leading-5 text-slate-500">
            {emptyDescription}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-slate-900/70 backdrop-blur-sm border border-slate-800/80 rounded-xl h-full">
      <div className="p-4 border-b border-slate-800/80">
        <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
          Analyst Review
        </p>
        <h3 className="mt-1 text-sm font-semibold text-slate-100">
          Incident Details
        </h3>
      </div>
      <div className="p-4 space-y-4">
        {/* Details Grid */}
        <div className="space-y-3 text-sm">
          <div className="flex justify-between">
            <span className="text-slate-500">Date & Time</span>
            <span className="text-slate-300">
              {incident?.date || incident?.detected_at || "N/A"}
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500">Threat Type</span>
            <span className="text-slate-300">
              {incident?.prediction || incident?.type || "N/A"}
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500">Source</span>
            <span className="text-slate-300 text-xs truncate max-w-[150px]">
              {incident?.source || incident?.sender || "Unknown"}
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500">Subject</span>
            <span className="text-slate-300 text-xs truncate max-w-[150px]">
              {incident?.subject || "No subject"}
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500">Confidence</span>
            <span className="text-slate-300">
              {formatConfidence(incident?.confidence)}
            </span>
          </div>
        </div>

        {/* Explanation */}
        <div>
          <p className="text-slate-500 text-xs mb-1">Explanation</p>
          <p className="text-slate-400 text-xs leading-relaxed">
            {explanation}
          </p>
        </div>

        {/* Automated Action */}
        <div className="pt-2 border-t border-slate-800">
          <p className="text-slate-500 text-xs mb-2">Automated Action</p>
          <div className="space-y-1 text-xs text-slate-400">
            {actions.length > 0 ? (
              actions.map((action, index) => (
                <p key={`${action}-${index}`}>
                  <span className="text-slate-300">
                    {String(action).replace(/_/g, " ")}
                  </span>
                </p>
              ))
            ) : (
              <p>No automated response action was required.</p>
            )}
          </div>
        </div>

        {/* Analyst Ticket */}
        {isThreat && (
          <div className="text-xs text-slate-400">
            A <span className="text-emerald-400">ticket</span> logged for{" "}
            <span className="text-slate-300">SOC analyst</span>
          </div>
        )}

        {/* Feedback Buttons */}
        <div className="flex gap-2 pt-2">
          <button className="flex-1 px-3 py-2 text-xs font-medium text-slate-300 bg-slate-800/50 border border-slate-700 rounded-lg hover:bg-slate-700/50 transition-colors">
            True Positive
          </button>
          <button className="flex-1 px-3 py-2 text-xs font-medium text-emerald-400 bg-emerald-900/20 border border-emerald-800/50 rounded-lg hover:bg-emerald-900/30 transition-colors">
            False Positive
          </button>
        </div>

        {/* Feedback Log */}
        <div className="pt-4 border-t border-slate-800">
          <p className="text-slate-500 text-xs mb-3">Feedback Log</p>
          <div className="flex justify-around">
            <div className="text-center">
              <p className="text-xs text-slate-500">True Positive</p>
              <p className="text-lg font-semibold text-slate-300">12</p>
            </div>
            <div className="text-center">
              <p className="text-xs text-slate-500">False Positive</p>
              <p className="text-lg font-semibold text-slate-300">3</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default IncidentDetails;
