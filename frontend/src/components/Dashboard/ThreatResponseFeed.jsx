import React from "react";
import { useDashboard } from "../../context/DashboardContext";
import {
  ShieldCheckIcon,
  BellAlertIcon,
  TrashIcon,
  EnvelopeIcon,
  ClockIcon,
  CheckCircleIcon,
} from "@heroicons/react/24/outline";

const ThreatResponseFeed = () => {
  const dashboardData = useDashboard() || {};
  const { liveThreats = [], responseActions = [] } = dashboardData;

  // Ensure arrays are valid
  const safeLiveThreats = Array.isArray(liveThreats) ? liveThreats : [];
  const safeResponseActions = Array.isArray(responseActions)
    ? responseActions
    : [];

  // Calculate threat breakdown
  const phishingCount = safeLiveThreats.filter(t => t?.module === 'phishing').length;
  const malwareCount = safeLiveThreats.filter(t => t?.module === 'malware').length;
  const ransomwareCount = safeLiveThreats.filter(t => t?.module === 'ransomware').length;

  // Combine threats and responses into a timeline
  const timelineItems = [];

  // Add threats to timeline
  safeLiveThreats.forEach((threat) => {
    if (threat) {
      timelineItems.push({
        type: "threat",
        id: threat.id,
        timestamp: threat.detected_at,
        data: threat,
      });
    }
  });

  // Add response actions to timeline
  safeResponseActions.forEach((action) => {
    if (action) {
      timelineItems.push({
        type: "response",
        id: `action-${action.threat_id}`,
        timestamp: action.timestamp,
        data: action,
      });
    }
  });

  // Sort by timestamp descending
  timelineItems.sort(
    (a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0)
  );

  const formatTime = (timestamp) => {
    if (!timestamp) return "";
    const date = new Date(timestamp);
    if (Number.isNaN(date.getTime())) return "";
    return date.toLocaleTimeString("en-US", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  };

  const formatConfidence = (confidence) => {
    const numeric = Number(confidence);
    if (!Number.isFinite(numeric)) return "N/A";
    return `${Math.round(numeric > 1 ? numeric : numeric * 100)}%`;
  };

  const getSeverityColor = (severity) => {
    switch (severity?.toUpperCase()) {
      case "CRITICAL":
        return "text-red-300 bg-red-500/15 border border-red-500/30";
      case "HIGH":
        return "text-red-300 bg-red-500/15 border border-red-500/30";
      case "MEDIUM":
        return "text-amber-300 bg-amber-500/15 border border-amber-500/30";
      case "LOW":
        return "text-emerald-300 bg-emerald-500/15 border border-emerald-500/30";
      default:
        return "text-cyan-300 bg-cyan-500/10 border border-cyan-500/25";
    }
  };

  const getModuleColor = (module) => {
    switch (module?.toLowerCase()) {
      case "phishing":
        return "bg-blue-500/20 text-blue-400 border border-blue-500/40";
      case "malware":
        return "bg-purple-500/20 text-purple-400 border border-purple-500/40";
      case "ransomware":
        return "bg-red-500/20 text-red-400 border border-red-500/40";
      default:
        return "bg-slate-500/20 text-slate-400 border border-slate-500/40";
    }
  };

  const getActionIcon = (actionType) => {
    switch (actionType) {
      case "quarantine_email":
        return <EnvelopeIcon className="h-4 w-4" />;
      case "block_sender":
        return <ShieldCheckIcon className="h-4 w-4" />;
      case "delete_email":
        return <TrashIcon className="h-4 w-4" />;
      case "send_alert":
        return <BellAlertIcon className="h-4 w-4" />;
      default:
        return <CheckCircleIcon className="h-4 w-4" />;
    }
  };

  return (
    <div className="relative bg-slate-900/70 backdrop-blur-sm border border-slate-800/80 hover:border-red-500/20 rounded-xl p-5 sm:p-6 transition-all duration-300 group overflow-hidden h-full">
      {/* Decorative accent */}
      <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-red-500/50 via-orange-500/30 to-transparent" />

      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-gradient-to-br from-red-500/30 to-orange-500/20 rounded-lg border border-red-500/20">
            <ShieldCheckIcon className="h-6 w-6 text-red-400" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-slate-100">
              Threat Response Feed
            </h2>
            <p className="text-sm text-slate-400">
              Primary operational feed for detections and response actions
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2 text-sm">
          <span className="text-slate-500">Threats:</span>
          <span className="text-red-400 font-bold">
            {safeLiveThreats.length}
          </span>
          <span className="text-slate-600 mx-1">|</span>
          <span className="text-slate-500">Resolved:</span>
          <span className="text-green-400 font-bold">
            {safeResponseActions.length}
          </span>
        </div>
      </div>

      {/* Threat Breakdown Summary */}
      {safeLiveThreats.length > 0 && (
        <div className="grid grid-cols-3 gap-3 mb-5 p-4 bg-slate-800/40 rounded-lg border border-slate-700/30">
          <div className="text-center">
            <div className="text-xs text-slate-500 mb-1.5 uppercase tracking-wide">Phishing</div>
            <div className="text-2xl font-bold text-blue-400 flex items-center justify-center gap-1">
              {phishingCount}
            </div>
          </div>
          <div className="text-center border-x border-slate-700/50">
            <div className="text-xs text-slate-500 mb-1.5 uppercase tracking-wide">Malware</div>
            <div className="text-2xl font-bold text-purple-400 flex items-center justify-center gap-1">
              {malwareCount}
            </div>
          </div>
          <div className="text-center">
            <div className="text-xs text-slate-500 mb-1.5 uppercase tracking-wide">Ransomware</div>
            <div className="text-2xl font-bold text-red-400 flex items-center justify-center gap-1">
              {ransomwareCount}
            </div>
          </div>
        </div>
      )}

      {/* Timeline */}
      {timelineItems.length > 0 ? (
        <div className="space-y-4 max-h-[400px] overflow-y-auto custom-scrollbar">
          {timelineItems.slice(0, 15).map((item, idx) => (
            <div key={item.id || idx} className="relative">
              {/* Timeline line */}
              {idx < timelineItems.length - 1 && (
                <div className="absolute left-[15px] top-[40px] bottom-[-16px] w-[2px] bg-slate-700" />
              )}

              {item.type === "threat" ? (
                // Threat Detected Item
                <div className="flex items-start space-x-4">
                  <div className="p-2 bg-red-500/20 rounded-full border-2 border-red-500/50 z-10">
                    <BellAlertIcon className="h-4 w-4 text-red-400" />
                  </div>
                  <div className="flex-1 bg-red-500/10 border border-red-500/30 rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-semibold text-red-400">
                        THREAT DETECTED
                      </span>
                      <span className="text-xs text-slate-500 flex items-center">
                        <ClockIcon className="h-3 w-3 mr-1" />
                        {formatTime(item.timestamp)}
                      </span>
                    </div>
                    <p className="text-sm text-slate-100 font-medium truncate">
                      {item.data.subject}
                    </p>
                    <p className="text-xs text-slate-400 mt-1">
                      From: {item.data.sender}
                    </p>
                    <div className="flex items-center flex-wrap gap-2 mt-3">
                      <span className={`text-xs px-2.5 py-1 rounded-md font-semibold uppercase ${getModuleColor(item.data.module || item.data.type || "phishing")}`}>
                        {item.data.module || item.data.type || "phishing"}
                      </span>
                      <span
                        className={`text-xs px-2.5 py-1 rounded-md font-semibold uppercase ${getSeverityColor(
                          item.data.severity
                        )}`}
                      >
                        {item.data.severity}
                      </span>
                      <span className="text-xs px-2.5 py-1 bg-slate-700/50 text-slate-300 rounded-md border border-slate-600/50">
                        Confidence {formatConfidence(item.data.confidence)}
                      </span>
                    </div>
                    <div className="text-xs text-slate-600 mt-2 font-mono">
                      ID: {item.data.id}
                    </div>
                    {item.data.action_taken && (
                      <div className="flex items-center space-x-2 mt-2">
                        <span className="text-xs text-green-400">Action:</span>
                        <span className="text-xs px-2 py-1 bg-green-500/20 text-green-400 rounded">
                          {String(item.data.action_taken).replace(/_/g, " ")}
                        </span>
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                // Response Action Item
                <div className="flex items-start space-x-4">
                  <div className="p-2 bg-green-500/20 rounded-full border-2 border-green-500/50 z-10">
                    <ShieldCheckIcon className="h-4 w-4 text-green-400" />
                  </div>
                  <div className="flex-1 bg-green-500/10 border border-green-500/30 rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-semibold text-green-400">
                        AUTO-RESOLVED
                      </span>
                      <span className="text-xs text-slate-500 flex items-center">
                        <ClockIcon className="h-3 w-3 mr-1" />
                        {formatTime(item.timestamp)}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mb-2">
                      Threat ID: {item.data.threat_id}
                    </p>
                    <div className="mb-2">
                      <span className={`text-xs px-2.5 py-1 rounded-md font-semibold uppercase ${getModuleColor(item.data.module || "phishing")}`}>
                        {item.data.module || "phishing"}
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {(item.data.actions || []).map((action, actionIdx) => (
                        <span
                          key={actionIdx}
                          className="flex items-center space-x-1 text-xs px-2 py-1 bg-green-500/20 text-green-400 rounded"
                        >
                          {getActionIcon(action)}
                          <span>{action.replace(/_/g, " ")}</span>
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      ) : (
        // Empty State
        <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 px-6 py-10 text-center">
          <ShieldCheckIcon className="h-12 w-12 mx-auto mb-3 text-emerald-300/70" />
          <p className="text-sm font-semibold text-emerald-200">
            No active threat activity in the live feed
          </p>
          <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-slate-400">
            ACDS is ready to surface detections, containment steps, and analyst
            follow-up here as soon as telemetry arrives.
          </p>
        </div>
      )}
    </div>
  );
};

export default ThreatResponseFeed;
