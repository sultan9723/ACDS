import React, { useState } from "react";
import { useDashboard } from "../../context/DashboardContext";
import {
  DocumentTextIcon,
  FunnelIcon,
  ArrowPathIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  ShieldExclamationIcon,
  ClockIcon,
  PlayIcon,
  CubeIcon,
} from "@heroicons/react/24/outline";

const SystemActivityLogs = () => {
  const dashboardData = useDashboard() || {};
  const {
    activityLogs = [],
    refreshActivityLogs = async () => {},
  } = dashboardData;

  const [filter, setFilter] = useState("all");
  const [refreshing, setRefreshing] = useState(false);

  const safeActivityLogs = Array.isArray(activityLogs) ? activityLogs : [];

  const currentLogs = safeActivityLogs;

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await refreshActivityLogs();
    } catch (error) {
      console.error("Failed to refresh logs:", error);
    } finally {
      setRefreshing(false);
    }
  };

  // Filter logs based on selection
  const filteredLogs = currentLogs.filter((log) => {
    if (filter === "all") return true;
    const eventType = log?.event || log?.action_type;
    return eventType === filter;
  });

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

  const getConfidence = (log) => log?.confidence ?? log?.details?.confidence;

  const isScanEvent = (event = "") => {
    const normalized = String(event).toLowerCase();
    return (
      normalized === "email_scanned" ||
      normalized === "email_processed" ||
      normalized === "malware_sample_scanned" ||
      normalized === "malware_processed"
    );
  };

  const isThreatEvent = (event = "") => {
    const normalized = String(event).toLowerCase();
    return normalized === "threat_response" || normalized === "threat_detected";
  };

  const isResolvedEvent = (event = "") => {
    const normalized = String(event).toLowerCase();
    return normalized === "threat_resolved";
  };

  const getEventIcon = (event) => {
    switch (event) {
      case "email_scanned":
      case "email_processed":
      case "malware_sample_scanned":
      case "malware_processed":
        return <DocumentTextIcon className="h-4 w-4 text-blue-400" />;
      case "threat_response":
      case "threat_detected":
        return <ShieldExclamationIcon className="h-4 w-4 text-red-400" />;
      case "threat_resolved":
        return <CheckCircleIcon className="h-4 w-4 text-green-400" />;
      case "error":
        return <ExclamationTriangleIcon className="h-4 w-4 text-red-400" />;
      case "test_completed":
      case "batch_completed":
      case "malware_batch_completed":
        return <CheckCircleIcon className="h-4 w-4 text-cyan-400" />;
      case "demo_started":
      case "demo_stopped":
        return <PlayIcon className="h-4 w-4 text-purple-400" />;
      case "batch_processed":
        return <CubeIcon className="h-4 w-4 text-amber-400" />;
      default:
        return <DocumentTextIcon className="h-4 w-4 text-slate-400" />;
    }
  };

  const getEventColor = (event) => {
    switch (event) {
      case "email_scanned":
      case "email_processed":
      case "malware_sample_scanned":
      case "malware_processed":
        return "border-l-blue-500";
      case "threat_response":
      case "threat_detected":
        return "border-l-red-500";
      case "threat_resolved":
        return "border-l-green-500";
      case "error":
        return "border-l-red-500";
      case "test_completed":
      case "batch_completed":
      case "malware_batch_completed":
        return "border-l-cyan-500";
      case "demo_started":
      case "demo_stopped":
        return "border-l-purple-500";
      case "batch_processed":
        return "border-l-amber-500";
      default:
        return "border-l-slate-500";
    }
  };

  return (
    <div className="relative bg-slate-900/70 backdrop-blur-sm border border-slate-800/80 hover:border-cyan-500/20 rounded-xl p-5 sm:p-6 transition-all duration-300 group overflow-hidden">
      {/* Decorative accent */}
      <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-purple-500/50 via-indigo-500/30 to-transparent" />

      {/* Header */}
      <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between mb-4">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-gradient-to-br from-purple-500/30 to-indigo-500/20 rounded-lg border border-purple-500/20">
            <DocumentTextIcon className="h-6 w-6 text-purple-400" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-slate-100">
              System Activity Logs
            </h2>
            <p className="text-sm text-slate-400">
              Real-time detection and response logs
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Filter */}
          <div className="flex items-center gap-2">
            <FunnelIcon className="h-4 w-4 text-slate-500" />
            <select
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="bg-slate-950/60 border border-slate-700 rounded-lg px-2 py-1 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-emerald-500/40"
            >
              <option value="all">All Events</option>
              <option value="email_scanned">Scans</option>
              <option value="email_processed">Processed</option>
              <option value="malware_sample_scanned">Malware Scans</option>
              <option value="threat_detected">Threats</option>
              <option value="threat_resolved">Resolved</option>
              <option value="malware_batch_completed">Malware Batches</option>
              <option value="batch_processed">Batches</option>
              <option value="error">Errors</option>
            </select>
          </div>

          {/* Refresh Button */}
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="p-2 bg-slate-950/60 border border-slate-700 hover:bg-slate-800 rounded-lg transition-colors"
          >
            <ArrowPathIcon
              className={`h-4 w-4 text-slate-400 ${
                refreshing ? "animate-spin" : ""
              }`}
            />
          </button>
        </div>
      </div>

      {/* Stats Bar */}
      <div className="flex items-center space-x-4 mb-4 text-xs">
        <span className="text-slate-500">
          Total: <span className="text-slate-300">{currentLogs.length}</span>
        </span>
        <span className="text-slate-600">|</span>
        <span className="text-blue-400">
          Scanned:{" "}
          {
            currentLogs.filter(
              (l) =>
                l &&
                (isScanEvent(l.event) || isScanEvent(l.action_type))
            ).length
          }
        </span>
        <span className="text-red-400">
          Threats:{" "}
          {
            currentLogs.filter(
              (l) =>
                l &&
                (isThreatEvent(l.event) ||
                  isThreatEvent(l.action_type) ||
                  l.is_threat ||
                  l.details?.is_threat)
            ).length
          }
        </span>
        <span className="text-green-400">
          Resolved:{" "}
          {
            currentLogs.filter(
              (l) => l && (isResolvedEvent(l.event) || isResolvedEvent(l.action_type))
            )
              .length
          }
        </span>
      </div>

      {/* Logs List */}
      {filteredLogs.length > 0 ? (
        <div className="space-y-2 max-h-[300px] overflow-y-auto custom-scrollbar">
          {filteredLogs.slice(0, 30).map((log, idx) => {
            const eventType = log.event || log.action_type || "unknown";
            return (
              <div
                key={log._id || log.id || idx}
                className={`flex items-start space-x-3 p-3 bg-slate-700/30 rounded-lg border-l-2 ${getEventColor(
                  eventType
                )}`}
              >
                {/* Icon */}
                <div className="mt-1">{getEventIcon(eventType)}</div>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm font-medium text-slate-200 capitalize">
                      {eventType.replace(/_/g, " ")}
                    </span>
                    <span className="text-xs text-slate-500 flex items-center">
                      <ClockIcon className="h-3 w-3 mr-1" />
                      {formatTime(log.timestamp || log.created_at)}
                    </span>
                  </div>

                  {/* Event specific details */}
                  {isScanEvent(eventType) && (
                    <div className="text-xs text-slate-400">
                      <span className="truncate block max-w-[300px] font-medium text-slate-300">
                        {log.subject ||
                          log.details?.subject ||
                          log.filename ||
                          log.details?.filename ||
                          log.message ||
                          "No subject"}
                      </span>
                      <span className="text-slate-500 text-[10px]">
                        Source: {log.sender || log.details?.sender || "Unknown"}
                      </span>
                      <span className="text-slate-500 text-[10px] ml-2 uppercase">
                        Module: {log.module || log.details?.module || "phishing"}
                      </span>
                      <div className="flex items-center space-x-3 mt-1">
                        <span
                          className={
                            log.is_phishing ||
                            log.is_malware ||
                            log.is_phishing_detected ||
                            log.details?.is_phishing ||
                            log.details?.is_malware
                              ? "text-red-400 font-medium"
                              : "text-green-400"
                          }
                        >
                          {log.is_phishing ||
                          log.is_malware ||
                          log.is_phishing_detected ||
                          log.details?.is_phishing ||
                          log.details?.is_malware
                            ? "⚠ Threat Detected"
                            : "✓ Safe"}
                        </span>
                        <span>
                          Confidence: {formatConfidence(getConfidence(log))}
                        </span>
                        {log.severity && (
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] ${
                              log.severity === "HIGH" ||
                              log.severity === "CRITICAL"
                                ? "bg-red-500/20 text-red-400"
                                : log.severity === "MEDIUM"
                                ? "bg-amber-500/20 text-amber-400"
                                : "bg-slate-500/20 text-slate-400"
                            }`}
                          >
                            {log.severity}
                          </span>
                        )}
                      </div>
                    </div>
                  )}

                  {isThreatEvent(eventType) && (
                    <div className="text-xs text-slate-400">
                      <div className="flex items-center gap-2">
                        <span className="text-red-400 font-medium">
                          Threat ID:{" "}
                          {log.threat_id || log.details?.threat_id || "Unknown"}
                        </span>
                        <span
                          className={`px-1.5 py-0.5 rounded ${
                            log.severity === "HIGH" ||
                            log.details?.severity === "HIGH" ||
                            log.severity === "CRITICAL" ||
                            log.details?.severity === "CRITICAL"
                              ? "bg-red-500/20 text-red-400"
                              : "bg-amber-500/20 text-amber-400"
                          }`}
                        >
                          {log.severity || log.details?.severity || "MEDIUM"}
                        </span>
                      </div>
                      {log.subject && (
                        <span className="text-slate-500 block mt-1">
                          Subject: {log.subject}
                        </span>
                      )}
                      <span className="text-slate-500 block mt-1 uppercase">
                        Module: {log.module || log.details?.module || "phishing"}
                      </span>
                      {(log.actions || log.details?.actions) && (
                        <div className="flex flex-wrap gap-1 mt-1">
                          <span className="text-slate-500">Actions:</span>
                          {(log.actions || log.details?.actions || []).map(
                            (action, i) => (
                              <span
                                key={i}
                                className="px-1.5 py-0.5 bg-blue-500/20 text-blue-400 rounded"
                              >
                                {typeof action === "string"
                                  ? action.replace(/_/g, " ")
                                  : action}
                              </span>
                            )
                          )}
                        </div>
                      )}
                    </div>
                  )}

                  {isResolvedEvent(eventType) && (
                    <div className="text-xs text-slate-400">
                      <span>Threat resolved automatically</span>
                      <span className="text-slate-500 block mt-1 uppercase">
                        Module: {log.module || log.details?.module || "phishing"}
                      </span>
                      {(log.action_taken || log.details?.action_taken) && (
                        <span className="text-slate-500 block mt-1">
                          Action: {String(log.action_taken || log.details?.action_taken).replace(/_/g, " ")}
                        </span>
                      )}
                      {log.details?.actions && (
                        <div className="flex flex-wrap gap-1 mt-1">
                          {log.details.actions.map((action, i) => (
                            <span
                              key={i}
                              className="px-1.5 py-0.5 bg-green-500/20 text-green-400 rounded"
                            >
                              {action}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  )}

                  {eventType === "batch_processed" && (
                    <div className="text-xs text-slate-400">
                      <span>
                        Processed: {log.details?.total_processed || 0} |
                        Phishing: {log.details?.phishing_count || 0} | Safe:{" "}
                        {log.details?.safe_count || 0}
                      </span>
                    </div>
                  )}

                  {eventType === "error" && (
                    <p className="text-xs text-red-400">
                      {log.error || log.details?.error || "Unknown error"}
                    </p>
                  )}

                  {(eventType === "test_completed" ||
                    eventType === "batch_completed" ||
                    eventType === "malware_batch_completed") && (
                    <div className="text-xs text-slate-400">
                      <span>
                        Processed:{" "}
                        {log.total_processed ||
                          log.details?.total_processed ||
                          log.details?.samples_processed ||
                          log.samples_processed ||
                          0}{" "}
                        | Accuracy:{" "}
                        {formatConfidence(log.accuracy ?? log.details?.accuracy)} | Threats:{" "}
                        {log.threats_found ||
                          log.details?.threats_found ||
                          log.details?.phishing_detected ||
                          log.details?.malware_detected ||
                          log.phishing_detected ||
                          log.malware_detected ||
                          0}
                      </span>
                    </div>
                  )}

                  {(eventType === "demo_started" ||
                    eventType === "demo_stopped") && (
                    <div className="text-xs text-slate-400">
                      <span>
                        {eventType === "demo_started"
                          ? "Demo mode activated"
                          : "Demo mode stopped"}
                      </span>
                      {log.details?.interval && (
                        <span className="ml-2">
                          Interval: {log.details.interval}s
                        </span>
                      )}
                    </div>
                  )}

                  {/* Session/Source ID */}
                  {(log.session_id || log.source) && (
                    <span className="text-xs text-slate-600 mt-1 block">
                      {log.session_id
                        ? `Session: ${log.session_id}`
                        : `Source: ${log.source}`}
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <div className="text-center py-8 text-slate-500">
          <DocumentTextIcon className="h-10 w-10 mx-auto mb-2 opacity-50" />
          <p className="text-sm">No activity logs yet</p>
          <p className="text-xs mt-1">
            Detection, response, and reporting events will appear here.
          </p>
        </div>
      )}
    </div>
  );
};

export default SystemActivityLogs;
