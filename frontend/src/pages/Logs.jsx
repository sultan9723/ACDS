import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Download,
  Filter,
  RefreshCw,
  Search,
  ShieldAlert,
  TerminalSquare,
} from "lucide-react";
import { fetchActivityLogs } from "../utils/api";

const EVENT_OPTIONS = [
  { value: "all", label: "All Events" },
  { value: "email_scanned", label: "Email Scans" },
  { value: "email_processed", label: "Email Processed" },
  { value: "threat_detected", label: "Threats" },
  { value: "threat_response", label: "Responses" },
  { value: "threat_resolved", label: "Resolved" },
  { value: "phishing_test_run_completed", label: "Phishing Runs" },
  { value: "error", label: "Errors" },
];

const MODULE_OPTIONS = ["all", "phishing", "malware", "ransomware"];
const SEVERITY_OPTIONS = ["all", "critical", "high", "medium", "low", "safe"];

const normalizeText = (value) => String(value || "").toLowerCase();

const formatEvent = (event) =>
  String(event || "unknown")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());

const formatTimestamp = (timestamp) => {
  if (!timestamp) return "N/A";
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return String(timestamp);

  return date.toLocaleString("en-US", {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
};

const formatConfidence = (value) => {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return "N/A";
  return `${Math.round(numeric > 1 ? numeric : numeric * 100)}%`;
};

const getLogId = (log, index) =>
  log?.id || log?._id || log?.threat_id || `${log?.event || "event"}-${index}`;

const getSeverity = (log) =>
  log?.severity || log?.details?.severity || (log?.is_threat ? "MEDIUM" : "SAFE");

const getSubject = (log) =>
  log?.subject ||
  log?.details?.subject ||
  log?.filename ||
  log?.details?.filename ||
  log?.message ||
  "No subject";

const getSource = (log) =>
  log?.sender ||
  log?.source ||
  log?.details?.sender ||
  log?.details?.source ||
  log?.user_email ||
  "System";

const getActions = (log) => {
  const actions =
    log?.actions ||
    log?.details?.actions ||
    (log?.action_taken ? [log.action_taken] : null) ||
    (log?.details?.action_taken ? [log.details.action_taken] : null);

  return Array.isArray(actions) ? actions : [];
};

const getConfidence = (log) => log?.confidence ?? log?.details?.confidence;

const eventTone = (event = "") => {
  const normalized = normalizeText(event);
  if (normalized.includes("error")) {
    return "border-red-500/30 bg-red-500/10 text-red-300";
  }
  if (normalized.includes("threat")) {
    return "border-red-500/30 bg-red-500/10 text-red-300";
  }
  if (normalized.includes("resolved") || normalized.includes("completed")) {
    return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
  }
  return "border-cyan-500/25 bg-cyan-500/10 text-cyan-200";
};

const severityTone = (severity = "") => {
  switch (String(severity).toUpperCase()) {
    case "CRITICAL":
    case "HIGH":
      return "border-red-500/30 bg-red-500/10 text-red-300";
    case "MEDIUM":
      return "border-amber-500/30 bg-amber-500/10 text-amber-300";
    case "LOW":
    case "SAFE":
      return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
    default:
      return "border-slate-700 bg-slate-800/50 text-slate-300";
  }
};

const escapeCsvValue = (value) => {
  const text = String(value ?? "");
  if (text.includes(",") || text.includes('"') || text.includes("\n")) {
    return `"${text.replace(/"/g, '""')}"`;
  }
  return text;
};

const Logs = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [eventFilter, setEventFilter] = useState("all");
  const [moduleFilter, setModuleFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [query, setQuery] = useState("");

  const loadLogs = useCallback(async ({ silent = false } = {}) => {
    if (silent) {
      setRefreshing(true);
    } else {
      setLoading(true);
    }
    setError("");

    try {
      const data = await fetchActivityLogs(200);
      setLogs(Array.isArray(data?.logs) ? data.logs : []);
    } catch (requestError) {
      setError(
        requestError?.message || "Unable to load system activity logs."
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadLogs();
  }, [loadLogs]);

  const filteredLogs = useMemo(() => {
    const normalizedQuery = normalizeText(query);

    return logs.filter((log) => {
      const event = log?.event || log?.action_type || "unknown";
      const module = normalizeText(log?.module || log?.details?.module || "system");
      const severity = normalizeText(getSeverity(log));
      const searchable = normalizeText(
        [
          event,
          module,
          severity,
          getSubject(log),
          getSource(log),
          log?.threat_id,
          log?.session_id,
          getActions(log).join(" "),
        ].join(" ")
      );

      if (eventFilter !== "all" && event !== eventFilter) return false;
      if (moduleFilter !== "all" && module !== moduleFilter) return false;
      if (severityFilter !== "all" && severity !== severityFilter) return false;
      if (normalizedQuery && !searchable.includes(normalizedQuery)) return false;
      return true;
    });
  }, [eventFilter, logs, moduleFilter, query, severityFilter]);

  const stats = useMemo(() => {
    const total = logs.length;
    const threats = logs.filter(
      (log) =>
        log?.is_threat ||
        normalizeText(log?.event || log?.action_type).includes("threat")
    ).length;
    const resolved = logs.filter((log) =>
      normalizeText(log?.event || log?.action_type).includes("resolved")
    ).length;
    const errors = logs.filter((log) =>
      normalizeText(log?.event || log?.action_type).includes("error")
    ).length;

    return { total, threats, resolved, errors };
  }, [logs]);

  const exportFilteredLogs = () => {
    const header = [
      "timestamp",
      "module",
      "event",
      "severity",
      "subject",
      "source",
      "confidence",
      "actions",
      "threat_id",
      "session_id",
    ];

    const rows = filteredLogs.map((log) => [
      log?.timestamp || log?.created_at || "",
      log?.module || log?.details?.module || "system",
      log?.event || log?.action_type || "unknown",
      getSeverity(log),
      getSubject(log),
      getSource(log),
      formatConfidence(getConfidence(log)),
      getActions(log).join("; "),
      log?.threat_id || log?.details?.threat_id || "",
      log?.session_id || "",
    ]);

    const csv = [header, ...rows]
      .map((row) => row.map(escapeCsvValue).join(","))
      .join("\n");

    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `acds-activity-logs-${new Date()
      .toISOString()
      .slice(0, 10)}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-5 pb-6">
      <div className="rounded-xl border border-slate-800/80 bg-slate-900/70 p-5 shadow-[0_18px_45px_rgba(2,6,23,0.18)]">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300/80">
              Audit Workspace
            </p>
            <h1 className="mt-1 text-2xl font-semibold tracking-tight text-slate-100">
              System Activity Logs
            </h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
              Review detection, response, report, and module test-run activity
              from the persisted operational event stream.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => loadLogs({ silent: true })}
              disabled={refreshing}
              className="inline-flex h-10 items-center gap-2 rounded-lg border border-slate-700 bg-slate-950/50 px-3 text-sm font-semibold text-slate-300 transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <RefreshCw
                className={`h-4 w-4 ${refreshing ? "animate-spin" : ""}`}
              />
              Refresh
            </button>
            <button
              type="button"
              onClick={exportFilteredLogs}
              disabled={filteredLogs.length === 0}
              className="inline-flex h-10 items-center gap-2 rounded-lg border border-cyan-500/30 bg-cyan-500/15 px-3 text-sm font-semibold text-cyan-100 transition hover:bg-cyan-500/25 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <Download className="h-4 w-4" />
              Export CSV
            </button>
          </div>
        </div>
      </div>

      <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-xl border border-slate-800/80 bg-slate-900/70 p-4">
          <div className="flex items-center justify-between">
            <p className="text-xs uppercase tracking-wide text-slate-500">
              Total Events
            </p>
            <TerminalSquare className="h-4 w-4 text-cyan-300" />
          </div>
          <p className="mt-3 text-2xl font-semibold text-slate-100">
            {stats.total}
          </p>
        </div>
        <div className="rounded-xl border border-slate-800/80 bg-slate-900/70 p-4">
          <div className="flex items-center justify-between">
            <p className="text-xs uppercase tracking-wide text-slate-500">
              Threat Events
            </p>
            <ShieldAlert className="h-4 w-4 text-red-300" />
          </div>
          <p className="mt-3 text-2xl font-semibold text-red-200">
            {stats.threats}
          </p>
        </div>
        <div className="rounded-xl border border-slate-800/80 bg-slate-900/70 p-4">
          <div className="flex items-center justify-between">
            <p className="text-xs uppercase tracking-wide text-slate-500">
              Resolved
            </p>
            <CheckCircle2 className="h-4 w-4 text-emerald-300" />
          </div>
          <p className="mt-3 text-2xl font-semibold text-emerald-200">
            {stats.resolved}
          </p>
        </div>
        <div className="rounded-xl border border-slate-800/80 bg-slate-900/70 p-4">
          <div className="flex items-center justify-between">
            <p className="text-xs uppercase tracking-wide text-slate-500">
              Errors
            </p>
            <AlertTriangle className="h-4 w-4 text-amber-300" />
          </div>
          <p className="mt-3 text-2xl font-semibold text-amber-200">
            {stats.errors}
          </p>
        </div>
      </section>

      <section className="rounded-xl border border-slate-800/80 bg-slate-900/70 p-4">
        <div className="flex flex-col gap-3 xl:flex-row xl:items-center">
          <div className="relative min-w-0 flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
            <input
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search subject, source, threat id, session, or action"
              className="h-10 w-full rounded-lg border border-slate-700 bg-slate-950/60 pl-9 pr-3 text-sm text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-cyan-500/60 focus:ring-2 focus:ring-cyan-500/20"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Filter className="h-4 w-4 text-slate-500" />
            <select
              value={eventFilter}
              onChange={(event) => setEventFilter(event.target.value)}
              className="h-10 rounded-lg border border-slate-700 bg-slate-950/60 px-3 text-sm text-slate-100 outline-none focus:border-cyan-500/60"
            >
              {EVENT_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
            <select
              value={moduleFilter}
              onChange={(event) => setModuleFilter(event.target.value)}
              className="h-10 rounded-lg border border-slate-700 bg-slate-950/60 px-3 text-sm text-slate-100 outline-none focus:border-cyan-500/60"
            >
              {MODULE_OPTIONS.map((module) => (
                <option key={module} value={module}>
                  {module === "all" ? "All Modules" : formatEvent(module)}
                </option>
              ))}
            </select>
            <select
              value={severityFilter}
              onChange={(event) => setSeverityFilter(event.target.value)}
              className="h-10 rounded-lg border border-slate-700 bg-slate-950/60 px-3 text-sm text-slate-100 outline-none focus:border-cyan-500/60"
            >
              {SEVERITY_OPTIONS.map((severity) => (
                <option key={severity} value={severity}>
                  {severity === "all" ? "All Severity" : formatEvent(severity)}
                </option>
              ))}
            </select>
          </div>
        </div>
      </section>

      <section className="overflow-hidden rounded-xl border border-slate-800/80 bg-slate-900/70">
        <div className="border-b border-slate-800/80 px-4 py-3">
          <div className="flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
                Event Stream
              </p>
              <h2 className="text-base font-semibold text-slate-100">
                Persisted Activity
              </h2>
            </div>
            <span className="text-xs text-slate-500">
              Showing {filteredLogs.length} of {logs.length}
            </span>
          </div>
        </div>

        {error && (
          <div className="border-b border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-200">
            {error}
          </div>
        )}

        {loading ? (
          <div className="space-y-3 p-4">
            {[1, 2, 3, 4, 5].map((item) => (
              <div
                key={item}
                className="h-14 animate-pulse rounded-lg bg-slate-800/70"
              />
            ))}
          </div>
        ) : filteredLogs.length === 0 ? (
          <div className="px-6 py-14 text-center">
            <TerminalSquare className="mx-auto h-10 w-10 text-slate-600" />
            <p className="mt-3 text-sm font-medium text-slate-300">
              No matching activity logs
            </p>
            <p className="mt-1 text-xs text-slate-500">
              Module test runs and detection workflows will appear after they
              persist activity events.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[1080px] text-left text-sm">
              <thead className="bg-slate-950/50 text-xs uppercase text-slate-500">
                <tr>
                  <th className="px-4 py-3">Timestamp</th>
                  <th className="px-4 py-3">Module</th>
                  <th className="px-4 py-3">Event</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Subject</th>
                  <th className="px-4 py-3">Source</th>
                  <th className="px-4 py-3">Confidence</th>
                  <th className="px-4 py-3">Actions</th>
                  <th className="px-4 py-3">Reference</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {filteredLogs.map((log, index) => {
                  const event = log?.event || log?.action_type || "unknown";
                  const severity = getSeverity(log);
                  const actions = getActions(log);
                  const reference =
                    log?.threat_id || log?.details?.threat_id || log?.session_id;

                  return (
                    <tr
                      key={getLogId(log, index)}
                      className="transition-colors hover:bg-slate-800/40"
                    >
                      <td className="px-4 py-3 font-mono text-xs text-slate-400">
                        {formatTimestamp(log?.timestamp || log?.created_at)}
                      </td>
                      <td className="px-4 py-3">
                        <span className="rounded-md border border-slate-700 bg-slate-950/50 px-2 py-1 text-xs font-semibold uppercase text-slate-300">
                          {log?.module || log?.details?.module || "system"}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`rounded-md border px-2 py-1 text-xs font-semibold uppercase ${eventTone(
                            event
                          )}`}
                        >
                          {formatEvent(event)}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`rounded-md border px-2 py-1 text-xs font-semibold uppercase ${severityTone(
                            severity
                          )}`}
                        >
                          {severity}
                        </span>
                      </td>
                      <td className="max-w-[260px] px-4 py-3 text-slate-300">
                        <span className="block truncate">{getSubject(log)}</span>
                      </td>
                      <td className="max-w-[220px] px-4 py-3 text-slate-400">
                        <span className="block truncate">{getSource(log)}</span>
                      </td>
                      <td className="px-4 py-3 text-slate-300">
                        {formatConfidence(getConfidence(log))}
                      </td>
                      <td className="max-w-[260px] px-4 py-3 text-slate-300">
                        {actions.length > 0 ? (
                          <div className="flex flex-wrap gap-1">
                            {actions.slice(0, 3).map((action) => (
                              <span
                                key={action}
                                className="rounded-md border border-emerald-500/25 bg-emerald-500/10 px-2 py-1 text-xs text-emerald-200"
                              >
                                {String(action).replace(/_/g, " ")}
                              </span>
                            ))}
                            {actions.length > 3 && (
                              <span className="rounded-md border border-slate-700 bg-slate-950/40 px-2 py-1 text-xs text-slate-400">
                                +{actions.length - 3}
                              </span>
                            )}
                          </div>
                        ) : (
                          <span className="text-slate-500">None</span>
                        )}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-slate-500">
                        {reference || getLogId(log, index)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
};

export default Logs;
