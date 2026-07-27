import React, { useCallback, useEffect, useState } from "react";
import EmailList from "../components/Phishing/EmailList";
import IncidentDetails from "../components/Dashboard/IncidentDetails";
import {
  fetchIncidentDetails,
  fetchPhishingScans,
  runPhishingTestRun,
} from "../utils/api";
import {
  ArrowPathIcon,
  PlayIcon,
  ShieldCheckIcon,
} from "@heroicons/react/24/outline";

const getEmailId = (email) => email?.id || email?.scan_id || email?.threat_id;

const getPrediction = (email) =>
  email?.prediction || (email?.is_phishing ? "Phishing" : "Safe");

const normalizeTestRunEmail = (item) => ({
  id: item.scan_id || item.sample_id,
  scan_id: item.scan_id,
  threat_id: item.threat_id,
  incident_id: item.incident_id,
  report_id: item.report_id,
  sender: item.sender,
  subject: item.subject,
  prediction: item.is_phishing ? "Phishing" : "Safe",
  confidence: item.confidence,
  severity: item.severity || "LOW",
  evidence: item.evidence || [],
  explanation: item.explanation,
  scanned_at: item.timestamp,
  data_source: "phishing_test_dataset",
});

const mergeEmails = (incoming, existing) => {
  const byId = new Map();

  [...incoming, ...existing].forEach((email, index) => {
    const id = getEmailId(email) || `${email?.sender || "email"}-${index}`;
    byId.set(id, email);
  });

  return Array.from(byId.values()).sort((a, b) => {
    const bTime = new Date(b?.scanned_at || b?.detected_at || 0).getTime();
    const aTime = new Date(a?.scanned_at || a?.detected_at || 0).getTime();
    return (Number.isFinite(bTime) ? bTime : 0) - (Number.isFinite(aTime) ? aTime : 0);
  });
};

const buildFallbackIncident = (email) => ({
  id: getEmailId(email),
  sender: email?.sender,
  source: email?.sender || email?.source,
  subject: email?.subject,
  prediction: getPrediction(email),
  confidence: email?.confidence,
  severity: email?.severity,
  report_id: email?.report_id,
  incident_id: email?.incident_id,
  threat_id: email?.threat_id,
  detected_at: email?.scanned_at || email?.detected_at,
  evidence: email?.evidence || [],
  explanation:
    email?.explanation ||
    (Array.isArray(email?.evidence) && email.evidence.length > 0
      ? email.evidence.join(" ")
      : getPrediction(email) === "Safe"
      ? "No phishing indicators were detected."
      : "Threat details are not available for this scan."),
});

const PhishingModule = () => {
  const [sampleCount, setSampleCount] = useState(5);
  const [running, setRunning] = useState(false);
  const [loadingEmails, setLoadingEmails] = useState(true);
  const [refreshingEmails, setRefreshingEmails] = useState(false);
  const [runResult, setRunResult] = useState(null);
  const [emails, setEmails] = useState([]);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [selectedEmailId, setSelectedEmailId] = useState(null);
  const [dataSource, setDataSource] = useState("");
  const [runError, setRunError] = useState("");
  const [loadError, setLoadError] = useState("");

  const loadEmails = useCallback(async ({ silent = false } = {}) => {
    if (silent) {
      setRefreshingEmails(true);
    } else {
      setLoadingEmails(true);
    }
    setLoadError("");

    try {
      const data = await fetchPhishingScans({ limit: 100 });
      setEmails(Array.isArray(data.emails) ? data.emails : []);
      setDataSource(data.dataSource || "unknown");
    } catch (error) {
      setLoadError(error?.detail || error?.message || "Unable to load phishing scans");
    } finally {
      setLoadingEmails(false);
      setRefreshingEmails(false);
    }
  }, []);

  useEffect(() => {
    loadEmails();
  }, [loadEmails]);

  const handleEmailSelect = useCallback(async (email) => {
    const emailId = getEmailId(email);
    setSelectedEmailId(emailId);

    if (!email?.threat_id) {
      setSelectedIncident(buildFallbackIncident(email));
      return;
    }

    try {
      const details = await fetchIncidentDetails(email.threat_id, {
        fallbackToMock: false,
      });
      setSelectedIncident(details);
    } catch (error) {
      setSelectedIncident(buildFallbackIncident(email));
    }
  }, []);

  const handleTestRun = async () => {
    setRunning(true);
    setRunError("");

    try {
      const result = await runPhishingTestRun({
        count: sampleCount,
        includeLegitimate: true,
      });
      const runEmails = (result.results || []).map(normalizeTestRunEmail);
      setRunResult(result);

      if (runEmails.length > 0) {
        setEmails((currentEmails) => mergeEmails(runEmails, currentEmails));
        const firstThreat = runEmails.find(
          (email) => getPrediction(email) === "Phishing"
        );
        await handleEmailSelect(firstThreat || runEmails[0]);
      }

      await loadEmails({ silent: true });
    } catch (error) {
      setRunError(error?.detail || error?.message || "Phishing test run failed");
    } finally {
      setRunning(false);
    }
  };

  const summary = runResult?.summary;

  return (
    <div className="space-y-5 min-h-[calc(100vh-100px)] pb-6">
      <div className="rounded-xl border border-slate-800/80 bg-slate-900/70 p-5 shadow-[0_18px_45px_rgba(2,6,23,0.18)]">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300/80">
              Detection Module
            </p>
            <h1 className="mt-1 text-2xl font-semibold tracking-tight text-slate-100">
              Email Phishing Detection
            </h1>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
              Monitor scanned emails, review model confidence, and triage
              phishing evidence with analyst feedback.
            </p>
          </div>
          <div className="flex flex-col gap-3 sm:items-end">
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded-full border border-emerald-500/25 bg-emerald-500/10 px-3 py-1 text-xs font-semibold text-emerald-200">
                System Active
              </span>
              <span className="rounded-full border border-cyan-500/25 bg-cyan-500/10 px-3 py-1 text-xs font-semibold text-cyan-200">
                {emails.length} scans loaded
              </span>
              {dataSource && (
                <span className="rounded-full border border-slate-700 bg-slate-950/40 px-3 py-1 text-xs text-slate-400">
                  Source: {dataSource}
                </span>
              )}
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => loadEmails({ silent: true })}
                disabled={running || refreshingEmails}
                className="inline-flex h-10 items-center gap-2 rounded-lg border border-slate-700 bg-slate-950/60 px-3 text-sm font-semibold text-slate-300 transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-60"
              >
                <ArrowPathIcon
                  className={`h-4 w-4 ${refreshingEmails ? "animate-spin" : ""}`}
                />
                Refresh
              </button>
              <select
                value={sampleCount}
                onChange={(event) => setSampleCount(Number(event.target.value))}
                disabled={running}
                className="h-10 rounded-lg border border-slate-700 bg-slate-950/70 px-3 text-sm text-slate-100 outline-none transition focus:border-cyan-500/60 focus:ring-2 focus:ring-cyan-500/20 disabled:cursor-not-allowed disabled:opacity-60"
              >
                <option value={3}>3 samples</option>
                <option value={5}>5 samples</option>
                <option value={10}>10 samples</option>
                <option value={15}>15 samples</option>
              </select>
              <button
                type="button"
                onClick={handleTestRun}
                disabled={running}
                className="inline-flex h-10 items-center gap-2 rounded-lg border border-cyan-500/30 bg-cyan-500/15 px-4 text-sm font-semibold text-cyan-100 transition hover:bg-cyan-500/25 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {running ? (
                  <ArrowPathIcon className="h-4 w-4 animate-spin" />
                ) : (
                  <PlayIcon className="h-4 w-4" />
                )}
                {running ? "Running..." : "Run Test"}
              </button>
            </div>
          </div>
        </div>

        {(summary || runError) && (
          <div
            className={`mt-4 rounded-lg border px-4 py-3 ${
              runError
                ? "border-red-500/30 bg-red-500/10"
                : "border-emerald-500/25 bg-emerald-500/10"
            }`}
          >
            {runError ? (
              <p className="text-sm text-red-200">{runError}</p>
            ) : (
              <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-sm">
                <span className="inline-flex items-center gap-2 font-semibold text-emerald-200">
                  <ShieldCheckIcon className="h-4 w-4" />
                  Test run completed
                </span>
                <span className="text-slate-300">
                  Scanned: {summary.total_scanned}
                </span>
                <span className="text-red-200">
                  Phishing: {summary.phishing_detected}
                </span>
                <span className="text-emerald-200">
                  Safe: {summary.safe_detected}
                </span>
                <span className="text-cyan-200">
                  Reports: {summary.persistence?.reports_generated || 0}
                </span>
              </div>
            )}
          </div>
        )}

        {loadError && (
          <div className="mt-4 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3">
            <p className="text-sm text-amber-100">{loadError}</p>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 items-start">
        <div className="lg:col-span-2 min-w-0">
          <EmailList
            emails={emails}
            loading={loadingEmails && emails.length === 0}
            selectedEmailId={selectedEmailId}
            onEmailSelect={handleEmailSelect}
          />
        </div>
        <div className="min-w-0 lg:sticky lg:top-24">
          <IncidentDetails
            incident={selectedIncident}
            emptyTitle="No email selected"
            emptyDescription="Select a phishing scan to review evidence, confidence, automated action, report references, and analyst feedback."
          />
        </div>
      </div>
    </div>
  );
};

export default PhishingModule;
