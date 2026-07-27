import React, { useState } from "react";
import EmailList from "../components/Phishing/EmailList";
import IncidentDetails from "../components/Dashboard/IncidentDetails";
import { useDashboard } from "../context/DashboardContext";
import { runPhishingTestRun } from "../utils/api";
import {
  ArrowPathIcon,
  PlayIcon,
  ShieldCheckIcon,
} from "@heroicons/react/24/outline";

const PhishingModule = () => {
  const dashboardData = useDashboard() || {};
  const refreshData = dashboardData.refreshData || (async () => {});
  const [sampleCount, setSampleCount] = useState(5);
  const [running, setRunning] = useState(false);
  const [runResult, setRunResult] = useState(null);
  const [lastRunEmails, setLastRunEmails] = useState([]);
  const [runError, setRunError] = useState("");

  const handleTestRun = async () => {
    setRunning(true);
    setRunError("");

    try {
      const result = await runPhishingTestRun({
        count: sampleCount,
        includeLegitimate: true,
      });
      setRunResult(result);
      setLastRunEmails(
        (result.results || []).map((item) => ({
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
          data_source: "test_run",
        }))
      );
      await refreshData();
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
                Real-time Monitoring
              </span>
            </div>
            <div className="flex flex-wrap items-center gap-2">
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
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 items-start">
        <div className="lg:col-span-2 min-w-0">
          <EmailList emailsOverride={lastRunEmails} />
        </div>
        <div className="min-w-0 lg:sticky lg:top-24">
          <IncidentDetails />
        </div>
      </div>
    </div>
  );
};

export default PhishingModule;
