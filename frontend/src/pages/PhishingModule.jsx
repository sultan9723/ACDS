import React from "react";
import EmailList from "../components/Phishing/EmailList";
import IncidentDetails from "../components/Dashboard/IncidentDetails";
import { useDashboard } from "../context/DashboardContext";

const PhishingModule = () => {
  const { runBatch } = useDashboard() || {};

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
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => runBatch?.(2, "email_phishing")}
              className="rounded-lg border border-cyan-500/30 bg-cyan-500/15 px-4 py-2 text-sm font-semibold text-cyan-100 transition-colors hover:bg-cyan-500/25"
            >
              Run Phishing Scan
            </button>
            <span className="rounded-full border border-emerald-500/25 bg-emerald-500/10 px-3 py-1 text-xs font-semibold text-emerald-200">
              System Active
            </span>
            <span className="rounded-full border border-cyan-500/25 bg-cyan-500/10 px-3 py-1 text-xs font-semibold text-cyan-200">
              Real-time Monitoring
            </span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 items-start">
        <div className="lg:col-span-2 min-w-0">
          <EmailList />
        </div>
        <div className="min-w-0 lg:sticky lg:top-24">
          <IncidentDetails />
        </div>
      </div>
    </div>
  );
};

export default PhishingModule;
