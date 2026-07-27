import React from "react";
import { Card, CardHeader, CardTitle, CardContent } from "../ui/Card";
import { Badge } from "../ui/Badge";

const getEmailId = (email, index) =>
  email?.id || email?.scan_id || email?.threat_id || `email-${index}`;

const getPrediction = (email) =>
  email?.prediction || (email?.is_phishing ? "Phishing" : "Safe");

const formatConfidence = (value) => {
  if (value === null || value === undefined || value === "") return "N/A";
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return "N/A";
  return `${Math.round(numeric > 1 ? numeric : numeric * 100)}%`;
};

const confidencePercent = (value) => {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 0;
  return Math.min(Math.max(numeric > 1 ? numeric : numeric * 100, 0), 100);
};

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

const getSeverityColor = (severity) => {
  switch (String(severity || "").toUpperCase()) {
    case "HIGH":
    case "CRITICAL":
      return "bg-red-500/15 text-red-200 border-red-500/30";
    case "MEDIUM":
      return "bg-amber-500/15 text-amber-200 border-amber-500/30";
    case "LOW":
    case "SAFE":
      return "bg-emerald-500/15 text-emerald-200 border-emerald-500/30";
    default:
      return "bg-cyan-500/10 text-cyan-200 border-cyan-500/25";
  }
};

const EmailList = ({
  emails = [],
  loading = false,
  selectedEmailId = null,
  onEmailSelect = () => {},
}) => {
  const safeEmails = Array.isArray(emails) ? emails : [];

  return (
    <Card className="bg-slate-900/70 border-slate-800/80">
      <CardHeader className="flex flex-row items-center justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
            Results Queue
          </p>
          <CardTitle className="mt-1 text-slate-100">Scanned Emails</CardTitle>
        </div>
        <span className="rounded-full border border-slate-700 bg-slate-950/40 px-3 py-1 text-xs text-slate-400">
          {safeEmails.length} scanned
        </span>
      </CardHeader>
      <CardContent className="p-0">
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <div className="h-8 w-8 animate-spin rounded-full border-b-2 border-cyan-500" />
          </div>
        ) : safeEmails.length === 0 ? (
          <div className="px-6 py-12 text-center">
            <p className="text-sm font-medium text-slate-300">
              No emails scanned yet
            </p>
            <p className="mt-2 text-sm text-slate-500">
              Run a phishing test from this page to populate detections,
              response actions, reports, and analyst evidence.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[920px] text-left text-sm">
              <thead className="border-b border-slate-800 bg-slate-900/50 text-xs uppercase text-slate-400">
                <tr>
                  <th className="px-6 py-3">Scanned</th>
                  <th className="px-6 py-3">Sender</th>
                  <th className="px-6 py-3">Subject</th>
                  <th className="px-6 py-3">Severity</th>
                  <th className="px-6 py-3">Confidence</th>
                  <th className="px-6 py-3">Prediction</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {safeEmails.map((email, index) => {
                  const emailId = getEmailId(email, index);
                  const prediction = getPrediction(email);
                  const confidence = confidencePercent(email?.confidence);
                  const isSelected = selectedEmailId === emailId;

                  return (
                    <tr
                      key={emailId}
                      onClick={() => onEmailSelect(email)}
                      className={`cursor-pointer transition-colors ${
                        isSelected
                          ? "bg-cyan-500/10"
                          : "hover:bg-slate-800/40"
                      }`}
                    >
                      <td className="px-6 py-3 font-mono text-xs text-slate-400">
                        {formatTime(email?.scanned_at || email?.detected_at)}
                      </td>
                      <td className="max-w-[220px] break-all px-6 py-3 text-slate-300">
                        {email?.sender || email?.source || "Unknown"}
                      </td>
                      <td className="max-w-[280px] truncate px-6 py-3 text-slate-300">
                        {email?.subject || email?.description || "No subject"}
                      </td>
                      <td className="px-6 py-3">
                        <span
                          className={`rounded border px-2 py-1 text-xs ${getSeverityColor(
                            email?.severity
                          )}`}
                        >
                          {email?.severity || "N/A"}
                        </span>
                      </td>
                      <td className="px-6 py-3">
                        <div className="flex items-center gap-2">
                          <div className="h-1.5 w-full max-w-[72px] rounded-full bg-slate-800">
                            <div
                              className={`h-1.5 rounded-full ${
                                prediction === "Phishing"
                                  ? "bg-red-500"
                                  : "bg-emerald-500"
                              }`}
                              style={{ width: `${confidence}%` }}
                            />
                          </div>
                          <span className="rounded-full border border-slate-700 bg-slate-950/40 px-2 py-0.5 text-xs text-slate-300">
                            {formatConfidence(email?.confidence)}
                          </span>
                        </div>
                      </td>
                      <td className="px-6 py-3">
                        <Badge
                          variant={
                            prediction === "Phishing"
                              ? "destructive"
                              : "success"
                          }
                        >
                          {prediction}
                        </Badge>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default EmailList;
