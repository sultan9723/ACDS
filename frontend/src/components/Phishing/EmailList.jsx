import React from "react";
import { Card, CardHeader, CardTitle, CardContent } from "../ui/Card";
import { Badge } from "../ui/Badge";
import { useDashboard } from "../../context/DashboardContext";
import { fetchIncidentDetails } from "../../utils/api";

const EmailList = ({ emailsOverride = [] }) => {
  const dashboardData = useDashboard() || {};
  const contextEmails = dashboardData.allEmails || [];
  const allEmails = emailsOverride.length > 0 ? emailsOverride : contextEmails;
  const setSelectedIncident = dashboardData.setSelectedIncident || (() => {});
  const loading = dashboardData.loading;

  const handleRowClick = async (email) => {
    const detailId = email?.threat_id;
    if (!detailId) {
      setSelectedIncident({
        id: email.id,
        sender: email.sender,
        subject: email.subject,
        prediction: email.prediction,
        confidence: email.confidence,
        severity: email.severity,
        explanation:
          email.explanation ||
          (Array.isArray(email.evidence) && email.evidence.length > 0
            ? email.evidence.join(" ")
            : email.prediction === "Safe"
            ? "No phishing indicators were detected."
            : "Threat details are not available for this scan."),
      });
      return;
    }

    try {
      const details = await fetchIncidentDetails(detailId);
      setSelectedIncident(details);
    } catch (error) {
      setSelectedIncident({
        id: email.id,
        sender: email.sender,
        subject: email.subject,
        prediction: email.prediction,
        confidence: email.confidence,
        severity: email.severity,
        explanation:
          email.explanation ||
          (Array.isArray(email.evidence) && email.evidence.length > 0
            ? email.evidence.join(" ")
            : email.prediction === "Safe"
            ? "No phishing indicators were detected."
            : "Threat details are not available for this scan."),
      });
    }
  };

  // Helper to format confidence value
  const formatConfidence = (value) => {
    if (!value && value !== 0) return "N/A";
    // Already in percentage format
    if (value > 1) return `${Math.round(value)}%`;
    // Convert from decimal
    return `${Math.round(value * 100)}%`;
  };

  // Get severity badge color
  const getSeverityColor = (severity) => {
    switch (severity?.toUpperCase()) {
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
          {allEmails.length} scanned
        </span>
      </CardHeader>
      <CardContent className="p-0">
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-500"></div>
          </div>
        ) : allEmails.length === 0 ? (
          <div className="px-6 py-12 text-center">
            <p className="text-sm font-medium text-slate-300">
              No emails scanned yet
            </p>
            <p className="mt-2 text-sm text-slate-500">
              Run a test from this page to populate phishing detections,
              response actions, reports, and analyst evidence.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left">
              <thead className="text-xs text-slate-400 uppercase bg-slate-900/50 border-b border-slate-800">
                <tr>
                  <th className="px-6 py-3">Sender</th>
                  <th className="px-6 py-3">Subject</th>
                  <th className="px-6 py-3">Severity</th>
                  <th className="px-6 py-3">Confidence</th>
                  <th className="px-6 py-3">Prediction</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {allEmails.map((email) => (
                  <tr
                    key={email.id}
                    onClick={() => handleRowClick(email)}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                  >
                    <td className="px-6 py-3 text-slate-300 break-all max-w-[220px]">
                      {email.sender || email.source || "Unknown"}
                    </td>
                    <td className="px-6 py-3 text-slate-300 max-w-[260px] truncate">
                      {email.subject || email.description || "No subject"}
                    </td>
                    <td className="px-6 py-3">
                      <span className={`text-xs px-2 py-1 rounded border ${getSeverityColor(email.severity)}`}>
                        {email.severity || "N/A"}
                      </span>
                    </td>
                    <td className="px-6 py-3">
                      <div className="flex items-center gap-2">
                        <div className="w-full bg-slate-800 rounded-full h-1.5 max-w-[72px]">
                          <div
                            className={`h-1.5 rounded-full ${
                              email.prediction === "Phishing"
                                ? "bg-red-500"
                                : "bg-emerald-500"
                            }`}
                            style={{ width: `${Math.min(email.confidence > 1 ? email.confidence : email.confidence * 100, 100)}%` }}
                          ></div>
                        </div>
                        <span className="rounded-full border border-slate-700 bg-slate-950/40 px-2 py-0.5 text-xs text-slate-300">
                          {formatConfidence(email.confidence)}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-3">
                      <Badge
                        variant={
                          email.prediction === "Phishing"
                            ? "destructive"
                            : "success"
                        }
                      >
                        {email.prediction || (email.is_phishing ? "Phishing" : "Safe")}
                      </Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default EmailList;
