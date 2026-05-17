import React, { useState, useEffect } from "react";
import { useDashboard } from "../context/DashboardContext";
import api from "../utils/api";
import {
  FileText,
  Download,
  RefreshCw,
  Calendar,
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  FileJson,
  FileType,
  Sparkles,
  TrendingUp,
  Target,
  Activity,
  File,
  Eye,
  Trash2,
} from "lucide-react";

const Reports = () => {
  const dashboardData = useDashboard() || {};
  const { refreshData } = dashboardData;
  const threats = dashboardData.threats || [];
  const stats = dashboardData.stats || {};
  const logs = dashboardData.logs || [];
  const [isGenerating, setIsGenerating] = useState(false);
  const [reportError, setReportError] = useState(null);
  const [reportSuccess, setReportSuccess] = useState(null);
  const [selectedReportType, setSelectedReportType] =
    useState("threat-summary");
  const [dateRange, setDateRange] = useState("7days");
  const [generatedReport, setGeneratedReport] = useState(null);
  
  // PDF Incident Reports State
  const [incidentReports, setIncidentReports] = useState([]);
  const [loadingReports, setLoadingReports] = useState(false);
  const [activeTab, setActiveTab] = useState("ai-report"); // "ai-report" or "incident-reports"

  // Refresh data on mount to get latest threats
  useEffect(() => {
    if (refreshData) {
      refreshData();
    }
    // Also fetch incident reports
    fetchIncidentReports();
  }, []);

  // Fetch PDF incident reports from backend
  const fetchIncidentReports = async () => {
    setLoadingReports(true);
    try {
      const response = await api.get("/reports/incidents", { params: { limit: 50 } });
      const data = response.data;
      if (data.success) {
        setIncidentReports(data.reports || []);
      }
    } catch (error) {
      console.error("Error fetching incident reports:", error);
    } finally {
      setLoadingReports(false);
    }
  };

  // Download PDF incident report
  const downloadPDFReport = async (reportId, filename) => {
    try {
      const response = await api.get(`/reports/incidents/${reportId}/download`, {
        responseType: "blob",
      });
      const blob = response.data;
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename || `incident_report_${reportId}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error("Error downloading report:", error);
    }
  };

  const downloadGeneratedReport = async (downloadUrl, filename) => {
    if (!downloadUrl) return;
    try {
      const apiPath = downloadUrl.replace(/^\/api\/v1/, "");
      const response = await api.get(apiPath, { responseType: "blob" });
      const blob = response.data;
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename || "acds_report.pdf";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error("Error downloading generated report:", error);
      setReportError("Report was generated, but the PDF download failed.");
    }
  };

  // Delete incident report
  const deleteReport = async (reportId) => {
    if (!window.confirm("Are you sure you want to delete this report?")) return;
    
    try {
      await api.delete(`/reports/incidents/${reportId}`);
      setIncidentReports(prev => prev.filter(r => r.report_id !== reportId));
    } catch (error) {
      console.error("Error deleting report:", error);
    }
  };

  // Format date for display
  const formatDate = (dateString) => {
    if (!dateString) return "Unknown";
    const date = new Date(dateString);
    return date.toLocaleString();
  };

  // Get severity color
  const getSeverityColor = (severity) => {
    switch (severity?.toUpperCase()) {
      case "CRITICAL": return "text-red-200 bg-red-500/15 border border-red-500/30";
      case "HIGH": return "text-rose-200 bg-rose-500/15 border border-rose-500/30";
      case "MEDIUM": return "text-amber-200 bg-amber-500/15 border border-amber-500/30";
      case "LOW": return "text-emerald-200 bg-emerald-500/15 border border-emerald-500/30";
      default: return "text-cyan-200 bg-cyan-500/10 border border-cyan-500/25";
    }
  };

  const reportTypes = [
    {
      id: "threat-summary",
      name: "Threat Summary Report",
      description: "Overview of all detected threats with AI analysis",
      icon: Shield,
    },
    {
      id: "detection-analysis",
      name: "Detection Analysis",
      description: "Detailed analysis of phishing detection performance",
      icon: Target,
    },
    {
      id: "incident-log",
      name: "Incident Log Report",
      description: "Complete log of all security incidents",
      icon: FileText,
    },
    {
      id: "performance-metrics",
      name: "Model Performance Report",
      description: "ML model accuracy, precision, recall metrics",
      icon: TrendingUp,
    },
  ];

  const generateAIReport = async () => {
    setIsGenerating(true);
    setReportError(null);
    setReportSuccess(null);

    try {
      if (refreshData) {
        await refreshData();
      }

      const response = await api.post("/reports/generate", {
        report_type: selectedReportType,
        date_range: dateRange,
        include_details: true,
        format: "pdf",
      });

      const report = response.data.report || response.data;
      const summary = report.summary || {};
      const moduleBreakdown = summary.module_breakdown || {};
      const severityBreakdown = summary.severity_breakdown || {};

      setGeneratedReport({
        ...report,
        generatedAt: report.generated_at,
        reportType: report.report_type,
        dateRange: report.date_range,
        summary: {
          totalThreats: summary.total_incidents || 0,
          phishingDetected: moduleBreakdown.phishing || 0,
          ransomwareDetected: moduleBreakdown.ransomware || 0,
          malwareDetected: moduleBreakdown.malware || 0,
          autoResolved: summary.state_breakdown?.closed || 0,
          pendingReview: summary.state_breakdown?.analysis_failed || 0,
          modelAccuracy: stats?.accuracy || 97.2,
          auditEvents: summary.total_audit_events || 0,
        },
        aiAnalysis: summary.executive_summary || "Report generated from current ACDS incidents and audit logs.",
        recommendations: (summary.recommended_actions || []).map((action) => ({
          priority: "Medium",
          title: action,
          description: "Review and validate this recommended SOC action.",
        })),
        threatBreakdown: Object.entries(moduleBreakdown).map(([type, count]) => ({
          type,
          count,
          percentage: summary.total_incidents
            ? ((count / summary.total_incidents) * 100).toFixed(1)
            : "0.0",
        })),
        severityBreakdown,
      });
      setReportSuccess("AI report generated successfully.");
      await fetchIncidentReports();
    } catch (error) {
      console.error("Error generating AI report:", error);
      setReportError(error.response?.data?.detail || error.message || "Failed to generate report.");
    } finally {
      setIsGenerating(false);
    }
  };

  const generateAIAnalysis = (threats, stats) => {
    const phishingCount = threats.filter((t) => t.type === "Phishing").length;
    const highConfidence = threats.filter(
      (t) => parseFloat(t.confidence) > 90
    ).length;

    return `
## AI-Powered Threat Analysis

### Overview
During the selected period, the Autonomous Cyber Defense System detected and analyzed **${
      threats.length
    } potential threats**, with **${phishingCount} confirmed phishing attempts**. The ML model maintained a high accuracy rate of **${
      stats?.modelAccuracy || 97.2
    }%**.

### Key Findings
1. **High-Confidence Detections**: ${highConfidence} threats were identified with >90% confidence, indicating strong pattern matching with known phishing indicators.

2. **Attack Vectors**: The majority of detected phishing attempts utilized urgency-based social engineering tactics, including fake account suspension notices and prize claims.

3. **Response Effectiveness**: ${Math.round(
      (threats.filter((t) => t.status === "Resolved").length / threats.length) *
        100
    )}% of threats were automatically resolved by the system, demonstrating effective autonomous response capabilities.

### Model Performance
- **True Positive Rate**: High detection rate for known phishing patterns
- **False Positive Rate**: Minimal false alerts, reducing analyst fatigue
- **Detection Speed**: Average detection time under 500ms

### Trend Analysis
The system has observed consistent threat patterns, with email-based phishing remaining the primary attack vector. URL analysis and content inspection continue to be the most effective detection methods.
    `.trim();
  };

  const generateRecommendations = (threats) => {
    return [
      {
        priority: "High",
        title: "Enhance Email Filtering Rules",
        description:
          "Based on detected patterns, update email gateway rules to block emails containing suspicious URL patterns.",
      },
      {
        priority: "Medium",
        title: "User Awareness Training",
        description:
          "Schedule phishing awareness training for departments with highest interaction with detected threats.",
      },
      {
        priority: "Medium",
        title: "Update Threat Intelligence",
        description:
          "Integrate latest threat intelligence feeds to improve detection of emerging phishing techniques.",
      },
      {
        priority: "Low",
        title: "Review False Positive Cases",
        description:
          "Analyze flagged legitimate emails to fine-tune model sensitivity.",
      },
    ];
  };

  const generateThreatBreakdown = (threats) => {
    const breakdown = {};
    threats.forEach((threat) => {
      breakdown[threat.type] = (breakdown[threat.type] || 0) + 1;
    });
    return Object.entries(breakdown).map(([type, count]) => ({
      type,
      count,
      percentage: ((count / threats.length) * 100).toFixed(1),
    }));
  };

  const generateTimeline = (threats) => {
    return threats.slice(0, 10).map((threat) => ({
      time: threat.time,
      type: threat.type,
      source: threat.sourceIP,
      status: threat.status,
      confidence: threat.confidence,
    }));
  };

  const exportReport = (format) => {
    if (!generatedReport) return;

    if (format === "json") {
      const blob = new Blob([JSON.stringify(generatedReport, null, 2)], {
        type: "application/json",
      });
      downloadFile(blob, `threat-report-${Date.now()}.json`);
    } else if (format === "txt") {
      const textContent = `
AUTONOMOUS CYBER DEFENSE SYSTEM - THREAT REPORT
Generated: ${new Date(generatedReport.generatedAt).toLocaleString()}
Report Type: ${generatedReport.reportType}
Date Range: ${generatedReport.dateRange}

=== SUMMARY ===
Total Threats: ${generatedReport.summary.totalThreats}
Phishing Detected: ${generatedReport.summary.phishingDetected}
Auto-Resolved: ${generatedReport.summary.autoResolved}
Pending Review: ${generatedReport.summary.pendingReview}
Model Accuracy: ${generatedReport.summary.modelAccuracy}%

=== AI ANALYSIS ===
${generatedReport.aiAnalysis}

=== RECOMMENDATIONS ===
${generatedReport.recommendations
  .map((r, i) => `${i + 1}. [${r.priority}] ${r.title}\n   ${r.description}`)
  .join("\n\n")}

=== THREAT BREAKDOWN ===
${generatedReport.threatBreakdown
  .map((t) => `- ${t.type}: ${t.count} (${t.percentage}%)`)
  .join("\n")}
      `.trim();

      const blob = new Blob([textContent], { type: "text/plain" });
      downloadFile(blob, `threat-report-${Date.now()}.txt`);
    }
  };

  const downloadFile = (blob, filename) => {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-5 pb-6">
      {/* Header */}
      <div className="rounded-xl border border-slate-800/80 bg-slate-900/70 p-5 shadow-[0_18px_45px_rgba(2,6,23,0.18)]">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300/80">
              AI Security Analyst Workspace
            </p>
            <h1 className="mt-1 flex items-center gap-2 text-2xl font-semibold tracking-tight text-slate-100">
              <Sparkles className="h-6 w-6 text-cyan-300" />
              AI Reports
            </h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
              Generate executive summaries, technical incident reports,
              response summaries, and threat intelligence summaries from current
              ACDS telemetry.
            </p>
          </div>
          <button
            onClick={fetchIncidentReports}
            className="inline-flex items-center justify-center gap-2 rounded-lg border border-slate-700/80 bg-slate-950/40 px-4 py-2 text-sm font-semibold text-slate-300 transition-colors hover:border-cyan-500/50 hover:text-cyan-200"
          >
            <RefreshCw className={`h-4 w-4 ${loadingReports ? 'animate-spin' : ''}`} />
            Refresh Reports
          </button>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex flex-wrap gap-2 border-b border-slate-800/80 pb-3">
        <button
          onClick={() => setActiveTab("ai-report")}
          className={`rounded-lg border px-4 py-2 text-sm font-medium transition-colors ${
            activeTab === "ai-report"
              ? "border-cyan-500/40 bg-cyan-500/10 text-cyan-200"
              : "border-transparent text-slate-400 hover:border-slate-700 hover:bg-slate-900/70 hover:text-slate-100"
          }`}
        >
          <Sparkles className="w-4 h-4 inline mr-2" />
          Generate AI Report
        </button>
        <button
          onClick={() => setActiveTab("incident-reports")}
          className={`rounded-lg border px-4 py-2 text-sm font-medium transition-colors flex items-center gap-2 ${
            activeTab === "incident-reports"
              ? "border-cyan-500/40 bg-cyan-500/10 text-cyan-200"
              : "border-transparent text-slate-400 hover:border-slate-700 hover:bg-slate-900/70 hover:text-slate-100"
          }`}
        >
          <File className="w-4 h-4" />
          PDF Incident Reports
          {incidentReports.length > 0 && (
            <span className="rounded-full bg-cyan-500/20 px-2 py-0.5 text-xs text-cyan-100">
              {incidentReports.length}
            </span>
          )}
        </button>
      </div>

      {/* AI Report Generation Tab */}
      {activeTab === "ai-report" && (
        <>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Report Type Selection */}
        <div className="lg:col-span-2 rounded-xl border border-slate-800/80 bg-slate-900/70 p-5 sm:p-6">
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
            Report Studio
          </p>
          <h2 className="mt-1 text-lg font-semibold text-slate-100 mb-4">
            Select Report Type
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {reportTypes.map((report) => (
              <button
                key={report.id}
                onClick={() => setSelectedReportType(report.id)}
                className={`p-4 rounded-lg border text-left transition-all ${
                  selectedReportType === report.id
                    ? "border-cyan-500/50 bg-cyan-500/10"
                    : "border-slate-800 bg-slate-950/40 hover:border-slate-700"
                }`}
              >
                <div className="flex items-start gap-3">
                  <report.icon
                    className={`w-5 h-5 mt-0.5 ${
                      selectedReportType === report.id
                        ? "text-cyan-300"
                        : "text-slate-400"
                    }`}
                  />
                  <div>
                    <h3 className="font-medium text-slate-100">{report.name}</h3>
                    <p className="text-sm text-slate-400 mt-1">
                      {report.description}
                    </p>
                  </div>
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Configuration Panel */}
        <div className="rounded-xl border border-slate-800/80 bg-slate-900/70 p-5 sm:p-6">
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
            Generation Controls
          </p>
          <h2 className="mt-1 text-lg font-semibold text-slate-100 mb-4">
            Configuration
          </h2>

          {/* Date Range */}
          <div className="mb-6">
            <label className="block text-sm text-slate-400 mb-2">
              <Calendar className="w-4 h-4 inline mr-2" />
              Date Range
            </label>
            <select
              value={dateRange}
              onChange={(e) => setDateRange(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950/60 px-4 py-2 text-slate-100 focus:outline-none focus:border-cyan-500/80"
            >
              <option value="24hours">Last 24 Hours</option>
              <option value="7days">Last 7 Days</option>
              <option value="30days">Last 30 Days</option>
              <option value="90days">Last 90 Days</option>
            </select>
          </div>

          {/* Generate Button */}
          <button
            onClick={generateAIReport}
            disabled={isGenerating}
            className="w-full rounded-lg border border-cyan-500/30 bg-cyan-500/15 px-4 py-3 font-semibold text-cyan-100 transition-all hover:bg-cyan-500/25 disabled:cursor-not-allowed disabled:opacity-50 flex items-center justify-center gap-2"
          >
            {isGenerating ? (
              <>
                <RefreshCw className="w-5 h-5 animate-spin" />
                Generating Report...
              </>
            ) : (
              <>
                <Sparkles className="w-5 h-5" />
                Generate AI Report
              </>
            )}
          </button>

          {reportSuccess && (
            <div className="mt-4 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200">
              {reportSuccess}
            </div>
          )}

          {reportError && (
            <div className="mt-4 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
              {reportError}
            </div>
          )}

          {/* Export Options */}
          {generatedReport && (
            <div className="mt-4 space-y-2">
              <p className="text-sm text-slate-400">Report Output</p>
              <div className="flex gap-2">
                <button
                  onClick={() => downloadGeneratedReport(generatedReport.download_url, generatedReport.file_name)}
                  className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-cyan-500/15 border border-cyan-500/30 rounded-lg text-cyan-100 hover:bg-cyan-500/25 transition-colors"
                >
                  <Download className="w-4 h-4" />
                  PDF
                </button>
                <button
                  onClick={() => exportReport("json")}
                  className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-slate-950/40 border border-slate-700 rounded-lg text-slate-300 hover:border-cyan-500/50 hover:text-cyan-200 transition-colors"
                >
                  <FileJson className="w-4 h-4" />
                  JSON
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Generated Report Display */}
      {generatedReport && (
        <div className="rounded-xl border border-slate-800/80 bg-slate-900/70 p-5 sm:p-6">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between mb-6">
            <div>
              <h2 className="text-lg font-semibold text-white flex items-center gap-2">
                <FileText className="w-5 h-5 text-cyan-300" />
                Generated Report Preview
              </h2>
              <div className="mt-2 flex flex-wrap gap-2 text-xs text-slate-400">
                <span className="rounded-full border border-slate-700 bg-slate-950/40 px-2.5 py-1">
                  ID: {generatedReport.report_id}
                </span>
                <span className="rounded-full border border-slate-700 bg-slate-950/40 px-2.5 py-1">
                  Status: {generatedReport.status || "generated"}
                </span>
                <span className="rounded-full border border-slate-700 bg-slate-950/40 px-2.5 py-1">
                  <Clock className="w-3.5 h-3.5 inline mr-1" />
                  {new Date(generatedReport.generatedAt).toLocaleString()}
                </span>
              </div>
            </div>
            <button
              onClick={() => downloadGeneratedReport(generatedReport.download_url, generatedReport.file_name)}
              className="inline-flex items-center justify-center gap-2 rounded-lg border border-cyan-500/30 bg-cyan-500/15 px-4 py-2 text-sm font-semibold text-cyan-100 transition-colors hover:bg-cyan-500/25"
            >
              <Download className="h-4 w-4" />
              Download PDF
            </button>
          </div>

          {/* Summary Stats */}
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-4 mb-6">
            <div className="rounded-lg border border-slate-800 bg-slate-950/45 p-4">
              <p className="text-sm text-slate-400">Total Threats</p>
              <p className="text-2xl font-bold text-white">
                {generatedReport.summary.totalThreats}
              </p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/45 p-4">
              <p className="text-sm text-slate-400">Phishing Detected</p>
              <p className="text-2xl font-bold text-red-400">
                {generatedReport.summary.phishingDetected}
              </p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/45 p-4">
              <p className="text-sm text-slate-400">Auto-Resolved</p>
              <p className="text-2xl font-bold text-emerald-400">
                {generatedReport.summary.autoResolved}
              </p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/45 p-4">
              <p className="text-sm text-slate-400">Pending Review</p>
              <p className="text-2xl font-bold text-amber-400">
                {generatedReport.summary.pendingReview}
              </p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/45 p-4">
              <p className="text-sm text-slate-400">Model Accuracy</p>
              <p className="text-2xl font-bold text-cyan-400">
                {generatedReport.summary.modelAccuracy}%
              </p>
            </div>
          </div>

          {/* AI Analysis */}
          <div className="mb-6">
            <h3 className="text-md font-semibold text-white mb-3 flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-cyan-400" />
              AI Analysis
            </h3>
            <div className="rounded-lg border border-slate-800 bg-slate-950/45 p-4">
              <div className="text-slate-300 whitespace-pre-line text-sm leading-7">
                {generatedReport.aiAnalysis}
              </div>
            </div>
          </div>

          {/* Recommendations */}
          <div className="mb-6">
            <h3 className="text-md font-semibold text-white mb-3 flex items-center gap-2">
              <Target className="w-4 h-4 text-cyan-400" />
              Recommendations
            </h3>
            <div className="space-y-3">
              {generatedReport.recommendations.map((rec, index) => (
                <div
                  key={index}
                  className="rounded-lg border border-slate-800 bg-slate-950/45 p-4 flex items-start gap-3"
                >
                  <span
                    className={`px-2 py-1 rounded text-xs font-medium ${
                      rec.priority === "High"
                        ? "bg-red-500/15 text-red-200 border border-red-500/30"
                        : rec.priority === "Medium"
                        ? "bg-amber-500/15 text-amber-200 border border-amber-500/30"
                        : "bg-emerald-500/15 text-emerald-200 border border-emerald-500/30"
                    }`}
                  >
                    {rec.priority}
                  </span>
                  <div>
                    <h4 className="font-medium text-slate-100">{rec.title}</h4>
                    <p className="text-sm text-slate-400 mt-1">
                      {rec.description}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Threat Breakdown */}
          <div>
            <h3 className="text-md font-semibold text-white mb-3 flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              Threat Breakdown
            </h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {generatedReport.threatBreakdown.map((item, index) => (
                <div key={index} className="rounded-lg border border-slate-800 bg-slate-950/45 p-4">
                  <p className="text-sm text-slate-400">{item.type}</p>
                  <p className="text-xl font-bold text-white">{item.count}</p>
                  <p className="text-sm text-cyan-400">{item.percentage}%</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Empty State */}
      {!generatedReport && !isGenerating && activeTab === "ai-report" && (
        <div className="rounded-xl border border-dashed border-slate-800 bg-slate-900/60 p-12 text-center">
          <FileText className="w-12 h-12 text-cyan-300/50 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-slate-100 mb-2">
            No Report Generated
          </h3>
          <p className="mx-auto max-w-xl text-slate-400 mb-4">
            Select a report type and generate an AI analyst report when you
            need an executive summary, technical incident narrative, response
            summary, or threat intelligence brief.
          </p>
        </div>
      )}
      </>
      )}

      {/* PDF Incident Reports Tab */}
      {activeTab === "incident-reports" && (
        <div className="space-y-6">
          {/* Stats Summary */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="rounded-xl border border-slate-800/80 bg-slate-900/70 p-4">
              <p className="text-sm text-slate-400">Total Reports</p>
              <p className="text-2xl font-bold text-white">{incidentReports.length}</p>
            </div>
            <div className="rounded-xl border border-slate-800/80 bg-slate-900/70 p-4">
              <p className="text-sm text-slate-400">Critical Severity</p>
              <p className="text-2xl font-bold text-red-400">
                {incidentReports.filter(r => r.severity?.toUpperCase() === "CRITICAL").length}
              </p>
            </div>
            <div className="rounded-xl border border-slate-800/80 bg-slate-900/70 p-4">
              <p className="text-sm text-slate-400">High Severity</p>
              <p className="text-2xl font-bold text-rose-400">
                {incidentReports.filter(r => r.severity?.toUpperCase() === "HIGH").length}
              </p>
            </div>
            <div className="rounded-xl border border-slate-800/80 bg-slate-900/70 p-4">
              <p className="text-sm text-slate-400">Average Confidence</p>
              <p className="text-2xl font-bold text-cyan-400">
                {incidentReports.length > 0 
                  ? (incidentReports.reduce((acc, r) => acc + (r.confidence || 0), 0) / incidentReports.length).toFixed(1)
                  : 0}%
              </p>
            </div>
          </div>

          {/* Reports List */}
          {loadingReports ? (
            <div className="rounded-xl border border-slate-800/80 bg-slate-900/70 p-12 text-center">
              <RefreshCw className="w-8 h-8 text-cyan-400 mx-auto mb-4 animate-spin" />
              <p className="text-slate-400">Loading incident reports...</p>
            </div>
          ) : incidentReports.length === 0 ? (
            <div className="rounded-xl border border-dashed border-slate-800 bg-slate-900/60 p-12 text-center">
              <File className="w-12 h-12 text-cyan-300/50 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-slate-100 mb-2">No Incident Reports Yet</h3>
              <p className="text-slate-400 mb-4">
                PDF incident reports are automatically generated when the system detects phishing threats.
              </p>
              <p className="text-sm text-slate-500">
                Run the Demo Scheduler to detect threats and generate reports.
              </p>
            </div>
          ) : (
            <div className="rounded-xl border border-slate-800/80 bg-slate-900/70 overflow-hidden">
              <div className="p-4 border-b border-slate-800/80">
                <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
                  <File className="w-5 h-5 text-cyan-400" />
                  Generated Incident Reports ({incidentReports.length})
                </h2>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full min-w-[980px]">
                  <thead className="bg-slate-950/50">
                    <tr>
                      <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-slate-500">Report ID</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-slate-500">Threat ID</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-slate-500">Severity</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-slate-500">Confidence</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-slate-500">Email Subject</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-slate-500">Generated At</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-slate-500">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/80">
                    {incidentReports.map((report) => (
                      <tr key={report.report_id} className="hover:bg-slate-800/40 transition-colors">
                        <td className="px-4 py-3">
                          <span className="font-mono text-sm text-cyan-400">{report.report_id}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="font-mono text-sm text-slate-300">{report.threat_id}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(report.severity)}`}>
                            {report.severity || "UNKNOWN"}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="rounded-full border border-slate-700 bg-slate-950/40 px-2 py-0.5 text-xs text-slate-200">{report.confidence?.toFixed(1)}%</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-slate-300 max-w-xs truncate block" title={report.email_subject}>
                            {report.email_subject?.substring(0, 40)}
                            {report.email_subject?.length > 40 ? "..." : ""}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-slate-400 text-sm">{formatDate(report.generated_at)}</span>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => downloadPDFReport(report.report_id, report.filename)}
                              className="p-2 hover:bg-cyan-500/20 rounded-lg text-cyan-400 transition-colors"
                              title="Download PDF"
                            >
                              <Download className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => deleteReport(report.report_id)}
                              className="p-2 hover:bg-red-500/20 rounded-lg text-red-400 transition-colors"
                              title="Delete Report"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default Reports;
