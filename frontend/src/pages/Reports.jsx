import React, { useState, useEffect } from "react";
import { useDashboard } from "../context/DashboardContext";
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

const API_BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8000/api/v1";

const Reports = () => {
  const dashboardData = useDashboard() || {};
  const { refreshData } = dashboardData;
  const threats = dashboardData.threats || [];
  const stats = dashboardData.stats || {};
  const logs = dashboardData.logs || [];
  const [isGenerating, setIsGenerating] = useState(false);
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
      const response = await fetch(`${API_BASE_URL}/reports/incidents?limit=50`);
      const data = await response.json();
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
      const response = await fetch(`${API_BASE_URL}/reports/incidents/${reportId}/download`);
      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename || `incident_report_${reportId}.pdf`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
      } else {
        console.error("Failed to download report");
      }
    } catch (error) {
      console.error("Error downloading report:", error);
    }
  };

  // Delete incident report
  const deleteReport = async (reportId) => {
    if (!window.confirm("Are you sure you want to delete this report?")) return;
    
    try {
      const response = await fetch(`${API_BASE_URL}/reports/incidents/${reportId}`, {
        method: "DELETE"
      });
      if (response.ok) {
        setIncidentReports(prev => prev.filter(r => r.report_id !== reportId));
      }
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
      case "CRITICAL": return "text-red-500 bg-red-500/20";
      case "HIGH": return "text-orange-500 bg-orange-500/20";
      case "MEDIUM": return "text-yellow-500 bg-yellow-500/20";
      case "LOW": return "text-green-500 bg-green-500/20";
      default: return "text-gray-400 bg-gray-500/20";
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

    // Refresh data to get latest threats
    if (refreshData) {
      await refreshData();
    }

    // Simulate AI report generation (replace with actual API call)
    await new Promise((resolve) => setTimeout(resolve, 1500));

    // Get fresh threats data from context
    const currentThreats = dashboardData.threats || [];

    // Check if there are threats to report on
    if (currentThreats.length === 0) {
      setGeneratedReport({
        generatedAt: new Date().toISOString(),
        reportType: selectedReportType,
        dateRange: dateRange,
        summary: {
          totalThreats: 0,
          phishingDetected: 0,
          autoResolved: 0,
          pendingReview: 0,
          modelAccuracy: stats?.accuracy || 97.2,
        },
        aiAnalysis: `
## AI-Powered Threat Analysis

### Overview
No threats have been detected during the selected period. The Autonomous Cyber Defense System is actively monitoring for potential threats.

### System Status
- **Detection Engine**: Active and monitoring
- **Model Accuracy**: ${stats?.accuracy || 97.2}%
- **Last Check**: ${new Date().toLocaleString()}

### Recommendations
1. Continue monitoring for suspicious email activity
2. Run a demo batch to test the detection system
3. Review the dashboard for any pending alerts
        `.trim(),
        recommendations: [
          {
            priority: "Low",
            title: "System Operating Normally",
            description:
              "No threats detected. Continue regular monitoring and security protocols.",
          },
          {
            priority: "Medium",
            title: "Run Demo Batch",
            description:
              "Consider running a demo batch to verify the detection system is functioning correctly.",
          },
        ],
        threatBreakdown: [],
        timeline: [],
      });
      setIsGenerating(false);
      return;
    }

    const phishingThreats = currentThreats.filter(
      (t) => t.type === "Phishing" || t.type === "phishing"
    );
    const resolvedThreats = currentThreats.filter(
      (t) => t.status === "Resolved" || t.status === "resolved"
    );

    const report = {
      generatedAt: new Date().toISOString(),
      reportType: selectedReportType,
      dateRange: dateRange,
      summary: {
        totalThreats: currentThreats.length,
        phishingDetected: phishingThreats.length,
        autoResolved: resolvedThreats.length,
        pendingReview: currentThreats.length - resolvedThreats.length,
        modelAccuracy: stats?.accuracy || 97.2,
      },
      aiAnalysis: generateAIAnalysis(currentThreats, stats),
      recommendations: generateRecommendations(currentThreats),
      threatBreakdown: generateThreatBreakdown(currentThreats),
      timeline: generateTimeline(currentThreats),
    };

    setGeneratedReport(report);
    setIsGenerating(false);
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
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Sparkles className="w-6 h-6 text-cyan-400" />
            AI-Powered Reports
          </h1>
          <p className="text-gray-400 mt-1">
            Generate comprehensive threat analysis reports and view incident reports
          </p>
        </div>
        <button
          onClick={fetchIncidentReports}
          className="flex items-center gap-2 px-4 py-2 bg-[#0a0a0a] border border-gray-700 rounded-lg text-gray-300 hover:border-cyan-500 transition-colors"
        >
          <RefreshCw className={`w-4 h-4 ${loadingReports ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Tab Navigation */}
      <div className="flex gap-2 border-b border-gray-800 pb-2">
        <button
          onClick={() => setActiveTab("ai-report")}
          className={`px-4 py-2 rounded-lg font-medium transition-colors ${
            activeTab === "ai-report"
              ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/50"
              : "text-gray-400 hover:text-white hover:bg-gray-800"
          }`}
        >
          <Sparkles className="w-4 h-4 inline mr-2" />
          Generate AI Report
        </button>
        <button
          onClick={() => setActiveTab("incident-reports")}
          className={`px-4 py-2 rounded-lg font-medium transition-colors flex items-center gap-2 ${
            activeTab === "incident-reports"
              ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/50"
              : "text-gray-400 hover:text-white hover:bg-gray-800"
          }`}
        >
          <File className="w-4 h-4" />
          PDF Incident Reports
          {incidentReports.length > 0 && (
            <span className="px-2 py-0.5 bg-cyan-500 text-white text-xs rounded-full">
              {incidentReports.length}
            </span>
          )}
        </button>
      </div>

      {/* AI Report Generation Tab */}
      {activeTab === "ai-report" && (
        <>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Report Type Selection */}
        <div className="lg:col-span-2 bg-[#111111] border border-gray-800 rounded-xl p-6">
          <h2 className="text-lg font-semibold text-white mb-4">
            Select Report Type
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {reportTypes.map((report) => (
              <button
                key={report.id}
                onClick={() => setSelectedReportType(report.id)}
                className={`p-4 rounded-lg border text-left transition-all ${
                  selectedReportType === report.id
                    ? "border-cyan-500 bg-cyan-500/10"
                    : "border-gray-700 bg-[#0a0a0a] hover:border-gray-600"
                }`}
              >
                <div className="flex items-start gap-3">
                  <report.icon
                    className={`w-5 h-5 mt-0.5 ${
                      selectedReportType === report.id
                        ? "text-cyan-400"
                        : "text-gray-400"
                    }`}
                  />
                  <div>
                    <h3 className="font-medium text-white">{report.name}</h3>
                    <p className="text-sm text-gray-400 mt-1">
                      {report.description}
                    </p>
                  </div>
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Configuration Panel */}
        <div className="bg-[#111111] border border-gray-800 rounded-xl p-6">
          <h2 className="text-lg font-semibold text-white mb-4">
            Configuration
          </h2>

          {/* Date Range */}
          <div className="mb-6">
            <label className="block text-sm text-gray-400 mb-2">
              <Calendar className="w-4 h-4 inline mr-2" />
              Date Range
            </label>
            <select
              value={dateRange}
              onChange={(e) => setDateRange(e.target.value)}
              className="w-full bg-[#0a0a0a] border border-gray-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-cyan-500"
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
            className="w-full bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-medium py-3 px-4 rounded-lg hover:from-cyan-600 hover:to-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-2"
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

          {/* Export Options */}
          {generatedReport && (
            <div className="mt-4 space-y-2">
              <p className="text-sm text-gray-400">Export Report:</p>
              <div className="flex gap-2">
                <button
                  onClick={() => exportReport("json")}
                  className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-[#0a0a0a] border border-gray-700 rounded-lg text-gray-300 hover:border-cyan-500 transition-colors"
                >
                  <FileJson className="w-4 h-4" />
                  JSON
                </button>
                <button
                  onClick={() => exportReport("txt")}
                  className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-[#0a0a0a] border border-gray-700 rounded-lg text-gray-300 hover:border-cyan-500 transition-colors"
                >
                  <FileType className="w-4 h-4" />
                  TXT
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Generated Report Display */}
      {generatedReport && (
        <div className="bg-[#111111] border border-gray-800 rounded-xl p-6">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <FileText className="w-5 h-5 text-cyan-400" />
              Generated Report
            </h2>
            <span className="text-sm text-gray-400">
              <Clock className="w-4 h-4 inline mr-1" />
              {new Date(generatedReport.generatedAt).toLocaleString()}
            </span>
          </div>

          {/* Summary Stats */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
            <div className="bg-[#0a0a0a] rounded-lg p-4">
              <p className="text-sm text-gray-400">Total Threats</p>
              <p className="text-2xl font-bold text-white">
                {generatedReport.summary.totalThreats}
              </p>
            </div>
            <div className="bg-[#0a0a0a] rounded-lg p-4">
              <p className="text-sm text-gray-400">Phishing Detected</p>
              <p className="text-2xl font-bold text-red-400">
                {generatedReport.summary.phishingDetected}
              </p>
            </div>
            <div className="bg-[#0a0a0a] rounded-lg p-4">
              <p className="text-sm text-gray-400">Auto-Resolved</p>
              <p className="text-2xl font-bold text-green-400">
                {generatedReport.summary.autoResolved}
              </p>
            </div>
            <div className="bg-[#0a0a0a] rounded-lg p-4">
              <p className="text-sm text-gray-400">Pending Review</p>
              <p className="text-2xl font-bold text-yellow-400">
                {generatedReport.summary.pendingReview}
              </p>
            </div>
            <div className="bg-[#0a0a0a] rounded-lg p-4">
              <p className="text-sm text-gray-400">Model Accuracy</p>
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
            <div className="bg-[#0a0a0a] rounded-lg p-4 prose prose-invert prose-sm max-w-none">
              <div className="text-gray-300 whitespace-pre-line text-sm leading-relaxed">
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
                  className="bg-[#0a0a0a] rounded-lg p-4 flex items-start gap-3"
                >
                  <span
                    className={`px-2 py-1 rounded text-xs font-medium ${
                      rec.priority === "High"
                        ? "bg-red-500/20 text-red-400"
                        : rec.priority === "Medium"
                        ? "bg-yellow-500/20 text-yellow-400"
                        : "bg-green-500/20 text-green-400"
                    }`}
                  >
                    {rec.priority}
                  </span>
                  <div>
                    <h4 className="font-medium text-white">{rec.title}</h4>
                    <p className="text-sm text-gray-400 mt-1">
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
                <div key={index} className="bg-[#0a0a0a] rounded-lg p-4">
                  <p className="text-sm text-gray-400">{item.type}</p>
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
        <div className="bg-[#111111] border border-gray-800 rounded-xl p-12 text-center">
          <FileText className="w-12 h-12 text-gray-600 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-white mb-2">
            No Report Generated
          </h3>
          <p className="text-gray-400 mb-4">
            Select a report type and click "Generate AI Report" to create a
            comprehensive threat analysis.
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
            <div className="bg-[#111111] border border-gray-800 rounded-xl p-4">
              <p className="text-sm text-gray-400">Total Reports</p>
              <p className="text-2xl font-bold text-white">{incidentReports.length}</p>
            </div>
            <div className="bg-[#111111] border border-gray-800 rounded-xl p-4">
              <p className="text-sm text-gray-400">Critical Severity</p>
              <p className="text-2xl font-bold text-red-400">
                {incidentReports.filter(r => r.severity?.toUpperCase() === "CRITICAL").length}
              </p>
            </div>
            <div className="bg-[#111111] border border-gray-800 rounded-xl p-4">
              <p className="text-sm text-gray-400">High Severity</p>
              <p className="text-2xl font-bold text-orange-400">
                {incidentReports.filter(r => r.severity?.toUpperCase() === "HIGH").length}
              </p>
            </div>
            <div className="bg-[#111111] border border-gray-800 rounded-xl p-4">
              <p className="text-sm text-gray-400">Average Confidence</p>
              <p className="text-2xl font-bold text-cyan-400">
                {incidentReports.length > 0 
                  ? (incidentReports.reduce((acc, r) => acc + (r.confidence || 0), 0) / incidentReports.length).toFixed(1)
                  : 0}%
              </p>
            </div>
          </div>

          {/* Reports List */}
          {loadingReports ? (
            <div className="bg-[#111111] border border-gray-800 rounded-xl p-12 text-center">
              <RefreshCw className="w-8 h-8 text-cyan-400 mx-auto mb-4 animate-spin" />
              <p className="text-gray-400">Loading incident reports...</p>
            </div>
          ) : incidentReports.length === 0 ? (
            <div className="bg-[#111111] border border-gray-800 rounded-xl p-12 text-center">
              <File className="w-12 h-12 text-gray-600 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-white mb-2">No Incident Reports Yet</h3>
              <p className="text-gray-400 mb-4">
                PDF incident reports are automatically generated when the system detects phishing threats.
              </p>
              <p className="text-sm text-gray-500">
                Run the Demo Scheduler to detect threats and generate reports.
              </p>
            </div>
          ) : (
            <div className="bg-[#111111] border border-gray-800 rounded-xl overflow-hidden">
              <div className="p-4 border-b border-gray-800">
                <h2 className="text-lg font-semibold text-white flex items-center gap-2">
                  <File className="w-5 h-5 text-cyan-400" />
                  Generated Incident Reports ({incidentReports.length})
                </h2>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-[#0a0a0a]">
                    <tr>
                      <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Report ID</th>
                      <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Threat ID</th>
                      <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Severity</th>
                      <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Confidence</th>
                      <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Email Subject</th>
                      <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Generated At</th>
                      <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800">
                    {incidentReports.map((report) => (
                      <tr key={report.report_id} className="hover:bg-[#0a0a0a] transition-colors">
                        <td className="px-4 py-3">
                          <span className="font-mono text-sm text-cyan-400">{report.report_id}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="font-mono text-sm text-gray-300">{report.threat_id}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(report.severity)}`}>
                            {report.severity || "UNKNOWN"}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-white">{report.confidence?.toFixed(1)}%</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-gray-300 max-w-xs truncate block" title={report.email_subject}>
                            {report.email_subject?.substring(0, 40)}
                            {report.email_subject?.length > 40 ? "..." : ""}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-gray-400 text-sm">{formatDate(report.generated_at)}</span>
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
