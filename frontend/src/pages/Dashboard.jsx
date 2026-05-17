import React, { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Bot,
  CheckCircle2,
  ClipboardCheck,
  Download,
  RefreshCw,
  Shield,
  Target,
  Zap,
} from "lucide-react";
import StatsCard from "../components/Dashboard/StatsCard";
import ThreatsOverTimeChart from "../components/Dashboard/ThreatsOverTimeChart";
import ThreatTypesChart from "../components/Dashboard/ThreatTypesChart";
import ThreatMonitoringTable from "../components/Dashboard/ThreatMonitoringTable";
import IncidentDetails from "../components/Dashboard/IncidentDetails";
import ModelPerformanceMetrics from "../components/Dashboard/ModelPerformanceMetrics";
import ModelPerformanceLogs from "../components/Dashboard/ModelPerformanceLogs";
import LiveTestingPanel from "../components/Dashboard/LiveTestingPanel";
import ThreatResponseFeed from "../components/Dashboard/ThreatResponseFeed";
import SystemActivityLogs from "../components/Dashboard/SystemActivityLogs";
import { useDashboard } from "../context/DashboardContext";
import api, { fetchSocLogs } from "../utils/api";
import { useNavigate } from "react-router-dom";

const severityRank = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

const Dashboard = () => {
  const dashboardData = useDashboard();
  const navigate = useNavigate();
  const [socLogs, setSocLogs] = useState([]);
  const [reportsGenerated, setReportsGenerated] = useState(0);
  const [fullSocRunning, setFullSocRunning] = useState(false);
  const [fullSocMessage, setFullSocMessage] = useState("");
  const [fullSocResult, setFullSocResult] = useState(null);
  const [reportGenerating, setReportGenerating] = useState(false);
  const [generatedReport, setGeneratedReport] = useState(null);

  const loading = dashboardData?.loading;

  const stats = dashboardData?.stats || {
    phishingDetected: 0,
    activeThreats: 0,
    autoResolved: 0,
    accuracy: 0,
    totalThreats: 0,
    resolvedThreats: 0,
  };
  const liveThreats = dashboardData?.liveThreats || [];
  const responseActions = dashboardData?.responseActions || [];
  const testResults = dashboardData?.testResults || [];

  const refreshData = dashboardData?.refreshData;

  const safeLiveThreats = Array.isArray(liveThreats) ? liveThreats : [];
  const safeResponseActions = Array.isArray(responseActions)
    ? responseActions
    : [];
  const safeTestResults = Array.isArray(testResults) ? testResults : [];
  const activityLogs = Array.isArray(dashboardData?.activityLogs)
    ? dashboardData.activityLogs
    : [];
  const allTelemetryRows = [...safeLiveThreats, ...activityLogs, ...socLogs];
  const highRiskAlerts = allTelemetryRows.filter((item) =>
    ["CRITICAL", "HIGH"].includes(String(item?.severity || "").toUpperCase())
  ).length;
  const confidenceValues = allTelemetryRows
    .map((item) => Number(item?.confidence ?? item?.details?.confidence))
    .filter((value) => !Number.isNaN(value));
  const averageConfidence =
    confidenceValues.length > 0
      ? Math.round(
          (confidenceValues.reduce((sum, value) => sum + (value > 1 ? value : value * 100), 0) /
            confidenceValues.length)
        )
      : 0;
  const lastScanSource = allTelemetryRows
    .map((item) => item?.detected_at || item?.timestamp || item?.created_at)
    .filter(Boolean)
    .sort()
    .at(-1);
  const totalIncidents = stats.totalThreats || allTelemetryRows.length || safeLiveThreats.length;
  const agentsOnline = 4;
  const moduleStatuses = [
    { label: "Email Phishing", status: "Active", tone: "cyan" },
    { label: "Malware", status: "Active", tone: "emerald" },
    { label: "Ransomware", status: "Active", tone: "amber" },
    { label: "Credential Stuffing", status: "Active", tone: "violet" },
  ];

  const loadSocSummary = async () => {
    try {
      const [logsResult, reportsResult] = await Promise.all([
        fetchSocLogs({ limit: 100 }),
        api.get("/reports/incidents", { params: { limit: 100 } }),
      ]);
      setSocLogs(logsResult?.logs || []);
      setReportsGenerated(reportsResult?.data?.count || reportsResult?.data?.reports?.length || 0);
    } catch (error) {
      console.error("Failed to load SOC dashboard summary:", error);
    }
  };

  useEffect(() => {
    let active = true;
    const loadInitialSocSummary = async () => {
      if (!active) return;
      await loadSocSummary();
    };
    loadInitialSocSummary();
    return () => {
      active = false;
    };
  }, []);

  const activeThreatCount = stats.activeThreats || safeLiveThreats.length;
  const automatedActionCount =
    stats.autoResolved || stats.resolvedThreats || safeResponseActions.length;
  const detectionAccuracy =
    safeTestResults.length > 0
      ? Math.round(
          (safeTestResults.filter((result) => result && result.correct).length /
            safeTestResults.length) *
            100
        )
      : stats.accuracy || 97.2;

  const mostCriticalThreat = useMemo(() => {
    if (safeLiveThreats.length === 0) return null;
    return [...safeLiveThreats].sort((a, b) => {
      const bRank = severityRank[String(b?.severity || "").toUpperCase()] || 0;
      const aRank = severityRank[String(a?.severity || "").toUpperCase()] || 0;
      return bRank - aRank;
    })[0];
  }, [safeLiveThreats]);

  const hasCriticalThreat =
    String(mostCriticalThreat?.severity || "").toUpperCase() === "CRITICAL";
  const posture = activeThreatCount > 0 ? "Attention Required" : "Protected";
  const postureTone = hasCriticalThreat
    ? "critical"
    : activeThreatCount > 0
    ? "warning"
    : "safe";
  const systemHealth =
    activeThreatCount === 0
      ? "Healthy"
      : hasCriticalThreat
      ? "Critical"
      : "Monitoring";
  const analystNextStep = mostCriticalThreat
    ? `Review ${mostCriticalThreat.module || "threat"} incident ${
        mostCriticalThreat.id || ""
      } and validate automated containment.`
    : "Monitor live feeds, refresh telemetry, or run a controlled test batch to validate readiness.";

  const handleFullSocRun = async () => {
    setFullSocRunning(true);
    setFullSocMessage("Running full multi-module SOC simulation...");
    setGeneratedReport(null);
    try {
      const response = await api.post("/demo/full-soc-run");
      if (response.data?.success) {
        setFullSocResult(response.data);
        setFullSocMessage("Full SOC simulation completed.");
        await refreshData?.();
        await loadSocSummary();
      } else {
        setFullSocMessage(response.data?.detail || "Full SOC simulation did not complete.");
      }
    } catch (error) {
      setFullSocMessage(error.response?.data?.detail || "Full SOC simulation failed. Check backend service and try again.");
    } finally {
      setFullSocRunning(false);
    }
  };

  const handleRefresh = async () => {
    try {
      await refreshData();
      await loadSocSummary();
      setFullSocMessage((current) => current || "Dashboard data refreshed.");
    } catch (error) {
      console.error("Failed to refresh:", error);
      setFullSocMessage("Refresh failed. Existing dashboard data is still available.");
    }
  };

  const handleGenerateReport = async () => {
    if (!fullSocResult) {
      setFullSocMessage("Run Full ACDS SOC Simulation first before generating a report.");
      return;
    }

    setReportGenerating(true);
    setGeneratedReport(null);
    setFullSocMessage("Generating SOC report from latest full simulation...");
    try {
      const response = await api.post("/reports/generate", {
        report_type: "threat_summary",
        date_range: "7days",
        include_details: true,
        format: "pdf",
      });
      const report = response.data?.report || response.data;
      setGeneratedReport(report);
      setReportsGenerated((count) => count + 1);
      setFullSocMessage("SOC report generated successfully.");
      await loadSocSummary();
    } catch (error) {
      console.error("Failed to generate SOC report:", error);
      setFullSocMessage(error.response?.data?.detail || "Failed to generate SOC report.");
    } finally {
      setReportGenerating(false);
    }
  };

  const getDownloadUrl = (downloadUrl) => {
    if (!downloadUrl) return null;
    if (/^https?:\/\//i.test(downloadUrl)) return downloadUrl;
    const apiBase = api.defaults.baseURL || "";
    const appBase = apiBase.replace(/\/api\/v1\/?$/, "");
    if (downloadUrl.startsWith("/api/v1")) return `${appBase}${downloadUrl}`;
    return `${apiBase}${downloadUrl.startsWith("/") ? "" : "/"}${downloadUrl}`;
  };

  const formatConfidence = (value) => {
    const numeric = Number(value);
    if (Number.isNaN(numeric)) return "Unknown";
    return `${Math.round(numeric > 1 ? numeric : numeric * 100)}%`;
  };

  const formatProcessingTime = (milliseconds) => {
    const numeric = Number(milliseconds);
    if (Number.isNaN(numeric)) return "Unknown";
    if (numeric < 1000) return `${numeric} ms`;
    return `${(numeric / 1000).toFixed(2)} s`;
  };

  const fullSocSeverity = fullSocResult?.severity_breakdown || {};
  const fullSocWarnings = Array.isArray(fullSocResult?.warnings) ? fullSocResult.warnings : [];
  const ransomwareStaticAnalysisNote = fullSocWarnings.some((warning) =>
    String(warning || "").toLowerCase().includes("ransomware static pe analysis completed")
  )
    ? "Ransomware module ran in safe static-analysis mode. Executable samples were analyzed without execution."
    : null;
  const userFacingWarnings = fullSocWarnings.filter((warning) => {
    const normalized = String(warning || "").toLowerCase();
    return (
      !normalized.includes("ransomware static pe analysis completed") &&
      !normalized.includes("existing incident ids were updated")
    );
  });
  const fullSocModuleBreakdown = Array.isArray(fullSocResult?.module_breakdown)
    ? fullSocResult.module_breakdown
    : [];
  const fullSocIncidents = Array.isArray(fullSocResult?.incidents) ? fullSocResult.incidents : [];

  if (loading) {
    return (
      <div className="space-y-5 animate-pulse">
        <div className="h-40 rounded-xl bg-slate-800/70"></div>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
          {[1, 2, 3, 4].map((item) => (
            <div key={item} className="h-32 rounded-xl bg-slate-800/70"></div>
          ))}
        </div>
        <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
          <div className="h-96 rounded-xl bg-slate-800/70 xl:col-span-2"></div>
          <div className="h-96 rounded-xl bg-slate-800/70"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <section className="rounded-xl border border-slate-800/80 bg-slate-900/70 p-5 shadow-[0_18px_45px_rgba(2,6,23,0.24)] backdrop-blur-sm sm:p-6">
        <div className="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
          <div className="max-w-3xl">
            <div className="mb-3 flex items-center gap-3">
              <div
                className={`flex h-11 w-11 items-center justify-center rounded-lg border ${
                  postureTone === "critical"
                    ? "border-red-500/30 bg-red-500/10 text-red-300"
                    : postureTone === "warning"
                    ? "border-amber-500/30 bg-amber-500/10 text-amber-300"
                    : "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                }`}
              >
                <Shield className="h-5 w-5" />
              </div>
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.22em] text-cyan-300/80">
                  Unified SOC Operations
                </p>
                <h1 className="text-2xl font-semibold tracking-tight text-slate-50 sm:text-3xl">
                  ACDS SOC Command Center
                </h1>
                <p className="mt-1 text-sm font-medium text-slate-300">
                  Posture: {posture}
                </p>
              </div>
            </div>
            <p className="text-sm leading-6 text-slate-400">
              AI-driven autonomous cyber defense for real-time detection,
              response, and analyst reporting.
            </p>
          </div>

          <div className="grid gap-3 sm:grid-cols-3 xl:min-w-[520px]">
            <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
              <p className="text-xs uppercase tracking-wide text-slate-500">
                Total Incidents
              </p>
              <p
                className={`mt-2 text-2xl font-semibold ${
                  activeThreatCount > 0 ? "text-red-300" : "text-emerald-300"
                }`}
              >
                {totalIncidents}
              </p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
              <p className="text-xs uppercase tracking-wide text-slate-500">
                High Risk Alerts
              </p>
              <p className="mt-2 truncate text-sm font-medium text-slate-100">
                {highRiskAlerts}
              </p>
              <p className="mt-1 text-xs text-slate-500">
                Critical or high severity events
              </p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
              <p className="text-xs uppercase tracking-wide text-slate-500">
                Analyst Next Step
              </p>
              <p className="mt-2 line-clamp-2 text-xs leading-5 text-slate-300">
                {analystNextStep}
              </p>
            </div>
          </div>
        </div>

        <div className="mt-5 flex flex-col gap-3 border-t border-slate-800/80 pt-5 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex flex-col gap-2">
            <div className="flex flex-wrap items-center gap-2">
            <span
              className="inline-flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs font-semibold text-emerald-300"
            >
              <span className="h-2 w-2 rounded-full bg-emerald-400" />
              SOC Ready
            </span>
            <span className="inline-flex items-center gap-2 rounded-lg border border-cyan-500/20 bg-cyan-500/10 px-3 py-2 text-xs font-semibold text-cyan-200">
              <Bot className="h-3.5 w-3.5" />
              {safeResponseActions.length} automated actions in feed
            </span>
            </div>
            <p className="max-w-2xl text-sm text-slate-400">
              Run a controlled chunk-based SOC simulation across all ACDS modules.
            </p>
            <p className="max-w-2xl text-xs text-slate-500">
              Demo mode processes small chunks from datasets/uploads for safe and repeatable analysis.
            </p>
            {fullSocMessage && (
              <div
                className={`rounded-lg border px-3 py-2 text-xs ${
                  fullSocRunning
                    ? "border-cyan-500/30 bg-cyan-500/10 text-cyan-100"
                    : fullSocResult
                    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-100"
                    : "border-amber-500/30 bg-amber-500/10 text-amber-100"
                }`}
              >
                {fullSocMessage}
              </div>
            )}
            {generatedReport?.download_url && (
              <a
                href={getDownloadUrl(generatedReport.download_url)}
                target="_blank"
                rel="noreferrer"
                className="inline-flex w-fit items-center gap-2 rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 py-2 text-xs font-semibold text-cyan-100 transition-all hover:bg-cyan-500/20"
              >
                <Download className="h-3.5 w-3.5" />
                Download PDF
              </a>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={handleFullSocRun}
              disabled={fullSocRunning}
              className="inline-flex items-center gap-2 rounded-lg border border-emerald-500/40 bg-emerald-500/20 px-4 py-2 text-sm font-semibold text-emerald-100 transition-all hover:bg-emerald-500/30 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <Zap className="h-4 w-4" />
              {fullSocRunning ? "Running full multi-module SOC simulation..." : "Run Full ACDS SOC Simulation"}
            </button>

            <button
              onClick={() => navigate("/dashboard/logs")}
              className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-950/40 px-3 py-2 text-sm font-semibold text-slate-300 transition-all hover:bg-slate-800"
            >
              <Activity className="h-4 w-4" />
              View Logs
            </button>

            <button
              onClick={handleGenerateReport}
              disabled={reportGenerating}
              className="inline-flex items-center gap-2 rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 py-2 text-sm font-semibold text-cyan-200 transition-all hover:bg-cyan-500/20 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <ClipboardCheck className="h-4 w-4" />
              {reportGenerating ? "Generating..." : "Generate Report"}
            </button>

            <button
              onClick={() => navigate("/dashboard/reports")}
              className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-950/40 px-3 py-2 text-sm font-semibold text-slate-300 transition-all hover:bg-slate-800"
            >
              <ArrowRight className="h-4 w-4" />
              Open Reports
            </button>

            <button
              onClick={handleRefresh}
              className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-950/40 px-3 py-2 text-sm font-semibold text-slate-300 transition-all hover:bg-slate-800"
              title="Refresh dashboard data"
            >
              <RefreshCw className="h-4 w-4" />
              Refresh
            </button>
          </div>
        </div>
      </section>

      {fullSocResult && (
        <section className="rounded-xl border border-slate-800/80 bg-slate-900/70 p-5 shadow-[0_18px_45px_rgba(2,6,23,0.18)] sm:p-6">
          <div className="mb-5 flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300/80">
                Full SOC Simulation
              </p>
              <h2 className="mt-1 text-lg font-semibold text-slate-100">
                Unified Analyst Run Summary
              </h2>
              <p className="mt-1 text-sm text-slate-500">
                Run ID: <span className="font-mono text-slate-300">{fullSocResult.run_id}</span>
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              <button
                onClick={() => navigate("/dashboard/logs")}
                className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-950/40 px-3 py-2 text-sm font-semibold text-slate-300 transition-all hover:bg-slate-800"
              >
                <Activity className="h-4 w-4" />
                View Logs
              </button>
              <button
                onClick={handleGenerateReport}
                disabled={reportGenerating}
                className="inline-flex items-center gap-2 rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 py-2 text-sm font-semibold text-cyan-200 transition-all hover:bg-cyan-500/20 disabled:cursor-not-allowed disabled:opacity-60"
              >
                <ClipboardCheck className="h-4 w-4" />
                {reportGenerating ? "Generating..." : "Generate Report"}
              </button>
              <button
                onClick={() => navigate("/dashboard/reports")}
                className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-950/40 px-3 py-2 text-sm font-semibold text-slate-300 transition-all hover:bg-slate-800"
              >
                <ArrowRight className="h-4 w-4" />
                Open Reports
              </button>
              {generatedReport?.download_url && (
                <a
                  href={getDownloadUrl(generatedReport.download_url)}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-sm font-semibold text-emerald-100 transition-all hover:bg-emerald-500/20"
                >
                  <Download className="h-4 w-4" />
                  Download PDF
                </a>
              )}
            </div>
          </div>

          {(ransomwareStaticAnalysisNote || userFacingWarnings.length > 0) && (
            <div className="mb-5 space-y-2">
              {ransomwareStaticAnalysisNote && (
                <div className="rounded-lg border border-cyan-500/25 bg-cyan-500/10 px-4 py-3 text-sm text-cyan-100">
                  {ransomwareStaticAnalysisNote}
                </div>
              )}
              {userFacingWarnings.map((warning, index) => (
                <div
                  key={`${warning}-${index}`}
                  className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-100"
                >
                  {warning}
                </div>
              ))}
            </div>
          )}

          <div className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-6">
            <div className="rounded-lg border border-slate-800 bg-slate-950/45 p-4">
              <p className="text-xs uppercase tracking-wide text-slate-500">Total Processed</p>
              <p className="mt-2 text-2xl font-semibold text-slate-100">{fullSocResult.total_processed ?? 0}</p>
            </div>
            <div className="rounded-lg border border-red-500/20 bg-red-500/10 p-4">
              <p className="text-xs uppercase tracking-wide text-red-300/80">Threats Detected</p>
              <p className="mt-2 text-2xl font-semibold text-red-200">{fullSocResult.threats_detected ?? 0}</p>
            </div>
            <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/10 p-4">
              <p className="text-xs uppercase tracking-wide text-emerald-300/80">Safe Events</p>
              <p className="mt-2 text-2xl font-semibold text-emerald-200">{fullSocResult.safe_detected ?? 0}</p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/45 p-4">
              <p className="text-xs uppercase tracking-wide text-slate-500">Processing Time</p>
              <p className="mt-2 text-2xl font-semibold text-slate-100">
                {formatProcessingTime(fullSocResult.processing_time_ms)}
              </p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/45 p-4">
              <p className="text-xs uppercase tracking-wide text-slate-500">Modules Processed</p>
              <p className="mt-2 text-2xl font-semibold text-slate-100">{fullSocResult.modules_processed ?? 0}</p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/45 p-4">
              <p className="text-xs uppercase tracking-wide text-slate-500">Severity</p>
              <p className="mt-2 text-sm font-semibold text-slate-200">
                C {fullSocSeverity.critical ?? 0} / H {fullSocSeverity.high ?? 0} / M {fullSocSeverity.medium ?? 0} / L {fullSocSeverity.low ?? 0}
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-5 2xl:grid-cols-2">
            <div className="overflow-x-auto rounded-lg border border-slate-800/80">
              <table className="w-full min-w-[760px] text-left text-sm">
                <thead className="border-b border-slate-800 bg-slate-950/60 text-xs uppercase tracking-wide text-slate-400">
                  <tr>
                    <th className="px-4 py-3">Module</th>
                    <th className="px-4 py-3">Processed</th>
                    <th className="px-4 py-3">Threats</th>
                    <th className="px-4 py-3">Safe</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Warning</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {fullSocModuleBreakdown.map((module) => (
                    <tr key={module.module} className="bg-slate-900/35 hover:bg-slate-800/40">
                      <td className="px-4 py-3 font-semibold text-slate-100">
                        {String(module.module || "unknown").replaceAll("_", " ")}
                      </td>
                      <td className="px-4 py-3 text-slate-300">{module.processed ?? 0}</td>
                      <td className="px-4 py-3 text-red-200">{module.threats ?? 0}</td>
                      <td className="px-4 py-3 text-emerald-200">{module.safe ?? 0}</td>
                      <td className="px-4 py-3">
                        <span
                          className={`rounded-full border px-2.5 py-1 text-xs font-semibold ${
                            module.status === "failed"
                              ? "border-red-500/30 bg-red-500/15 text-red-200"
                              : "border-emerald-500/30 bg-emerald-500/10 text-emerald-200"
                          }`}
                        >
                          {module.status || "unknown"}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs text-amber-100">
                        {module.warning || "None"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="overflow-x-auto rounded-lg border border-slate-800/80">
              <table className="w-full min-w-[900px] text-left text-sm">
                <thead className="border-b border-slate-800 bg-slate-950/60 text-xs uppercase tracking-wide text-slate-400">
                  <tr>
                    <th className="px-4 py-3">Incident ID</th>
                    <th className="px-4 py-3">Module</th>
                    <th className="px-4 py-3">Prediction</th>
                    <th className="px-4 py-3">Severity</th>
                    <th className="px-4 py-3">Confidence</th>
                    <th className="px-4 py-3">Lifecycle State</th>
                    <th className="px-4 py-3">Summary</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {fullSocIncidents.map((incident) => {
                    const failed = incident.lifecycle_state === "analysis_failed";
                    return (
                      <tr
                        key={incident.incident_id}
                        className={failed ? "bg-amber-500/10 hover:bg-amber-500/15" : "bg-slate-900/35 hover:bg-slate-800/40"}
                      >
                        <td className="px-4 py-3 font-mono text-xs text-slate-200">{incident.incident_id}</td>
                        <td className="px-4 py-3 text-slate-300">{String(incident.module || "unknown").replaceAll("_", " ")}</td>
                        <td className="px-4 py-3">
                          <span
                            className={`rounded-full border px-2.5 py-1 text-xs font-semibold ${
                              incident.prediction === "SAFE"
                                ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-200"
                                : "border-red-500/30 bg-red-500/15 text-red-200"
                            }`}
                          >
                            {incident.prediction || "Unknown"}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-slate-300">{incident.severity || "Unknown"}</td>
                        <td className="px-4 py-3 text-slate-300">{formatConfidence(incident.confidence)}</td>
                        <td className="px-4 py-3">
                          <span
                            className={`rounded-full border px-2.5 py-1 text-xs font-semibold ${
                              failed
                                ? "border-amber-500/30 bg-amber-500/15 text-amber-100"
                                : "border-slate-700 bg-slate-950/45 text-slate-300"
                            }`}
                          >
                            {String(incident.lifecycle_state || "unknown").replaceAll("_", " ")}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-xs leading-5 text-slate-300">{incident.summary || "No summary available."}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </section>
      )}

      <section className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
        {moduleStatuses.map((module) => (
          <div
            key={module.label}
            className="rounded-xl border border-slate-800/80 bg-slate-900/70 p-4 shadow-[0_18px_45px_rgba(2,6,23,0.16)]"
          >
            <div className="flex items-center justify-between gap-3">
              <div>
                <p className="text-xs uppercase tracking-[0.16em] text-slate-500">
                  Module
                </p>
                <h3 className="mt-1 text-sm font-semibold text-slate-100">
                  {module.label}
                </h3>
              </div>
              <span className="inline-flex items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs font-semibold text-emerald-200">
                <span className="h-2 w-2 rounded-full bg-emerald-400" />
                {module.status}
              </span>
            </div>
          </div>
        ))}
      </section>

      <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-6">
        <StatsCard
          title="Total Incidents"
          value={totalIncidents}
          icon={<AlertTriangle className="h-5 w-5" />}
          description="Incidents and audit events visible to the SOC dashboard"
          tone={totalIncidents > 0 ? "info" : "safe"}
        />
        <StatsCard
          title="High Risk Alerts"
          value={highRiskAlerts}
          icon={<Shield className="h-5 w-5" />}
          description="Critical and high severity detections across modules"
          tone={highRiskAlerts > 0 ? "critical" : "safe"}
        />
        <StatsCard
          title="Reports Generated"
          value={reportsGenerated}
          icon={<ClipboardCheck className="h-5 w-5" />}
          description="Reusable PDF reports available for analyst review"
          tone="safe"
        />
        <StatsCard
          title="Average Confidence"
          value={`${averageConfidence}%`}
          icon={<Target className="h-5 w-5" />}
          description="Mean confidence from incidents and SOC audit logs"
          tone="info"
        />
        <StatsCard
          title="Last Scan"
          value={
            lastScanSource
              ? new Date(lastScanSource).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
              : "Unknown"
          }
          icon={<Activity className="h-5 w-5" />}
          description="Most recent detection or audit event timestamp"
          tone="neutral"
        />
        <StatsCard
          title="Agents Online"
          value={agentsOnline}
          icon={<Bot className="h-5 w-5" />}
          description="Detection, explainability, response, and report agents"
          tone="safe"
        />
      </section>

      <section className="grid grid-cols-1 gap-5 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <ThreatResponseFeed />
        </div>
        <div className="rounded-xl border border-slate-800/80 bg-slate-900/70 p-5 shadow-[0_18px_45px_rgba(2,6,23,0.18)]">
          <div className="mb-5 flex items-start justify-between gap-3">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300/80">
                AI Analyst Summary
              </p>
              <h2 className="mt-1 text-lg font-semibold text-slate-100">
                Current Security Posture
              </h2>
            </div>
            <Bot className="h-5 w-5 text-cyan-300" />
          </div>

          <div className="space-y-4">
            <div className="rounded-lg border border-slate-800 bg-slate-950/45 p-4">
              <p className="text-xs uppercase tracking-wide text-slate-500">
                Are we safe right now?
              </p>
              <p
                className={`mt-2 text-sm font-semibold ${
                  activeThreatCount > 0 ? "text-amber-300" : "text-emerald-300"
                }`}
              >
                {activeThreatCount > 0
                  ? "ACDS is monitoring active threats."
                  : "No active threats are currently reported."}
              </p>
            </div>

            <div className="rounded-lg border border-slate-800 bg-slate-950/45 p-4">
              <p className="text-xs uppercase tracking-wide text-slate-500">
                Most critical incident
              </p>
              <p className="mt-2 text-sm font-medium text-slate-100">
                {mostCriticalThreat?.subject || "No critical incident selected"}
              </p>
              <p className="mt-1 text-xs text-slate-500">
                {mostCriticalThreat
                  ? `${mostCriticalThreat.severity || "Unknown"} severity from ${
                      mostCriticalThreat.module || "detection"
                    }`
                  : "Live detections will appear here when available."}
              </p>
            </div>

            <div className="rounded-lg border border-slate-800 bg-slate-950/45 p-4">
              <p className="text-xs uppercase tracking-wide text-slate-500">
                Analyst action
              </p>
              <p className="mt-2 text-sm leading-6 text-slate-300">
                {analystNextStep}
              </p>
            </div>

            <div className="flex items-center gap-2 text-xs text-slate-500">
              <CheckCircle2 className="h-4 w-4 text-emerald-300" />
              Summary uses existing dashboard telemetry and response data.
            </div>
          </div>
        </div>
      </section>

      <section className="grid grid-cols-1 gap-5 xl:grid-cols-5">
        <div className="xl:col-span-3">
          <ThreatMonitoringTable />
        </div>
        <div className="xl:col-span-2">
          <IncidentDetails />
        </div>
      </section>

      <section>
        <div className="mb-3 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">
              Validation
            </p>
            <h2 className="text-lg font-semibold text-slate-100">
              Live Threat Detection Simulation
            </h2>
            <p className="mt-1 text-sm text-slate-500">
              Demo mode uses chunk-based processing for safe controlled analysis. Production deployment can integrate real-time streaming.
            </p>
          </div>
          <span className="inline-flex items-center gap-2 rounded-full border border-slate-700 bg-slate-900/70 px-3 py-1 text-xs text-slate-400">
            <ArrowRight className="h-3.5 w-3.5" />
            Multi-module workflow
          </span>
        </div>
        <LiveTestingPanel />
      </section>

      <section className="grid grid-cols-1 gap-5 xl:grid-cols-2">
        <SystemActivityLogs />
        <div className="grid grid-cols-1 gap-5">
          <ThreatsOverTimeChart />
          <ThreatTypesChart />
        </div>
      </section>

      <ModelPerformanceMetrics />
      <ModelPerformanceLogs />
    </div>
  );
};

export default Dashboard;
