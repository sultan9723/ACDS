import React, { useState } from "react";
import RansomwareList from "../components/Ransomware/RansomwareList";
import RansomwareThreatDetails from "../components/Ransomware/RansomwareThreatDetails";
import ThreeLayerDetectionScanner from "../components/Ransomware/ThreeLayerDetectionScanner";
import { useDashboard } from "../context/DashboardContext";

const RansomwareModule = () => {
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [activeTab, setActiveTab] = useState("scanner");
  const [recentScans, setRecentScans] = useState([]);
  const { runBatch } = useDashboard() || {};

  const normalizeScanHistoryItem = (result) => {
    const detection = result.pipeline_results?.detection || {};
    const layer3 = result.layers?.layer3_mass_encryption || {};
    const isRansomware =
      detection.is_ransomware ||
      result.overall_verdict === "RANSOMWARE_DETECTED" ||
      layer3.status === "threat_detected";

    return {
      id:
        result.incident_id ||
        result.threat_id ||
        result.scan_id ||
        result.sample?.sha256 ||
        `${Date.now()}`,
      raw_result: result,
      command_preview:
        result.command ||
        result.pipeline_results?.detection?.command ||
        result.filename ||
        result.sample?.filename ||
        result.triggered_layers?.join(", ") ||
        "Layered ransomware analysis",
      source_host: result.source_host || "TEST-WORKSTATION",
      prediction: isRansomware ? "Ransomware" : "Safe",
      confidence:
        result.detection_confidence ??
        detection.confidence ??
        layer3.confidence ??
        0,
      severity: result.severity || layer3.threat_level || "LOW",
      behavior_categories:
        result.pipeline_results?.explainability?.behavior_categories ||
        result.triggered_layers ||
        layer3.indicators ||
        [],
      scanned_at: result.timestamp || new Date().toISOString(),
    };
  };

  const handleThreeLayerDetection = (result) => {
    setSelectedThreat(result);
    setRecentScans((prev) => [normalizeScanHistoryItem(result), ...prev].slice(0, 50));
    setActiveTab("history");
  };

  return (
    <div className="space-y-5 min-h-[calc(100vh-100px)] pb-6">
      <div className="rounded-xl border border-slate-800/80 bg-slate-900/70 p-5 shadow-[0_18px_45px_rgba(2,6,23,0.18)]">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300/80">
              Detection Module
            </p>
            <h1 className="mt-1 text-2xl font-semibold tracking-tight text-slate-100">
              Ransomware Detection System
            </h1>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
              Run layered command, behavior, and executable analysis while
              preserving the current automated response workflow.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => {
                setActiveTab("history");
                runBatch?.(2, "ransomware");
              }}
              className="rounded-lg border border-cyan-500/30 bg-cyan-500/15 px-4 py-2 text-sm font-semibold text-cyan-100 transition-colors hover:bg-cyan-500/25"
            >
              Analyze Uploaded Executables
            </button>
            <span className="rounded-full border border-emerald-500/25 bg-emerald-500/10 px-3 py-1 text-xs font-semibold text-emerald-200">
              3-Layer Detection Active
            </span>
            <span className="rounded-full border border-cyan-500/25 bg-cyan-500/10 px-3 py-1 text-xs font-semibold text-cyan-200">
              ML + Rules
            </span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 items-start">
        <div className="lg:col-span-2 min-w-0 flex flex-col space-y-4">
          <div className="flex gap-2">
            <button
              onClick={() => setActiveTab("scanner")}
              className={`rounded-lg border px-4 py-2 text-sm font-medium transition-colors ${
                activeTab === "scanner"
                  ? "border-emerald-500/30 bg-emerald-500/15 text-emerald-200"
                  : "border-slate-800 bg-slate-900/70 text-slate-400 hover:text-slate-200"
              }`}
            >
              3-Layer Scanner
            </button>
            <button
              onClick={() => setActiveTab("history")}
              className={`rounded-lg border px-4 py-2 text-sm font-medium transition-colors ${
                activeTab === "history"
                  ? "border-emerald-500/30 bg-emerald-500/15 text-emerald-200"
                  : "border-slate-800 bg-slate-900/70 text-slate-400 hover:text-slate-200"
              }`}
            >
              Scan History
            </button>
          </div>

          {activeTab === "scanner" && (
            <div className="min-w-0">
              <ThreeLayerDetectionScanner
                onDetectionResult={handleThreeLayerDetection}
              />
            </div>
          )}

          {activeTab === "history" && (
            <div className="min-w-0">
              <RansomwareList
                onSelectThreat={setSelectedThreat}
                recentScans={recentScans}
                onScanComplete={handleThreeLayerDetection}
              />
            </div>
          )}
        </div>
        <div className="min-w-0 lg:sticky lg:top-24 lg:max-h-[calc(100vh-120px)] lg:overflow-y-auto">
          <RansomwareThreatDetails threat={selectedThreat} />
        </div>
      </div>
    </div>
  );
};

export default RansomwareModule;
