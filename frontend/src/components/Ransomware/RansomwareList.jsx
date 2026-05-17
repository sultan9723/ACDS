import React, { useState, useEffect } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "../ui/Card";
import { Badge } from "../ui/Badge";
import api, { analyzeRansomwareUploads } from "../../utils/api";

const RansomwareList = ({ onSelectThreat, recentScans = [], onScanComplete }) => {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [scanInput, setScanInput] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [uploadScanning, setUploadScanning] = useState(false);
  const [uploadError, setUploadError] = useState(null);

  // Fetch scan history on mount
  useEffect(() => {
    fetchScans();
  }, []);

  useEffect(() => {
    if (!recentScans.length) return;
    setScans((prev) => {
      const existingIds = new Set(prev.map((scan) => scan.id));
      const newItems = recentScans.filter((scan) => !existingIds.has(scan.id));
      return [...newItems, ...prev];
    });
  }, [recentScans]);

  const fetchScans = async () => {
    setLoading(true);
    try {
      const res = await api.get("/ransomware/scans/list", { params: { limit: 50 } });
      const data = res.data;
      if (data.success) {
        const existingIds = new Set(recentScans.map((scan) => scan.id));
        const fetchedScans = (data.scans || []).filter((scan) => !existingIds.has(scan.id));
        setScans([...recentScans, ...fetchedScans]);
      }
    } catch (e) {
      console.error("Failed to fetch ransomware scans:", e);
    } finally {
      setLoading(false);
    }
  };

  const handleScan = async () => {
    if (!scanInput.trim()) return;
    setScanning(true);
    setScanResult(null);
    try {
      const res = await api.post("/ransomware/scan", { command: scanInput });
      const data = res.data;
      if (data.success) {
        setScanResult(data.result);
        if (onSelectThreat) onSelectThreat(data.result);
        if (onScanComplete) onScanComplete(data.result);

        // Add result directly to top of scan list
        const detection = data.result.pipeline_results?.detection || {};
        const newScan = {
          id: data.result.incident_id,
          command_preview: scanInput,
          source_host: "unknown",
          prediction: detection.is_ransomware ? "Ransomware" : "Safe",
          confidence: detection.confidence || 0,
          severity: data.result.severity || "LOW",
          behavior_categories: data.result.pipeline_results?.explainability?.behavior_categories || [],
          scanned_at: new Date().toISOString(),
        };
        setScans((prev) => [newScan, ...prev]);
      }
    } catch (e) {
      console.error("Scan failed:", e);
    } finally {
      setScanning(false);
    }
  };

  const handleAnalyzeUploads = async () => {
    setUploadScanning(true);
    setUploadError(null);
    try {
      const data = await analyzeRansomwareUploads(2);
      const uploadScans = (data.results || []).map((result) => ({
        id: result.incident_id,
        raw_result: result,
        command_preview: result.filename,
        source_host: "uploaded-sample",
        prediction: result.prediction === "RANSOMWARE" ? "Ransomware" : "Safe",
        confidence: result.confidence || 0,
        severity: result.severity || "LOW",
        behavior_categories: result.evidence || [],
        scanned_at: result.created_at,
      }));

      setScans((prev) => [...uploadScans, ...prev]);
      if (uploadScans[0]?.raw_result) {
        onSelectThreat?.(uploadScans[0].raw_result);
        onScanComplete?.(uploadScans[0].raw_result);
      }
    } catch (e) {
      setUploadError(e.detail || e.message || "Upload analysis failed");
    } finally {
      setUploadScanning(false);
    }
  };

  const formatConfidence = (value) => {
    if (!value && value !== 0) return "N/A";
    if (value > 1) return `${Math.round(value)}%`;
    return `${Math.round(value * 100)}%`;
  };

  const getSeverityColor = (severity) => {
    switch (severity?.toUpperCase()) {
      case "CRITICAL":
        return "bg-red-500/15 text-red-200 border-red-500/30";
      case "HIGH":
        return "bg-rose-500/15 text-rose-200 border-rose-500/30";
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
    <div className="space-y-4 flex flex-col">
      {/* Scan Input */}
      <Card className="bg-slate-900/70 border-slate-800/80">
        <CardHeader>
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
            Primary Workflow
          </p>
          <CardTitle className="text-slate-100 text-base">Scan Command</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-2">
            <input
              type="text"
              value={scanInput}
              onChange={(e) => setScanInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
              placeholder="Enter process command to scan... e.g. vssadmin delete shadows /all"
              className="flex-1 bg-slate-950/60 border border-slate-700 text-slate-200 text-sm rounded-lg px-4 py-2 placeholder-slate-600 focus:outline-none focus:border-emerald-500/80"
            />
            <button
              onClick={handleScan}
              disabled={scanning || !scanInput.trim()}
              className="px-4 py-2 border border-emerald-500/30 bg-emerald-500/20 hover:bg-emerald-500/30 disabled:bg-slate-800 disabled:text-slate-500 text-emerald-100 text-sm font-medium rounded-lg transition-colors flex items-center gap-2"
            >
              {scanning ? (
                <>
                  <div className="animate-spin rounded-full h-3 w-3 border-b-2 border-white"></div>
                  Scanning...
                </>
              ) : (
                "Scan"
              )}
            </button>
          </div>

          <div className="mt-3 flex flex-col gap-2 border-t border-slate-800 pt-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="text-sm font-medium text-slate-300">Uploaded Executable Batch</p>
              <p className="text-xs text-slate-500">Default batch size: 2 files</p>
            </div>
            <button
              onClick={handleAnalyzeUploads}
              disabled={uploadScanning}
              className="rounded-lg border border-cyan-500/30 bg-cyan-500/15 px-4 py-2 text-sm font-medium text-cyan-100 transition-colors hover:bg-cyan-500/25 disabled:border-slate-700 disabled:bg-slate-800 disabled:text-slate-500"
            >
              {uploadScanning ? "Analyzing..." : "Analyze Uploads"}
            </button>
          </div>

          {uploadError && (
            <div className="mt-3 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
              {uploadError}
            </div>
          )}

          {/* Inline scan result banner */}
          {scanResult && (
            <div
              className={`mt-3 px-4 py-3 rounded-lg border text-sm flex items-center justify-between ${
                scanResult.pipeline_results?.detection?.is_ransomware
                  ? "bg-red-900/30 border-red-800 text-red-300"
                  : "bg-emerald-500/10 border-emerald-500/30 text-emerald-300"
              }`}
            >
              <span>
                {scanResult.pipeline_results?.detection?.is_ransomware
                  ? "⚠ Ransomware detected!"
                  : "✓ Command appears safe"}
                {" — "}
                Severity:{" "}
                <strong>{scanResult.severity}</strong> | Confidence:{" "}
                <strong>
                  {formatConfidence(
                    scanResult.pipeline_results?.detection?.confidence
                  )}
                </strong>
              </span>
              <span className="text-xs text-slate-400">
                {scanResult.incident_id}
              </span>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Scan History Table */}
      <Card className="bg-slate-900/70 border-slate-800/80">
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
              Results Queue
            </p>
            <CardTitle className="mt-1 text-slate-100">Scan History</CardTitle>
          </div>
          <span className="rounded-full border border-slate-700 bg-slate-950/40 px-3 py-1 text-xs text-slate-400">
            {scans.length} commands
          </span>
        </CardHeader>
        <CardContent className="p-0 overflow-x-auto">
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-emerald-500"></div>
            </div>
          ) : scans.length === 0 ? (
            <div className="px-6 py-12 text-center">
              <p className="text-sm font-medium text-slate-300">No commands scanned yet</p>
              <p className="text-sm mt-2 text-slate-500">
                Use the scanner above to analyze a command
              </p>
            </div>
          ) : (
            <table className="w-full min-w-[840px] text-sm text-left">
              <thead className="text-xs text-slate-400 uppercase bg-slate-900/50 border-b border-slate-800">
                <tr>
                  <th className="px-6 py-3">Command</th>
                  <th className="px-6 py-3">Host</th>
                  <th className="px-6 py-3">Severity</th>
                  <th className="px-6 py-3">Confidence</th>
                  <th className="px-6 py-3">Result</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {scans.map((scan) => (
                  <tr
                    key={scan.id}
                    onClick={() => onSelectThreat?.(scan.raw_result || scan)}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                  >
                    <td className="px-6 py-3 text-slate-300 max-w-[220px] truncate font-mono text-xs">
                      {scan.command_preview || "—"}
                    </td>
                    <td className="px-6 py-3 text-slate-400 text-xs">
                      {scan.source_host || "unknown"}
                    </td>
                    <td className="px-6 py-3">
                      <span
                        className={`text-xs px-2 py-1 rounded border ${getSeverityColor(
                          scan.severity
                        )}`}
                      >
                        {scan.severity || "N/A"}
                      </span>
                    </td>
                    <td className="px-6 py-3">
                      <div className="flex items-center gap-2">
                        <div className="w-full bg-slate-800 rounded-full h-1.5 max-w-[72px]">
                          <div
                            className={`h-1.5 rounded-full ${
                              scan.prediction === "Ransomware"
                                ? "bg-red-500"
                                : "bg-emerald-500"
                            }`}
                            style={{
                              width: `${Math.min(
                                scan.confidence > 1
                                  ? scan.confidence
                                  : scan.confidence * 100,
                                100
                              )}%`,
                            }}
                          ></div>
                        </div>
                        <span className="rounded-full border border-slate-700 bg-slate-950/40 px-2 py-0.5 text-xs text-slate-300">
                          {formatConfidence(scan.confidence)}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-3">
                      <Badge
                        variant={
                          scan.prediction === "Ransomware"
                            ? "destructive"
                            : "success"
                        }
                      >
                        {scan.prediction || "Safe"}
                      </Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default RansomwareList;
