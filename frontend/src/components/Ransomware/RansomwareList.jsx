import React, { useState, useEffect } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "../ui/Card";
import { Badge } from "../ui/Badge";

const API_BASE = (import.meta.env.VITE_API_URL || "http://localhost:8000/api/v1").replace(/\/$/, "");

const RansomwareList = ({ onSelectThreat, recentScans = [], onScanComplete }) => {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [scanInput, setScanInput] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);

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
      const res = await fetch(`${API_BASE}/ransomware/scans/list?limit=50`);
      const data = await res.json();
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
      const res = await fetch(`${API_BASE}/ransomware/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command: scanInput }),
      });
      const data = await res.json();
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

  const formatConfidence = (value) => {
    if (!value && value !== 0) return "N/A";
    if (value > 1) return `${Math.round(value)}%`;
    return `${Math.round(value * 100)}%`;
  };

  const getSeverityColor = (severity) => {
    switch (severity?.toUpperCase()) {
      case "CRITICAL":
        return "bg-red-900/50 text-red-400 border-red-900";
      case "HIGH":
        return "bg-orange-900/50 text-orange-400 border-orange-900";
      case "MEDIUM":
        return "bg-yellow-900/50 text-yellow-400 border-yellow-900";
      case "LOW":
      case "SAFE":
        return "bg-green-900/50 text-green-400 border-green-900";
      default:
        return "bg-slate-900/50 text-slate-400 border-slate-700";
    }
  };

  return (
    <div className="space-y-4 h-full flex flex-col">
      {/* Scan Input */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-slate-200 text-base">
            Scan Command
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-2">
            <input
              type="text"
              value={scanInput}
              onChange={(e) => setScanInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
              placeholder="Enter process command to scan... e.g. vssadmin delete shadows /all"
              className="flex-1 bg-slate-800 border border-slate-700 text-slate-200 text-sm rounded-lg px-4 py-2 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
            />
            <button
              onClick={handleScan}
              disabled={scanning || !scanInput.trim()}
              className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-700 disabled:text-slate-500 text-white text-sm font-medium rounded-lg transition-colors flex items-center gap-2"
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

          {/* Inline scan result banner */}
          {scanResult && (
            <div
              className={`mt-3 px-4 py-3 rounded-lg border text-sm flex items-center justify-between ${
                scanResult.pipeline_results?.detection?.is_ransomware
                  ? "bg-red-900/30 border-red-800 text-red-300"
                  : "bg-green-900/30 border-green-800 text-green-300"
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
      <Card className="bg-slate-900/50 border-slate-800 flex-1 min-h-0">
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-slate-200">Scan History</CardTitle>
          <span className="text-xs text-slate-500">
            {scans.length} commands scanned
          </span>
        </CardHeader>
        <CardContent className="p-0 overflow-y-auto max-h-[400px]">
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-emerald-500"></div>
            </div>
          ) : scans.length === 0 ? (
            <div className="text-center py-12 text-slate-500">
              <p>No commands scanned yet</p>
              <p className="text-sm mt-1">
                Use the scanner above to analyze a command
              </p>
            </div>
          ) : (
            <table className="w-full text-sm text-left">
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
                    className="hover:bg-slate-800/30 transition-colors cursor-pointer"
                  >
                    <td className="px-6 py-4 text-slate-300 max-w-[220px] truncate font-mono text-xs">
                      {scan.command_preview || "—"}
                    </td>
                    <td className="px-6 py-4 text-slate-400 text-xs">
                      {scan.source_host || "unknown"}
                    </td>
                    <td className="px-6 py-4">
                      <span
                        className={`text-xs px-2 py-1 rounded border ${getSeverityColor(
                          scan.severity
                        )}`}
                      >
                        {scan.severity || "N/A"}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <div className="w-full bg-slate-700 rounded-full h-1.5 max-w-[60px]">
                          <div
                            className={`h-1.5 rounded-full ${
                              scan.prediction === "Ransomware"
                                ? "bg-red-500"
                                : "bg-green-500"
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
                        <span className="text-xs text-slate-400">
                          {formatConfidence(scan.confidence)}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4">
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
