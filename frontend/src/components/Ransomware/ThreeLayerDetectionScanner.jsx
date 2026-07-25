import React, { useEffect, useRef, useState } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "../ui/Card";
import { Badge } from "../ui/Badge";

const API_BASE = (import.meta.env.VITE_API_URL || "http://localhost:8000/api/v1").replace(/\/$/, "");

const fakeLogs = [
  "Monitoring file system...",
  "Scanning process activity...",
  "Analyzing network connections...",
  "Checking shadow copy status...",
  "Monitoring registry changes...",
  "Scanning for suspicious extensions...",
  "Analyzing file entropy changes...",
  "Checking for backup interference...",
];

const ThreeLayerDetectionScanner = ({ onDetectionResult }) => {
  const detectionTimeoutsRef = useRef([]);
  const responseTimeoutsRef = useRef([]);
  const activeUploadRef = useRef(null);

  const [commandInput, setCommandInput] = useState("");
  const [binaryPath, setBinaryPath] = useState("");
  const [fileCount, setFileCount] = useState(50);
  const [detectingMode, setDetectingMode] = useState("command");
  const [detecting, setDetecting] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [selectedExe, setSelectedExe] = useState(null);
  const [uploadingExe, setUploadingExe] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploadPhase, setUploadPhase] = useState("Idle");
  const [uploadResult, setUploadResult] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const [activityLogs, setActivityLogs] = useState([]);
  const [fileActivitySpike, setFileActivitySpike] = useState(0);
  const [detectionTimeline, setDetectionTimeline] = useState([]);
  const [autoResponseSteps, setAutoResponseSteps] = useState([]);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanPhase, setScanPhase] = useState("Idle");
  const [isMonitoring, setIsMonitoring] = useState(true);

  const clearDetectionTimers = () => {
    detectionTimeoutsRef.current.forEach((timerId) => clearTimeout(timerId));
    detectionTimeoutsRef.current = [];
  };

  const clearResponseTimers = () => {
    responseTimeoutsRef.current.forEach((timerId) => clearTimeout(timerId));
    responseTimeoutsRef.current = [];
  };

  const scheduleDetectionStep = (delay, label, progress) => {
    const timerId = setTimeout(() => {
      setDetectionTimeline((prev) => [...prev, label]);
      setScanProgress(progress);
      setScanPhase(label);
    }, delay);
    detectionTimeoutsRef.current.push(timerId);
  };

  const scheduleResponseStep = (delay, updater) => {
    const timerId = setTimeout(updater, delay);
    responseTimeoutsRef.current.push(timerId);
  };

  useEffect(() => {
    if (!isMonitoring) return undefined;
    const interval = setInterval(() => {
      const randomLog = fakeLogs[Math.floor(Math.random() * fakeLogs.length)];
      const timestamp = new Date().toLocaleTimeString();
      setActivityLogs((prev) => [...prev.slice(-9), `[${timestamp}] ${randomLog}`]);
    }, 1500);
    return () => clearInterval(interval);
  }, [isMonitoring]);

  useEffect(() => {
    if (!detecting) {
      setFileActivitySpike(0);
      return undefined;
    }
    const interval = setInterval(() => {
      setFileActivitySpike((prev) => {
        const increment = Math.floor(Math.random() * 15) + 5;
        return Math.min(prev + increment, fileCount);
      });
    }, 200);
    return () => clearInterval(interval);
  }, [detecting, fileCount]);

  useEffect(() => {
    return () => {
      clearDetectionTimers();
      clearResponseTimers();
      if (activeUploadRef.current) {
        activeUploadRef.current.abort();
      }
    };
  }, []);

  const scanDisabled =
    detecting ||
    (detectingMode === "command" && !commandInput.trim()) ||
    (detectingMode === "full" && !commandInput.trim());

  const handleFileCountChange = (event) => {
    const nextValue = Number(event.target.value);
    if (!Number.isFinite(nextValue)) return;
    const clampedValue = Math.max(10, Math.min(200, nextValue));
    setFileCount(clampedValue);
  };

  const handleThreeLayerDetection = async () => {
    if (scanDisabled) return;
    const currentFileCount = Number.isFinite(fileCount) ? fileCount : 50;

    clearDetectionTimers();
    clearResponseTimers();
    setDetecting(true);
    setError(null);
    setDetectionTimeline(["Analysis started"]);
    setAutoResponseSteps([]);
    setScanProgress(8);
    setScanPhase("Preparing request");

    try {
      scheduleDetectionStep(350, "Scanning command patterns", 30);
      scheduleDetectionStep(700, "Analyzing file activity", 55);
      scheduleDetectionStep(1050, "Cross-referencing layers", 75);

      const fileActivities =
        detectingMode !== "command"
          ? Array.from({ length: currentFileCount }, (_, i) => ({
              path: `C:/Users/Documents/file_${String(i).padStart(4, "0")}.${
                i % 3 === 0 ? "xlsx" : "docx"
              }`,
              operation: "modify",
              extension: detectingMode === "encryption" ? ".encrypted" : `.ext${i}`,
              process_pid: 1234,
              process_name: detectingMode === "encryption" ? "malware.exe" : "test_process.exe",
              source_host: "TEST-WORKSTATION",
            }))
          : null;

      let endpoint = `${API_BASE}/ransomware/detect-layers`;
      let payload = {
        command: detectingMode !== "encryption" ? commandInput : null,
        binary_path: binaryPath.trim() || null,
        process_name: "test_process.exe",
        process_pid: 1234,
        source_host: "TEST-WORKSTATION",
        user: "test@domain.com",
        file_activities: fileActivities,
      };

      if (detectingMode === "command") {
        endpoint = `${API_BASE}/ransomware/scan`;
        payload = {
          command: commandInput,
          source_host: "TEST-WORKSTATION",
          process_name: "test_process.exe",
          user: "test@domain.com",
        };
      } else if (detectingMode === "encryption") {
        endpoint = `${API_BASE}/ransomware/monitor-encryption`;
        payload = fileActivities;
      }

      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(data.detail || `Detection request failed with HTTP ${response.status}`);
      }
      if (!data.success) {
        throw new Error(data.detail || "Detection failed");
      }

      const nextResult =
        detectingMode === "encryption"
          ? normalizeEncryptionResult(data, currentFileCount)
          : {
              ...data.result,
              command: detectingMode === "command" ? commandInput : data.result.command,
              source_host: data.result.source_host || "TEST-WORKSTATION",
              process_name: data.result.process_name || "test_process.exe",
            };

      clearDetectionTimers();
      setResult(nextResult);
      setScanProgress(100);
      setScanPhase("Analysis complete");
      setDetectionTimeline((prev) => [...prev, "Analysis complete"]);

      if (nextResult.overall_verdict === "RANSOMWARE_DETECTED") {
        scheduleResponseStep(500, () => setAutoResponseSteps(["Process termination simulation queued"]));
        scheduleResponseStep(900, () =>
          setAutoResponseSteps((prev) => [...prev, "Hash block recommendation recorded"])
        );
        scheduleResponseStep(1300, () =>
          setAutoResponseSteps((prev) => [...prev, "Network isolation recommendation prepared"])
        );
        scheduleResponseStep(1700, () =>
          setAutoResponseSteps((prev) => [...prev, "SOC alert workflow ready"])
        );
      }

      if (onDetectionResult) onDetectionResult(nextResult);
    } catch (exc) {
      clearDetectionTimers();
      setError(`Error: ${exc.message}`);
      setScanPhase("Analysis failed");
      setDetectionTimeline((prev) => [...prev, "Analysis failed"]);
    } finally {
      setDetecting(false);
    }
  };

  const handleExeSelection = (file) => {
    if (!file) return;
    setSelectedExe(file);
    setUploadResult(null);
    setError(null);
    setUploadProgress(0);
    setUploadPhase("Ready");
  };

  const handleExeUpload = async () => {
    if (!selectedExe || uploadingExe) return;

    setUploadingExe(true);
    setUploadProgress(0);
    setUploadPhase("Uploading sample");
    setUploadResult(null);
    setError(null);

    const formData = new FormData();
    formData.append("file", selectedExe);

    const xhr = new XMLHttpRequest();
    activeUploadRef.current = xhr;
    xhr.open("POST", `${API_BASE}/ransomware/upload-executable`);
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) {
        setUploadProgress(Math.round((event.loaded / event.total) * 100));
        setUploadPhase("Uploading sample");
      }
    };
    xhr.onload = () => {
      setUploadingExe(false);
      activeUploadRef.current = null;
      try {
        const data = JSON.parse(xhr.responseText || "{}");
        if (xhr.status >= 200 && xhr.status < 300 && data.success) {
          setUploadProgress(100);
          setUploadPhase("Analysis complete");
          setUploadResult(data.result);
          setResult(data.result);
          setBinaryPath(data.result.sample?.path || "");
          if (onDetectionResult) onDetectionResult(data.result);
        } else {
          setUploadPhase("Analysis failed");
          setError(data.detail || "Executable analysis failed");
        }
      } catch (parseError) {
        setUploadPhase("Analysis failed");
        setError(`Executable analysis failed: ${parseError.message}`);
      }
    };
    xhr.onerror = () => {
      setUploadingExe(false);
      activeUploadRef.current = null;
      setUploadPhase("Upload failed");
      setError("Executable upload failed");
    };
    xhr.onabort = () => {
      setUploadingExe(false);
      activeUploadRef.current = null;
      setUploadPhase("Upload cancelled");
    };
    xhr.send(formData);
  };

  const formatConfidence = (value) => {
    if (!value && value !== 0) return "N/A";
    if (value > 1) return `${Math.round(value)}%`;
    return `${Math.round(value * 100)}%`;
  };

  const normalizeEncryptionResult = (data, filesTracked) => {
    const alert = data.alert || {};
    return {
      timestamp: alert.timestamp || new Date().toISOString(),
      layers: {
        layer3_mass_encryption: data.alert_raised
          ? {
              status: "threat_detected",
              threat_level: alert.threat_level,
              confidence: alert.confidence || 0,
              indicators: alert.detected_indicators || [],
              affected_files: alert.affected_files_count || filesTracked,
              process_name: alert.process_name,
              process_pid: alert.process_pid,
              recommended_action: alert.recommended_action,
              is_backup_safe: alert.is_backup_safe,
            }
          : {
              status: "monitoring",
              confidence: 0,
              note: data.message || "File activity monitored - no threats detected",
            },
      },
      overall_verdict: data.alert_raised ? "RANSOMWARE_DETECTED" : "BENIGN",
      detection_confidence: alert.confidence || 0,
      severity: alert.threat_level || "LOW",
      triggered_layers: data.alert_raised ? ["Layer 3: Mass-Encryption"] : [],
      source_host: "TEST-WORKSTATION",
      process_name: alert.process_name || "test_process.exe",
      process_pid: alert.process_pid || 1234,
      response_recommendations: data.response_recommendations || [],
      reporting: data.reporting,
      processing_time_ms: 0,
    };
  };

  const resultVerdict = result?.overall_verdict || (
    result?.pipeline_results?.detection?.is_ransomware ? "RANSOMWARE_DETECTED" : "BENIGN"
  );

  const resultTone =
    resultVerdict === "RANSOMWARE_DETECTED"
      ? "border-red-800 bg-red-900/20"
      : resultVerdict === "SUSPICIOUS"
      ? "border-yellow-800 bg-yellow-900/20"
      : "border-green-800 bg-green-900/20";

  return (
    <div className="space-y-4">
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-slate-200 text-base">3-Layer Detection Mode</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-3 gap-2">
            {[
              { id: "command", label: "Layer 1 Only", desc: "Command behavior analysis" },
              { id: "encryption", label: "Layer 3 Only", desc: "Encryption detection" },
              { id: "full", label: "All 3 Layers", desc: "Full analysis" },
            ].map((mode) => (
              <button
                key={mode.id}
                type="button"
                onClick={() => {
                  clearDetectionTimers();
                  clearResponseTimers();
                  setDetectingMode(mode.id);
                  setResult(null);
                  setScanProgress(0);
                  setScanPhase("Idle");
                  setDetectionTimeline([]);
                  setAutoResponseSteps([]);
                }}
                className={`p-3 rounded-lg border-2 transition-all text-left ${
                  detectingMode === mode.id
                    ? "border-emerald-500 bg-emerald-900/20"
                    : "border-slate-700 bg-slate-800/20 hover:border-slate-600"
                }`}
              >
                <p className="text-sm font-semibold text-slate-200">{mode.label}</p>
                <p className="text-xs text-slate-500">{mode.desc}</p>
              </button>
            ))}
          </div>

          {(detectingMode === "command" || detectingMode === "full") && (
            <div>
              <label className="text-xs text-slate-500 uppercase block mb-2">Command to Analyze</label>
              <input
                type="text"
                value={commandInput}
                onChange={(event) => setCommandInput(event.target.value)}
                placeholder="e.g., cmd.exe /c vssadmin delete shadows /all"
                className="w-full bg-slate-800 border border-slate-700 text-slate-200 text-sm rounded-lg px-3 py-2 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
              />
              <p className="text-xs text-slate-500 mt-1">{commandInput.length} characters</p>
            </div>
          )}

          {detectingMode === "full" && (
            <div>
              <label className="text-xs text-slate-500 uppercase block mb-2">
                Binary Path (quarantine only)
              </label>
              <input
                type="text"
                value={binaryPath}
                onChange={(event) => setBinaryPath(event.target.value)}
                placeholder="backend/data/quarantine/sample.exe"
                className="w-full bg-slate-800 border border-slate-700 text-slate-200 text-sm rounded-lg px-3 py-2 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
              />
              <p className="text-xs text-slate-500 mt-1">
                Layer 2 accepts files stored in backend/data/quarantine.
              </p>
            </div>
          )}

          {(detectingMode === "encryption" || detectingMode === "full") && (
            <div>
              <label className="text-xs text-slate-500 uppercase block mb-2">Simulated File Activities</label>
              <div className="flex items-center gap-3">
                <input
                  type="range"
                  min="10"
                  max="200"
                  step="10"
                  value={String(fileCount)}
                  onInput={handleFileCountChange}
                  onChange={handleFileCountChange}
                  aria-valuemin={10}
                  aria-valuemax={200}
                  aria-valuenow={fileCount}
                  className="flex-1 h-2 bg-slate-700 rounded-lg cursor-pointer accent-emerald-500"
                />
                <span className="text-sm font-semibold text-slate-300 min-w-[50px]">{fileCount} files</span>
              </div>
              <p className="text-xs text-slate-500 mt-2">
                Simulates {fileCount} rapid file modifications with ransomware-like extensions.
              </p>
            </div>
          )}

          {error && (
            <div className="bg-red-900/30 border border-red-800 text-red-400 text-sm rounded-lg px-3 py-2">
              {error}
            </div>
          )}

          <button
            type="button"
            onClick={handleThreeLayerDetection}
            disabled={scanDisabled}
            className="w-full px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-700 disabled:text-slate-500 text-white text-sm font-medium rounded-lg transition-colors flex items-center justify-center gap-2"
          >
            {detecting ? (
              <>
                <div className="animate-spin rounded-full h-3 w-3 border-b-2 border-white" />
                Analyzing...
              </>
            ) : (
              "Analyze with 3-Layer Detection"
            )}
          </button>

          {(detecting || detectionTimeline.length > 0) && (
            <div className="rounded-lg border border-slate-800 bg-slate-800/30 p-3 space-y-3">
              <div className="flex justify-between text-xs text-slate-400">
                <span>{scanPhase}</span>
                <span>{scanProgress}%</span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-700">
                <div
                  className="h-2 rounded-full bg-emerald-500 transition-all"
                  style={{ width: `${scanProgress}%` }}
                />
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                  <p className="text-xs text-slate-500 uppercase mb-2">Detection Timeline</p>
                  <div className="space-y-1">
                    {detectionTimeline.slice(-5).map((item, index) => (
                      <p key={`${item}-${index}`} className="text-xs text-slate-300">
                        {item}
                      </p>
                    ))}
                  </div>
                </div>
                <div>
                  <p className="text-xs text-slate-500 uppercase mb-2">File Activity</p>
                  <p className="text-xs text-slate-300">
                    {fileActivitySpike}/{fileCount} events observed during scan
                  </p>
                  {autoResponseSteps.length > 0 && (
                    <div className="mt-2 space-y-1">
                      {autoResponseSteps.map((item, index) => (
                        <p key={`${item}-${index}`} className="text-xs text-emerald-300">
                          {item}
                        </p>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-slate-200 text-base">Executable File Analysis</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div
            onDragOver={(event) => {
              event.preventDefault();
              setDragActive(true);
            }}
            onDragLeave={() => setDragActive(false)}
            onDrop={(event) => {
              event.preventDefault();
              setDragActive(false);
              handleExeSelection(event.dataTransfer.files?.[0]);
            }}
            className={`border-2 border-dashed rounded-lg p-5 text-center transition-colors ${
              dragActive ? "border-emerald-500 bg-emerald-900/20" : "border-slate-700 bg-slate-800/20"
            }`}
          >
            <p className="text-sm font-medium text-slate-200">Drop an EXE sample here</p>
            <p className="text-xs text-slate-500 mt-1">
              PE headers, SHA256, entropy, suspicious imports, YARA, and ML score
            </p>
            <input
              type="file"
              accept=".exe,.dll,.scr,.bin,application/x-msdownload"
              onChange={(event) => handleExeSelection(event.target.files?.[0])}
              className="mt-3 block w-full text-xs text-slate-400 file:mr-3 file:rounded file:border-0 file:bg-slate-700 file:px-3 file:py-2 file:text-slate-200 hover:file:bg-slate-600"
            />
          </div>

          {selectedExe && (
            <div className="flex items-center justify-between gap-3 bg-slate-800/40 rounded-lg p-3">
              <div className="min-w-0">
                <p className="text-sm text-slate-200 truncate">{selectedExe.name}</p>
                <p className="text-xs text-slate-500">{(selectedExe.size / 1024).toFixed(1)} KB</p>
              </div>
              <button
                type="button"
                onClick={handleExeUpload}
                disabled={uploadingExe}
                className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-700 disabled:text-slate-500 text-white text-sm font-medium rounded-lg transition-colors"
              >
                {uploadingExe ? "Analyzing..." : "Analyze EXE"}
              </button>
            </div>
          )}

          {(uploadingExe || uploadProgress > 0) && (
            <div>
              <div className="flex justify-between text-xs text-slate-500 mb-1">
                <span>{uploadPhase}</span>
                <span>{uploadProgress}%</span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-700">
                <div
                  className="h-2 rounded-full bg-emerald-500 transition-all"
                  style={{ width: `${uploadProgress}%` }}
                />
              </div>
            </div>
          )}

          {uploadResult && (
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
              <div className="bg-slate-800/50 rounded-lg p-3">
                <p className="text-xs text-slate-500 mb-1">Verdict</p>
                <p
                  className={`text-sm font-bold ${
                    uploadResult.overall_verdict === "RANSOMWARE_DETECTED"
                      ? "text-red-400"
                      : uploadResult.overall_verdict === "SUSPICIOUS"
                      ? "text-yellow-400"
                      : "text-green-400"
                  }`}
                >
                  {uploadResult.overall_verdict?.replace(/_/g, " ")}
                </p>
              </div>
              <div className="bg-slate-800/50 rounded-lg p-3">
                <p className="text-xs text-slate-500 mb-1">Severity</p>
                <p className="text-sm font-bold text-slate-200">{uploadResult.severity}</p>
              </div>
              <div className="bg-slate-800/50 rounded-lg p-3">
                <p className="text-xs text-slate-500 mb-1">Confidence</p>
                <p className="text-sm font-bold text-slate-200">
                  {formatConfidence(uploadResult.detection_confidence)}
                </p>
              </div>
              <div className="bg-slate-800/50 rounded-lg p-3">
                <p className="text-xs text-slate-500 mb-1">SHA256</p>
                <p className="text-xs font-mono text-slate-300 truncate">{uploadResult.sample?.sha256}</p>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-slate-200 text-base">Live Monitoring</CardTitle>
            <button
              type="button"
              onClick={() => setIsMonitoring((value) => !value)}
              className="rounded border border-slate-700 bg-slate-800/70 px-3 py-1 text-xs font-semibold text-slate-200 hover:border-cyan-700 hover:text-cyan-300"
            >
              {isMonitoring ? "Pause" : "Resume"}
            </button>
          </div>
        </CardHeader>
        <CardContent>
          {activityLogs.length === 0 ? (
            <p className="text-xs text-slate-500">Monitoring logs will appear here.</p>
          ) : (
            <div className="space-y-1">
              {activityLogs.map((item, index) => (
                <p key={`${item}-${index}`} className="text-xs font-mono text-slate-400">
                  {item}
                </p>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {result && (
        <Card className={`border-2 ${resultTone}`}>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-slate-200">Detection Result</CardTitle>
              <Badge
                variant={
                  resultVerdict === "RANSOMWARE_DETECTED"
                    ? "destructive"
                    : resultVerdict === "SUSPICIOUS"
                    ? "warning"
                    : "success"
                }
              >
                {resultVerdict.replace(/_/g, " ")}
              </Badge>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-slate-800/50 rounded-lg p-3">
                <p className="text-xs text-slate-500 mb-1">Confidence</p>
                <p className="text-lg font-bold text-slate-200">
                  {formatConfidence(result.detection_confidence)}
                </p>
              </div>
              <div className="bg-slate-800/50 rounded-lg p-3">
                <p className="text-xs text-slate-500 mb-1">Processing Time</p>
                <p className="text-lg font-bold text-slate-200">{result.processing_time_ms}ms</p>
              </div>
            </div>

            <div>
              <p className="text-xs text-slate-500 uppercase mb-2">Layers</p>
              <div className="space-y-2">
                {result.layers?.layer1_command_behavior && (
                  <div className="flex items-center justify-between p-2 bg-slate-800/30 rounded">
                    <span className="text-sm text-slate-300">Layer 1: Command Behavior</span>
                    {result.layers.layer1_command_behavior.is_ransomware ? (
                      <Badge variant="destructive">Detected</Badge>
                    ) : result.layers.layer1_command_behavior.status === "error" ? (
                      <Badge variant="secondary">Error</Badge>
                    ) : (
                      <Badge variant="success">Safe</Badge>
                    )}
                  </div>
                )}
                {result.layers?.layer2_pe_header && (
                  <div className="flex items-center justify-between p-2 bg-slate-800/30 rounded">
                    <span className="text-sm text-slate-300">Layer 2: PE Header</span>
                    {result.layers.layer2_pe_header.is_ransomware ? (
                      <Badge variant="destructive">Detected</Badge>
                    ) : result.layers.layer2_pe_header.status === "error" ? (
                      <Badge variant="secondary">Error</Badge>
                    ) : result.layers.layer2_pe_header.status === "success" ? (
                      <Badge variant="success">Analyzed</Badge>
                    ) : (
                      <Badge variant="secondary">Waiting</Badge>
                    )}
                  </div>
                )}
                {result.layers?.layer3_mass_encryption && (
                  <div className="flex items-center justify-between p-2 bg-slate-800/30 rounded">
                    <span className="text-sm text-slate-300">Layer 3: Mass-Encryption</span>
                    {result.layers.layer3_mass_encryption.status === "threat_detected" ? (
                      <Badge variant="destructive">Detected</Badge>
                    ) : result.layers.layer3_mass_encryption.status === "error" ? (
                      <Badge variant="secondary">Error</Badge>
                    ) : (
                      <Badge variant="success">Clear</Badge>
                    )}
                  </div>
                )}
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default ThreeLayerDetectionScanner;
