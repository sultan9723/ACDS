import React, { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Download,
  KeyRound,
  RefreshCw,
  ShieldCheck,
  TestTube2,
} from "lucide-react";
import {
  analyzeCredentialStuffingEvents,
  getCredentialStuffingAlerts,
  getCredentialStuffingHealth,
  getCredentialStuffingReportUrl,
  getCredentialStuffingRetrainingData,
  simulateCredentialStuffingAttack,
  submitCredentialLoginEvent,
  submitCredentialStuffingFeedback,
} from "../utils/api";

const initialEvent = {
  username: "analyst.demo",
  ip_address: "198.51.100.25",
  success: "false",
  user_agent: "Mozilla/5.0 ACDS Demo",
  country: "US",
};

const severityClass = {
  CRITICAL: "bg-red-500/15 text-red-200 border-red-500/30",
  HIGH: "bg-rose-500/15 text-rose-200 border-rose-500/30",
  MEDIUM: "bg-amber-500/15 text-amber-200 border-amber-500/30",
  LOW: "bg-emerald-500/15 text-emerald-200 border-emerald-500/30",
  SAFE: "bg-emerald-500/15 text-emerald-200 border-emerald-500/30",
};

const formatValue = (value) => {
  if (value === null || value === undefined || value === "") return "N/A";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "number") return Number.isInteger(value) ? value : value.toFixed(2);
  return String(value);
};

const formatDetectionPhase = (value) => {
  const mappings = {
    rule_based_with_optional_ml: "Rule + Optional ML",
    rule_based: "Rule Based",
    ml_model: "ML Model",
    hybrid: "Hybrid",
  };

  if (!value) return "N/A";
  if (mappings[value]) return mappings[value];

  return String(value)
    .replace(/_/g, " ")
    .replace(/\w\S*/g, (word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase());
};

const formatDate = (value) => {
  if (!value) return "N/A";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
};

const getErrorMessage = (error) =>
  error?.detail || error?.message || "Request failed. Check backend availability.";

const HealthCard = ({ label, value, tone = "default", title }) => {
  const toneClass =
    tone === "good"
      ? "text-emerald-300"
      : tone === "warn"
      ? "text-amber-300"
      : "text-slate-200";

  return (
    <div className="rounded-lg border border-slate-800/80 bg-slate-900/70 p-4">
      <p className="text-xs uppercase tracking-wider text-slate-500">{label}</p>
      <p
        title={title}
        className={`mt-2 max-w-full truncate text-lg font-semibold ${toneClass}`}
      >
        {formatValue(value)}
      </p>
    </div>
  );
};

const ActionButton = ({ children, icon: Icon, className = "", ...props }) => (
  <button
    className={`inline-flex items-center justify-center gap-2 rounded-lg border border-slate-700/80 bg-slate-800/70 px-3 py-2 text-sm font-medium text-slate-100 transition-colors hover:border-slate-600 hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-50 ${className}`}
    {...props}
  >
    {Icon ? <Icon size={16} /> : null}
    {children}
  </button>
);

const DetailPill = ({ label, value }) => (
  <div className="rounded-lg border border-slate-800/80 bg-slate-950/45 px-3 py-2">
    <p className="text-[11px] uppercase tracking-wider text-slate-500">{label}</p>
    <p className="mt-1 text-sm font-medium text-slate-100">{formatValue(value)}</p>
  </div>
);

const CredentialStuffingModule = () => {
  const [health, setHealth] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [retrainingData, setRetrainingData] = useState(null);
  const [detectionResult, setDetectionResult] = useState(null);
  const [formData, setFormData] = useState(initialEvent);
  const [loading, setLoading] = useState({
    health: false,
    alerts: false,
    retraining: false,
    action: false,
    feedback: null,
  });
  const [error, setError] = useState("");

  const latestTrainingRecord = useMemo(() => {
    const records = retrainingData?.records || retrainingData?.retraining_data || [];
    return Array.isArray(records) && records.length > 0 ? records[0] : null;
  }, [retrainingData]);

  const retrainingCount = useMemo(() => {
    if (typeof retrainingData?.count === "number") return retrainingData.count;
    const records = retrainingData?.records || retrainingData?.retraining_data || [];
    return Array.isArray(records) ? records.length : 0;
  }, [retrainingData]);

  const fetchHealth = async () => {
    setLoading((prev) => ({ ...prev, health: true }));
    setError("");
    try {
      const data = await getCredentialStuffingHealth();
      setHealth(data || null);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setLoading((prev) => ({ ...prev, health: false }));
    }
  };

  const fetchAlerts = async () => {
    setLoading((prev) => ({ ...prev, alerts: true }));
    setError("");
    try {
      const data = await getCredentialStuffingAlerts({ limit: 50 });
      setAlerts(Array.isArray(data?.alerts) ? data.alerts : []);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setLoading((prev) => ({ ...prev, alerts: false }));
    }
  };

  const fetchRetrainingData = async () => {
    setLoading((prev) => ({ ...prev, retraining: true }));
    setError("");
    try {
      const data = await getCredentialStuffingRetrainingData({ limit: 20 });
      setRetrainingData(data || null);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setLoading((prev) => ({ ...prev, retraining: false }));
    }
  };

  const refreshAll = async () => {
    await Promise.all([fetchHealth(), fetchAlerts(), fetchRetrainingData()]);
  };

  useEffect(() => {
    refreshAll();
  }, []);

  const handleInputChange = (event) => {
    const { name, value } = event.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const handleManualSubmit = async (event) => {
    event.preventDefault();
    setLoading((prev) => ({ ...prev, action: true }));
    setError("");
    try {
      const result = await submitCredentialLoginEvent({
        username: formData.username,
        ip_address: formData.ip_address,
        success: formData.success === "true",
        user_agent: formData.user_agent,
        country: formData.country,
      });
      setDetectionResult(result);
      await Promise.all([fetchAlerts(), fetchRetrainingData()]);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setLoading((prev) => ({ ...prev, action: false }));
    }
  };

  const handleSimulateAttack = async () => {
    setLoading((prev) => ({ ...prev, action: true }));
    setError("");
    try {
      const result = await simulateCredentialStuffingAttack({
        source_ip: "198.51.100.25",
        username_prefix: "demo_user",
        count: 12,
      });
      setDetectionResult(result);
      await Promise.all([fetchAlerts(), fetchRetrainingData()]);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setLoading((prev) => ({ ...prev, action: false }));
    }
  };

  const handleBatchAnalyze = async () => {
    setLoading((prev) => ({ ...prev, action: true }));
    setError("");
    try {
      const now = Date.now();
      const events = Array.from({ length: 12 }, (_, index) => ({
        username: `batch_user_${index % 7}`,
        ip_address: "203.0.113.42",
        success: false,
        user_agent: `ACDS Batch Browser ${index % 3}`,
        country: index % 2 === 0 ? "US" : "GB",
        timestamp: new Date(now - (12 - index) * 10000).toISOString(),
      }));
      const result = await analyzeCredentialStuffingEvents(events);
      setDetectionResult(result);
      await Promise.all([fetchAlerts(), fetchRetrainingData()]);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setLoading((prev) => ({ ...prev, action: false }));
    }
  };

  const handleFeedback = async (alertId, feedback) => {
    setLoading((prev) => ({ ...prev, feedback: `${alertId}:${feedback}` }));
    setError("");
    try {
      await submitCredentialStuffingFeedback({
        alert_id: alertId,
        feedback,
        analyst: "frontend_analyst",
      });
      await Promise.all([fetchAlerts(), fetchRetrainingData()]);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setLoading((prev) => ({ ...prev, feedback: null }));
    }
  };

  const openReport = (alertId) => {
    window.open(getCredentialStuffingReportUrl(alertId), "_blank", "noopener,noreferrer");
  };

  const resultFeatures = detectionResult?.features || {};
  const resultEvidence = Array.isArray(detectionResult?.evidence)
    ? detectionResult.evidence
    : [];

  return (
    <div className="space-y-5 min-h-[calc(100vh-100px)] pb-8">
      <div className="rounded-xl border border-slate-800/80 bg-slate-900/70 p-5 shadow-[0_18px_45px_rgba(2,6,23,0.18)]">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300/80">
              Detection Module
            </p>
            <h1 className="mt-1 text-2xl font-semibold tracking-tight text-slate-100">
              Credential Stuffing Detection
            </h1>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
              Monitor login behavior with explainable rules, optional model
              scoring, analyst feedback, and retraining evidence.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={handleBatchAnalyze}
              disabled={loading.action}
              className="rounded-lg border border-cyan-500/30 bg-cyan-500/15 px-4 py-2 text-sm font-semibold text-cyan-100 transition-colors hover:bg-cyan-500/25 disabled:cursor-not-allowed disabled:opacity-60"
            >
              Run Credential Stuffing Analysis
            </button>
            <span className="rounded-full border border-emerald-500/25 bg-emerald-500/10 px-3 py-1 text-xs font-semibold text-emerald-200">
              System Active
            </span>
            <span className="rounded-full border border-cyan-500/25 bg-cyan-500/10 px-3 py-1 text-xs font-semibold text-cyan-200">
              Hybrid ML + Rule Engine
            </span>
          </div>
        </div>
      </div>

      {error ? (
        <div className="rounded-lg border border-red-900/70 bg-red-950/40 px-4 py-3 text-sm text-red-200">
          {error}
        </div>
      ) : null}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-5">
        <HealthCard
          label="Module Status"
          value={health?.status || "unknown"}
          tone={health?.status === "healthy" ? "good" : "warn"}
        />
        <HealthCard
          label="Database"
          value={health?.database_available}
          tone={health?.database_available ? "good" : "warn"}
        />
        <HealthCard
          label="Collections"
          value={health?.collections_available}
          tone={health?.collections_available ? "good" : "warn"}
        />
        <HealthCard
          label="Model"
          value={health?.model_available}
          tone={health?.model_available ? "good" : "warn"}
        />
        <HealthCard
          label="Detection Phase"
          value={formatDetectionPhase(health?.phase)}
          title={health?.phase || "N/A"}
        />
      </div>

      <div className="flex flex-wrap gap-3 rounded-xl border border-slate-800/80 bg-slate-900/70 p-4">
        <ActionButton icon={RefreshCw} onClick={fetchHealth} disabled={loading.health}>
          Refresh Health
        </ActionButton>
        <ActionButton icon={AlertTriangle} onClick={handleSimulateAttack} disabled={loading.action}>
          Simulate Attack
        </ActionButton>
        <ActionButton icon={TestTube2} onClick={handleBatchAnalyze} disabled={loading.action}>
          Run Credential Stuffing Analysis
        </ActionButton>
        <ActionButton icon={Activity} onClick={fetchAlerts} disabled={loading.alerts}>
          Refresh Alerts
        </ActionButton>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        <form
          onSubmit={handleManualSubmit}
          className="rounded-xl border border-slate-800/80 bg-slate-900/70 p-5"
        >
          <div className="mb-5 flex items-center gap-2">
            <KeyRound className="h-5 w-5 text-emerald-400" />
            <h2 className="text-lg font-semibold text-slate-100">Manual Login Event</h2>
          </div>

          <div className="space-y-4">
            {[
              ["username", "Username"],
              ["ip_address", "IP Address"],
              ["user_agent", "User Agent"],
              ["country", "Country"],
            ].map(([name, label]) => (
              <label key={name} className="block">
                <span className="text-xs font-medium uppercase tracking-wider text-slate-500">
                  {label}
                </span>
                <input
                  name={name}
                  value={formData[name]}
                  onChange={handleInputChange}
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2 text-sm text-slate-100 outline-none transition-colors focus:border-emerald-500"
                />
              </label>
            ))}

            <label className="block">
              <span className="text-xs font-medium uppercase tracking-wider text-slate-500">
                Success
              </span>
              <select
                name="success"
                value={formData.success}
                onChange={handleInputChange}
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2 text-sm text-slate-100 outline-none transition-colors focus:border-emerald-500"
              >
                <option value="false">false</option>
                <option value="true">true</option>
              </select>
            </label>

            <ActionButton
              type="submit"
              icon={ShieldCheck}
              disabled={loading.action}
              className="w-full border-emerald-700 bg-emerald-600/20 text-emerald-200 hover:bg-emerald-600/30"
            >
              Submit Event
            </ActionButton>
          </div>
        </form>

        <div className="rounded-xl border border-slate-800/80 bg-slate-900/70 p-5 xl:col-span-2">
          <div className="mb-5 flex items-center justify-between gap-3">
            <h2 className="text-lg font-semibold text-slate-100">Detection Result</h2>
            {detectionResult?.severity ? (
              <span
                className={`rounded-full border px-3 py-1 text-xs font-semibold ${
                  severityClass[detectionResult.severity] || "border-slate-700 bg-slate-800 text-slate-300"
                }`}
              >
                {detectionResult.severity}
              </span>
            ) : null}
          </div>

          {detectionResult ? (
            <div className="space-y-5">
              <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
                <DetailPill label="Confidence" value={detectionResult.confidence} />
                <DetailPill label="Risk Score" value={detectionResult.risk_score} />
                <DetailPill label="Source" value={detectionResult.detection_source} />
                <DetailPill label="Action" value={detectionResult.recommended_action} />
                <DetailPill label="Model Prediction" value={detectionResult.model_prediction} />
                <DetailPill label="Model Confidence" value={detectionResult.model_confidence} />
                <DetailPill label="Alert Created" value={detectionResult.alert_created} />
                <DetailPill label="Alert ID" value={detectionResult.alert_id} />
              </div>

              <div>
                <h3 className="mb-2 text-sm font-semibold text-slate-300">Evidence</h3>
                <ul className="space-y-2">
                  {(resultEvidence.length ? resultEvidence : ["No evidence returned."]).map((item, index) => (
                    <li key={`${item}-${index}`} className="rounded-lg bg-slate-950/50 px-3 py-2 text-sm text-slate-300">
                      {item}
                    </li>
                  ))}
                </ul>
              </div>

              <div>
                <h3 className="mb-2 text-sm font-semibold text-slate-300">Features</h3>
                <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                  {Object.entries(resultFeatures).length > 0 ? (
                    Object.entries(resultFeatures).map(([key, value]) => (
                      <div key={key} className="flex items-center justify-between rounded-lg bg-slate-950/50 px-3 py-2 text-sm">
                        <span className="text-slate-500">{key}</span>
                        <span className="font-medium text-slate-200">{formatValue(value)}</span>
                      </div>
                    ))
                  ) : (
                    <p className="text-sm text-slate-500">No feature data returned.</p>
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div className="flex min-h-[260px] flex-col items-center justify-center rounded-lg border border-dashed border-slate-800 px-6 text-center">
              <p className="text-sm font-medium text-slate-300">
                No detection result selected
              </p>
              <p className="mt-2 max-w-md text-xs leading-5 text-slate-500">
                Submit a login event, simulate an attack, or run batch analysis
                to populate risk scoring and evidence.
              </p>
            </div>
          )}
        </div>
      </div>

      <div className="rounded-xl border border-slate-800/80 bg-slate-900/70">
        <div className="flex flex-col gap-2 border-b border-slate-800/80 p-5 md:flex-row md:items-center md:justify-between">
          <div>
            <h2 className="text-lg font-semibold text-slate-100">Recent Alerts</h2>
            <p className="text-sm text-slate-500">
              {loading.alerts ? "Loading alerts..." : `${alerts.length} alerts loaded`}
            </p>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full min-w-[980px] text-left text-sm">
            <thead className="border-b border-slate-800 text-xs uppercase tracking-wider text-slate-500">
              <tr>
                <th className="px-4 py-3">Alert ID</th>
                <th className="px-4 py-3">Source IP</th>
                <th className="px-4 py-3">Username</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Confidence</th>
                <th className="px-4 py-3">Source</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Created</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {alerts.length > 0 ? (
                alerts.map((alert) => (
                  <tr
                    key={alert.alert_id || alert.id}
                    className="text-slate-300 transition-colors hover:bg-slate-800/35"
                  >
                    <td className="px-4 py-3 font-mono text-xs text-emerald-300">
                      {formatValue(alert.alert_id)}
                    </td>
                    <td className="px-4 py-3">{formatValue(alert.source_ip)}</td>
                    <td className="px-4 py-3">{formatValue(alert.username)}</td>
                    <td className="px-4 py-3">
                      <span
                        className={`rounded-full border px-2 py-1 text-xs ${
                          severityClass[alert.severity] || "border-slate-700 bg-slate-800 text-slate-300"
                        }`}
                      >
                        {formatValue(alert.severity)}
                      </span>
                    </td>
                    <td className="px-4 py-3">{formatValue(alert.confidence)}</td>
                    <td className="px-4 py-3">{formatValue(alert.detection_source)}</td>
                    <td className="px-4 py-3">{formatValue(alert.status)}</td>
                    <td className="px-4 py-3">{formatDate(alert.created_at)}</td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-2">
                        {["true_positive", "false_positive", "needs_review"].map((feedback) => (
                          <button
                            key={feedback}
                            onClick={() => handleFeedback(alert.alert_id, feedback)}
                            disabled={loading.feedback === `${alert.alert_id}:${feedback}`}
                            className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-300 transition-colors hover:border-emerald-700 hover:text-emerald-300 disabled:opacity-50"
                          >
                            {feedback.replace("_", " ")}
                          </button>
                        ))}
                        <button
                          onClick={() => openReport(alert.alert_id)}
                          className="inline-flex items-center gap-1 rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-300 transition-colors hover:border-blue-700 hover:text-blue-300"
                        >
                          <Download size={13} />
                          Report
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="9" className="px-4 py-10 text-center">
                    <p className="text-sm font-medium text-slate-300">
                      No credential stuffing alerts found
                    </p>
                    <p className="mt-1 text-xs text-slate-500">
                      New alerts will appear here after suspicious login
                      patterns are submitted or simulated.
                    </p>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="rounded-xl border border-slate-800/80 bg-slate-900/70 p-5">
        <div className="mb-4 flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
          <div>
            <h2 className="text-lg font-semibold text-slate-100">Retraining Summary</h2>
            <p className="text-sm text-slate-500">
              Analyst feedback records prepared for future model improvement.
            </p>
          </div>
          <ActionButton icon={RefreshCw} onClick={fetchRetrainingData} disabled={loading.retraining}>
            Refresh Retraining
          </ActionButton>
        </div>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          <HealthCard label="Labeled Records" value={retrainingCount} />
          <HealthCard label="Latest Feedback" value={latestTrainingRecord?.feedback} />
          <HealthCard label="Latest Label" value={latestTrainingRecord?.label} />
        </div>
      </div>
    </div>
  );
};

export default CredentialStuffingModule;
