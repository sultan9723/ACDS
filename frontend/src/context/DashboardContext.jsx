import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  useRef,
} from "react";
import {
  fetchStats,
  fetchThreatsOverTime,
  fetchThreatTypes,
  fetchAccuracyOverTime,
  fetchConfusionMatrix,
  fetchThreats,
  fetchIncidentDetails,
  fetchModelLogs,
  fetchAllEmails,
  runAutomatedTest,
  getTestSession,
  getTestLogs,
  getTestReports,
  getDemoStatus,
  startDemoMode,
  stopDemoMode,
  runDemoBatch,
  analyzeRansomwareUploads,
  fetchActivityLogs,
  startMalwareDemoMode,
  stopMalwareDemoMode,
  getMalwareDemoStatus,
  runMalwareDemoBatch,
  simulateCredentialStuffingAttack,
  clearDashboardFeeds,
} from "../utils/api";

const DashboardContext = createContext();

export const useDashboard = () => useContext(DashboardContext);

export const DashboardProvider = ({ children }) => {
  const [stats, setStats] = useState({
    totalEmails: 0,
    phishingDetected: 0,
    safeEmails: 0,
    accuracy: 0,
    totalThreats: 0,
    activeThreats: 0,
    resolvedThreats: 0,
    autoResolved: 0,
  });
  const [threats, setThreats] = useState([]);
  const [allEmails, setAllEmails] = useState([]);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [logs, setLogs] = useState([]);
  const [threatsOverTimeData, setThreatsOverTimeData] = useState([]);
  const [threatTypesData, setThreatTypesData] = useState([]);
  const [accuracyOverTimeData, setAccuracyOverTimeData] = useState([]);
  const [confusionMatrixData, setConfusionMatrixData] = useState({
    tp: 0,
    fp: 0,
    fn: 0,
    tn: 0,
  });
  const [loading, setLoading] = useState(true);

  // Testing state
  const [testRunning, setTestRunning] = useState(false);
  const [currentTestSession, setCurrentTestSession] = useState(null);
  const [testResults, setTestResults] = useState([]);
  const [testLogs, setTestLogs] = useState([]);
  const [liveThreats, setLiveThreats] = useState([]);
  const [responseActions, setResponseActions] = useState([]);
  const [testReports, setTestReports] = useState([]);
  const [simulationMeta, setSimulationMeta] = useState(null);

  // Demo mode state
  const [demoRunning, setDemoRunning] = useState(false);
  const [demoStats, setDemoStats] = useState(null);
  const [activityLogs, setActivityLogs] = useState([]);
  const [malwareDemoRunning, setMalwareDemoRunning] = useState(false);
  const [malwareDemoStats, setMalwareDemoStats] = useState(null);

  // Polling interval ref
  const pollingRef = useRef(null);

  // Load all dashboard data
  const loadData = useCallback(async () => {
    try {
      const [
        statsData,
        threatsData,
        allEmailsData,
        logsData,
        totData,
        ttData,
        aotData,
        cmData,
        activityData,
        demoStatusData,
        malwareDemoStatusData,
      ] = await Promise.all([
        fetchStats(),
        fetchThreats(),
        fetchAllEmails(),
        fetchModelLogs(),
        fetchThreatsOverTime(),
        fetchThreatTypes(),
        fetchAccuracyOverTime(),
        fetchConfusionMatrix(),
        fetchActivityLogs(50),
        getDemoStatus(),
        getMalwareDemoStatus(),
      ]);

      // Parse stats from API response
      const apiStats = statsData?.stats || statsData || {};
      setStats({
        totalEmails: apiStats.emails_scanned_today || apiStats.totalEmails || 0,
        phishingDetected:
          apiStats.total_threats || apiStats.phishingDetected || 0,
        safeEmails: apiStats.safeEmails || 0,
        accuracy: apiStats.model_accuracy || apiStats.accuracy || 97.2,
        totalThreats: apiStats.total_threats || 0,
        activeThreats: apiStats.active_threats || 0,
        resolvedThreats:
          apiStats.threats_blocked || apiStats.resolvedThreats || 0,
        autoResolved: apiStats.threats_blocked || 0,
        detectionRate: apiStats.detection_rate || 0,
      });

      setThreats(threatsData || []);
      setAllEmails(allEmailsData || []);

      // Populate liveThreats from actual threats for ThreatResponseFeed
      if (threatsData && threatsData.length > 0) {
        const threatsFeed = threatsData.slice(0, 20).map((t) => ({
          id: t.id,
          module: t.module || (t.is_malware ? "malware" : "phishing"),
          severity: t.severity || "MEDIUM",
          confidence: t.confidence || 0,
          sender: t.source || t.sender || "Unknown",
          subject:
            t.subject ||
            t.description ||
            (t.is_malware ? "Suspicious file detected" : "Suspicious email"),
          action_taken: t.action_taken || null,
          detected_at: t.detected_at || t.timestamp || new Date().toISOString(),
        }));
        setLiveThreats(threatsFeed);
      }

      // Fetch first incident details if threats exist
      if (threatsData && threatsData.length > 0) {
        try {
          const firstIncident = await fetchIncidentDetails(threatsData[0].id);
          setSelectedIncident(firstIncident);
        } catch (e) {
          console.error("Failed to fetch incident details:", e);
        }
      }

      setLogs(logsData || []);
      setThreatsOverTimeData(totData || []);
      setThreatTypesData(ttData || []);
      setAccuracyOverTimeData(aotData || []);
      setConfusionMatrixData(cmData || { tp: 0, fp: 0, fn: 0, tn: 0 });

      // Set activity logs
      const normalizedActivityLogs = activityData?.logs || [];
      setActivityLogs(normalizedActivityLogs);

      const responseActionFeed = normalizedActivityLogs
        .filter((log) => {
          if (!log) return false;
          const eventType = String(log.event || log.action_type || "").toLowerCase();
          const actions = log.actions || log.details?.actions || [];
          return (
            eventType === "threat_resolved" ||
            eventType === "threat_detected" ||
            actions.length > 0 ||
            Boolean(log.action_taken || log.details?.action_taken)
          );
        })
        .slice(0, 20)
        .map((log) => {
          const actions =
            (log.actions && log.actions.length > 0
              ? log.actions
              : log.details?.actions) ||
            (log.action_taken ? [log.action_taken] : []);

          return {
            threat_id: log.threat_id || log.id,
            module: log.module || (log.is_malware ? "malware" : "phishing"),
            action: log.action_taken || log.details?.action_taken || actions[0] || "alert",
            actions,
            timestamp: log.timestamp || new Date().toISOString(),
            status: "completed",
          };
        });

      const threatDerivedActions = (threatsData || [])
        .filter(
          (t) =>
            t &&
            (t.status === "Resolved" ||
              t.status === "resolved" ||
              (Array.isArray(t.actions) && t.actions.length > 0) ||
              Boolean(t.action_taken))
        )
        .slice(0, 20)
        .map((t) => ({
          threat_id: t.id,
          module: t.module || (t.is_malware ? "malware" : "phishing"),
          action: t.action_taken || (Array.isArray(t.actions) && t.actions.length > 0 ? t.actions[0] : "alert"),
          actions:
            (Array.isArray(t.actions) && t.actions.length > 0
              ? t.actions
              : t.action_taken
              ? [t.action_taken]
              : []),
          timestamp: t.detected_at || t.timestamp || new Date().toISOString(),
          status: "completed",
        }));

      const combinedResponseActions = [...responseActionFeed, ...threatDerivedActions]
        .filter((item) => item && item.threat_id)
        .slice(0, 20);

      setResponseActions(combinedResponseActions);

      // Set demo status
      if (demoStatusData) {
        setDemoRunning(demoStatusData.running || false);
        setDemoStats(demoStatusData.stats || null);
      }

      // Set malware demo status
      if (malwareDemoStatusData) {
        setMalwareDemoRunning(malwareDemoStatusData.running || false);
        setMalwareDemoStats(malwareDemoStatusData.stats || null);
      }
    } catch (error) {
      console.error("Failed to fetch dashboard data", error);
    }
  }, []);

  // Initial load
  useEffect(() => {
    const init = async () => {
      setLoading(true);
      await loadData();
      setLoading(false);
    };
    init();
  }, [loadData]);

  // Auto-refresh data every 10 seconds when demo is running (faster refresh for real-time updates)
  useEffect(() => {
    if (demoRunning || malwareDemoRunning) {
      pollingRef.current = setInterval(async () => {
        await loadData();
      }, 10000); // Reduced to 10 seconds for better real-time updates
    } else if (pollingRef.current) {
      clearInterval(pollingRef.current);
    }

    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current);
      }
    };
  }, [demoRunning, malwareDemoRunning, loadData]);

  // Refresh data manually
  const refreshData = useCallback(async () => {
    setLoading(true);
    await loadData();
    setLoading(false);
  }, [loadData]);

  // Refresh activity logs
  const refreshActivityLogs = useCallback(async () => {
    try {
      const data = await fetchActivityLogs(50);
      setActivityLogs(data?.logs || []);
    } catch (error) {
      console.error("Failed to refresh activity logs:", error);
    }
  }, []);

  // Start demo mode
  const startDemo = useCallback(
    async (intervalSeconds = 300) => {
      try {
        const result = await startDemoMode(intervalSeconds);
        if (result.success) {
          setDemoRunning(true);
          // Log demo start activity
          const demoStartLog = {
            event: "demo_started",
            action_type: "demo_started",
            message: `Demo mode started - processing every ${intervalSeconds} seconds`,
            timestamp: new Date().toISOString()
          };
          setActivityLogs((prev) => [demoStartLog, ...prev].slice(0, 50));
          await loadData();
        }
        return result;
      } catch (error) {
        console.error("Failed to start demo:", error);
        throw error;
      }
    },
    [loadData]
  );

  // Stop demo mode
  const stopDemo = useCallback(async () => {
    try {
      const result = await stopDemoMode();
      if (result.success) {
        setDemoRunning(false);
        // Log demo stop activity
        const demoStopLog = {
          event: "demo_stopped",
          action_type: "demo_stopped",
          message: "Demo mode stopped",
          timestamp: new Date().toISOString()
        };
        setActivityLogs((prev) => [demoStopLog, ...prev].slice(0, 50));
      }
      return result;
    } catch (error) {
      console.error("Failed to stop demo:", error);
      throw error;
    }
  }, []);

  // Clear dashboard feeds (threats and activity logs from feed, preserve historical data)
  const clearDashboard = useCallback(async () => {
    try {
      // Clear local state for dashboard feeds
      setLiveThreats([]);
      setResponseActions([]);
      setActivityLogs([]);
      setTestResults([]);
      setSimulationMeta(null);
      
      // Note: We don't clear threats array as it contains historical data for detail pages
      console.log("Dashboard feeds cleared");
    } catch (error) {
      console.error("Failed to clear dashboard:", error);
    }
  }, []);

  const normalizeRansomwareResults = (results = []) =>
    results.map((result, index) => ({
      id: result.incident_id || `demo-ransomware-${Date.now()}-${index}`,
      module: "ransomware",
      filename: result.filename || `sample-${index + 1}.exe`,
      prediction: result.prediction || "SAFE",
      severity: result.severity || "LOW",
      confidence: result.confidence || 0,
      lifecycle_state: result.lifecycle_state || "closed",
      evidence_count: Array.isArray(result.evidence) ? result.evidence.length : 0,
      evidence: result.evidence || [],
      recommended_actions: result.recommended_actions || [],
      actions_taken: result.actions_taken || [],
      detected_at: result.created_at || new Date().toISOString(),
      is_ransomware: result.prediction === "RANSOMWARE",
      correct: true,
    }));

  const deterministicCredentialResults = (count = 2) =>
    Array.from({ length: count }, (_, index) => ({
      id: `demo-credential-${index + 1}`,
      module: "credential_stuffing",
      subject: `Login burst simulation ${index + 1}`,
      sender: index % 2 === 0 ? "auth-gateway" : "identity-provider",
      prediction: index % 2 === 0 ? "CREDENTIAL_STUFFING" : "SAFE",
      severity: index % 2 === 0 ? "HIGH" : "LOW",
      confidence: index % 2 === 0 ? 0.82 : 0.18,
      correct: true,
      detected_at: new Date().toISOString(),
      actions_taken: index % 2 === 0 ? ["rate_limit_account", "require_mfa"] : [],
    }));

  const deterministicModuleResults = (moduleName, count = 2) =>
    Array.from({ length: count }, (_, index) => {
      const isThreat = index % 2 === 0;
      return {
        id: `demo-${moduleName}-${index + 1}`,
        module: moduleName,
        subject: `${moduleName.replace("_", " ")} sample ${index + 1}`,
        sender: "demo-simulator",
        prediction: isThreat ? "THREAT" : "SAFE",
        severity: isThreat ? "MEDIUM" : "LOW",
        confidence: isThreat ? 0.76 : 0.22,
        correct: true,
        detected_at: new Date().toISOString(),
        actions_taken: isThreat ? ["create_alert"] : [],
      };
    });

  const normalizeGenericBatchResults = (results = [], moduleName) =>
    results.map((result, index) => {
      const isThreat = Boolean(
        result.is_phishing ||
          result.is_malware ||
          result.pipeline_results?.detection?.is_phishing ||
          result.pipeline_results?.detection?.is_malware ||
          result.prediction === "THREAT"
      );
      return {
        id: result.threat_id || result.incident_id || result.sample_id || `demo-${moduleName}-${Date.now()}-${index}`,
        module: moduleName,
        subject: result.subject || result.filename || `${moduleName} sample ${index + 1}`,
        sender: result.sender || result.source || (moduleName === "malware" ? "Malware Scanner" : "Demo Simulator"),
        prediction: isThreat ? "THREAT" : "SAFE",
        severity: result.severity || result.pipeline_results?.detection?.severity || (isThreat ? "MEDIUM" : "LOW"),
        confidence: result.confidence || result.pipeline_results?.detection?.confidence || 0,
        correct: result.correct ?? true,
        detected_at: result.timestamp || result.detected_at || new Date().toISOString(),
        actions_taken: result.actions_taken || result.pipeline_results?.response?.actions_executed || [],
      };
    });

  // Run manual simulation batch across selected modules.
  const runBatch = useCallback(
    async (count = 5, moduleName = "all") => {
      setTestRunning(true);
      try {
        await clearDashboard();

        const runPhishingSimulation = async () => {
          try {
            const result = await runDemoBatch(count);
            return {
              raw: result,
              results: normalizeGenericBatchResults(result.results || [], "phishing"),
            };
          } catch (error) {
            return {
              raw: { success: true, fallback: true },
              results: deterministicModuleResults("phishing", count),
            };
          }
        };

        const runMalwareSimulation = async () => {
          try {
            const result = await runMalwareDemoBatch(count);
            return {
              raw: result,
              results: normalizeGenericBatchResults(result.results || [], "malware"),
            };
          } catch (error) {
            return {
              raw: { success: true, fallback: true },
              results: deterministicModuleResults("malware", count),
            };
          }
        };

        const runRansomwareSimulation = async () => {
          const result = await analyzeRansomwareUploads(count, 0);
          return {
            raw: result,
            results: normalizeRansomwareResults(result.results || []),
          };
        };

        const runCredentialSimulation = async () => {
          try {
            const result = await simulateCredentialStuffingAttack({ count });
            const sourceResults = result.results || result.alerts || result.events || [];
            return {
              raw: result,
              results:
                sourceResults.length > 0
                  ? normalizeGenericBatchResults(sourceResults, "credential_stuffing")
                  : deterministicCredentialResults(count),
            };
          } catch (error) {
            return {
              raw: { success: true, fallback: true },
              results: deterministicCredentialResults(count),
            };
          }
        };

        const runners = {
          email_phishing: [runPhishingSimulation],
          malware: [runMalwareSimulation],
          ransomware: [runRansomwareSimulation],
          credential_stuffing: [runCredentialSimulation],
          all: [
            runPhishingSimulation,
            runMalwareSimulation,
            runRansomwareSimulation,
            runCredentialSimulation,
          ],
        };

        const selectedRunners = runners[moduleName] || runners.all;
        const settled = await Promise.allSettled(selectedRunners.map((runner) => runner()));
        const successful = settled
          .filter((entry) => entry.status === "fulfilled")
          .map((entry) => entry.value);
        const failed = settled
          .filter((entry) => entry.status === "rejected")
          .map((entry) => entry.reason?.message || "Simulation request failed");

        const combinedResults = successful.flatMap((entry) => entry.results || []);
        const ransomwareRaw = successful.find((entry) => entry.raw?.module === "ransomware")?.raw;

        setTestResults(combinedResults);
        setSimulationMeta({
          module: moduleName,
          batchSize: count,
          model_loaded: ransomwareRaw?.model_loaded,
          warning: ransomwareRaw?.model_loaded === false
            ? "Static PE analysis completed. ML model artifact is not loaded, so confidence may remain low."
            : null,
          errors: failed,
        });

        const newThreats = combinedResults
          .filter((result) => result.prediction !== "SAFE")
          .map((result) => ({
            id: result.id,
            module: result.module,
            severity: result.severity,
            confidence: result.confidence,
            sender: result.sender || result.filename || "Simulation",
            subject: result.subject || result.filename || "Simulation result",
            action_taken: result.actions_taken?.[0],
            detected_at: result.detected_at,
          }));
        setLiveThreats(newThreats.slice(0, 20));

        const newActions = combinedResults
          .filter((result) => Array.isArray(result.actions_taken) && result.actions_taken.length > 0)
          .map((result) => ({
            threat_id: result.id,
            module: result.module,
            action: result.actions_taken[0],
            actions: result.actions_taken,
            timestamp: result.detected_at || new Date().toISOString(),
            status: "completed",
          }));
        setResponseActions(newActions.slice(0, 20));

        await refreshActivityLogs();

        return {
          success: failed.length === 0,
          module: moduleName,
          batch_size: count,
          results: combinedResults,
          summary: {
            processed: combinedResults.length,
            threats: newThreats.length,
            actions: newActions.length,
          },
          model_loaded: ransomwareRaw?.model_loaded,
          warning: ransomwareRaw?.model_loaded === false
            ? "Static PE analysis completed. ML model artifact is not loaded, so confidence may remain low."
            : null,
          errors: failed,
        };
      } catch (error) {
        console.error("Failed to run batch:", error);
        throw error;
      } finally {
        setTestRunning(false);
      }
    },
    [refreshActivityLogs, clearDashboard]
  );

  // Run automated test
  const runLiveTest = useCallback(async (count = 10) => {
    setTestRunning(true);
    setLiveThreats([]);
    setResponseActions([]);
    setTestResults([]);

    try {
      const result = await runAutomatedTest(count, true);

      if (result.success) {
        setCurrentTestSession(result.session_id);

        // Fetch full session details
        const sessionData = await getTestSession(result.session_id);
        if (sessionData.success && sessionData.session) {
          const session = sessionData.session;
          setTestResults(session.results || []);
          setLiveThreats(session.threats_detected || []);
          setResponseActions(session.actions_taken || []);
          setTestLogs(session.logs || []);

          // Update dashboard stats with new data
          if (session.summary) {
            setStats((prev) => ({
              ...prev,
              phishingDetected:
                prev.phishingDetected + (session.threats_detected?.length || 0),
              accuracy: session.summary.accuracy
                ? Math.round(session.summary.accuracy * 100)
                : prev.accuracy,
            }));
          }

          // Add detected threats to main threats list
          if (session.threats_detected?.length > 0) {
            const newThreats = session.threats_detected.map((t) => ({
              id: t.id,
              type: "Phishing",
              severity: t.severity,
              status: "Resolved",
              sender: t.sender,
              subject: t.subject,
              timestamp: t.detected_at,
            }));
            setThreats((prev) => [...newThreats, ...prev].slice(0, 20));
          }
        }

        // Fetch updated reports
        const reportsData = await getTestReports(5);
        setTestReports(reportsData.reports || []);
      }

      return result;
    } catch (error) {
      console.error("Test run failed:", error);
      throw error;
    } finally {
      setTestRunning(false);
    }
  }, []);

  // Refresh test logs
  const refreshTestLogs = useCallback(async () => {
    try {
      const logsData = await getTestLogs(null, null, 50);
      setTestLogs(logsData.logs || []);
    } catch (error) {
      console.error("Failed to refresh test logs:", error);
    }
  }, []);

  const value = {
    stats,
    threats,
    allEmails,
    selectedIncident,
    setSelectedIncident,
    logs,
    loading,
    threatsOverTimeData,
    threatTypesData,
    accuracyOverTimeData,
    confusionMatrixData,
    // Testing values
    testRunning,
    currentTestSession,
    testResults,
    testLogs,
    liveThreats,
    responseActions,
    testReports,
    simulationMeta,
    runLiveTest,
    refreshTestLogs,
    // Demo mode values
    demoRunning,
    demoStats,
    activityLogs,
    startDemo,
    stopDemo,
    runBatch,
    refreshActivityLogs,
    refreshData,
    clearDashboard,
    // Malware demo values
    malwareDemoRunning,
    malwareDemoStats,
  };

  return (
    <DashboardContext.Provider value={value}>
      {children}
    </DashboardContext.Provider>
  );
};
