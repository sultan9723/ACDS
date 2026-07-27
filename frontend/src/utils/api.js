import axios from "axios";
import phishingData from "../mocks/phishingData.json";
import emailDetails from "../mocks/emailDetails.json";

// Create an axios instance.
// Local development is standardized on 8000. Normalize stale 8010 values before
// the first request so login does not depend on restarting Vite after env edits.
const DEFAULT_API_URL = "http://127.0.0.1:8000/api/v1";
const normalizeApiUrl = (url) => {
  try {
    const parsed = new URL(url || DEFAULT_API_URL);
    if (
      ["127.0.0.1", "localhost"].includes(parsed.hostname) &&
      parsed.port === "8010"
    ) {
      parsed.port = "8000";
    }
    return parsed.toString().replace(/\/$/, "");
  } catch {
    return DEFAULT_API_URL;
  }
};
const configuredApiUrl = normalizeApiUrl(import.meta.env.VITE_API_URL);
const API_URLS = Array.from(
  new Set([
    configuredApiUrl,
    DEFAULT_API_URL,
    "http://localhost:8000/api/v1",
  ])
);
let activeApiUrl = configuredApiUrl;
export const AUTH_TOKEN_KEY = "authToken";
export const AUTH_USER_KEY = "authUser";

export const clearStoredAuth = () => {
  localStorage.removeItem(AUTH_TOKEN_KEY);
  localStorage.removeItem(AUTH_USER_KEY);
  localStorage.removeItem("token");
  localStorage.removeItem("user");
};

const api = axios.create({
  baseURL: activeApiUrl,
  timeout: 10000,
  headers: {
    "Content-Type": "application/json",
  },
});

const getNextApiUrl = (currentUrl) => {
  const currentIndex = API_URLS.indexOf(currentUrl);
  if (currentIndex === -1) {
    return API_URLS[0];
  }
  return API_URLS[currentIndex + 1];
};

const isNetworkFailure = (error) =>
  !error.response &&
  (error.code === "ECONNABORTED" ||
    error.code === "ERR_NETWORK" ||
    error.message === "Network Error" ||
    error.request);

// Add auth token to requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem(AUTH_TOKEN_KEY) || localStorage.getItem("token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Handle auth errors
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    const nextApiUrl = getNextApiUrl(originalRequest?.baseURL || activeApiUrl);

    if (originalRequest && isNetworkFailure(error) && nextApiUrl) {
      activeApiUrl = nextApiUrl;
      api.defaults.baseURL = nextApiUrl;
      originalRequest.baseURL = nextApiUrl;
      return api(originalRequest);
    }

    if (error.response?.status === 401) {
      clearStoredAuth();
    }
    return Promise.reject(error);
  }
);

const apiError = (error, fallbackMessage) => {
  if (!error.response) {
    return {
      message: `Cannot reach backend API at ${activeApiUrl}. Confirm the backend is running on 127.0.0.1:8000.`,
    };
  }
  return error.response?.data || { message: fallbackMessage };
};

// Toggle between mock and real API
// Set to false to use real backend, true for mock data
const USE_MOCK = import.meta.env.VITE_USE_MOCK === "true" || false;

// ==================== AUTH API ====================

export const loginUser = async (email, password) => {
  try {
    const response = await api.post("/auth/login", { email, password });
    return response.data;
  } catch (error) {
    throw apiError(error, "Login failed");
  }
};

export const registerUser = async (userData) => {
  try {
    const response = await api.post("/auth/register", userData);
    return response.data;
  } catch (error) {
    throw error.response?.data || { message: "Registration failed" };
  }
};

export const verifyToken = async () => {
  try {
    const response = await api.post("/auth/verify");
    return response.data;
  } catch (error) {
    throw apiError(error, "Token verification failed");
  }
};

export const getUserProfile = async () => {
  try {
    const response = await api.get("/auth/profile");
    return response.data;
  } catch (error) {
    throw apiError(error, "Failed to get profile");
  }
};

export const logoutUser = async () => {
  try {
    const response = await api.post("/auth/logout");
    return response.data;
  } catch (error) {
    throw apiError(error, "Logout failed");
  }
};

// ==================== DASHBOARD API ====================

export const fetchStats = async () => {
  if (USE_MOCK) {
    return new Promise((resolve) => {
      setTimeout(() => resolve(phishingData.stats), 500);
    });
  }
  try {
    const response = await api.get("/dashboard/stats");
    return response.data;
  } catch (error) {
    console.error("Error fetching stats:", error);
    return phishingData.stats;
  }
};

export const fetchThreatsOverTime = async () => {
  if (USE_MOCK) {
    return new Promise((resolve) => {
      setTimeout(() => resolve(phishingData.detectionsOverTime), 500);
    });
  }
  try {
    const response = await api.get("/dashboard/activity");
    return response.data.activity || phishingData.detectionsOverTime;
  } catch (error) {
    console.error("Error fetching threats over time:", error);
    return phishingData.detectionsOverTime;
  }
};

export const fetchThreatTypes = async () => {
  if (USE_MOCK) {
    return new Promise((resolve) => {
      setTimeout(() => resolve(phishingData.threatTypes), 500);
    });
  }
  try {
    const response = await api.get("/dashboard/stats");
    return response.data.threat_types || phishingData.threatTypes;
  } catch (error) {
    console.error("Error fetching threat types:", error);
    return phishingData.threatTypes;
  }
};

export const fetchAccuracyOverTime = async () => {
  if (USE_MOCK) {
    return new Promise((resolve) => {
      setTimeout(() => resolve(phishingData.accuracyOverTime), 500);
    });
  }
  try {
    const response = await api.get("/dashboard/model-status");
    return response.data.accuracy_history || phishingData.accuracyOverTime;
  } catch (error) {
    console.error("Error fetching accuracy:", error);
    return phishingData.accuracyOverTime;
  }
};

export const fetchConfusionMatrix = async () => {
  if (USE_MOCK) {
    return new Promise((resolve) => {
      setTimeout(() => resolve(phishingData.confusionMatrix), 500);
    });
  }
  try {
    const response = await api.get("/dashboard/model-status");
    return response.data.confusion_matrix || phishingData.confusionMatrix;
  } catch (error) {
    console.error("Error fetching confusion matrix:", error);
    return phishingData.confusionMatrix;
  }
};

export const fetchModelStatus = async () => {
  try {
    const response = await api.get("/dashboard/model-status");
    return response.data;
  } catch (error) {
    console.error("Error fetching model status:", error);
    return null;
  }
};

// ==================== THREATS API ====================

export const fetchThreats = async () => {
  if (USE_MOCK) {
    return new Promise((resolve) => {
      setTimeout(() => resolve(phishingData.recentEmails), 500);
    });
  }
  try {
    const response = await api.get("/dashboard/recent-threats");
    return response.data.threats || phishingData.recentEmails;
  } catch (error) {
    console.error("Error fetching threats:", error);
    return phishingData.recentEmails;
  }
};

export const fetchAllThreats = async (params = {}) => {
  try {
    const response = await api.get("/threats/list", { params });
    return response.data;
  } catch (error) {
    console.error("Error fetching all threats:", error);
    return { threats: [], total: 0 };
  }
};

export const fetchThreatDetails = async (threatId) => {
  try {
    const response = await api.get(`/threats/${threatId}`);
    return response.data;
  } catch (error) {
    console.error("Error fetching threat details:", error);
    throw error;
  }
};

export const scanEmail = async (emailContent, subject = "", sender = "") => {
  try {
    const response = await api.post("/threats/scan", {
      content: emailContent,
      subject,
      sender,
    });
    return response.data;
  } catch (error) {
    console.error("Error scanning email:", error);
    throw error.response?.data || { message: "Scan failed" };
  }
};

export const scanEmailBatch = async (emails) => {
  try {
    const response = await api.post("/threats/scan/batch", { emails });
    return response.data;
  } catch (error) {
    console.error("Error batch scanning:", error);
    throw error.response?.data || { message: "Batch scan failed" };
  }
};

export const runPhishingTestRun = async ({
  count = 5,
  includeLegitimate = true,
} = {}) => {
  try {
    const response = await api.post("/threats/phishing/test-run", {
      count,
      include_legitimate: includeLegitimate,
    }, {
      timeout: 60000,
    });
    return response.data;
  } catch (error) {
    console.error("Error running phishing test run:", error);
    throw error.response?.data || { message: "Phishing test run failed" };
  }
};

// ==================== FEEDBACK API ====================

export const submitFeedback = async (feedbackData) => {
  try {
    const response = await api.post("/feedback/", feedbackData);
    return response.data;
  } catch (error) {
    console.error("Error submitting feedback:", error);
    throw error.response?.data || { message: "Feedback submission failed" };
  }
};

export const getFeedbackSummary = async () => {
  try {
    const response = await api.get("/feedback/summary");
    return response.data;
  } catch (error) {
    console.error("Error fetching feedback summary:", error);
    return null;
  }
};

// ==================== CREDENTIAL STUFFING API ====================

export const getCredentialStuffingHealth = async () => {
  try {
    const response = await api.get("/credential-stuffing/health");
    return response.data;
  } catch (error) {
    console.error("Error fetching credential stuffing health:", error);
    throw error.response?.data || { message: "Failed to fetch credential stuffing health" };
  }
};

export const submitCredentialLoginEvent = async (eventData) => {
  try {
    const response = await api.post("/credential-stuffing/login-event", eventData);
    return response.data;
  } catch (error) {
    console.error("Error submitting credential login event:", error);
    throw error.response?.data || { message: "Failed to submit login event" };
  }
};

export const analyzeCredentialStuffingEvents = async (events) => {
  try {
    const response = await api.post("/credential-stuffing/analyze", { events });
    return response.data;
  } catch (error) {
    console.error("Error analyzing credential stuffing events:", error);
    throw error.response?.data || { message: "Failed to analyze credential stuffing events" };
  }
};

export const simulateCredentialStuffingAttack = async (options = {}) => {
  try {
    const response = await api.post("/credential-stuffing/simulate-attack", options);
    return response.data;
  } catch (error) {
    console.error("Error simulating credential stuffing attack:", error);
    throw error.response?.data || { message: "Failed to simulate credential stuffing attack" };
  }
};

export const getCredentialStuffingAlerts = async (params = {}) => {
  try {
    const response = await api.get("/credential-stuffing/alerts", { params });
    return response.data;
  } catch (error) {
    console.error("Error fetching credential stuffing alerts:", error);
    throw error.response?.data || { message: "Failed to fetch credential stuffing alerts" };
  }
};

export const submitCredentialStuffingFeedback = async (feedbackData) => {
  try {
    const response = await api.post("/credential-stuffing/feedback", feedbackData);
    return response.data;
  } catch (error) {
    console.error("Error submitting credential stuffing feedback:", error);
    throw error.response?.data || { message: "Failed to submit credential stuffing feedback" };
  }
};

export const getCredentialStuffingRetrainingData = async (params = {}) => {
  try {
    const response = await api.get("/credential-stuffing/retraining-data", { params });
    return response.data;
  } catch (error) {
    console.error("Error fetching credential stuffing retraining data:", error);
    throw error.response?.data || { message: "Failed to fetch credential stuffing retraining data" };
  }
};

export const getCredentialStuffingReportUrl = (alertId) =>
  `${activeApiUrl}/credential-stuffing/report/${alertId}`;

// ==================== REPORTS API ====================

export const generateReport = async (reportType, options = {}) => {
  try {
    const response = await api.post("/reports/generate", {
      report_type: reportType,
      ...options,
    });
    return response.data;
  } catch (error) {
    console.error("Error generating report:", error);
    throw error.response?.data || { message: "Report generation failed" };
  }
};

export const getReportTypes = async () => {
  try {
    const response = await api.get("/reports/types");
    return response.data;
  } catch (error) {
    console.error("Error fetching report types:", error);
    return [];
  }
};

export const exportReport = async (reportId, format = "pdf") => {
  try {
    const response = await api.get(`/reports/export/${reportId}`, {
      params: { format },
    });
    return response.data;
  } catch (error) {
    console.error("Error exporting report:", error);
    throw error.response?.data || { message: "Report export failed" };
  }
};

// ==================== LEGACY FUNCTIONS ====================

export const fetchIncidentDetails = async (id) => {
  if (USE_MOCK) {
    return new Promise((resolve) => {
      const detail = emailDetails.find((d) => d.id === id) || emailDetails[0];
      setTimeout(() => resolve(detail), 500);
    });
  }
  try {
    const response = await api.get(`/threats/${id}`);
    return response.data;
  } catch (error) {
    const detail = emailDetails.find((d) => d.id === id) || emailDetails[0];
    return detail;
  }
};

export const fetchModelLogs = async () => {
  if (USE_MOCK) {
    return new Promise((resolve) => {
      setTimeout(() => resolve(phishingData.modelLogs), 500);
    });
  }
  try {
    // First try to get from activity logs
    const activityResponse = await api.get("/dashboard/activity-logs", {
      params: { limit: 50 },
    });

    if (activityResponse.data?.logs?.length > 0) {
      // Transform activity logs to model logs format
      const modelLogs = activityResponse.data.logs
        .filter(
          (log) =>
            log.event === "email_scanned" || log.event === "threat_detected"
        )
        .map((log, index) => ({
          id: log.id || index + 1,
          date: log.timestamp
            ? new Date(log.timestamp).toLocaleDateString()
            : "N/A",
          type:
            log.is_phishing || log.details?.is_phishing ? "Phishing" : "Safe",
          decision:
            log.is_phishing || log.details?.is_phishing
              ? "True Positive"
              : "True Negative",
          action:
            log.is_phishing || log.details?.is_phishing
              ? "Quarantine"
              : "Allowed",
          modelVersion: "v2.0",
          confidence: log.confidence || log.details?.confidence || 0,
          subject: log.subject || log.details?.subject || "N/A",
        }));

      if (modelLogs.length > 0) {
        return modelLogs;
      }
    }

    // Fallback to model-status endpoint
    const response = await api.get("/dashboard/model-status");
    return response.data.logs || phishingData.modelLogs;
  } catch (error) {
    return phishingData.modelLogs;
  }
};

export const fetchAllEmails = async () => {
  if (USE_MOCK) {
    return new Promise((resolve) => {
      setTimeout(() => resolve(emailDetails), 500);
    });
  }
  try {
    // First try to get scanned emails from database
    const response = await api.get("/threats/scans/list", { params: { limit: 100 } });
    if (response.data.success && response.data.emails?.length > 0) {
      return response.data.emails;
    }
    // Fallback to threats list
    const threatsResponse = await api.get("/threats/list");
    return threatsResponse.data.threats || emailDetails;
  } catch (error) {
    console.error("Error fetching emails:", error);
    return emailDetails;
  }
};

// ==================== TESTING API ====================

export const getTestSamples = async (sampleType = "mixed", count = 5) => {
  try {
    const response = await api.get("/testing/samples", {
      params: { sample_type: sampleType, count },
    });
    return response.data;
  } catch (error) {
    console.error("Error fetching test samples:", error);
    throw error.response?.data || { message: "Failed to get test samples" };
  }
};

export const runAutomatedTest = async (count = 10, includeResponse = true) => {
  try {
    const response = await api.post("/testing/run", null, {
      params: { count, include_response: includeResponse },
    });
    return response.data;
  } catch (error) {
    console.error("Error running automated test:", error);
    throw error.response?.data || { message: "Test run failed" };
  }
};

export const getTestSession = async (sessionId) => {
  try {
    const response = await api.get(`/testing/session/${sessionId}`);
    return response.data;
  } catch (error) {
    console.error("Error fetching test session:", error);
    throw error.response?.data || { message: "Failed to get session" };
  }
};

export const getTestSessions = async (limit = 10) => {
  try {
    const response = await api.get("/testing/sessions", { params: { limit } });
    return response.data;
  } catch (error) {
    console.error("Error fetching test sessions:", error);
    return { sessions: [], total: 0 };
  }
};

export const getTestLogs = async (
  sessionId = null,
  eventType = null,
  limit = 50
) => {
  try {
    const params = { limit };
    if (sessionId) params.session_id = sessionId;
    if (eventType) params.event_type = eventType;

    const response = await api.get("/testing/logs", { params });
    return response.data;
  } catch (error) {
    console.error("Error fetching test logs:", error);
    return { logs: [], total: 0 };
  }
};

export const getTestReports = async (limit = 10) => {
  try {
    const response = await api.get("/testing/reports", { params: { limit } });
    return response.data;
  } catch (error) {
    console.error("Error fetching test reports:", error);
    return { reports: [], total: 0 };
  }
};

export const getTestReport = async (reportId) => {
  try {
    const response = await api.get(`/testing/reports/${reportId}`);
    return response.data;
  } catch (error) {
    console.error("Error fetching test report:", error);
    throw error.response?.data || { message: "Failed to get report" };
  }
};

// ==================== HEALTH CHECK ====================

export const checkBackendHealth = async () => {
  try {
    const response = await axios.get("http://localhost:8000/health");
    return { connected: true, ...response.data };
  } catch (error) {
    return { connected: false, error: error.message };
  }
};

// ==================== DEMO MODE API ====================

export const startDemoMode = async (intervalSeconds = 300, batchSize = 5) => {
  try {
    const response = await api.post("/demo/start", {
      interval_seconds: intervalSeconds,
      batch_size: batchSize,
    });
    return response.data;
  } catch (error) {
    console.error("Error starting demo mode:", error);
    throw error.response?.data || { message: "Failed to start demo mode" };
  }
};

export const stopDemoMode = async () => {
  try {
    const response = await api.post("/demo/stop");
    return response.data;
  } catch (error) {
    console.error("Error stopping demo mode:", error);
    throw error.response?.data || { message: "Failed to stop demo mode" };
  }
};

export const getDemoStatus = async () => {
  try {
    const response = await api.get("/demo/status");
    return response.data;
  } catch (error) {
    console.error("Error fetching demo status:", error);
    return { running: false, stats: null };
  }
};

export const runDemoBatch = async (count = 5) => {
  try {
    const response = await api.post("/demo/run-batch", { count });
    return response.data;
  } catch (error) {
    console.error("Error running demo batch:", error);
    throw error.response?.data || { message: "Failed to run batch" };
  }
};

export const setDemoInterval = async (intervalSeconds) => {
  try {
    const response = await api.post("/demo/set-interval", null, {
      params: { interval_seconds: intervalSeconds },
    });
    return response.data;
  } catch (error) {
    console.error("Error setting demo interval:", error);
    throw error.response?.data || { message: "Failed to set interval" };
  }
};

// ==================== ACTIVITY LOGS API ====================

export const fetchActivityLogs = async (limit = 50, eventType = null) => {
  try {
    const params = { limit };
    if (eventType) params.event_type = eventType;

    const response = await api.get("/dashboard/activity-logs", { params });
    return response.data;
  } catch (error) {
    console.error("Error fetching activity logs:", error);
    return { logs: [], count: 0 };
  }
};

// ==================== MALWARE DEMO MODE API ====================

export const startMalwareDemoMode = async (intervalSeconds = 300, batchSize = 5) => {
  try {
    const response = await api.post("/malware/demo/start", {
      interval_seconds: intervalSeconds,
      batch_size: batchSize,
    });
    return response.data;
  } catch (error) {
    console.error("Error starting malware demo:", error);
    throw error.response?.data || { message: "Failed to start malware demo" };
  }
};

export const stopMalwareDemoMode = async () => {
  try {
    const response = await api.post("/malware/demo/stop");
    return response.data;
  } catch (error) {
    console.error("Error stopping malware demo:", error);
    throw error.response?.data || { message: "Failed to stop malware demo" };
  }
};

export const getMalwareDemoStatus = async () => {
  try {
    const response = await api.get("/malware/demo/status");
    return response.data;
  } catch (error) {
    console.error("Error fetching malware demo status:", error);
    return { success: false, running: false };
  }
};

export const runMalwareDemoBatch = async (count = 5) => {
  try {
    const response = await api.post("/malware/demo/run-batch", { count });
    return response.data;
  } catch (error) {
    console.error("Error running malware demo batch:", error);
    throw error.response?.data || { message: "Failed to run malware batch" };
  }
};

export const getMalwareScans = async (limit = 50) => {
  try {
    const response = await api.get("/malware/scans/list", { params: { limit } });
    return response.data;
  } catch (error) {
    console.error("Error fetching malware scans:", error);
    return { success: false, scans: [] };
  }
};

export const scanMalwareFile = async (fileData) => {
  try {
    const response = await api.post("/malware/scan", fileData);
    return response.data;
  } catch (error) {
    console.error("Error scanning malware file:", error);
    throw error.response?.data || { message: "Malware scan failed" };
  }
};

// ==================== DASHBOARD CLEAR API ====================

export const clearDashboardFeeds = async () => {
  try {
    const response = await api.post("/dashboard/clear-feeds");
    return response.data;
  } catch (error) {
    console.error("Error clearing dashboard feeds:", error);
    throw error.response?.data || { message: "Failed to clear dashboard" };
  }
};

export default api;
