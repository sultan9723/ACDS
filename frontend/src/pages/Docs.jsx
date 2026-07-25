import React, { useState } from "react";
import { Link } from "react-router-dom";
import {
  Shield,
  Book,
  Code,
  Terminal,
  Settings,
  Zap,
  Database,
  Lock,
  ArrowLeft,
  ChevronRight,
  Search,
  Copy,
  Check,
  ExternalLink,
} from "lucide-react";

// Abstract decoration component
const AbstractDecoration = () => (
  <div className="absolute inset-0 overflow-hidden pointer-events-none">
    {/* Gradient orbs */}
    <div className="absolute top-20 right-10 w-72 h-72 bg-emerald-500/10 rounded-full blur-3xl animate-pulse" />
    <div className="absolute top-96 left-10 w-96 h-96 bg-teal-500/5 rounded-full blur-3xl" />
    <div
      className="absolute bottom-40 right-1/4 w-64 h-64 bg-emerald-600/10 rounded-full blur-3xl animate-pulse"
      style={{ animationDelay: "1s" }}
    />
    <div className="absolute top-1/2 left-1/2 w-80 h-80 bg-cyan-500/5 rounded-full blur-3xl" />

    {/* Grid pattern */}
    <div className="absolute inset-0 bg-[linear-gradient(rgba(16,185,129,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(16,185,129,0.03)_1px,transparent_1px)] bg-[size:60px_60px]" />

    {/* Floating shapes - scattered across the page */}
    <div className="absolute top-32 right-20 w-4 h-4 border border-emerald-500/20 rotate-45" />
    <div className="absolute top-64 right-40 w-6 h-6 border border-emerald-500/10 rounded-full" />
    <div className="absolute top-48 left-1/3 w-3 h-3 bg-emerald-500/20 rotate-45" />
    <div className="absolute bottom-96 left-20 w-8 h-8 border border-teal-500/10 rounded-lg rotate-12" />
    <div className="absolute bottom-64 right-32 w-2 h-2 bg-emerald-400/30 rounded-full" />
    <div className="absolute top-80 right-1/4 w-5 h-5 border border-emerald-400/15 rounded-full" />
    <div className="absolute top-1/3 right-16 w-3 h-3 border border-teal-400/20 rotate-45" />
    <div className="absolute bottom-1/3 left-1/4 w-4 h-4 bg-emerald-500/10 rounded-full" />

    {/* Decorative lines */}
    <div className="absolute top-40 left-80 w-32 h-px bg-gradient-to-r from-emerald-500/20 to-transparent" />
    <div className="absolute top-60 right-96 w-24 h-px bg-gradient-to-l from-teal-500/20 to-transparent" />
    <div className="absolute bottom-80 left-1/3 w-40 h-px bg-gradient-to-r from-transparent via-emerald-500/15 to-transparent" />

    {/* Corner accents */}
    <div className="absolute top-20 left-20 w-20 h-20 border-l border-t border-emerald-500/10 rounded-tl-3xl" />
    <div className="absolute bottom-20 right-20 w-20 h-20 border-r border-b border-emerald-500/10 rounded-br-3xl" />

    {/* Dotted patterns */}
    <div className="absolute top-1/4 right-1/3 flex gap-2">
      <div className="w-1.5 h-1.5 bg-emerald-500/20 rounded-full" />
      <div className="w-1.5 h-1.5 bg-emerald-500/15 rounded-full" />
      <div className="w-1.5 h-1.5 bg-emerald-500/10 rounded-full" />
    </div>
    <div className="absolute bottom-1/4 left-1/3 flex gap-2">
      <div className="w-1.5 h-1.5 bg-teal-500/10 rounded-full" />
      <div className="w-1.5 h-1.5 bg-teal-500/15 rounded-full" />
      <div className="w-1.5 h-1.5 bg-teal-500/20 rounded-full" />
    </div>
  </div>
);

const Docs = () => {
  const [activeSection, setActiveSection] = useState("getting-started");
  const [copiedCode, setCopiedCode] = useState(null);

  const copyToClipboard = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(id);
    setTimeout(() => setCopiedCode(null), 2000);
  };

  const sections = [
    { id: "getting-started", title: "Getting Started", icon: Zap },
    { id: "installation", title: "Installation", icon: Terminal },
    { id: "configuration", title: "Configuration", icon: Settings },
    { id: "api-reference", title: "API Reference", icon: Code },
    { id: "agents", title: "AI Agents", icon: Shield },
    { id: "ml-model", title: "ML Model", icon: Database },
    { id: "security", title: "Security", icon: Lock },
  ];

  const CodeBlock = ({ code, language, id }) => (
    <div className="relative group">
      <div className="bg-slate-950 rounded-lg border border-slate-800 overflow-hidden">
        <div className="flex items-center justify-between px-4 py-2 bg-slate-900 border-b border-slate-800">
          <span className="text-xs text-slate-400">{language}</span>
          <button
            onClick={() => copyToClipboard(code, id)}
            className="text-slate-400 hover:text-emerald-400 transition-colors"
          >
            {copiedCode === id ? (
              <Check className="w-4 h-4" />
            ) : (
              <Copy className="w-4 h-4" />
            )}
          </button>
        </div>
        <pre className="p-4 overflow-x-auto">
          <code className="text-sm text-slate-300">{code}</code>
        </pre>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-emerald-950 relative">
      <AbstractDecoration />

      {/* Navigation */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-slate-900/80 backdrop-blur-xl border-b border-slate-800/50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center space-x-4">
              <Link
                to="/"
                className="flex items-center space-x-2 text-slate-400 hover:text-emerald-400 transition-colors"
              >
                <ArrowLeft className="w-5 h-5" />
                <span>Back</span>
              </Link>
              <div className="h-6 w-px bg-slate-700"></div>
              <div className="flex items-center space-x-2">
                <Book className="w-5 h-5 text-emerald-400" />
                <span className="text-white font-semibold">Documentation</span>
              </div>
            </div>
            <div className="relative">
              <Search className="w-5 h-5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search docs..."
                className="bg-slate-800 border border-slate-700 rounded-lg pl-10 pr-4 py-2 text-sm text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500 w-64"
              />
            </div>
          </div>
        </div>
      </nav>

      <div className="pt-16 flex">
        {/* Sidebar */}
        <aside className="fixed left-0 top-16 bottom-0 w-64 bg-slate-900/30 backdrop-blur-sm border-r border-slate-800/50 overflow-y-auto">
          <nav className="p-4 space-y-1">
            {sections.map((section) => (
              <button
                key={section.id}
                onClick={() => setActiveSection(section.id)}
                className={`w-full flex items-center space-x-3 px-4 py-2.5 rounded-lg transition-all ${
                  activeSection === section.id
                    ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                    : "text-slate-400 hover:text-white hover:bg-slate-800"
                }`}
              >
                <section.icon className="w-5 h-5" />
                <span className="text-sm font-medium">{section.title}</span>
              </button>
            ))}
          </nav>
        </aside>

        {/* Content */}
        <main className="ml-64 flex-1 p-8 max-w-4xl relative z-10 animate-fade-in">
          {activeSection === "getting-started" && (
            <div className="space-y-8">
              <div>
                <div className="flex items-center gap-2 text-emerald-400 text-sm font-medium mb-2">
                  <Zap className="w-4 h-4" />
                  <span>INTRODUCTION</span>
                </div>
                <h1 className="text-3xl font-bold text-white mb-4">
                  Getting Started with ACDS
                </h1>
                <p className="text-slate-400 leading-relaxed text-lg">
                  Welcome to the Autonomous Cyber Defense System (ACDS) â€” an
                  advanced, AI-powered email security platform designed to
                  detect and neutralize phishing threats in real-time. This
                  documentation will guide you through setup, configuration, and
                  integration.
                </p>
              </div>

              {/* Prerequisites */}
              <div className="bg-gradient-to-r from-emerald-500/10 to-transparent border-l-2 border-emerald-500 rounded-r-xl p-6">
                <h2 className="text-lg font-semibold text-white mb-3">
                  Prerequisites
                </h2>
                <ul className="grid grid-cols-2 gap-3 text-slate-300">
                  <li className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-emerald-400" />
                    Python 3.9 or higher
                  </li>
                  <li className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-emerald-400" />
                    Node.js 18+ & npm
                  </li>
                  <li className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-emerald-400" />
                    Docker (optional)
                  </li>
                  <li className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-emerald-400" />
                    4GB RAM minimum
                  </li>
                </ul>
              </div>

              <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
                <h2 className="text-xl font-semibold text-white mb-4">
                  Quick Start Guide
                </h2>
                <ol className="space-y-6">
                  <li className="flex items-start space-x-4">
                    <span className="w-8 h-8 bg-gradient-to-br from-emerald-500 to-emerald-600 rounded-lg flex items-center justify-center text-white text-sm font-bold shrink-0 shadow-lg shadow-emerald-500/20">
                      1
                    </span>
                    <div className="flex-1">
                      <p className="text-white font-medium mb-2">
                        Clone the Repository
                      </p>
                      <CodeBlock
                        code="git clone https://github.com/yourusername/ACDS-FYP.git
cd ACDS-FYP"
                        language="bash"
                        id="clone"
                      />
                    </div>
                  </li>
                  <li className="flex items-start space-x-4">
                    <span className="w-8 h-8 bg-gradient-to-br from-emerald-500 to-emerald-600 rounded-lg flex items-center justify-center text-white text-sm font-bold shrink-0 shadow-lg shadow-emerald-500/20">
                      2
                    </span>
                    <div className="flex-1">
                      <p className="text-white font-medium mb-2">
                        Set Up the Backend
                      </p>
                      <CodeBlock
                        code={`# Create virtual environment
python -m venv .venv

# Activate (Windows)
.venv\\Scripts\\activate

# Install dependencies
pip install -r requirements.txt`}
                        language="bash"
                        id="backend-setup"
                      />
                    </div>
                  </li>
                  <li className="flex items-start space-x-4">
                    <span className="w-8 h-8 bg-gradient-to-br from-emerald-500 to-emerald-600 rounded-lg flex items-center justify-center text-white text-sm font-bold shrink-0 shadow-lg shadow-emerald-500/20">
                      3
                    </span>
                    <div className="flex-1">
                      <p className="text-white font-medium mb-2">
                        Start the Backend Server
                      </p>
                      <CodeBlock
                        code={`cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000`}
                        language="bash"
                        id="start-backend"
                      />
                      <p className="text-slate-400 text-sm mt-2">
                        API will be available at{" "}
                        <code className="text-emerald-400 bg-slate-800 px-2 py-0.5 rounded">
                          http://localhost:8000
                        </code>
                      </p>
                    </div>
                  </li>
                  <li className="flex items-start space-x-4">
                    <span className="w-8 h-8 bg-gradient-to-br from-emerald-500 to-emerald-600 rounded-lg flex items-center justify-center text-white text-sm font-bold shrink-0 shadow-lg shadow-emerald-500/20">
                      4
                    </span>
                    <div className="flex-1">
                      <p className="text-white font-medium mb-2">
                        Launch the Frontend Dashboard
                      </p>
                      <CodeBlock
                        code={`# In a new terminal
cd frontend
npm install
npm run dev`}
                        language="bash"
                        id="start-frontend"
                      />
                      <p className="text-slate-400 text-sm mt-2">
                        Dashboard available at{" "}
                        <code className="text-emerald-400 bg-slate-800 px-2 py-0.5 rounded">
                          http://localhost:5173
                        </code>
                      </p>
                    </div>
                  </li>
                </ol>
              </div>

              <div>
                <h2 className="text-xl font-semibold text-white mb-4">
                  System Architecture Overview
                </h2>
                <p className="text-slate-400 mb-6">
                  ACDS employs a multi-agent architecture where specialized AI
                  agents work collaboratively to provide comprehensive email
                  security:
                </p>
                <div className="grid grid-cols-2 gap-4">
                  {[
                    {
                      title: "Detection Agent",
                      desc: "ML-powered classification using TF-IDF vectorization and Logistic Regression with 95.9% accuracy",
                      color: "emerald",
                    },
                    {
                      title: "Intel Agent",
                      desc: "Extracts Indicators of Compromise (IOCs) including malicious URLs, domains, and suspicious patterns",
                      color: "blue",
                    },
                    {
                      title: "Response Agent",
                      desc: "Executes automated containment actions based on threat severity and configurable SOAR rules",
                      color: "orange",
                    },
                    {
                      title: "Alert Agent",
                      desc: "Manages notification routing and severity-based alerting for security operations",
                      color: "purple",
                    },
                  ].map((agent, i) => (
                    <div
                      key={i}
                      className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 hover:border-emerald-500/30 transition-colors"
                    >
                      <div className="flex items-center gap-2 mb-2">
                        <div
                          className={`w-2 h-2 rounded-full bg-${agent.color}-400`}
                        />
                        <h3 className="text-white font-semibold">
                          {agent.title}
                        </h3>
                      </div>
                      <p className="text-slate-400 text-sm leading-relaxed">
                        {agent.desc}
                      </p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Next Steps */}
              <div className="bg-slate-800/30 border border-slate-700 rounded-xl p-6">
                <h3 className="text-white font-semibold mb-3">Next Steps</h3>
                <div className="grid grid-cols-3 gap-4">
                  <button
                    onClick={() => setActiveSection("installation")}
                    className="flex items-center gap-2 text-slate-400 hover:text-emerald-400 transition-colors"
                  >
                    <ChevronRight className="w-4 h-4" />
                    <span className="text-sm">Installation Options</span>
                  </button>
                  <button
                    onClick={() => setActiveSection("api-reference")}
                    className="flex items-center gap-2 text-slate-400 hover:text-emerald-400 transition-colors"
                  >
                    <ChevronRight className="w-4 h-4" />
                    <span className="text-sm">API Reference</span>
                  </button>
                  <button
                    onClick={() => setActiveSection("configuration")}
                    className="flex items-center gap-2 text-slate-400 hover:text-emerald-400 transition-colors"
                  >
                    <ChevronRight className="w-4 h-4" />
                    <span className="text-sm">Configuration</span>
                  </button>
                </div>
              </div>
            </div>
          )}

          {activeSection === "api-reference" && (
            <div className="space-y-8">
              <div>
                <div className="flex items-center gap-2 text-emerald-400 text-sm font-medium mb-2">
                  <Code className="w-4 h-4" />
                  <span>API DOCUMENTATION</span>
                </div>
                <h1 className="text-3xl font-bold text-white mb-4">
                  REST API Reference
                </h1>
                <p className="text-slate-400 leading-relaxed text-lg">
                  Complete reference for integrating with the ACDS API. All
                  endpoints are prefixed with{" "}
                  <code className="text-emerald-400 bg-slate-800 px-2 py-0.5 rounded">
                    /api/v1
                  </code>
                </p>
              </div>

              {/* Base URL Info */}
              <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4 flex items-center justify-between">
                <div>
                  <p className="text-slate-400 text-sm">Base URL</p>
                  <code className="text-white font-mono">
                    http://localhost:8000/api/v1
                  </code>
                </div>
                <div className="flex items-center gap-2">
                  <span className="px-2 py-1 bg-emerald-500/20 text-emerald-400 text-xs font-medium rounded">
                    REST
                  </span>
                  <span className="px-2 py-1 bg-blue-500/20 text-blue-400 text-xs font-medium rounded">
                    JSON
                  </span>
                </div>
              </div>

              <div className="space-y-6">
                {/* Scan Endpoint */}
                <div className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden">
                  <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-800/30">
                    <div className="flex items-center space-x-3">
                      <span className="px-3 py-1.5 bg-emerald-500/20 text-emerald-400 text-xs font-bold rounded-lg">
                        POST
                      </span>
                      <code className="text-white font-mono">/scan</code>
                    </div>
                    <span className="text-slate-500 text-sm">
                      Analyze email content
                    </span>
                  </div>
                  <div className="p-6 space-y-4">
                    <p className="text-slate-400">
                      Analyzes email content for phishing indicators using the
                      ML detection pipeline. Returns classification result,
                      confidence score, and extracted IOCs.
                    </p>

                    <div>
                      <h4 className="text-white font-medium mb-2 flex items-center gap-2">
                        <span className="w-1.5 h-1.5 bg-emerald-400 rounded-full" />
                        Request Body
                      </h4>
                      <CodeBlock
                        code={`{
  "content": "Urgent: Your account has been compromised...",
  "metadata": {
    "sender": "security@suspicious-domain.com",
    "subject": "Account Security Alert",
    "received_at": "2025-01-15T10:30:00Z"
  }
}`}
                        language="json"
                        id="scan-req"
                      />
                    </div>

                    <div>
                      <h4 className="text-white font-medium mb-2 flex items-center gap-2">
                        <span className="w-1.5 h-1.5 bg-blue-400 rounded-full" />
                        Success Response{" "}
                        <span className="text-slate-500 font-normal text-sm">
                          200 OK
                        </span>
                      </h4>
                      <CodeBlock
                        code={`{
  "success": true,
  "result": {
    "is_phishing": true,
    "confidence": 0.9534,
    "risk_level": "HIGH",
    "indicators": {
      "urls": ["http://suspicious-link.com/login"],
      "urgency_score": 0.85,
      "suspicious_keywords": ["urgent", "compromised", "verify"]
    },
    "recommended_action": "quarantine_email"
  },
  "processing_time_ms": 47
}`}
                        language="json"
                        id="scan-res"
                      />
                    </div>
                  </div>
                </div>

                {/* Live Test Endpoint */}
                <div className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden">
                  <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-800/30">
                    <div className="flex items-center space-x-3">
                      <span className="px-3 py-1.5 bg-emerald-500/20 text-emerald-400 text-xs font-bold rounded-lg">
                        POST
                      </span>
                      <code className="text-white font-mono">/test/run</code>
                    </div>
                    <span className="text-slate-500 text-sm">
                      Run live detection test
                    </span>
                  </div>
                  <div className="p-6 space-y-4">
                    <p className="text-slate-400">
                      Executes a batch test using samples from the dataset to
                      validate system performance.
                    </p>
                    <CodeBlock
                      code={`// Request
{ "count": 10 }

// Response
{
  "success": true,
  "summary": {
    "total": 10,
    "correct": 9,
    "accuracy": 0.90,
    "phishing_detected": 4,
    "legitimate_detected": 5
  }
}`}
                      language="json"
                      id="test-run"
                    />
                  </div>
                </div>

                {/* Stats Endpoint */}
                <div className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden">
                  <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-800/30">
                    <div className="flex items-center space-x-3">
                      <span className="px-3 py-1.5 bg-blue-500/20 text-blue-400 text-xs font-bold rounded-lg">
                        GET
                      </span>
                      <code className="text-white font-mono">
                        /dashboard/stats
                      </code>
                    </div>
                    <span className="text-slate-500 text-sm">
                      System statistics
                    </span>
                  </div>
                  <div className="p-6">
                    <p className="text-slate-400 mb-4">
                      Returns aggregated system metrics including detection
                      statistics and model performance.
                    </p>
                    <CodeBlock
                      code={`{
  "success": true,
  "result": {
    "phishing_detected": 247,
    "active_threats": 5,
    "auto_resolved": 61,
    "accuracy": 95.9,
    "model_version": "1.0.0"
  }
}`}
                      language="json"
                      id="stats-res"
                    />
                  </div>
                </div>

                {/* Health Endpoint */}
                <div className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden">
                  <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-800/30">
                    <div className="flex items-center space-x-3">
                      <span className="px-3 py-1.5 bg-blue-500/20 text-blue-400 text-xs font-bold rounded-lg">
                        GET
                      </span>
                      <code className="text-white font-mono">/health</code>
                    </div>
                    <span className="text-slate-500 text-sm">Health check</span>
                  </div>
                  <div className="p-6">
                    <p className="text-slate-400 mb-4">
                      Verifies API and ML model availability. Use for monitoring
                      and load balancer health checks.
                    </p>
                    <CodeBlock
                      code={`{
  "status": "healthy",
  "model_loaded": true,
  "version": "1.0.0",
  "uptime_seconds": 86400
}`}
                      language="json"
                      id="health-res"
                    />
                  </div>
                </div>
              </div>

              {/* Error Codes */}
              <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
                <h2 className="text-xl font-semibold text-white mb-4">
                  Error Codes
                </h2>
                <div className="space-y-2">
                  {[
                    {
                      code: "400",
                      desc: "Bad Request - Invalid input parameters",
                    },
                    {
                      code: "401",
                      desc: "Unauthorized - Authentication required",
                    },
                    {
                      code: "422",
                      desc: "Validation Error - Request body validation failed",
                    },
                    {
                      code: "500",
                      desc: "Internal Server Error - Server-side error",
                    },
                  ].map((error, i) => (
                    <div
                      key={i}
                      className="flex items-center gap-4 py-2 border-b border-slate-800 last:border-0"
                    >
                      <code className="text-red-400 font-mono w-12">
                        {error.code}
                      </code>
                      <span className="text-slate-400">{error.desc}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {activeSection === "installation" && (
            <div className="space-y-8">
              <div>
                <div className="flex items-center gap-2 text-emerald-400 text-sm font-medium mb-2">
                  <Terminal className="w-4 h-4" />
                  <span>SETUP GUIDE</span>
                </div>
                <h1 className="text-3xl font-bold text-white mb-4">
                  Installation Guide
                </h1>
                <p className="text-slate-400 leading-relaxed text-lg">
                  Choose from multiple deployment options based on your
                  environment and requirements.
                </p>
              </div>

              {/* Docker Installation */}
              <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-xl font-semibold text-white flex items-center space-x-2">
                    <span>ðŸ³ Docker Deployment</span>
                  </h2>
                  <span className="px-3 py-1 bg-emerald-500/20 text-emerald-400 text-xs font-medium rounded-full">
                    Recommended
                  </span>
                </div>
                <p className="text-slate-400 mb-4">
                  The fastest way to get ACDS running with all dependencies
                  pre-configured.
                </p>
                <CodeBlock
                  code={`# Clone the repository
git clone https://github.com/yourusername/ACDS-FYP.git
cd ACDS-FYP

# Build and start all services
docker-compose up -d --build

# Verify containers are running
docker-compose ps

# View real-time logs
docker-compose logs -f

# Stop all services
docker-compose down`}
                  language="bash"
                  id="docker-install"
                />
                <div className="mt-4 p-4 bg-blue-500/10 border border-blue-500/20 rounded-lg">
                  <p className="text-blue-400 text-sm">
                    <strong>Note:</strong> Docker Compose will automatically set
                    up the backend API (port 8000) and frontend dashboard (port
                    5173).
                  </p>
                </div>
              </div>

              {/* Manual Installation */}
              <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
                <h2 className="text-xl font-semibold text-white mb-4">
                  ðŸ› ï¸ Manual Installation
                </h2>
                <p className="text-slate-400 mb-4">
                  For development or custom configurations, set up each
                  component separately.
                </p>

                <div className="space-y-6">
                  <div>
                    <h3 className="text-white font-medium mb-3 flex items-center gap-2">
                      <span className="w-6 h-6 bg-slate-700 rounded flex items-center justify-center text-xs">
                        1
                      </span>
                      Backend Setup (Python/FastAPI)
                    </h3>
                    <CodeBlock
                      code={`# Navigate to project root
cd ACDS-FYP

# Create and activate virtual environment
python -m venv .venv

# Windows
.venv\\Scripts\\activate

# macOS/Linux
source .venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Start the backend server
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000`}
                      language="bash"
                      id="backend-manual"
                    />
                  </div>

                  <div>
                    <h3 className="text-white font-medium mb-3 flex items-center gap-2">
                      <span className="w-6 h-6 bg-slate-700 rounded flex items-center justify-center text-xs">
                        2
                      </span>
                      Frontend Setup (React/Vite)
                    </h3>
                    <CodeBlock
                      code={`# Open a new terminal
cd ACDS-FYP/frontend

# Install Node.js dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build`}
                      language="bash"
                      id="frontend-manual"
                    />
                  </div>
                </div>
              </div>

              {/* Verification */}
              <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
                <h2 className="text-xl font-semibold text-white mb-4">
                  âœ… Verify Installation
                </h2>
                <div className="space-y-4">
                  <div className="flex items-start gap-4">
                    <Check className="w-5 h-5 text-emerald-400 mt-0.5" />
                    <div>
                      <p className="text-white font-medium">Backend API</p>
                      <p className="text-slate-400 text-sm">
                        Visit{" "}
                        <code className="text-emerald-400 bg-slate-800 px-2 py-0.5 rounded">
                          http://localhost:8000/docs
                        </code>{" "}
                        to see the Swagger UI
                      </p>
                    </div>
                  </div>
                  <div className="flex items-start gap-4">
                    <Check className="w-5 h-5 text-emerald-400 mt-0.5" />
                    <div>
                      <p className="text-white font-medium">
                        Frontend Dashboard
                      </p>
                      <p className="text-slate-400 text-sm">
                        Open{" "}
                        <code className="text-emerald-400 bg-slate-800 px-2 py-0.5 rounded">
                          http://localhost:5173
                        </code>{" "}
                        in your browser
                      </p>
                    </div>
                  </div>
                  <div className="flex items-start gap-4">
                    <Check className="w-5 h-5 text-emerald-400 mt-0.5" />
                    <div>
                      <p className="text-white font-medium">Health Check</p>
                      <p className="text-slate-400 text-sm">
                        Test API with{" "}
                        <code className="text-emerald-400 bg-slate-800 px-2 py-0.5 rounded">
                          curl http://localhost:8000/api/v1/health
                        </code>
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeSection === "configuration" && (
            <div className="space-y-8">
              <div>
                <div className="flex items-center gap-2 text-emerald-400 text-sm font-medium mb-2">
                  <Settings className="w-4 h-4" />
                  <span>SYSTEM CONFIGURATION</span>
                </div>
                <h1 className="text-3xl font-bold text-white mb-4">
                  Configuration
                </h1>
                <p className="text-slate-400 leading-relaxed text-lg">
                  Customize ACDS behavior through environment variables and
                  configuration files.
                </p>
              </div>

              {/* Environment Variables */}
              <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
                <h2 className="text-xl font-semibold text-white mb-4">
                  Environment Variables
                </h2>
                <p className="text-slate-400 mb-4">
                  Create a{" "}
                  <code className="text-emerald-400 bg-slate-800 px-2 py-0.5 rounded">
                    .env
                  </code>{" "}
                  file in the project root or set these variables in your
                  environment.
                </p>
                <div className="overflow-hidden rounded-lg border border-slate-700">
                  <table className="w-full">
                    <thead className="bg-slate-800/50">
                      <tr>
                        <th className="text-left px-4 py-3 text-sm font-semibold text-slate-300">
                          Variable
                        </th>
                        <th className="text-left px-4 py-3 text-sm font-semibold text-slate-300">
                          Default
                        </th>
                        <th className="text-left px-4 py-3 text-sm font-semibold text-slate-300">
                          Description
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-700">
                      {[
                        {
                          name: "API_HOST",
                          default: "0.0.0.0",
                          desc: "Backend API server host address",
                        },
                        {
                          name: "API_PORT",
                          default: "8000",
                          desc: "Backend API server port",
                        },
                        {
                          name: "LOG_LEVEL",
                          default: "INFO",
                          desc: "Logging verbosity (DEBUG, INFO, WARNING, ERROR)",
                        },
                        {
                          name: "MODEL_PATH",
                          default: "models/",
                          desc: "Directory containing ML model files",
                        },
                        {
                          name: "CORS_ORIGINS",
                          default: "*",
                          desc: "Allowed CORS origins (comma-separated)",
                        },
                        {
                          name: "RATE_LIMIT",
                          default: "100",
                          desc: "API requests per minute per IP",
                        },
                      ].map((env, i) => (
                        <tr key={i} className="hover:bg-slate-800/30">
                          <td className="px-4 py-3">
                            <code className="text-emerald-400 text-sm">
                              {env.name}
                            </code>
                          </td>
                          <td className="px-4 py-3">
                            <code className="text-slate-500 text-sm">
                              {env.default}
                            </code>
                          </td>
                          <td className="px-4 py-3 text-slate-400 text-sm">
                            {env.desc}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Sample .env file */}
              <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
                <h2 className="text-xl font-semibold text-white mb-4">
                  Sample Configuration File
                </h2>
                <CodeBlock
                  code={`# .env - ACDS Configuration
# =========================

# API Server Settings
API_HOST=0.0.0.0
API_PORT=8000

# Logging
LOG_LEVEL=INFO

# ML Model
MODEL_PATH=models/
CONFIDENCE_THRESHOLD=0.7

# Security
CORS_ORIGINS=http://localhost:5173,http://localhost:3000
RATE_LIMIT=100

# Frontend
VITE_API_URL=http://localhost:8000/api/v1`}
                  language="bash"
                  id="env-sample"
                />
              </div>

              {/* SOAR Rules */}
              <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
                <h2 className="text-xl font-semibold text-white mb-4">
                  SOAR Automation Rules
                </h2>
                <p className="text-slate-400 mb-4">
                  Customize automated response actions in{" "}
                  <code className="text-emerald-400 bg-slate-800 px-2 py-0.5 rounded">
                    backend/orchestration/automation_rules.json
                  </code>
                </p>
                <CodeBlock
                  code={`{
  "rules": [
    {
      "name": "high_severity_quarantine",
      "condition": {
        "severity": "HIGH",
        "confidence": ">= 0.9"
      },
      "action": "quarantine_email",
      "notify": true
    },
    {
      "name": "critical_block_sender",
      "condition": {
        "severity": "CRITICAL"
      },
      "action": "block_sender",
      "notify": true,
      "escalate": true
    }
  ]
}`}
                  language="json"
                  id="soar-rules"
                />
              </div>
            </div>
          )}

          {activeSection === "agents" && (
            <div className="space-y-8">
              <div>
                <div className="flex items-center gap-2 text-emerald-400 text-sm font-medium mb-2">
                  <Shield className="w-4 h-4" />
                  <span>MULTI-AGENT ARCHITECTURE</span>
                </div>
                <h1 className="text-3xl font-bold text-white mb-4">
                  AI Agent System
                </h1>
                <p className="text-slate-400 leading-relaxed text-lg">
                  ACDS employs a collaborative multi-agent architecture where
                  specialized agents work together to provide comprehensive
                  threat detection, analysis, and response.
                </p>
              </div>

              {/* Architecture Diagram */}
              <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
                <h2 className="text-lg font-semibold text-white mb-4">
                  Agent Pipeline Flow
                </h2>
                <div className="flex items-center justify-between gap-2 overflow-x-auto py-4">
                  {[
                    { name: "Email Input", color: "slate" },
                    { name: "Detection Agent", color: "emerald" },
                    { name: "Intel Agent", color: "blue" },
                    { name: "Response Agent", color: "orange" },
                    { name: "Alert Agent", color: "purple" },
                  ].map((step, i) => (
                    <React.Fragment key={i}>
                      <div
                        className={`px-4 py-3 rounded-lg border ${
                          step.color === "slate"
                            ? "bg-slate-800 border-slate-600"
                            : step.color === "emerald"
                            ? "bg-emerald-500/10 border-emerald-500/30"
                            : step.color === "blue"
                            ? "bg-blue-500/10 border-blue-500/30"
                            : step.color === "orange"
                            ? "bg-orange-500/10 border-orange-500/30"
                            : "bg-purple-500/10 border-purple-500/30"
                        } whitespace-nowrap`}
                      >
                        <span
                          className={`text-sm font-medium ${
                            step.color === "slate"
                              ? "text-slate-300"
                              : step.color === "emerald"
                              ? "text-emerald-400"
                              : step.color === "blue"
                              ? "text-blue-400"
                              : step.color === "orange"
                              ? "text-orange-400"
                              : "text-purple-400"
                          }`}
                        >
                          {step.name}
                        </span>
                      </div>
                      {i < 4 && (
                        <ChevronRight className="w-5 h-5 text-slate-600 shrink-0" />
                      )}
                    </React.Fragment>
                  ))}
                </div>
              </div>

              <div className="grid gap-6">
                {[
                  {
                    name: "Detection Agent",
                    file: "detection_agent.py",
                    desc: "The primary classification engine that analyzes email content using a trained ML model. Employs TF-IDF vectorization combined with Logistic Regression to achieve 95.9% accuracy in distinguishing phishing from legitimate emails.",
                    capabilities: [
                      "Binary classification (phishing/legitimate)",
                      "Confidence score calculation",
                      "Feature extraction from email text",
                      "Real-time prediction pipeline",
                    ],
                    methods: [
                      "analyze(email_content)",
                      "get_confidence()",
                      "classify()",
                    ],
                    color: "emerald",
                  },
                  {
                    name: "Intel Agent",
                    file: "intel_agent.py",
                    desc: "Performs deep analysis of email content to extract Indicators of Compromise (IOCs). Identifies malicious URLs, suspicious domains, IP addresses, and behavioral patterns that indicate phishing attempts.",
                    capabilities: [
                      "URL extraction and validation",
                      "Domain reputation analysis",
                      "Suspicious keyword detection",
                      "Sender pattern analysis",
                    ],
                    methods: [
                      "analyze(email_data)",
                      "extract_iocs()",
                      "get_indicators()",
                    ],
                    color: "blue",
                  },
                  {
                    name: "Response Agent",
                    file: "response_agent.py",
                    desc: "Orchestrates automated response actions based on threat severity and configurable SOAR rules. Determines appropriate containment measures and executes them according to defined policies.",
                    capabilities: [
                      "Automated email quarantine",
                      "Sender blocking",
                      "Threat escalation",
                      "Action logging and audit",
                    ],
                    methods: [
                      "analyze(threat_data)",
                      "execute_action()",
                      "get_recommended_action()",
                    ],
                    color: "orange",
                  },
                  {
                    name: "Alert Agent",
                    file: "alert_agent.py",
                    desc: "Manages the notification and alerting subsystem. Routes alerts based on severity levels, maintains notification queues, and ensures security teams are informed of detected threats.",
                    capabilities: [
                      "Severity-based routing",
                      "Alert aggregation",
                      "Notification management",
                      "Dashboard updates",
                    ],
                    methods: [
                      "analyze(alert_data)",
                      "send_alert()",
                      "get_severity()",
                    ],
                    color: "purple",
                  },
                ].map((agent, i) => (
                  <div
                    key={i}
                    className={`bg-slate-900/50 border rounded-xl p-6 ${
                      agent.color === "emerald"
                        ? "border-emerald-500/20 hover:border-emerald-500/40"
                        : agent.color === "blue"
                        ? "border-blue-500/20 hover:border-blue-500/40"
                        : agent.color === "orange"
                        ? "border-orange-500/20 hover:border-orange-500/40"
                        : "border-purple-500/20 hover:border-purple-500/40"
                    } transition-colors`}
                  >
                    <div className="flex items-start justify-between mb-4">
                      <div>
                        <h3 className="text-xl font-semibold text-white mb-1">
                          {agent.name}
                        </h3>
                        <code className="text-slate-500 text-sm">
                          {agent.file}
                        </code>
                      </div>
                      <div
                        className={`w-3 h-3 rounded-full ${
                          agent.color === "emerald"
                            ? "bg-emerald-400"
                            : agent.color === "blue"
                            ? "bg-blue-400"
                            : agent.color === "orange"
                            ? "bg-orange-400"
                            : "bg-purple-400"
                        }`}
                      />
                    </div>
                    <p className="text-slate-400 mb-4 leading-relaxed">
                      {agent.desc}
                    </p>

                    <div className="mb-4">
                      <h4 className="text-sm font-medium text-slate-300 mb-2">
                        Capabilities
                      </h4>
                      <ul className="grid grid-cols-2 gap-2">
                        {agent.capabilities.map((cap, j) => (
                          <li
                            key={j}
                            className="flex items-center gap-2 text-sm text-slate-400"
                          >
                            <Check className="w-3 h-3 text-emerald-400" />
                            {cap}
                          </li>
                        ))}
                      </ul>
                    </div>

                    <div>
                      <h4 className="text-sm font-medium text-slate-300 mb-2">
                        Key Methods
                      </h4>
                      <div className="flex flex-wrap gap-2">
                        {agent.methods.map((method, j) => (
                          <code
                            key={j}
                            className={`px-3 py-1.5 rounded text-sm ${
                              agent.color === "emerald"
                                ? "bg-emerald-500/10 text-emerald-400"
                                : agent.color === "blue"
                                ? "bg-blue-500/10 text-blue-400"
                                : agent.color === "orange"
                                ? "bg-orange-500/10 text-orange-400"
                                : "bg-purple-500/10 text-purple-400"
                            }`}
                          >
                            {method}
                          </code>
                        ))}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeSection === "ml-model" && (
            <div className="space-y-8">
              <div>
                <div className="flex items-center gap-2 text-emerald-400 text-sm font-medium mb-2">
                  <Database className="w-4 h-4" />
                  <span>MACHINE LEARNING</span>
                </div>
                <h1 className="text-3xl font-bold text-white mb-4">
                  ML Model Architecture
                </h1>
                <p className="text-slate-400 leading-relaxed text-lg">
                  Technical documentation for the phishing detection machine
                  learning pipeline, including model architecture, training
                  methodology, and performance metrics.
                </p>
              </div>

              {/* Model Overview */}
              <div className="bg-gradient-to-r from-emerald-500/10 to-transparent border-l-2 border-emerald-500 rounded-r-xl p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-xl font-semibold text-white mb-2">
                      Model Performance
                    </h2>
                    <p className="text-slate-400">
                      Production-ready classifier achieving industry-leading
                      accuracy
                    </p>
                  </div>
                  <div className="text-right">
                    <p className="text-4xl font-bold text-emerald-400">
                      95.90%
                    </p>
                    <p className="text-slate-500 text-sm">Test Accuracy</p>
                  </div>
                </div>
              </div>

              {/* Specifications */}
              <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
                <h2 className="text-xl font-semibold text-white mb-6">
                  Model Specifications
                </h2>
                <div className="grid grid-cols-3 gap-4">
                  {[
                    {
                      label: "Algorithm",
                      value: "Logistic Regression",
                      icon: "ðŸ§ ",
                    },
                    { label: "Vectorizer", value: "TF-IDF", icon: "ðŸ“Š" },
                    { label: "Accuracy", value: "95.90%", icon: "ðŸŽ¯" },
                    { label: "Training Samples", value: "18,650", icon: "ðŸ“š" },
                    { label: "Max Features", value: "5,000", icon: "ðŸ”¢" },
                    { label: "N-gram Range", value: "(1, 2)", icon: "ðŸ“" },
                  ].map((spec, i) => (
                    <div
                      key={i}
                      className="bg-slate-800/50 rounded-xl p-4 border border-slate-700"
                    >
                      <div className="flex items-center gap-2 mb-2">
                        <span>{spec.icon}</span>
                        <p className="text-slate-400 text-sm">{spec.label}</p>
                      </div>
                      <p className="text-white font-semibold text-lg">
                        {spec.value}
                      </p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Pipeline */}
              <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
                <h2 className="text-xl font-semibold text-white mb-4">
                  Processing Pipeline
                </h2>
                <div className="space-y-4">
                  {[
                    {
                      step: 1,
                      title: "Text Preprocessing",
                      desc: "Input text is cleaned, normalized, and tokenized. HTML tags, special characters, and noise are removed.",
                    },
                    {
                      step: 2,
                      title: "TF-IDF Vectorization",
                      desc: "Text is converted to numerical features using Term Frequency-Inverse Document Frequency with max 5,000 features.",
                    },
                    {
                      step: 3,
                      title: "Feature Engineering",
                      desc: "Additional features extracted: URL count, urgency keywords, sender patterns, and email structure analysis.",
                    },
                    {
                      step: 4,
                      title: "Classification",
                      desc: "Logistic Regression model outputs probability scores for phishing (1) or legitimate (0) classification.",
                    },
                    {
                      step: 5,
                      title: "Confidence Scoring",
                      desc: "Prediction probability is converted to a confidence percentage for decision-making.",
                    },
                  ].map((item, i) => (
                    <div key={i} className="flex gap-4">
                      <div className="w-8 h-8 bg-emerald-500/20 rounded-lg flex items-center justify-center text-emerald-400 font-bold shrink-0">
                        {item.step}
                      </div>
                      <div>
                        <h3 className="text-white font-medium">{item.title}</h3>
                        <p className="text-slate-400 text-sm">{item.desc}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Code Example */}
              <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
                <h2 className="text-xl font-semibold text-white mb-4">
                  Usage Example
                </h2>
                <CodeBlock
                  code={`from ml.phishing_model import PhishingDetector

# Initialize detector
detector = PhishingDetector()

# Analyze email content
email_text = "Urgent: Your account has been compromised..."
result = detector.predict(email_text)

print(f"Is Phishing: {result['is_phishing']}")
print(f"Confidence: {result['confidence']:.2%}")
print(f"Risk Level: {result['risk_level']}")`}
                  language="python"
                  id="ml-usage"
                />
              </div>

              {/* Performance Metrics */}
              <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
                <h2 className="text-xl font-semibold text-white mb-4">
                  Evaluation Metrics
                </h2>
                <div className="grid grid-cols-4 gap-4">
                  {[
                    {
                      metric: "Precision",
                      value: "96.2%",
                      desc: "True positive rate",
                    },
                    { metric: "Recall", value: "95.5%", desc: "Sensitivity" },
                    {
                      metric: "F1 Score",
                      value: "95.8%",
                      desc: "Harmonic mean",
                    },
                    {
                      metric: "AUC-ROC",
                      value: "0.978",
                      desc: "Area under curve",
                    },
                  ].map((m, i) => (
                    <div
                      key={i}
                      className="text-center p-4 bg-slate-800/30 rounded-lg"
                    >
                      <p className="text-2xl font-bold text-emerald-400">
                        {m.value}
                      </p>
                      <p className="text-white font-medium text-sm">
                        {m.metric}
                      </p>
                      <p className="text-slate-500 text-xs">{m.desc}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {activeSection === "security" && (
            <div className="space-y-8">
              <div>
                <div className="flex items-center gap-2 text-emerald-400 text-sm font-medium mb-2">
                  <Lock className="w-4 h-4" />
                  <span>SECURITY & COMPLIANCE</span>
                </div>
                <h1 className="text-3xl font-bold text-white mb-4">
                  Security Best Practices
                </h1>
                <p className="text-slate-400 leading-relaxed text-lg">
                  Security configurations, best practices, and compliance
                  considerations for deploying ACDS in production environments.
                </p>
              </div>

              {/* Security Features */}
              <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
                <h2 className="text-xl font-semibold text-white mb-6">
                  Built-in Security Features
                </h2>
                <div className="grid grid-cols-2 gap-4">
                  {[
                    {
                      feature: "JWT Authentication",
                      desc: "Secure token-based authentication for API access",
                      icon: "ðŸ”",
                    },
                    {
                      feature: "Role-Based Access Control",
                      desc: "Granular permissions for different user roles",
                      icon: "ðŸ‘¥",
                    },
                    {
                      feature: "API Rate Limiting",
                      desc: "Protection against abuse and DoS attacks",
                      icon: "âš¡",
                    },
                    {
                      feature: "Input Sanitization",
                      desc: "All inputs validated and sanitized",
                      icon: "ðŸ›¡ï¸",
                    },
                    {
                      feature: "Comprehensive Audit Logs",
                      desc: "Full audit trail of all system actions",
                      icon: "ðŸ“‹",
                    },
                    {
                      feature: "CORS Configuration",
                      desc: "Configurable cross-origin resource sharing",
                      icon: "ðŸŒ",
                    },
                    {
                      feature: "HTTPS/TLS Support",
                      desc: "Encrypted communications in transit",
                      icon: "ðŸ”’",
                    },
                    {
                      feature: "Secure Headers",
                      desc: "Security headers for XSS, clickjacking protection",
                      icon: "ðŸ“„",
                    },
                  ].map((item, i) => (
                    <div
                      key={i}
                      className="flex items-start gap-3 p-4 bg-slate-800/30 rounded-lg border border-slate-700 hover:border-emerald-500/30 transition-colors"
                    >
                      <span className="text-2xl">{item.icon}</span>
                      <div>
                        <h3 className="text-white font-medium">
                          {item.feature}
                        </h3>
                        <p className="text-slate-400 text-sm">{item.desc}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Production Checklist */}
              <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
                <h2 className="text-xl font-semibold text-white mb-4">
                  Production Deployment Checklist
                </h2>
                <div className="space-y-3">
                  {[
                    "Enable HTTPS with valid SSL/TLS certificates",
                    "Configure proper CORS origins (avoid wildcard in production)",
                    "Set strong JWT secret keys and rotate regularly",
                    "Enable rate limiting appropriate for your traffic",
                    "Configure firewall rules to restrict API access",
                    "Set up monitoring and alerting for security events",
                    "Regular security audits and penetration testing",
                    "Keep all dependencies updated for security patches",
                    "Implement proper backup and disaster recovery",
                    "Review and restrict access to sensitive configurations",
                  ].map((item, i) => (
                    <label
                      key={i}
                      className="flex items-center gap-3 p-3 bg-slate-800/30 rounded-lg cursor-pointer hover:bg-slate-800/50 transition-colors"
                    >
                      <div className="w-5 h-5 rounded border-2 border-slate-600 flex items-center justify-center">
                        <Check className="w-3 h-3 text-emerald-400 opacity-0" />
                      </div>
                      <span className="text-slate-300">{item}</span>
                    </label>
                  ))}
                </div>
              </div>

              {/* Security Configuration */}
              <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
                <h2 className="text-xl font-semibold text-white mb-4">
                  Security Configuration Example
                </h2>
                <CodeBlock
                  code={`# Production Security Settings
# ============================

# Authentication
JWT_SECRET_KEY=your-256-bit-secret-key-here
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# CORS (specify exact origins)
CORS_ORIGINS=https://yourdomain.com,https://app.yourdomain.com
CORS_ALLOW_CREDENTIALS=true

# Rate Limiting
RATE_LIMIT_PER_MINUTE=60
RATE_LIMIT_BURST=100

# Security Headers
ENABLE_SECURITY_HEADERS=true
HSTS_MAX_AGE=31536000

# Logging
AUDIT_LOG_ENABLED=true
LOG_SENSITIVE_DATA=false`}
                  language="bash"
                  id="security-config"
                />
              </div>

              {/* Warning */}
              <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6">
                <div className="flex items-start gap-3">
                  <div className="w-10 h-10 bg-red-500/20 rounded-lg flex items-center justify-center shrink-0">
                    <Lock className="w-5 h-5 text-red-400" />
                  </div>
                  <div>
                    <h3 className="text-red-400 font-semibold mb-2">
                      Security Notice
                    </h3>
                    <p className="text-slate-400 text-sm leading-relaxed">
                      Never expose API keys, JWT secrets, or other sensitive
                      credentials in client-side code or public repositories.
                      Always use environment variables and secure secret
                      management solutions in production deployments.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
};

export default Docs;
