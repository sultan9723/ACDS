import React, { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  Shield,
  Zap,
  Brain,
  Lock,
  ChevronRight,
  ChevronDown,
  AlertTriangle,
  CheckCircle,
  BarChart3,
  Eye,
  Menu,
  X,
  ArrowRight,
  Github,
  Twitter,
  Linkedin,
} from "lucide-react";

const Landing = () => {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    setLoaded(true);
  }, []);

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 20);
    };
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const features = [
    {
      icon: Brain,
      title: "Four Threat Engines",
      description:
        "Unified detection coverage for phishing, ransomware, malware, and credential stuffing workflows.",
    },
    {
      icon: Zap,
      title: "Real-Time Analysis",
      description:
        "Analyze events, executable samples, commands, and login behavior with live risk scoring and evidence capture.",
    },
    {
      icon: Eye,
      title: "Analyst Evidence",
      description:
        "Expose detection reasoning, confidence, indicators, timelines, and recommended next actions for SOC review.",
    },
    {
      icon: Shield,
      title: "Automated Response",
      description:
        "Coordinate safe response recommendations, quarantine workflows, audit trails, and response status tracking.",
    },
    {
      icon: BarChart3,
      title: "SOC Dashboard",
      description:
        "Monitor active threats, system health, automated actions, detection history, and operational posture.",
    },
    {
      icon: Lock,
      title: "AI Reporting Loop",
      description:
        "Generate incident reports, capture analyst feedback, and support retraining data for continuous improvement.",
    },
  ];

  const stats = [
    { value: "4", label: "Threat Engines" },
    { value: "Live", label: "Real-Time Monitoring" },
    { value: "SOAR", label: "Automated Response" },
    { value: "AI", label: "Incident Reports" },
  ];

  const navDropdowns = {
    Features: [
      "Phishing Detection",
      "Ransomware Detection",
      "Malware Detection",
      "Credential Stuffing",
      "Automated Response",
      "AI Reports",
    ],
    "How It Works": [
      "Data Ingestion",
      "Detection Engines",
      "Threat Scoring",
      "Automated Response",
      "Analyst Feedback",
      "AI Reports",
    ],
    Architecture: [
      "System Design",
      "ML Pipeline",
      "Backend APIs",
      "SOC Dashboard Flow",
    ],
  };

  const getDropdownHref = (label) =>
    label === "Features" ? "#features" : "#how-it-works";

  return (
    <div
      className={`min-h-screen bg-slate-950 text-slate-100 transition-opacity duration-500 ${
        loaded ? "opacity-100" : "opacity-0"
      }`}
    >
      {/* Navigation */}
      <nav
        className={`fixed left-0 right-0 top-0 z-50 transition-all duration-300 ${
          scrolled
            ? "border-b border-slate-800/80 bg-slate-950/90 shadow-lg shadow-slate-950/20 backdrop-blur-md"
            : "bg-transparent"
        }`}
      >
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="flex h-16 items-center justify-between">
            {/* Logo */}
            <div className="flex h-full items-center space-x-2">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-emerald-400 to-emerald-600 shadow-lg shadow-emerald-950/20">
                <Shield className="h-6 w-6 text-white" />
              </div>
              <span className="bg-gradient-to-r from-emerald-400 to-emerald-200 bg-clip-text text-xl font-bold leading-none text-transparent">
                ACDS
              </span>
            </div>

            {/* Desktop Navigation */}
            <div className="hidden items-center gap-2 md:flex">
              {Object.entries(navDropdowns).map(([label, items]) => (
                <div key={label} className="group relative">
                  <a
                    href={getDropdownHref(label)}
                    className="inline-flex items-center gap-1.5 rounded-lg px-3 py-2 text-sm font-medium text-slate-300 transition-colors hover:bg-slate-900/70 hover:text-emerald-300"
                  >
                    <span>{label}</span>
                    <ChevronDown className="h-4 w-4 text-slate-500 transition-transform group-hover:rotate-180 group-hover:text-emerald-300" />
                  </a>
                  <div className="invisible absolute left-0 top-full z-50 mt-3 w-64 translate-y-1 rounded-xl border border-slate-800/90 bg-slate-950/95 p-2 opacity-0 shadow-2xl shadow-slate-950/40 backdrop-blur-xl transition-all duration-150 group-hover:visible group-hover:translate-y-0 group-hover:opacity-100">
                    <div className="mb-1 px-3 py-2 text-xs font-semibold uppercase tracking-[0.16em] text-cyan-300/70">
                      {label}
                    </div>
                    {items.map((item) => (
                      <a
                        key={item}
                        href={getDropdownHref(label)}
                        className="block rounded-lg px-3 py-2 text-sm text-slate-300 transition-colors hover:bg-slate-900 hover:text-emerald-200"
                      >
                        {item}
                      </a>
                    ))}
                  </div>
                </div>
              ))}
              <Link
                to="/docs"
                className="rounded-lg px-3 py-2 text-sm font-medium text-slate-300 transition-colors hover:bg-slate-900/70 hover:text-emerald-300"
              >
                Documentation
              </Link>
              <Link
                to="/blog"
                className="rounded-lg px-3 py-2 text-sm font-medium text-slate-300 transition-colors hover:bg-slate-900/70 hover:text-emerald-300"
              >
                Blog
              </Link>
            </div>

            {/* Auth Buttons */}
            <div className="hidden items-center space-x-4 md:flex">
              <Link
                to="/login"
                className="rounded-lg px-4 py-2 text-sm font-medium text-slate-300 transition-colors hover:bg-slate-900/70 hover:text-emerald-300"
              >
                Sign In
              </Link>
              <Link
                to="/login"
                className="rounded-lg border border-emerald-400/30 bg-emerald-500/20 px-5 py-2 text-sm font-semibold text-emerald-50 shadow-lg shadow-emerald-950/20 transition-all duration-200 hover:bg-emerald-500/30"
              >
                Launch Dashboard
              </Link>
            </div>

            {/* Mobile Menu Button */}
            <button
              className="rounded-lg p-2 text-slate-300 transition-colors hover:bg-slate-900/70 hover:text-emerald-300 md:hidden"
              onClick={() => setIsMenuOpen(!isMenuOpen)}
              aria-label="Toggle navigation menu"
            >
              {isMenuOpen ? <X size={24} /> : <Menu size={24} />}
            </button>
          </div>
        </div>

        {/* Mobile Menu */}
        {isMenuOpen && (
          <div className="border-t border-slate-800 bg-slate-950/95 backdrop-blur-md md:hidden">
            <div className="space-y-4 px-4 py-4">
              {Object.entries(navDropdowns).map(([label, items]) => (
                <div key={label} className="rounded-xl border border-slate-800/80 bg-slate-900/35 p-3">
                  <a
                    href={getDropdownHref(label)}
                    className="mb-2 flex items-center justify-between text-sm font-semibold text-slate-200 hover:text-emerald-300"
                    onClick={() => setIsMenuOpen(false)}
                  >
                    <span>{label}</span>
                    <ChevronRight className="h-4 w-4 text-slate-500" />
                  </a>
                  <div className="grid grid-cols-1 gap-1">
                    {items.map((item) => (
                      <a
                        key={item}
                        href={getDropdownHref(label)}
                        className="rounded-lg px-2 py-1.5 text-sm text-slate-400 transition-colors hover:bg-slate-900 hover:text-emerald-200"
                        onClick={() => setIsMenuOpen(false)}
                      >
                        {item}
                      </a>
                    ))}
                  </div>
                </div>
              ))}
              <Link
                to="/docs"
                className="block rounded-lg px-3 py-2 text-slate-300 hover:bg-slate-900/70 hover:text-emerald-400"
              >
                Documentation
              </Link>
              <Link
                to="/blog"
                className="block rounded-lg px-3 py-2 text-slate-300 hover:bg-slate-900/70 hover:text-emerald-400"
              >
                Blog
              </Link>
              <div className="space-y-3 border-t border-slate-800 pt-4">
                <Link
                  to="/login"
                  className="block rounded-lg py-2 text-center text-slate-300 hover:bg-slate-900/70 hover:text-emerald-400"
                >
                  Sign In
                </Link>
                <Link
                  to="/login"
                  className="block rounded-lg border border-emerald-400/30 bg-emerald-500/20 py-2 text-center font-medium text-emerald-50"
                >
                  Launch Dashboard
                </Link>
              </div>
            </div>
          </div>
        )}
      </nav>

      {/* Hero Section */}
      <section className="relative overflow-hidden px-4 pb-20 pt-32 sm:px-6 lg:px-8">
        {/* Background Effects */}
        <div className="absolute inset-0 overflow-hidden">
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_left,rgba(20,184,166,0.16),transparent_30rem),radial-gradient(circle_at_bottom_right,rgba(14,165,233,0.10),transparent_28rem),linear-gradient(135deg,#020617_0%,#07111f_48%,#0b1220_100%)]"></div>
          <div className="absolute inset-0 opacity-[0.07] [background-image:linear-gradient(rgba(148,163,184,0.35)_1px,transparent_1px),linear-gradient(90deg,rgba(148,163,184,0.35)_1px,transparent_1px)] [background-size:56px_56px]"></div>
          <div className="absolute bottom-0 left-1/2 h-px w-full -translate-x-1/2 bg-gradient-to-r from-transparent via-emerald-500/40 to-transparent"></div>
        </div>

        <div className="relative mx-auto max-w-7xl">
          <div className="mx-auto max-w-4xl text-center">
            {/* Badge */}
            <div className="mb-8 inline-flex items-center space-x-2 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-4 py-1.5">
              <span className="h-2 w-2 animate-pulse rounded-full bg-emerald-400"></span>
              <span className="text-sm font-medium text-emerald-400">
                AI-Driven Autonomous Cyber Defense
              </span>
            </div>

            {/* Headline */}
            <h1 className="mb-6 text-4xl font-bold leading-tight text-white sm:text-5xl lg:text-6xl">
              Autonomous Cyber Defense
              <span className="block bg-gradient-to-r from-emerald-400 via-emerald-300 to-teal-400 bg-clip-text text-transparent">
                for Real-Time Threats
              </span>
            </h1>

            {/* Subheadline */}
            <p className="mx-auto mb-10 max-w-3xl text-lg leading-relaxed text-slate-400 sm:text-xl">
              ACDS detects phishing, ransomware, malware, and credential
              stuffing attacks, triggers automated response actions, and
              generates AI-powered reports for SOC analysts.
            </p>

            {/* CTA Buttons */}
            <div className="mb-16 flex flex-col items-center justify-center gap-4 sm:flex-row">
              <button
                onClick={() => navigate("/login")}
                className="group flex w-full items-center justify-center space-x-2 rounded-xl border border-emerald-400/30 bg-emerald-500/20 px-8 py-3.5 text-lg font-semibold text-emerald-50 shadow-xl shadow-emerald-950/25 transition-all duration-200 hover:bg-emerald-500/30 sm:w-auto"
              >
                <span>Launch Dashboard</span>
                <ArrowRight className="h-5 w-5 transition-transform group-hover:translate-x-1" />
              </button>
              <a
                href="#how-it-works"
                className="flex w-full items-center justify-center space-x-2 rounded-xl border border-slate-700 bg-slate-800/50 px-8 py-3.5 text-lg font-semibold text-slate-300 transition-all duration-200 hover:border-slate-600 hover:bg-slate-800 hover:text-white sm:w-auto"
              >
                <span>View System Flow</span>
              </a>
            </div>

            {/* Stats */}
            <div className="mx-auto grid max-w-3xl grid-cols-2 gap-8 md:grid-cols-4">
              {stats.map((stat, index) => (
                <div key={index} className="text-center">
                  <div className="mb-1 bg-gradient-to-r from-emerald-400 to-emerald-200 bg-clip-text text-3xl font-bold text-transparent sm:text-4xl">
                    {stat.value}
                  </div>
                  <div className="text-sm text-slate-500">{stat.label}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Dashboard Preview */}
          <div className="relative mx-auto mt-20 max-w-5xl">
            <div className="rounded-2xl border border-slate-800/90 bg-slate-900/55 p-2 shadow-2xl shadow-slate-950/40 backdrop-blur-sm">
              <div className="overflow-hidden rounded-xl bg-slate-950">
                {/* Mock Dashboard Header */}
                <div className="flex items-center justify-between border-b border-slate-800 bg-slate-900 px-6 py-4">
                  <div className="flex items-center space-x-4">
                    <div className="flex space-x-2">
                      <div className="h-3 w-3 rounded-full bg-red-500"></div>
                      <div className="h-3 w-3 rounded-full bg-yellow-500"></div>
                      <div className="h-3 w-3 rounded-full bg-green-500"></div>
                    </div>
                    <span className="text-sm text-slate-500">
                      ACDS Command Center
                    </span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <div className="h-2 w-2 animate-pulse rounded-full bg-emerald-400"></div>
                    <span className="text-xs text-emerald-400">Live</span>
                  </div>
                </div>

                {/* Mock Dashboard Content */}
                <div className="grid grid-cols-1 gap-4 p-6 md:grid-cols-3">
                  <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-4">
                    <div className="mb-2 flex items-center justify-between">
                      <span className="text-sm text-slate-400">
                        Active Threats
                      </span>
                      <AlertTriangle className="h-5 w-5 text-red-400" />
                    </div>
                    <div className="text-2xl font-bold text-white">12</div>
                    <div className="mt-1 text-xs text-red-300">
                      3 critical incidents
                    </div>
                  </div>
                  <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-4">
                    <div className="mb-2 flex items-center justify-between">
                      <span className="text-sm text-slate-400">
                        Automated Actions
                      </span>
                      <Shield className="h-5 w-5 text-cyan-400" />
                    </div>
                    <div className="text-2xl font-bold text-white">38</div>
                    <div className="mt-1 text-xs text-emerald-400">
                      Quarantine and alerting
                    </div>
                  </div>
                  <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-4">
                    <div className="mb-2 flex items-center justify-between">
                      <span className="text-sm text-slate-400">
                        System Health
                      </span>
                      <CheckCircle className="h-5 w-5 text-emerald-400" />
                    </div>
                    <div className="text-2xl font-bold text-white">Healthy</div>
                    <div className="mt-1 text-xs text-slate-400">
                      Engines available
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="px-4 py-20 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-7xl">
          <div className="mb-16 text-center">
            <h2 className="mb-4 text-3xl font-bold text-white sm:text-4xl">
              Enterprise AI SOC Capabilities
            </h2>
            <p className="mx-auto max-w-2xl text-slate-400">
              ACDS connects threat detection, response orchestration,
              visualization, reporting, and analyst feedback in one operational
              workflow.
            </p>
          </div>

          <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
            {features.map((feature, index) => (
              <div
                key={index}
                className="group rounded-2xl border border-slate-800 bg-slate-900/50 p-6 transition-all duration-300 hover:border-emerald-500/30 hover:bg-slate-900/80"
              >
                <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-gradient-to-br from-emerald-500/20 to-emerald-600/20 transition-all duration-300 group-hover:from-emerald-500/30 group-hover:to-emerald-600/30">
                  <feature.icon className="h-6 w-6 text-emerald-400" />
                </div>
                <h3 className="mb-2 text-xl font-semibold text-white">
                  {feature.title}
                </h3>
                <p className="leading-relaxed text-slate-400">
                  {feature.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* How It Works Section */}
      <section
        id="how-it-works"
        className="bg-slate-900/30 px-4 py-20 sm:px-6 lg:px-8"
      >
        <div className="mx-auto max-w-7xl">
          <div className="mb-16 text-center">
            <h2 className="mb-4 text-3xl font-bold text-white sm:text-4xl">
              ACDS System Flow
            </h2>
            <p className="mx-auto max-w-2xl text-slate-400">
              The platform ingests security signals, applies layered detection,
              recommends safe response actions, and turns outcomes into analyst
              reports and feedback.
            </p>
          </div>

          <div className="grid grid-cols-1 gap-8 md:grid-cols-4">
            {[
              {
                step: "01",
                title: "Signal Intake",
                description:
                  "Emails, login events, file activity, executable samples, and system events enter the analysis workflow.",
                icon: Eye,
              },
              {
                step: "02",
                title: "Layered Detection",
                description:
                  "Specialized engines classify phishing, ransomware, malware, and credential stuffing indicators.",
                icon: Brain,
              },
              {
                step: "03",
                title: "Response Orchestration",
                description:
                  "Safe automated response actions, quarantine workflows, and audit entries are prepared for review.",
                icon: Shield,
              },
              {
                step: "04",
                title: "Report and Feedback",
                description:
                  "AI reports, analyst feedback, historical logs, and retraining data close the operational loop.",
                icon: BarChart3,
              },
            ].map((item, index) => (
              <div key={index} className="relative">
                {index < 3 && (
                  <div className="absolute left-full top-12 z-0 hidden h-px w-full bg-gradient-to-r from-emerald-500/50 to-transparent md:block"></div>
                )}
                <div className="relative z-10 text-center">
                  <div className="relative mx-auto mb-4 flex h-24 w-24 items-center justify-center rounded-2xl border border-slate-700 bg-gradient-to-br from-slate-800 to-slate-900">
                    <item.icon className="h-10 w-10 text-emerald-400" />
                    <div className="absolute -right-2 -top-2 flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-500 text-sm font-bold text-white">
                      {item.step}
                    </div>
                  </div>
                  <h3 className="mb-2 text-lg font-semibold text-white">
                    {item.title}
                  </h3>
                  <p className="text-sm text-slate-400">{item.description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="px-4 py-20 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-4xl">
          <div className="relative overflow-hidden rounded-3xl border border-emerald-500/30 bg-gradient-to-r from-emerald-600/20 to-teal-600/20 p-8 text-center sm:p-12">
            <div className="absolute inset-0 bg-gradient-to-r from-emerald-500/5 to-teal-500/5"></div>
            <div className="relative">
              <h2 className="mb-4 text-3xl font-bold text-white sm:text-4xl">
                Enter the ACDS Command Center
              </h2>
              <p className="mx-auto mb-8 max-w-xl text-slate-300">
                Monitor threat engines, review active incidents, coordinate
                response actions, and generate AI-assisted security reports from
                a single enterprise SOC workspace.
              </p>
              <div className="flex flex-col items-center justify-center gap-4 sm:flex-row">
                <button
                  onClick={() => navigate("/login")}
                  className="flex w-full items-center justify-center space-x-2 rounded-xl bg-white px-8 py-3.5 text-lg font-semibold text-slate-900 shadow-xl transition-all duration-200 hover:bg-slate-100 sm:w-auto"
                >
                  <span>Launch Dashboard</span>
                  <ChevronRight className="h-5 w-5" />
                </button>
                <Link
                  to="/docs"
                  className="flex w-full items-center justify-center space-x-2 px-8 py-3.5 text-lg font-semibold text-emerald-400 transition-colors hover:text-emerald-300 sm:w-auto"
                >
                  <span>Read Documentation</span>
                </Link>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-slate-800 px-4 py-12 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-7xl">
          <div className="mb-8 grid grid-cols-1 gap-8 md:grid-cols-4">
            {/* Brand */}
            <div className="md:col-span-1">
              <div className="mb-4 flex items-center space-x-2">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-emerald-400 to-emerald-600">
                  <Shield className="h-6 w-6 text-white" />
                </div>
                <span className="bg-gradient-to-r from-emerald-400 to-emerald-200 bg-clip-text text-xl font-bold text-transparent">
                  ACDS
                </span>
              </div>
              <p className="text-sm text-slate-400">
                An AI-driven autonomous cyber defense system for real-time
                detection, response, analyst feedback, and incident reporting.
              </p>
            </div>

            {/* Links */}
            <div>
              <h4 className="mb-4 font-semibold text-white">Product</h4>
              <ul className="space-y-2">
                <li>
                  <a
                    href="#features"
                    className="text-sm text-slate-400 transition-colors hover:text-emerald-400"
                  >
                    Features
                  </a>
                </li>
                <li>
                  <a
                    href="#how-it-works"
                    className="text-sm text-slate-400 transition-colors hover:text-emerald-400"
                  >
                    Architecture
                  </a>
                </li>
                <li>
                  <Link
                    to="/docs"
                    className="text-sm text-slate-400 transition-colors hover:text-emerald-400"
                  >
                    Documentation
                  </Link>
                </li>
              </ul>
            </div>

            <div>
              <h4 className="mb-4 font-semibold text-white">Company</h4>
              <ul className="space-y-2">
                <li>
                  <Link
                    to="/blog"
                    className="text-sm text-slate-400 transition-colors hover:text-emerald-400"
                  >
                    Blog
                  </Link>
                </li>
                <li>
                  <a
                    href="#"
                    className="text-sm text-slate-400 transition-colors hover:text-emerald-400"
                  >
                    About Us
                  </a>
                </li>
                <li>
                  <a
                    href="#"
                    className="text-sm text-slate-400 transition-colors hover:text-emerald-400"
                  >
                    Contact
                  </a>
                </li>
              </ul>
            </div>

            <div>
              <h4 className="mb-4 font-semibold text-white">Legal</h4>
              <ul className="space-y-2">
                <li>
                  <a
                    href="#"
                    className="text-sm text-slate-400 transition-colors hover:text-emerald-400"
                  >
                    Privacy Policy
                  </a>
                </li>
                <li>
                  <a
                    href="#"
                    className="text-sm text-slate-400 transition-colors hover:text-emerald-400"
                  >
                    Terms of Service
                  </a>
                </li>
              </ul>
            </div>
          </div>

          <div className="flex flex-col items-center justify-between border-t border-slate-800 pt-8 md:flex-row">
            <p className="mb-4 text-sm text-slate-500 md:mb-0">
              © 2025 ACDS. All rights reserved.
            </p>
            <div className="flex items-center space-x-4">
              <a
                href="#"
                className="text-slate-400 transition-colors hover:text-emerald-400"
              >
                <Github className="h-5 w-5" />
              </a>
              <a
                href="#"
                className="text-slate-400 transition-colors hover:text-emerald-400"
              >
                <Twitter className="h-5 w-5" />
              </a>
              <a
                href="#"
                className="text-slate-400 transition-colors hover:text-emerald-400"
              >
                <Linkedin className="h-5 w-5" />
              </a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Landing;
