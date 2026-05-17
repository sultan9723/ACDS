import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import {
  Shield,
  Mail,
  Lock,
  AlertCircle,
  Loader2,
  ArrowLeft,
} from "lucide-react";

const Login = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const { login, enableDemoMode } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setIsLoading(true);

    if (!email || !password) {
      setError("Please enter both email and password");
      setIsLoading(false);
      return;
    }

    const result = await login(email, password);

    if (result.success) {
      navigate("/dashboard");
    } else {
      setError(result.error || "Login failed. Please try again.");
    }

    setIsLoading(false);
  };

  const handleDemoMode = () => {
    setError("");
    enableDemoMode();
    navigate("/dashboard");
  };

  return (
    <div className="relative flex min-h-screen items-start justify-center overflow-x-hidden overflow-y-auto bg-slate-950 px-4 pb-10 pt-28 text-slate-100 sm:px-6 sm:pb-12 sm:pt-32 lg:items-center lg:pt-28">
      <div className="absolute inset-0">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_left,rgba(20,184,166,0.16),transparent_30rem),radial-gradient(circle_at_bottom_right,rgba(14,165,233,0.10),transparent_28rem),linear-gradient(135deg,#020617_0%,#07111f_48%,#0b1220_100%)]" />
        <div className="absolute inset-0 opacity-[0.08] [background-image:linear-gradient(rgba(148,163,184,0.35)_1px,transparent_1px),linear-gradient(90deg,rgba(148,163,184,0.35)_1px,transparent_1px)] [background-size:48px_48px]" />
        <div className="absolute left-1/2 top-1/2 h-[34rem] w-[34rem] -translate-x-1/2 -translate-y-1/2 rounded-full bg-emerald-500/5 blur-3xl" />
      </div>

      <div className="relative z-10 w-full max-w-5xl">
        <Link
          to="/"
          className="mb-8 inline-flex items-center gap-2 rounded-lg border border-slate-700/70 bg-slate-950/45 px-3.5 py-2.5 text-sm font-medium text-slate-300 shadow-lg shadow-slate-950/20 backdrop-blur-md transition-colors hover:border-emerald-400/35 hover:bg-slate-900/75 hover:text-emerald-200 focus:outline-none focus:ring-2 focus:ring-emerald-400/60 focus:ring-offset-2 focus:ring-offset-slate-950"
          aria-label="Back to public home page"
        >
          <ArrowLeft className="h-5 w-5" />
          <span>Back to Home</span>
        </Link>

        <div className="mx-auto w-full max-w-md">
          <div className="mb-7 text-center">
          <div className="mb-4 inline-flex h-14 w-14 items-center justify-center rounded-2xl border border-emerald-400/30 bg-gradient-to-br from-emerald-400 to-teal-500 shadow-[0_0_40px_rgba(16,185,129,0.22)]">
            <Shield className="h-7 w-7 text-white" />
          </div>
          <p className="mb-2 text-xs font-semibold uppercase tracking-[0.24em] text-cyan-300/80">
            Enterprise AI SOC
          </p>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-50 sm:text-3xl">
            ACDS Admin Portal
          </h1>
          <p className="mt-2 text-sm leading-6 text-slate-400">
            Secure access for autonomous cyber defense monitoring, response,
            and analyst operations.
          </p>
        </div>

          <div className="rounded-2xl border border-slate-800/80 bg-slate-900/75 p-6 shadow-[0_24px_80px_rgba(2,6,23,0.46)] backdrop-blur-xl sm:p-8">
          <div className="mb-6 border-b border-slate-800/80 pb-5">
            <h2 className="text-lg font-semibold text-slate-100">
              Sign in to continue
            </h2>
            <p className="mt-1 text-sm text-slate-500">
              Use the admin credentials configured for this environment.
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-6">
            {error && (
              <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300">
                <AlertCircle className="h-4 w-4 flex-shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <div>
              <label className="mb-2 block text-sm font-medium text-slate-300">
                Email Address
              </label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-500" />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full rounded-lg border border-slate-700/80 bg-slate-950/70 py-3 pl-10 pr-4 text-white placeholder-slate-600 transition-colors focus:outline-none focus:border-emerald-500/80 focus:ring-2 focus:ring-emerald-500/20"
                  placeholder="admin@acds.com"
                />
              </div>
            </div>

            <div>
              <label className="mb-2 block text-sm font-medium text-slate-300">
                Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-500" />
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full rounded-lg border border-slate-700/80 bg-slate-950/70 py-3 pl-10 pr-4 text-white placeholder-slate-600 transition-colors focus:outline-none focus:border-emerald-500/80 focus:ring-2 focus:ring-emerald-500/20"
                  placeholder="Enter password"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="flex w-full items-center justify-center gap-2 rounded-lg border border-emerald-400/30 bg-emerald-500/20 px-4 py-3 font-semibold text-emerald-50 shadow-lg shadow-emerald-950/20 transition-all hover:bg-emerald-500/30 focus:outline-none focus:ring-2 focus:ring-emerald-400/70 focus:ring-offset-2 focus:ring-offset-slate-950 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {isLoading ? (
                <>
                  <Loader2 className="h-5 w-5 animate-spin" />
                  Authenticating...
                </>
              ) : (
                "Sign In"
              )}
            </button>

            <div className="space-y-3 border-t border-slate-800/80 pt-5">
              <button
                type="button"
                onClick={handleDemoMode}
                className="flex w-full items-center justify-center gap-2 rounded-lg border border-cyan-400/25 bg-cyan-500/10 px-4 py-3 font-semibold text-cyan-100 shadow-lg shadow-cyan-950/10 transition-all hover:border-cyan-300/40 hover:bg-cyan-500/15 focus:outline-none focus:ring-2 focus:ring-cyan-400/60 focus:ring-offset-2 focus:ring-offset-slate-950"
              >
                Continue in Demo Mode
              </button>
              <p className="text-center text-xs leading-5 text-slate-500">
                Demo Mode is for local presentation only.
              </p>
            </div>
          </form>

          <div className="mt-6 rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-4">
            <p className="mb-2 text-xs font-semibold uppercase tracking-[0.16em] text-cyan-300/80">
              Local Development
            </p>
            <p className="text-xs leading-5 text-slate-400">
              Admin credentials are configured through{" "}
              <span className="text-emerald-400">backend/.env</span> for local
              development.
            </p>
          </div>
        </div>

          <p className="mt-6 text-center text-sm text-slate-600">
            © 2025 ACDS - Autonomous Cyber Defense System
          </p>
        </div>
      </div>
    </div>
  );
};

export default Login;
