import React, { useState, useEffect } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "../ui/Card";

const API_BASE = "http://localhost:8000/api/v1";

const ThreeLayerDetectionDashboard = () => {
  const [layerStatus, setLayerStatus] = useState(null);
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState({
    total_threats: 0,
    critical: 0,
    high: 0,
    medium: 0,
    layer1_detections: 0,
    layer3_detections: 0,
  });

  useEffect(() => {
    fetchLayerStatus();
    fetchThreats();
  }, []);

  const fetchLayerStatus = async () => {
    try {
      const res = await fetch(`${API_BASE}/ransomware/layers/status`);
      const data = await res.json();
      if (data.success) {
        setLayerStatus(data.status);
      }
    } catch (e) {
      console.error("Failed to fetch layer status:", e);
    }
  };

  const fetchThreats = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/ransomware/list?limit=100`);
      const data = await res.json();
      if (data.success) {
        setThreats(data.threats || []);
        
        // Calculate stats
        const newStats = {
          total_threats: data.threats?.length || 0,
          critical: (data.threats || []).filter((t) => t.severity === "CRITICAL").length,
          high: (data.threats || []).filter((t) => t.severity === "HIGH").length,
          medium: (data.threats || []).filter((t) => t.severity === "MEDIUM").length,
          layer1_detections: 0,
          layer3_detections: 0,
        };
        
        setStats(newStats);
      }
    } catch (e) {
      console.error("Failed to fetch threats:", e);
    } finally {
      setLoading(false);
    }
  };

  const getLayerStatusColor = (status) => {
    switch (status?.toLowerCase()) {
      case "operational":
        return "bg-green-900/50 text-green-400 border-green-800";
      case "degraded":
        return "bg-yellow-900/50 text-yellow-400 border-yellow-800";
      default:
        return "bg-red-900/50 text-red-400 border-red-800";
    }
  };

  const StatCard = ({ label, value, color = "text-slate-200" }) => (
    <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700">
      <p className="text-xs text-slate-500 uppercase mb-2">{label}</p>
      <p className={`text-2xl font-bold ${color}`}>{value}</p>
    </div>
  );

  return (
    <div className="space-y-6">
      {/* Overall Status */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-slate-200">
            3-Layer Detection System Status
          </CardTitle>
        </CardHeader>
        <CardContent>
          {loading || !layerStatus ? (
            <div className="text-center py-8 text-slate-500">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-emerald-500 mx-auto"></div>
            </div>
          ) : (
            <div className="space-y-4">
              {/* Overall Status Badge */}
              <div className="flex items-center gap-3">
                <div
                  className={`w-3 h-3 rounded-full ${
                    layerStatus.overall_status === "operational"
                      ? "bg-green-500 animate-pulse"
                      : "bg-yellow-500"
                  }`}
                ></div>
                <span
                  className={`text-sm font-semibold px-3 py-1 rounded border ${getLayerStatusColor(
                    layerStatus.overall_status
                  )}`}
                >
                  {layerStatus.overall_status?.toUpperCase()}
                </span>
              </div>

              {/* Layers Grid */}
              <div className="grid grid-cols-3 gap-4 mt-4">
                {/* Layer 1 */}
                <div className="bg-slate-900/50 rounded-lg border border-slate-700 p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <div className="w-8 h-8 rounded-lg bg-blue-900/50 flex items-center justify-center text-blue-400 font-bold text-sm">
                      1
                    </div>
                    <p className="text-sm font-semibold text-slate-200">
                      Command Behavior
                    </p>
                  </div>
                  <p className="text-xs text-slate-500 mb-2">
                    {layerStatus.layers?.layer1_command_behavior?.model}
                  </p>
                  <div
                    className={`text-xs px-2 py-1 rounded border inline-block ${
                      layerStatus.layers?.layer1_command_behavior?.status ===
                      "ready"
                        ? "bg-green-900/30 text-green-400 border-green-800/50"
                        : "bg-slate-800 text-slate-400 border-slate-700"
                    }`}
                  >
                    {layerStatus.layers?.layer1_command_behavior?.status ||
                      "N/A"}
                  </div>
                </div>

                {/* Layer 2 */}
                <div className="bg-slate-900/50 rounded-lg border border-slate-700 p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <div className="w-8 h-8 rounded-lg bg-purple-900/50 flex items-center justify-center text-purple-400 font-bold text-sm">
                      2
                    </div>
                    <p className="text-sm font-semibold text-slate-200">
                      PE Header Binary
                    </p>
                  </div>
                  <p className="text-xs text-slate-500 mb-2">
                    {layerStatus.layers?.layer2_pe_header?.model}
                  </p>
                  <div
                    className={`text-xs px-2 py-1 rounded border inline-block ${
                      layerStatus.layers?.layer2_pe_header?.status === "ready"
                        ? "bg-green-900/30 text-green-400 border-green-800/50"
                        : "bg-slate-800 text-slate-400 border-slate-700"
                    }`}
                  >
                    {layerStatus.layers?.layer2_pe_header?.status || "N/A"}
                  </div>
                </div>

                {/* Layer 3 */}
                <div className="bg-slate-900/50 rounded-lg border border-slate-700 p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <div className="w-8 h-8 rounded-lg bg-orange-900/50 flex items-center justify-center text-orange-400 font-bold text-sm">
                      3
                    </div>
                    <p className="text-sm font-semibold text-slate-200">
                      Mass-Encryption
                    </p>
                  </div>
                  <p className="text-xs text-slate-500 mb-2">
                    {layerStatus.layers?.layer3_mass_encryption?.model}
                  </p>
                  <div
                    className={`text-xs px-2 py-1 rounded border inline-block ${
                      layerStatus.layers?.layer3_mass_encryption?.status ===
                      "ready"
                        ? "bg-green-900/30 text-green-400 border-green-800/50"
                        : "bg-slate-800 text-slate-400 border-slate-700"
                    }`}
                  >
                    {layerStatus.layers?.layer3_mass_encryption?.status ||
                      "N/A"}
                  </div>
                </div>
              </div>

              {/* Layer 3 Features */}
              {layerStatus.layers?.layer3_mass_encryption?.features && (
                <div className="border-t border-slate-700 pt-4 mt-4">
                  <p className="text-xs text-slate-500 uppercase mb-3">
                    Layer 3 Features
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {layerStatus.layers.layer3_mass_encryption.features.map(
                      (feature) => (
                        <span
                          key={feature}
                          className="text-xs px-2 py-1 bg-slate-800/50 text-slate-400 rounded border border-slate-700"
                        >
                          {feature}
                        </span>
                      )
                    )}
                  </div>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Threat Statistics */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Total Threats"
          value={stats.total_threats}
          color="text-slate-200"
        />
        <StatCard label="Critical" value={stats.critical} color="text-red-400" />
        <StatCard
          label="High Severity"
          value={stats.high}
          color="text-orange-400"
        />
        <StatCard
          label="Medium Severity"
          value={stats.medium}
          color="text-yellow-400"
        />
      </div>

      {/* Recent Threats */}
      {!loading && threats.length > 0 && (
        <Card className="bg-slate-900/50 border-slate-800">
          <CardHeader>
            <CardTitle className="text-slate-200">
              Recent Ransomware Threats
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-sm text-left">
                <thead className="text-xs text-slate-400 uppercase bg-slate-900/50 border-b border-slate-800">
                  <tr>
                    <th className="px-4 py-3">Threat ID</th>
                    <th className="px-4 py-3">Severity</th>
                    <th className="px-4 py-3">Confidence</th>
                    <th className="px-4 py-3">Source Host</th>
                    <th className="px-4 py-3">Detected At</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {threats.slice(0, 10).map((threat) => (
                    <tr
                      key={threat.id}
                      className="hover:bg-slate-800/30 transition-colors"
                    >
                      <td className="px-4 py-3 font-mono text-xs text-slate-300">
                        {threat.id}
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`text-xs px-2 py-1 rounded border ${
                            threat.severity === "CRITICAL"
                              ? "bg-red-900/30 text-red-400 border-red-800/50"
                              : threat.severity === "HIGH"
                              ? "bg-orange-900/30 text-orange-400 border-orange-800/50"
                              : "bg-yellow-900/30 text-yellow-400 border-yellow-800/50"
                          }`}
                        >
                          {threat.severity}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-slate-300">
                        {threat.confidence
                          ? `${Math.round(threat.confidence * 100)}%`
                          : "N/A"}
                      </td>
                      <td className="px-4 py-3 text-slate-400">
                        {threat.source_host}
                      </td>
                      <td className="px-4 py-3 text-slate-500 text-xs">
                        {new Date(threat.detected_at).toLocaleDateString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default ThreeLayerDetectionDashboard;
