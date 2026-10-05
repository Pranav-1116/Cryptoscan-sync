import React, { useEffect, useState } from "react";
import { Badge } from "../components/ui";
import { apiSystemHealthStatus, apiScannerEnginesHealth, SystemServiceHealth, ScannerEngineHealth } from "../lib/api";

export default function SystemHealth() {
  const [services, setServices] = useState<SystemServiceHealth[]>([]);
  const [scanners, setScanners] = useState<ScannerEngineHealth[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastCheck, setLastCheck] = useState<string>("");

  const refreshHealth = async () => {
    setLoading(true);
    try {
      const [svc, scn] = await Promise.all([
        apiSystemHealthStatus(),
        apiScannerEnginesHealth()
      ]);
      setServices(svc);
      setScanners(scn);
      setLastCheck(new Date().toLocaleTimeString());
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refreshHealth();
    const interval = setInterval(refreshHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="page" style={{ maxWidth: "1100px", margin: "0 auto", padding: "10px 0 60px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "24px" }}>
        <div>
          <span style={{ fontSize: "12px", fontFamily: "var(--mono)", color: "var(--cyan)", letterSpacing: "0.1em", textTransform: "uppercase" }}>Platform Observability</span>
          <h1 style={{ fontSize: "26px", fontWeight: 700, margin: "4px 0 6px" }}>System Health & Daemon Telemetry</h1>
          <p style={{ margin: 0, fontSize: "13.5px", color: "var(--dim)" }}>
            Live status of continuous monitoring daemons, deterministic engines, and scanning workers.
          </p>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <span style={{ fontSize: "12px", color: "var(--dim)" }}>Last check: {lastCheck || "Syncing..."}</span>
          <button onClick={refreshHealth} className="btn outline sm" disabled={loading}>
            {loading ? "Checking..." : "Refresh Status"}
          </button>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px", marginBottom: "28px" }}>
        {/* Core Services */}
        <div className="panel" style={{ padding: "20px" }}>
          <h2 style={{ fontSize: "16px", fontWeight: 600, margin: "0 0 16px" }}>Backend Control Plane Services</h2>
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {services.map((s) => (
              <div
                key={s.name}
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  padding: "10px 12px",
                  background: "var(--bg-2)",
                  borderRadius: "var(--r)",
                  border: "1px solid var(--line)"
                }}
              >
                <div>
                  <div style={{ fontWeight: 600, fontSize: "13px" }}>{s.name}</div>
                  <div style={{ fontSize: "11px", color: "var(--dim)", marginTop: "2px" }}>
                    Latency: {s.latencyMs}ms · {s.details || "Authoritative heartbeat active"}
                  </div>
                </div>
                <Badge tone={s.status === "Operational" ? "green" : "red"}>{s.status}</Badge>
              </div>
            ))}
          </div>
        </div>

        {/* Scanner Engine Daemons */}
        <div className="panel" style={{ padding: "20px" }}>
          <h2 style={{ fontSize: "16px", fontWeight: 600, margin: "0 0 16px" }}>Continuous Ingest & Scanner Daemons</h2>
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {scanners.map((scn) => (
              <div
                key={scn.id}
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  padding: "10px 12px",
                  background: "var(--bg-2)",
                  borderRadius: "var(--r)",
                  border: "1px solid var(--line)"
                }}
              >
                <div>
                  <div style={{ fontWeight: 600, fontSize: "13px" }}>{scn.name}</div>
                  <div style={{ fontSize: "11px", color: "var(--dim)", marginTop: "2px" }}>
                    State: {scn.lastObservation} · Discovered: {scn.assetsDiscovered} assets
                  </div>
                </div>
                <Badge tone={scn.status === "Healthy" ? "green" : "red"}>{scn.status}</Badge>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
