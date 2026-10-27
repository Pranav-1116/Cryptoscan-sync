import React, { useEffect, useState } from "react";
import { Badge } from "../components/ui";
import {
  apiSystemHealthStatus, apiScannerEnginesHealth, apiConnectorsHealth,
  SystemServiceHealth, ScannerEngineHealth, ConnectorHealth,
} from "../lib/api";

export default function SystemHealth() {
  const [services, setServices] = useState<SystemServiceHealth[]>([]);
  const [scanners, setScanners] = useState<ScannerEngineHealth[]>([]);
  /* §4.8 (round 79): connectors measured from the outbound delivery audit —
   * registration/enabled is configuration, not health. */
  const [connectors, setConnectors] = useState<ConnectorHealth[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastCheck, setLastCheck] = useState<string>("");

  const refreshHealth = async () => {
    setLoading(true);
    try {
      const [svc, scn, con] = await Promise.all([
        apiSystemHealthStatus(),
        apiScannerEnginesHealth(),
        apiConnectorsHealth()
      ]);
      setServices(svc);
      setScanners(scn);
      setConnectors(con ? con.connectors : null);
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
                    Latency: {s.latencyMs === null ? "not measured" : `${s.latencyMs}ms`} · {s.details || "No independent probe"}
                  </div>
                </div>
                <Badge tone={s.status === "Operational" ? "green" : s.status === "Degraded" ? "amber" : s.status === "Offline" ? "red" : "neutral"}>{s.status}</Badge>
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
                <Badge tone={scn.status === "Healthy" ? "green" : scn.status === "On demand" ? "neutral" : "red"}>{scn.status}</Badge>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Connectors / outbound integrations — measured from the delivery audit */}
      <div className="panel" style={{ padding: "20px", marginBottom: "28px" }}>
        <h2 style={{ fontSize: "16px", fontWeight: 600, margin: "0 0 6px" }}>Connectors & Outbound Integrations</h2>
        <p style={{ margin: "0 0 16px", fontSize: "12px", color: "var(--dim)" }}>
          Measured from the outbound delivery audit (one row per real signed HTTP attempt or air-gap skip).
          Registration and the enabled flag are configuration, not health — a connector with no delivery
          history reports <b>Not measured</b>, never a derived &quot;connected&quot;.
        </p>
        {connectors === null && (
          <div style={{ fontSize: "13px", color: "var(--dim)" }}>
            Connector probe unavailable or not authenticated — status Not measured, never inferred.
          </div>
        )}
        {connectors !== null && connectors.length === 0 && (
          <div style={{ fontSize: "13px", color: "var(--dim)" }}>
            No integrations registered — nothing to measure.
          </div>
        )}
        {connectors !== null && connectors.length > 0 && (
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {connectors.map((c) => (
              <div
                key={c.integration_id}
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
                  <div style={{ fontWeight: 600, fontSize: "13px" }}>{c.name} <span style={{ color: "var(--dim)", fontWeight: 400 }}>· {c.kind}</span></div>
                  <div style={{ fontSize: "11px", color: "var(--dim)", marginTop: "2px" }}>
                    {c.detail}
                    {c.last_delivery?.age_s != null ? ` · ${c.last_delivery.age_s}s ago` : ""}
                  </div>
                </div>
                <Badge tone={c.status === "Operational" ? "green" : c.status === "Degraded" ? "red" : c.status === "Disabled" ? "neutral" : "amber"}>{c.status}</Badge>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
