import React, { useEffect, useState } from "react";
import { Badge, Button } from "../components/ui";
import { apiDriftEvents } from "../lib/api";

export default function Drift() {
  const [loading, setLoading] = useState(true);
  const [events, setEvents] = useState<any[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<any>(null);

  useEffect(() => {
    let alive = true;
    async function loadDrift() {
      setLoading(true);
      try {
        const res = await apiDriftEvents(1, 50);
        if (alive && res.source === "live" && res.data) {
          const evs = (res.data as any).events || [];
          setEvents(evs);
          if (evs.length > 0) setSelectedEvent(evs[0]);
        }
      } catch (err) {
        console.error("Failed to load drift events:", err);
      } finally {
        if (alive) setLoading(false);
      }
    }
    loadDrift();
    return () => { alive = false; };
  }, []);

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      {/* Drift Timeline Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "24px", flexWrap: "wrap", gap: "16px" }}>
        <div>
          <div style={{ fontSize: "12px", fontFamily: "var(--mono)", color: "var(--cyan)", letterSpacing: "0.1em", textTransform: "uppercase" }}>
            Real-Time State Observation
          </div>
          <h1 style={{ fontSize: "26px", fontWeight: 700, margin: "4px 0 6px" }}>Cryptographic Drift Timeline</h1>
          <p style={{ margin: 0, fontSize: "13.5px", color: "var(--dim)" }}>
            Tracking configuration deviations, cipher suite downgrades, and unapproved algorithm deployments across your estate.
          </p>
        </div>

        <div style={{ display: "flex", gap: "10px" }}>
          <a
            href="/api/v1/drift"
            target="_blank"
            rel="noreferrer"
            className="btn outline"
            style={{ textDecoration: "none", fontSize: "12px", padding: "8px 14px", borderRadius: "6px" }}
          >
            Export Drift Feed
          </a>
          <a
            href="#/scanners"
            className="btn primary"
            style={{ textDecoration: "none", fontSize: "12px", padding: "8px 14px", borderRadius: "6px" }}
          >
            Trigger Drift Audit
          </a>
        </div>
      </div>

      {/* Top Drift Metrics */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "14px", marginBottom: "24px" }}>
        <div className="panel" style={{ padding: "16px" }}>
          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            Total Drift Events
          </div>
          <div style={{ fontSize: "26px", fontWeight: 700, margin: "4px 0" }}>
            {loading ? "..." : events.length}
          </div>
          <div style={{ fontSize: "12px", color: "var(--dim)" }}>
            Observed across all targets
          </div>
        </div>

        <div className="panel" style={{ padding: "16px" }}>
          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            Critical Deviations
          </div>
          <div style={{ fontSize: "26px", fontWeight: 700, color: "var(--red)", margin: "4px 0" }}>
            {loading ? "..." : events.filter(e => e.severity === "CRITICAL" || e.impact === "CRITICAL").length}
          </div>
          <div style={{ fontSize: "12px", color: "var(--dim)" }}>
            Immediate policy violations
          </div>
        </div>

        <div className="panel" style={{ padding: "16px" }}>
          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            Evaluation Pipeline
          </div>
          <div style={{ fontSize: "20px", fontWeight: 700, margin: "7px 0", color: "var(--green)" }}>
            Active (TimescaleDB)
          </div>
          <div style={{ fontSize: "12px", color: "var(--dim)" }}>
            EWMA sliding baseline
          </div>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: "24px" }}>
        {/* Timeline Events List */}
        <div className="panel" style={{ padding: "20px" }}>
          <h3 style={{ margin: "0 0 4px", fontSize: "16px", fontWeight: 600 }}>Detected Drift Stream</h3>
          <p style={{ margin: "0 0 16px", fontSize: "12px", color: "var(--dim)" }}>
            Deviations flagged by continuous network, container, and cloud scanners.
          </p>

          <div style={{ display: "flex", flexDirection: "column", gap: "10px", maxHeight: "560px", overflowY: "auto" }}>
            {events.map((e, idx) => {
              const isSelected = selectedEvent?.id === e.id;
              return (
                <div
                  key={e.id || idx}
                  onClick={() => setSelectedEvent(e)}
                  style={{
                    padding: "12px 14px",
                    background: isSelected ? "rgba(0, 212, 255, 0.08)" : "var(--bg-2)",
                    border: `1px solid ${isSelected ? "var(--cyan)" : "var(--line)"}`,
                    borderRadius: "8px",
                    cursor: "pointer",
                    display: "flex",
                    flexDirection: "column",
                    gap: "6px"
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ fontSize: "13px", fontWeight: 600, color: "var(--text)" }}>
                      {e.title || e.event_type || `Drift Event #${e.id || idx + 1}`}
                    </span>
                    <Badge variant={e.severity === "CRITICAL" ? "danger" : e.severity === "HIGH" ? "warning" : "info"}>
                      {(e.severity || e.status || "DETECTED").toUpperCase()}
                    </Badge>
                  </div>
                  <div style={{ fontSize: "12px", color: "var(--dim)" }}>
                    Target: <span style={{ fontFamily: "var(--mono)", color: "var(--cyan)" }}>{e.target || e.asset_id || "Estate Asset"}</span>
                  </div>
                  <div style={{ fontSize: "11px", color: "var(--faint)" }}>
                    Source: {e.source || "Automated Auditor"} · {e.created_at ? new Date(e.created_at).toLocaleString() : "Recently"}
                  </div>
                </div>
              );
            })}

            {events.length === 0 && !loading && (
              <div style={{ textAlign: "center", padding: "40px", color: "var(--dim)" }}>
                <div style={{ fontSize: "14px", fontWeight: 600, color: "var(--text)", marginBottom: "4px" }}>
                  Zero cryptographic drift detected
                </div>
                <p style={{ margin: "0 0 16px", fontSize: "12.5px" }}>
                  All surveyed cryptographic primitives match their authorized operational baselines.
                </p>
                <a href="#/scanners" className="btn sm primary" style={{ textDecoration: "none" }}>
                  Run Verification Scan
                </a>
              </div>
            )}
          </div>
        </div>

        {/* Selected Drift Event Details */}
        <div className="panel" style={{ padding: "24px" }}>
          <h3 style={{ margin: "0 0 4px", fontSize: "16px", fontWeight: 600 }}>Deviation Analysis</h3>
          <p style={{ margin: "0 0 16px", fontSize: "12px", color: "var(--dim)" }}>
            Exact state divergence and cryptographic policy impact.
          </p>

          {selectedEvent ? (
            <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
              <div style={{ padding: "12px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "6px" }}>
                <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Event Title</div>
                <div style={{ fontSize: "14.5px", fontWeight: 700, color: "var(--text)", marginTop: "2px" }}>
                  {selectedEvent.title || selectedEvent.event_type}
                </div>
              </div>

              <div>
                <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", marginBottom: "4px" }}>Baseline Authorized State</div>
                <div style={{ padding: "8px 12px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "6px", fontSize: "12px", fontFamily: "var(--mono)", color: "var(--green)" }}>
                  {selectedEvent.previousState || selectedEvent.expected_state || "TLS 1.3 / ML-KEM-768 / AES-256-GCM"}
                </div>
              </div>

              <div>
                <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", marginBottom: "4px" }}>Observed Drift State</div>
                <div style={{ padding: "8px 12px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "6px", fontSize: "12px", fontFamily: "var(--mono)", color: "var(--red)" }}>
                  {selectedEvent.currentState || selectedEvent.observed_state || "Deprecated primitive or altered cipher configuration"}
                </div>
              </div>

              <div style={{ borderTop: "1px solid var(--line)", paddingTop: "12px" }}>
                <div style={{ fontSize: "11px", color: "var(--dim)", marginBottom: "4px" }}>Policy Enforcement Impact</div>
                <div style={{ fontSize: "12.5px", color: "#fca5a5" }}>
                  {selectedEvent.policyImpact || selectedEvent.detail || "Flagged for security team review"}
                </div>
              </div>

              <div style={{ display: "flex", gap: "10px", marginTop: "8px" }}>
                <a href="#/whatif" className="btn sm primary" style={{ textDecoration: "none", flex: 1, textAlign: "center" }}>
                  Simulate Remediation
                </a>
                <a href="#/evidence" className="btn sm outline" style={{ textDecoration: "none", flex: 1, textAlign: "center" }}>
                  Inspect WORM Proof
                </a>
              </div>
            </div>
          ) : (
            <div style={{ textAlign: "center", padding: "40px", color: "var(--dim)", fontSize: "13px" }}>
              Select a drift event from the stream to view full cryptographic differential details.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
