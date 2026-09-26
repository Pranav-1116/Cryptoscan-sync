import React, { useEffect, useState } from "react";
import { Badge, Button } from "../components/ui";
import { apiComplianceEvidence, apiComplianceRetention } from "../lib/api";

export default function Compliance() {
  const [loading, setLoading] = useState(true);
  const [evidenceData, setEvidenceData] = useState<any>(null);
  const [retentionData, setRetentionData] = useState<any>(null);
  const [selectedStandard, setSelectedStandard] = useState("PCI-DSS");

  useEffect(() => {
    let alive = true;
    async function loadCompliance() {
      setLoading(true);
      try {
        const [evRes, retRes] = await Promise.all([
          apiComplianceEvidence(),
          apiComplianceRetention(),
        ]);
        if (alive) {
          if (evRes.source === "live" && evRes.data) setEvidenceData(evRes.data);
          if (retRes.source === "live" && retRes.data) setRetentionData(retRes.data);
        }
      } catch (err) {
        console.error("Failed to load compliance evidence:", err);
      } finally {
        if (alive) setLoading(false);
      }
    }
    loadCompliance();
    return () => { alive = false; };
  }, []);

  const controls = evidenceData?.controls || [];
  const passCount = controls.filter((c: any) => c.status === "pass").length;
  const failCount = controls.filter((c: any) => c.status === "fail").length;
  const totalCount = controls.length;
  const complianceScore = totalCount > 0 ? Math.round((passCount / totalCount) * 100) : 100;

  const standards = [
    { id: "PCI-DSS", name: "PCI-DSS v4.0.1", tag: "Payment Systems" },
    { id: "NIST", name: "NIST SP 800-131A / IR 8547", tag: "Quantum Transition" },
    { id: "DORA", name: "DORA (EU 2022/2554)", tag: "Operational Resilience" },
    { id: "FIPS", name: "FIPS 140-3", tag: "Module Validation" },
    { id: "SOC2", name: "SOC 2 Type II (CC6.1)", tag: "Transmission Security" },
  ];

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      {/* Compliance Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "24px", flexWrap: "wrap", gap: "16px" }}>
        <div>
          <div style={{ fontSize: "12px", fontFamily: "var(--mono)", color: "var(--cyan)", letterSpacing: "0.1em", textTransform: "uppercase" }}>
            Evidence-Backed Governance Engine
          </div>
          <h1 style={{ fontSize: "26px", fontWeight: 700, margin: "4px 0 6px" }}>Continuous Regulatory Compliance</h1>
          <p style={{ margin: 0, fontSize: "13.5px", color: "var(--dim)" }}>
            Deterministic policy verification. Every compliance status is backed by authoritative platform observations and immutable WORM logs.
          </p>
        </div>

        <div style={{ display: "flex", gap: "10px" }}>
          <a
            href="/api/v1/compliance/evidence"
            target="_blank"
            rel="noreferrer"
            className="btn outline"
            style={{ textDecoration: "none", fontSize: "12px", padding: "8px 14px", borderRadius: "6px" }}
          >
            Export Compliance Evidence
          </a>
          <a
            href="#/evidence"
            className="btn primary"
            style={{ textDecoration: "none", fontSize: "12px", padding: "8px 14px", borderRadius: "6px" }}
          >
            Audit Evidence Lake
          </a>
        </div>
      </div>

      {/* Top 4 Metric Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "14px", marginBottom: "24px" }}>
        <div className="panel" style={{ padding: "18px" }}>
          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            Compliance Posture Score
          </div>
          <div style={{ fontSize: "28px", fontWeight: 700, color: complianceScore >= 90 ? "var(--green)" : "var(--amber)", margin: "4px 0" }}>
            {loading ? "..." : `${complianceScore}%`}
          </div>
          <div style={{ fontSize: "12px", color: "var(--dim)" }}>
            {passCount} passing out of {totalCount} evaluated controls
          </div>
        </div>

        <div className="panel" style={{ padding: "18px" }}>
          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            Active Violations
          </div>
          <div style={{ fontSize: "28px", fontWeight: 700, color: failCount > 0 ? "var(--red)" : "var(--green)", margin: "4px 0" }}>
            {loading ? "..." : failCount}
          </div>
          <div style={{ fontSize: "12px", color: "var(--dim)" }}>
            Requiring immediate remediation
          </div>
        </div>

        <div className="panel" style={{ padding: "18px" }}>
          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            WORM Retention Policy
          </div>
          <div style={{ fontSize: "24px", fontWeight: 700, margin: "6px 0" }}>
            {loading ? "..." : `${retentionData?.policy?.audit_log_years ?? 7} Years`}
          </div>
          <div style={{ fontSize: "12px", color: "var(--green)" }}>
            Immutable append-only lock
          </div>
        </div>

        <div className="panel" style={{ padding: "18px" }}>
          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            Supervisory Alignment
          </div>
          <div style={{ fontSize: "20px", fontWeight: 700, margin: "7px 0", color: "var(--cyan)" }}>
            Harmonized
          </div>
          <div style={{ fontSize: "12px", color: "var(--dim)" }}>
            Cross-regulatory mapping
          </div>
        </div>
      </div>

      {/* Standards Selection */}
      <div style={{ display: "flex", gap: "10px", marginBottom: "20px", flexWrap: "wrap" }}>
        {standards.map((s) => (
          <button
            key={s.id}
            onClick={() => setSelectedStandard(s.id)}
            style={{
              padding: "8px 16px",
              borderRadius: "8px",
              border: "1px solid var(--line)",
              background: selectedStandard === s.id ? "var(--cyan)" : "var(--bg-2)",
              color: selectedStandard === s.id ? "#04121d" : "var(--text)",
              fontWeight: selectedStandard === s.id ? 700 : 500,
              fontSize: "12.5px",
              cursor: "pointer"
            }}
          >
            {s.name}
          </button>
        ))}
      </div>

      {/* Evidence Table */}
      <div className="panel" style={{ padding: "20px" }}>
        <h3 style={{ margin: "0 0 4px", fontSize: "16px", fontWeight: 600 }}>Deterministic Control Verifications</h3>
        <p style={{ margin: "0 0 16px", fontSize: "12px", color: "var(--dim)" }}>
          Evaluated controls backed by live configuration telemetry and signed scanner artifacts.
        </p>

        <div style={{ overflowX: "auto" }}>
          <table className="tbl" style={{ width: "100%" }}>
            <thead>
              <tr>
                <th>Control Key</th>
                <th>Status</th>
                <th>Observed Evidence Details</th>
                <th>Evaluated Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {controls.map((c: any, idx: number) => (
                <tr key={idx}>
                  <td>
                    <span style={{ fontFamily: "var(--mono)", fontSize: "12.5px", fontWeight: 600, color: "var(--cyan)" }}>
                      {c.control}
                    </span>
                  </td>
                  <td>
                    <Badge variant={c.status === "pass" ? "success" : "danger"}>
                      {c.status.toUpperCase()}
                    </Badge>
                  </td>
                  <td>
                    <span style={{ fontFamily: "var(--mono)", fontSize: "11.5px", color: "var(--text)" }}>
                      {typeof c.evidence === "object" ? JSON.stringify(c.evidence) : String(c.evidence)}
                    </span>
                  </td>
                  <td>
                    <span style={{ fontSize: "12px", color: "var(--dim)" }}>
                      {c.checked_at ? new Date(c.checked_at).toLocaleString() : "Live"}
                    </span>
                  </td>
                </tr>
              ))}

              {controls.length === 0 && !loading && (
                <tr>
                  <td colSpan={4} style={{ textAlign: "center", padding: "36px", color: "var(--dim)" }}>
                    No policy evidence registered yet. Configure compliance frameworks in Settings.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
