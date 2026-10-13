import { Link } from "react-router-dom";
import React, { useEffect, useState } from "react";
import { Badge } from "../components/ui";
import { apiComplianceEvidence, apiComplianceRetention } from "../lib/api";
import AuthenticatedDownload from "../components/AuthenticatedDownload";

/* Compliance truth rules (product vision §4.3, P0 trust gap):
 * - No controls returned is NOT a 100% score — it is "not evaluated".
 * - A missing retention policy is NOT "7 years" — it is "not configured".
 * - "unknown" is a status of its own, distinct from FAIL.
 * - The evidence engine evaluates SOC-2-style platform controls; framework
 *   buttons filter by an explicit mapping and say plainly when a framework
 *   has no mapped controls, instead of implying all five are evaluated. */

const STANDARD_CONTROL_KEYS: Record<string, RegExp[]> = {
  "SOC2": [
    /^access\./, /^config\./, /^audit\./, /^deploy\./, /^protection\./, /^retention\./,
  ],
  // The evidence engine has no control mapping for these frameworks yet.
  // Selecting them must show "nothing evaluated", never the SOC-2 rows.
  "PCI-DSS": [], "NIST": [], "DORA": [], "FIPS": [],
};

type EvidenceState =
  | { phase: "loading" }
  | { phase: "live"; controls: any[] }
  | { phase: "offline" };

export default function Compliance() {
  const [evidence, setEvidence] = useState<EvidenceState>({ phase: "loading" });
  const [retentionData, setRetentionData] = useState<any>(null);
  const [retentionLive, setRetentionLive] = useState(false);
  const [selectedStandard, setSelectedStandard] = useState("SOC2");

  useEffect(() => {
    let alive = true;
    async function loadCompliance() {
      setEvidence({ phase: "loading" });
      try {
        const [evRes, retRes] = await Promise.all([
          apiComplianceEvidence(),
          apiComplianceRetention(),
        ]);
        if (!alive) return;
        if (evRes.source === "live" && evRes.data) {
          const controls = Array.isArray(evRes.data.controls) ? evRes.data.controls : [];
          setEvidence({ phase: "live", controls });
        } else {
          setEvidence({ phase: "offline" });
        }
        if (retRes.source === "live" && retRes.data) {
          setRetentionData(retRes.data);
          setRetentionLive(true);
        } else {
          setRetentionLive(false);
        }
      } catch (err) {
        console.error("Failed to load compliance evidence:", err);
        if (alive) setEvidence({ phase: "offline" });
      }
    }
    loadCompliance();
    return () => { alive = false; };
  }, []);

  const allControls = evidence.phase === "live" ? evidence.controls : [];
  const passCount = allControls.filter((c: any) => c.status === "pass").length;
  const failCount = allControls.filter((c: any) => c.status === "fail").length;
  const unknownCount = allControls.filter(
    (c: any) => c.status !== "pass" && c.status !== "fail").length;
  const totalCount = allControls.length;
  // No denominator -> no percentage. Empty is "not evaluated", never 100%.
  const evaluated = totalCount > 0 && evidence.phase === "live";
  const complianceScore = evaluated ? Math.round((passCount / totalCount) * 100) : null;

  const patterns = STANDARD_CONTROL_KEYS[selectedStandard] ?? [];
  const controls = patterns.length
    ? allControls.filter((c: any) => patterns.some((p) => p.test(String(c.control ?? ""))))
    : [];
  const standardMapped = patterns.length > 0;

  const standards = [
    { id: "SOC2", name: "SOC 2 Type II (CC-series)", tag: "Platform controls" },
    { id: "PCI-DSS", name: "PCI-DSS v4.0.1", tag: "Not mapped" },
    { id: "NIST", name: "NIST SP 800-131A / IR 8547", tag: "Not mapped" },
    { id: "DORA", name: "DORA (EU 2022/2554)", tag: "Not mapped" },
    { id: "FIPS", name: "FIPS 140-3", tag: "Not mapped" },
  ];

  const retentionYears = retentionLive ? retentionData?.policy?.audit_log_years : undefined;
  const mappedFrameworks = Object.values(STANDARD_CONTROL_KEYS).filter((p) => p.length > 0).length;

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
            Deterministic policy verification over platform controls. Framework certifications are external; this page reports what the engine has actually evaluated.
          </p>
        </div>

        <div style={{ display: "flex", gap: "10px" }}>
          <AuthenticatedDownload
            path="/api/v1/compliance/evidence"
            filename="compliance-evidence.json"
            className="btn outline"
            style={{ fontSize: "12px", padding: "8px 14px", borderRadius: "var(--r)" }}
          >
            Export Compliance Evidence
          </AuthenticatedDownload>
          <Link
            to="/evidence"
            className="btn primary"
            style={{ textDecoration: "none", fontSize: "12px", padding: "8px 14px", borderRadius: "var(--r)" }}
          >
            Audit Evidence Lake
          </Link>
        </div>
      </div>

      {evidence.phase === "offline" && (
        <div className="panel" style={{ padding: "14px 18px", marginBottom: "18px", borderColor: "var(--amber)" }}>
          <span style={{ color: "var(--amber)", fontWeight: 600 }}>Compliance evidence is unavailable.</span>{" "}
          <span style={{ color: "var(--dim)", fontSize: "13px" }}>
            Nothing below is evaluated — no score is shown while the evidence source is unreachable.
          </span>
        </div>
      )}

      {/* Top 4 Metric Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "14px", marginBottom: "24px" }}>
        <div className="panel" style={{ padding: "18px" }}>
          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            Compliance Posture Score
          </div>
          <div style={{ fontSize: "28px", fontWeight: 700, color: complianceScore === null ? "var(--dim)" : complianceScore >= 90 ? "var(--green)" : "var(--amber)", margin: "4px 0" }}>
            {evidence.phase === "loading" ? "..." : complianceScore === null ? "—" : `${complianceScore}%`}
          </div>
          <div style={{ fontSize: "12px", color: "var(--dim)" }}>
            {evaluated
              ? `${passCount} passing out of ${totalCount} evaluated controls`
              : "Not evaluated — the engine returned no controls"}
          </div>
        </div>

        <div className="panel" style={{ padding: "18px" }}>
          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            Active Violations
          </div>
          <div style={{ fontSize: "28px", fontWeight: 700, color: failCount > 0 ? "var(--red)" : evaluated ? "var(--green)" : "var(--dim)", margin: "4px 0" }}>
            {evidence.phase === "loading" ? "..." : evaluated ? failCount : "—"}
          </div>
          <div style={{ fontSize: "12px", color: "var(--dim)" }}>
            {evaluated
              ? unknownCount > 0
                ? `${failCount} failed · ${unknownCount} not evaluable (unknown)`
                : "Requiring immediate remediation"
              : "No evaluation — no violation claim"}
          </div>
        </div>

        <div className="panel" style={{ padding: "18px" }}>
          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            WORM Retention Policy
          </div>
          <div style={{ fontSize: "24px", fontWeight: 700, margin: "6px 0" }}>
            {evidence.phase === "loading"
              ? "..."
              : retentionYears !== undefined && retentionYears !== null
                ? `${retentionYears} Years`
                : "Not configured"}
          </div>
          <div style={{ fontSize: "12px", color: retentionYears != null ? "var(--green)" : "var(--dim)" }}>
            {retentionYears != null
              ? "Configured platform policy (enforcement is per-write)"
              : "No configured value is claimed — the default is not enforcement"}
          </div>
        </div>

        <div className="panel" style={{ padding: "18px" }}>
          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            Framework Coverage
          </div>
          <div style={{ fontSize: "20px", fontWeight: 700, margin: "7px 0", color: "var(--cyan)" }}>
            {mappedFrameworks} of {Object.keys(STANDARD_CONTROL_KEYS).length} mapped
          </div>
          <div style={{ fontSize: "12px", color: "var(--dim)" }}>
            Platform-control engine covers SOC 2-style checks; other mappings are not implemented
          </div>
        </div>
      </div>

      {/* Standards Selection — an explicit, honest filter */}
      <div style={{ display: "flex", gap: "10px", marginBottom: "20px", flexWrap: "wrap" }}>
        {standards.map((s) => (
          <button
            key={s.id}
            onClick={() => setSelectedStandard(s.id)}
            title={s.tag}
            style={{
              padding: "8px 16px",
              borderRadius: "var(--r)",
              border: "1px solid var(--line)",
              background: selectedStandard === s.id ? "var(--cyan)" : "var(--bg-2)",
              color: selectedStandard === s.id ? "var(--on-accent)" : "var(--text)",
              fontWeight: selectedStandard === s.id ? 700 : 500,
              fontSize: "12.5px",
              cursor: "pointer",
              opacity: s.tag === "Not mapped" ? 0.7 : 1,
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
          Evaluated controls from live platform state. Selecting a framework filters to its mapped controls.
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
                    <Badge variant={c.status === "pass" ? "success" : c.status === "fail" ? "danger" : "neutral"}>
                      {String(c.status ?? "unknown").toUpperCase()}
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

              {evidence.phase === "live" && standardMapped && controls.length === 0 && (
                <tr>
                  <td colSpan={4} style={{ textAlign: "center", padding: "36px", color: "var(--dim)" }}>
                    No policy evidence registered for this framework yet. Run a scan or configure compliance frameworks.
                  </td>
                </tr>
              )}

              {evidence.phase === "live" && !standardMapped && (
                <tr>
                  <td colSpan={4} style={{ textAlign: "center", padding: "36px", color: "var(--dim)" }}>
                    The evidence engine has no control mapping for this framework — nothing has been evaluated against it.
                    This is not a pass and not a fail.
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
