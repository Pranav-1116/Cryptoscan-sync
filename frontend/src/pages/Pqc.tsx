import React, { useEffect, useState } from "react";
import { Badge, Button } from "../components/ui";
import { apiTechBomLive, apiBankingRoadmap, apiBankingHndl } from "../lib/api";
import AuthenticatedDownload from "../components/AuthenticatedDownload";

export default function Pqc() {
  const [loading, setLoading] = useState(true);
  const [techBom, setTechBom] = useState<any>(null);
  const [roadmap, setRoadmap] = useState<any>(null);
  const [hndl, setHndl] = useState<any>(null);

  useEffect(() => {
    let alive = true;
    async function loadPqc() {
      setLoading(true);
      try {
        const [tbRes, rmRes, hndlRes] = await Promise.all([
          apiTechBomLive(),
          apiBankingRoadmap(),
          apiBankingHndl(5),
        ]);

        if (alive) {
          if (tbRes.source === "live" && tbRes.data) setTechBom(tbRes.data);
          if (rmRes.source === "live" && rmRes.data) setRoadmap(rmRes.data);
          if (hndlRes.source === "live" && hndlRes.data) setHndl(hndlRes.data);
        }
      } catch (err) {
        console.error("Failed to load PQC readiness data:", err);
      } finally {
        if (alive) setLoading(false);
      }
    }

    loadPqc();
    return () => { alive = false; };
  }, []);

  const totalComponents = techBom?.total_components ?? 0;
  const weakLegacy = roadmap?.weak_legacy_instances ?? 0;
  const totalInScope = roadmap?.total_in_scope ?? 0;
  const phases = roadmap?.phases || [];

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      {/* PQC Readiness Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "24px", flexWrap: "wrap", gap: "16px" }}>
        <div>
          <div style={{ fontSize: "12px", fontFamily: "var(--mono)", color: "var(--cyan)", letterSpacing: "0.1em", textTransform: "uppercase" }}>
            NIST FIPS 203 / 204 / 205 Compliance
          </div>
          <h1 style={{ fontSize: "26px", fontWeight: 700, margin: "4px 0 6px" }}>Post-Quantum Readiness</h1>
          <p style={{ margin: 0, fontSize: "13.5px", color: "var(--dim)" }}>
            Tracking vulnerability to Shor's algorithm, Harvest-Now-Decrypt-Later (HNDL) exposure, and hybrid PQC transition.
          </p>
        </div>

        <div style={{ display: "flex", gap: "10px" }}>
          <AuthenticatedDownload
            path="/api/v1/banking/roadmap"
            filename="ir-8547-roadmap.json"
            className="btn outline"
            style={{ fontSize: "12px", padding: "8px 14px", borderRadius: "6px" }}
          >
            Export IR 8547 Roadmap
          </AuthenticatedDownload>
          <a
            href="#/cbom"
            className="btn primary"
            style={{ textDecoration: "none", fontSize: "12px", padding: "8px 14px", borderRadius: "6px" }}
          >
            Filter CBOM
          </a>
        </div>
      </div>

      {/* Top 4 Metric Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "14px", marginBottom: "24px" }}>
        <div className="panel" style={{ padding: "18px" }}>
          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            Total In-Scope Cryptography
          </div>
          <div style={{ fontSize: "28px", fontWeight: 700, margin: "4px 0" }}>
            {loading ? "..." : totalInScope}
          </div>
          <div style={{ fontSize: "12px", color: "var(--dim)" }}>
            Surveyed components across Technology BOM
          </div>
        </div>

        <div className="panel" style={{ padding: "18px" }}>
          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            Weak Legacy Primitives
          </div>
          <div style={{ fontSize: "28px", fontWeight: 700, color: weakLegacy > 0 ? "var(--red)" : "var(--green)", margin: "4px 0" }}>
            {loading ? "..." : weakLegacy}
          </div>
          <div style={{ fontSize: "12px", color: "var(--dim)" }}>
            DES / 3DES / RC4 / MD5 / SHA-1
          </div>
        </div>

        <div className="panel" style={{ padding: "18px" }}>
          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            HNDL Confidentiality Risk
          </div>
          <div style={{ fontSize: "28px", fontWeight: 700, color: hndl?.at_risk ? "var(--red)" : "var(--green)", margin: "4px 0" }}>
            {loading ? "..." : (hndl?.total ?? 0)}
          </div>
          <div style={{ fontSize: "12px", color: "var(--dim)" }}>
            Harvest-Now-Decrypt-Later exposed records
          </div>
        </div>

        <div className="panel" style={{ padding: "18px" }}>
          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            Transition Anchor
          </div>
          <div style={{ fontSize: "16px", fontWeight: 700, margin: "9px 0", color: "var(--cyan)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
            NIST IR 8547
          </div>
          <div style={{ fontSize: "12px", color: "var(--dim)" }}>
            2030 Deprecation · 2035 Disallowance
          </div>
        </div>
      </div>

      {/* Migration Roadmap Phases */}
      <div className="panel" style={{ padding: "20px", marginBottom: "24px" }}>
        <h3 style={{ margin: "0 0 4px", fontSize: "16px", fontWeight: 600 }}>NIST IR 8547 Migration Roadmap</h3>
        <p style={{ margin: "0 0 18px", fontSize: "12px", color: "var(--dim)" }}>
          Deterministic timeline and instance counts calculated across your verified estate.
        </p>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: "16px" }}>
          {phases.map((p: any, idx: number) => (
            <div
              key={idx}
              style={{
                padding: "16px",
                background: "var(--bg-2)",
                border: "1px solid var(--line)",
                borderRadius: "8px",
                display: "flex",
                flexDirection: "column",
                gap: "8px"
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: "12px", fontFamily: "var(--mono)", color: "var(--cyan)", fontWeight: 700 }}>
                  Phase {p.phase}
                </span>
                <Badge variant={p.deadline && p.deadline <= 2027 ? "warning" : "info"}>
                  {p.deadline ? `Target: ${p.deadline}` : "Continuous"}
                </Badge>
              </div>

              <div style={{ fontSize: "13.5px", fontWeight: 600, color: "var(--text)" }}>
                {p.title}
              </div>

              <div style={{ marginTop: "auto", paddingTop: "8px", borderTop: "1px dashed var(--line)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: "11.5px", color: "var(--dim)" }}>Instances in Scope</span>
                <span style={{ fontSize: "14px", fontWeight: 700, color: p.instance_count > 0 ? "var(--amber)" : "var(--text)" }}>
                  {p.instance_count}
                </span>
              </div>
            </div>
          ))}

          {phases.length === 0 && !loading && (
            <div style={{ padding: "24px", textAlign: "center", color: "var(--dim)", gridColumn: "1 / -1" }}>
              No migration phases calculated yet. Run discovery scans to classify estate cryptography.
            </div>
          )}
        </div>
      </div>

      {/* Primary Standards Reference Table */}
      <div className="panel" style={{ padding: "20px" }}>
        <h3 style={{ margin: "0 0 4px", fontSize: "16px", fontWeight: 600 }}>Standard Reference: Quantum Vulnerability Taxonomy</h3>
        <p style={{ margin: "0 0 16px", fontSize: "12px", color: "var(--dim)" }}>
          Official NIST / CNSA 2.0 algorithm transition classification matrix.
        </p>

        <div style={{ overflowX: "auto" }}>
          <table className="tbl" style={{ width: "100%" }}>
            <thead>
              <tr>
                <th>Algorithm Family</th>
                <th>Underlying Math Problem</th>
                <th>Quantum Threat Mechanism</th>
                <th>Post-Quantum Replacement</th>
                <th>Transition Status</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td style={{ fontWeight: 600, color: "var(--text)" }}>RSA (1024-4096)</td>
                <td>Integer Factorization</td>
                <td>Shor's Algorithm (Polynomial Time)</td>
                <td>ML-DSA-65 / SLH-DSA / ML-KEM</td>
                <td><Badge variant="danger">DISALLOWED POST-2035</Badge></td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600, color: "var(--text)" }}>ECDSA / ECDH (P-256, P-384, Ed25519)</td>
                <td>Elliptic Curve Discrete Log</td>
                <td>Shor's Algorithm (Polynomial Time)</td>
                <td>ML-DSA (FIPS 204) / ML-KEM (FIPS 203)</td>
                <td><Badge variant="danger">DISALLOWED POST-2035</Badge></td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600, color: "var(--text)" }}>Diffie-Hellman / DSA</td>
                <td>Discrete Logarithm</td>
                <td>Shor's Algorithm (Polynomial Time)</td>
                <td>ML-KEM-768 / X25519MLKEM768</td>
                <td><Badge variant="danger">DISALLOWED POST-2030</Badge></td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600, color: "var(--text)" }}>AES-128</td>
                <td>Symmetric Substitution-Permutation</td>
                <td>Grover's Algorithm (Halves Effective Security to 64-bit)</td>
                <td>AES-256 (Grover-Resistant 128-bit margin)</td>
                <td><Badge variant="warning">DEPRECATED POST-2030</Badge></td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600, color: "var(--text)" }}>AES-256 / SHA-384 / SHA-512</td>
                <td>Symmetric / Hash Sponge</td>
                <td>Grover's / Brassard-Høyer-Tapp</td>
                <td>FIPS 203 / 204 / 205 Ready</td>
                <td><Badge variant="success">QUANTUM SECURE</Badge></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
