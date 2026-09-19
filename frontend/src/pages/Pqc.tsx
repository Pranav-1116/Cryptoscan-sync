import React, { useState } from "react";
import { Badge, Button, ProgressBar } from "../components/ui";

export default function Pqc() {
  const [selectedAlgo, setSelectedAlgo] = useState<string>("RSA");

  const inventory = {
    total: 12482,
    vulnerable: 4218,
    migrationReady: 5821,
    requiresAssessment: 2443,
  };

  const exposureBreakdown = [
    { algo: "RSA", total: 5410, vulnerable: 3940, pct: 72, risk: "CRITICAL", desc: "Shor's algorithm breaks integer factorization. All RSA keys &lt;4096 vulnerable." },
    { algo: "ECC / ECDSA", total: 3120, vulnerable: 2190, pct: 70, risk: "CRITICAL", desc: "Shor's algorithm solves elliptic curve discrete logs. P-256 and P-384 vulnerable." },
    { algo: "Diffie-Hellman", total: 1204, vulnerable: 1102, pct: 91, risk: "CRITICAL", desc: "Discrete logarithm breaks classical DH key exchange in polynomial time." },
    { algo: "AES", total: 6890, vulnerable: 0, pct: 0, risk: "LOW", desc: "Grover's algorithm halves effective security. AES-256 remains 128-bit quantum secure." },
    { algo: "SHA-2 / SHA-3", total: 8412, vulnerable: 0, pct: 0, risk: "LOW", desc: "Collision resistance reduced by cube-root / square-root, SHA-256+ remains secure." },
    { algo: "ML-KEM / ML-DSA", total: 1420, vulnerable: 0, pct: 0, risk: "QUANTUM_SAFE", desc: "NIST FIPS 203/204 lattice-based primitives (Module Learning with Errors)." },
  ];

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      {/* 13. PQC Readiness Header */}
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
          <a href="#/whatif" className="btn primary" style={{ textDecoration: "none" }}>
            Simulate PQC Swaps (CDT)
          </a>
          <a href="#/cbom" className="btn outline" style={{ textDecoration: "none" }}>
            Filter CBOM
          </a>
        </div>
      </div>

      {/* Top 4 Metric Cards (Section 13 spec) */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "16px", marginBottom: "28px" }}>
        <div className="panel" style={{ padding: "18px 20px" }}>
          <div style={{ fontSize: "12px", color: "var(--dim)", marginBottom: "4px" }}>Overall Inventory</div>
          <div style={{ fontSize: "28px", fontWeight: 700, fontFamily: "var(--mono)" }}>{inventory.total.toLocaleString()}</div>
          <div style={{ fontSize: "11px", color: "var(--faint)", marginTop: "4px" }}>Cryptographic components</div>
        </div>

        <div className="panel" style={{ padding: "18px 20px" }}>
          <div style={{ fontSize: "12px", color: "var(--dim)", marginBottom: "4px" }}>PQC Vulnerable</div>
          <div style={{ fontSize: "28px", fontWeight: 700, fontFamily: "var(--mono)", color: "var(--red)" }}>{inventory.vulnerable.toLocaleString()}</div>
          <div style={{ fontSize: "11px", color: "var(--red)", marginTop: "4px" }}>Subject to Shor's algorithm</div>
        </div>

        <div className="panel" style={{ padding: "18px 20px" }}>
          <div style={{ fontSize: "12px", color: "var(--dim)", marginBottom: "4px" }}>Migration Ready</div>
          <div style={{ fontSize: "28px", fontWeight: 700, fontFamily: "var(--mono)", color: "var(--green)" }}>{inventory.migrationReady.toLocaleString()}</div>
          <div style={{ fontSize: "11px", color: "var(--green)", marginTop: "4px" }}>Hybrid dual-stack supported</div>
        </div>

        <div className="panel" style={{ padding: "18px 20px" }}>
          <div style={{ fontSize: "12px", color: "var(--dim)", marginBottom: "4px" }}>Requires Assessment</div>
          <div style={{ fontSize: "28px", fontWeight: 700, fontFamily: "var(--mono)", color: "var(--amber)" }}>{inventory.requiresAssessment.toLocaleString()}</div>
          <div style={{ fontSize: "11px", color: "var(--dim)", marginTop: "4px" }}>Third-party & firmware blackboxes</div>
        </div>
      </div>

      {/* Algorithm Exposure Section */}
      <div className="panel" style={{ padding: "24px", marginBottom: "24px" }}>
        <h3 style={{ margin: "0 0 6px", fontSize: "16px" }}>Algorithm Exposure & Quantum Threat Analysis</h3>
        <p style={{ margin: "0 0 20px", fontSize: "13px", color: "var(--dim)" }}>
          Evaluation based on NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and CNSA 2.0 timeline requirements.
        </p>

        <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
          {exposureBreakdown.map((item) => (
            <div
              key={item.algo}
              onClick={() => setSelectedAlgo(item.algo)}
              style={{
                padding: "16px",
                background: "var(--bg-2)",
                border: "1px solid var(--line)",
                borderRadius: "8px",
                cursor: "pointer",
                transition: "all 0.15s ease"
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                  <span style={{ fontWeight: 700, fontSize: "15px", fontFamily: "var(--mono)" }}>{item.algo}</span>
                  <span style={{ fontSize: "12px", color: "var(--dim)" }}>{item.total.toLocaleString()} total instances</span>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                  {item.vulnerable > 0 ? (
                    <span style={{ fontSize: "12.5px", color: "var(--red)", fontFamily: "var(--mono)" }}>
                      {item.vulnerable.toLocaleString()} vulnerable ({item.pct}%)
                    </span>
                  ) : (
                    <span style={{ fontSize: "12.5px", color: "var(--green)", fontFamily: "var(--mono)" }}>
                      Quantum Secure
                    </span>
                  )}
                  <Badge tone={item.risk === "CRITICAL" ? "red" : item.risk === "QUANTUM_SAFE" ? "green" : "blue"}>
                    {item.risk}
                  </Badge>
                </div>
              </div>

              <div style={{ marginBottom: "8px" }}>
                <ProgressBar value={item.pct} tone={item.pct > 50 ? "red" : "green"} />
              </div>

              <p style={{ margin: 0, fontSize: "12px", color: "var(--dim)", lineHeight: 1.4 }}>
                {item.desc}
              </p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
