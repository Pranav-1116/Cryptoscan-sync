import React, { useState } from "react";
import { Badge, Button } from "../components/ui";

export default function Compliance() {
  const [selectedStandard, setSelectedStandard] = useState("PCI-DSS v4.0.1");

  const standards = [
    { name: "PCI-DSS v4.0.1", score: 94, status: "COMPLIANT", violations: 2, desc: "Payment card cryptography, key lengths, and bespoke cryptographic software inventory." },
    { name: "NIST SP 800-131A / PQC", score: 68, status: "ACTION_REQUIRED", violations: 12, desc: "Transition of cryptographic algorithms and key lengths to post-quantum standards." },
    { name: "DORA (EU 2022/2554)", score: 92, status: "COMPLIANT", violations: 3, desc: "Digital Operational Resilience Act cryptographic risk and third-party ICT audit." },
    { name: "FIPS 140-3", score: 88, status: "COMPLIANT", violations: 4, desc: "Security requirements for cryptographic modules and hardware security partitions." },
    { name: "SOC 2 Type II (CC6.1)", score: 100, status: "COMPLIANT", violations: 0, desc: "Logical access and transmission encryption controls." },
  ];

  const policyRules = [
    { rule: "TLS Protocol Minimum Level (TLS ≥ 1.2)", status: "PASS", evidence: "OBS-8F93A21", standard: "PCI-DSS / NIST", desc: "No SSL 3.0, TLS 1.0, or TLS 1.1 handshakes observed on active endpoints." },
    { rule: "RSA Key Size Minimum (RSA ≥ 2048-bit)", status: "PASS", evidence: "OBS-8F93A22", standard: "NIST SP 800-131A", desc: "All 5,410 active RSA keys meet or exceed 2048-bit modulus length." },
    { rule: "Prohibit Deprecated Hashes (No MD5 / SHA-1)", status: "FAIL", evidence: "OBS-9921FA", standard: "PCI-DSS Req 12.3.3", desc: "Legacy ATM mainframe switch negotiated TLS with MD5 HMAC signature." },
    { rule: "Approved Cryptographic Algorithms List", status: "PASS", evidence: "OBS-8F93A24", standard: "FIPS 140-3", desc: "All in-use ciphers match the organization's approved catalog." },
    { rule: "Certificate Expiration Window (> 30 days)", status: "FAIL", evidence: "OBS-4411BC", standard: "DORA Article 9", desc: "Wildcard cert *.production.internal expires in 14 days without active ACME automation." },
    { rule: "Post-Quantum Hybrid Readiness (FIPS 203)", status: "PASS", evidence: "OBS-2D99E10", standard: "CNSA 2.0", desc: "Dual-key ML-KEM-768 enabled on all inter-datacenter mesh routers." }
  ];

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      {/* 15. Compliance Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "24px", flexWrap: "wrap", gap: "16px" }}>
        <div>
          <div style={{ fontSize: "12px", fontFamily: "var(--mono)", color: "var(--cyan)", letterSpacing: "0.1em", textTransform: "uppercase" }}>
            Evidence-Backed Governance Engine
          </div>
          <h1 style={{ fontSize: "26px", fontWeight: 700, margin: "4px 0 6px" }}>Continuous Regulatory Compliance</h1>
          <p style={{ margin: 0, fontSize: "13.5px", color: "var(--dim)" }}>
            Deterministic policy evaluation. Every compliance status is proven by an immutable cryptographic observation, not AI claims.
          </p>
        </div>

        <div style={{ display: "flex", gap: "10px" }}>
          <Button variant="outline" onClick={() => alert("Generating auditor report package with signed proofs...")}>
            Generate Auditor Report
          </Button>
          <a href="#/evidence" className="btn primary" style={{ textDecoration: "none" }}>
            Audit Evidence Lake
          </a>
        </div>
      </div>

      {/* Compliance Standards Tabs */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "14px", marginBottom: "28px" }}>
        {standards.map((s) => {
          const isSelected = selectedStandard === s.name;
          return (
            <div
              key={s.name}
              onClick={() => setSelectedStandard(s.name)}
              style={{
                padding: "16px 18px",
                background: isSelected ? "rgba(0, 212, 255, 0.08)" : "var(--panel)",
                border: isSelected ? "1px solid var(--cyan)" : "1px solid var(--line)",
                borderRadius: "10px",
                cursor: "pointer",
                transition: "all 0.15s ease"
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                <span style={{ fontWeight: 600, fontSize: "13.5px", color: isSelected ? "var(--cyan)" : "var(--text)" }}>{s.name}</span>
                <Badge tone={s.status === "COMPLIANT" ? "green" : "red"}>{s.status}</Badge>
              </div>
              <div style={{ fontSize: "24px", fontWeight: 700, fontFamily: "var(--mono)", color: s.score === 100 ? "var(--green)" : s.score >= 90 ? "var(--cyan)" : "var(--amber)" }}>
                {s.score}%
              </div>
              <div style={{ fontSize: "11px", color: "var(--dim)", marginTop: "4px" }}>
                {s.violations === 0 ? "Zero violations" : `${s.violations} active violations`}
              </div>
            </div>
          );
        })}
      </div>

      {/* Policy Verification Table (Section 15 Spec) */}
      <div className="panel" style={{ padding: "24px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
          <div>
            <h3 style={{ margin: 0, fontSize: "16px", fontWeight: 600 }}>Deterministic Policy Verification</h3>
            <div style={{ fontSize: "12px", color: "var(--dim)", marginTop: "2px" }}>
              Active rules enforced continuously against live telemetry and CBOM components.
            </div>
          </div>
          <Badge tone="cyan">SINGLE-PASS EVALUATION</Badge>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
          {policyRules.map((r, idx) => {
            const isPass = r.status === "PASS";
            return (
              <div
                key={idx}
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  padding: "14px 18px",
                  background: isPass ? "var(--bg-2)" : "rgba(239, 68, 68, 0.06)",
                  border: isPass ? "1px solid var(--line)" : "1px solid rgba(239, 68, 68, 0.25)",
                  borderRadius: "8px",
                  gap: "16px",
                  flexWrap: "wrap"
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "12px", minWidth: "280px", flex: 1 }}>
                  <span style={{ fontSize: "16px", fontWeight: 700, color: isPass ? "var(--green)" : "var(--red)" }}>
                    {isPass ? "✓" : "✕"}
                  </span>
                  <div>
                    <div style={{ fontWeight: 600, fontSize: "13.5px", color: "var(--text)" }}>{r.rule}</div>
                    <div style={{ fontSize: "12px", color: "var(--dim)", marginTop: "2px" }}>{r.desc}</div>
                  </div>
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
                  <span style={{ fontSize: "11px", background: "var(--panel)", padding: "3px 8px", borderRadius: "4px", color: "var(--dim)" }}>
                    {r.standard}
                  </span>
                  <div style={{ textAlign: "right" }}>
                    <div style={{ fontSize: "11px", color: "var(--faint)" }}>Deterministic Proof</div>
                    <a href="#/evidence" style={{ fontFamily: "var(--mono)", fontSize: "12px", color: "var(--cyan)" }}>
                      {r.evidence} →
                    </a>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
