import React, { useState } from "react";
import { Badge, Button } from "../components/ui";

export default function Drift() {
  const [selectedEvent, setSelectedEvent] = useState<any>(null);

  const driftEvents = [
    {
      id: "DFT-1082",
      title: "RSA Certificate Cipher Suite Downgrade",
      time: "14 minutes ago",
      target: "api-payments.production.internal",
      previousState: "TLS 1.3 / X25519 / AES_256_GCM_SHA384",
      currentState: "TLS 1.2 / RSA-2048 / AES_128_CBC_SHA (CBC mode detected)",
      evidenceHash: "0x8fa2...c31b",
      policyImpact: "CRITICAL: Violates PCI-DSS 4.0 & Insecure CBC Ciphersuite Policy",
      source: "Network eBPF Sniffer Daemon"
    },
    {
      id: "DFT-1081",
      title: "Unapproved OpenSSL 1.1.1 Deployment in K8s Pod",
      time: "2 hours ago",
      target: "k8s-pod: auth-service-7f99b-x2c9",
      previousState: "OpenSSL 3.0.12 with FIPS Provider 3.0",
      currentState: "OpenSSL 1.1.1u (Deprecated legacy library with EOL crypto primitives)",
      evidenceHash: "0x77ab...91fe",
      policyImpact: "HIGH: Deprecated library detected in production workload",
      source: "Container Admission Controller & Syft SBOM"
    },
    {
      id: "DFT-1080",
      title: "Wildcard TLS Certificate Rotation without Dual-Key PQC",
      time: "5 hours ago",
      target: "*.checkout.bank.internal",
      previousState: "ECDSA P-384 Certificate",
      currentState: "RSA-2048 Certificate (Legacy CA fallback)",
      evidenceHash: "0x334d...e201",
      policyImpact: "MEDIUM: Regression from ECC to RSA, increasing PQC migration debt",
      source: "Certificate Transparency Monitor"
    },
    {
      id: "DFT-1079",
      title: "Cloud KMS Customer Key Policy Weakening",
      time: "Yesterday at 18:22 UTC",
      target: "arn:aws:kms:us-east-1:123456789012:key/mrk-98ab42",
      previousState: "Key Rotation Enabled (365d) + Multi-Region Replica",
      currentState: "Automatic Key Rotation Disabled",
      evidenceHash: "0x11ff...89ca",
      policyImpact: "HIGH: Violates SOC2 CC6.1 & CIS AWS Benchmark v2.0",
      source: "Cloud Security Posture Engine"
    }
  ];

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      {/* 14. Crypto Drift Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "24px", flexWrap: "wrap", gap: "16px" }}>
        <div>
          <div style={{ fontSize: "12px", fontFamily: "var(--mono)", color: "var(--cyan)", letterSpacing: "0.1em", textTransform: "uppercase" }}>
            TimescaleDB Continuous Baselining
          </div>
          <h1 style={{ fontSize: "26px", fontWeight: 700, margin: "4px 0 6px" }}>Cryptographic Drift Timeline</h1>
          <p style={{ margin: 0, fontSize: "13.5px", color: "var(--dim)" }}>
            Tracking unauthorized cryptographic modifications, cipher suite regressions, and library drift in real-time.
          </p>
        </div>

        <div style={{ display: "flex", gap: "10px" }}>
          <Button variant="outline" onClick={() => alert("Simulating drift rollback plan in CDT...")}>
            Simulate Rollback (CDT)
          </Button>
          <a href="#/security-policy" className="btn primary" style={{ textDecoration: "none" }}>
            Configure Drift Rules
          </a>
        </div>
      </div>

      {/* Timeline Layout */}
      <div className="panel" style={{ padding: "24px" }}>
        <h3 style={{ margin: "0 0 16px", fontSize: "15px", fontWeight: 600 }}>Detected Crypto Drift Events</h3>

        <div style={{ position: "relative", paddingLeft: "24px", borderLeft: "2px solid var(--line)" }}>
          {driftEvents.map((ev, idx) => (
            <div key={ev.id} style={{ marginBottom: "28px", position: "relative" }}>
              {/* Timeline Node Dot */}
              <div
                style={{
                  position: "absolute",
                  left: "-31px",
                  top: "4px",
                  width: "12px",
                  height: "12px",
                  borderRadius: "50%",
                  background: ev.policyImpact.includes("CRITICAL") ? "var(--red)" : "var(--cyan)",
                  boxShadow: `0 0 8px ${ev.policyImpact.includes("CRITICAL") ? "var(--red)" : "var(--cyan)"}`
                }}
              />

              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "6px" }}>
                <div>
                  <span style={{ fontSize: "11px", fontFamily: "var(--mono)", color: "var(--faint)" }}>{ev.id} · {ev.time}</span>
                  <div style={{ fontWeight: 600, fontSize: "15px", color: "var(--text)" }}>{ev.title}</div>
                  <div style={{ fontSize: "12px", color: "var(--cyan)", fontFamily: "var(--mono)", marginTop: "2px" }}>{ev.target}</div>
                </div>
                <Badge tone={ev.policyImpact.includes("CRITICAL") ? "red" : "orange"}>
                  {ev.policyImpact.includes("CRITICAL") ? "CRITICAL DRIFT" : "HIGH DRIFT"}
                </Badge>
              </div>

              {/* State Transition Block */}
              <div style={{ display: "grid", gridTemplateColumns: "1fr auto 1fr", gap: "12px", alignItems: "center", padding: "12px 14px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "8px", margin: "10px 0" }}>
                <div>
                  <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Previous Verified State</div>
                  <div style={{ fontSize: "12.5px", fontFamily: "var(--mono)", color: "var(--green)", marginTop: "2px" }}>{ev.previousState}</div>
                </div>
                <span style={{ color: "var(--faint)", fontSize: "16px" }}>➔</span>
                <div>
                  <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Current Drifted State</div>
                  <div style={{ fontSize: "12.5px", fontFamily: "var(--mono)", color: "var(--red)", marginTop: "2px" }}>{ev.currentState}</div>
                </div>
              </div>

              {/* Policy Impact & Evidence Footer */}
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "12px", flexWrap: "wrap", gap: "8px" }}>
                <span style={{ color: "var(--dim)" }}>
                  <b>Impact:</b> {ev.policyImpact}
                </span>
                <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                  <span style={{ fontFamily: "var(--mono)", color: "var(--cyan)" }}>Evidence: {ev.evidenceHash}</span>
                  <a href="#/evidence" style={{ color: "var(--cyan)" }}>Inspect Evidence →</a>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
