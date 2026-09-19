import React, { useState } from "react";
import { Badge, Button, Tabs } from "../components/ui";

interface AssetRecord {
  id: string;
  name: string;
  status: "Active" | "Inactive" | "Deprecating";
  risk: "PQC Migration Required" | "Hybrid Ready" | "Quantum Safe" | "Legacy Deprecated";
  algorithm: string;
  keySize: string;
  protocol: string;
  location: string;
  owner: string;
  firstObserved: string;
  lastObserved: string;
  evidenceId: string;
}

export default function Assets() {
  const [selectedAsset, setSelectedAsset] = useState<AssetRecord>({
    id: "AST-8812",
    name: "RSA-2048 Wildcard Ingress Certificate",
    status: "Active",
    risk: "PQC Migration Required",
    algorithm: "RSA",
    keySize: "2048",
    protocol: "TLS 1.2",
    location: "api.production.example",
    owner: "Payments Platform",
    firstObserved: "2026-08-21",
    lastObserved: "2026-09-19",
    evidenceId: "OBS-8F93A21"
  });

  const [activeTab, setActiveTab] = useState(0);
  const tabNames = ["Overview", "Evidence", "Dependencies", "Usage", "History", "Policy", "PQC"];

  const assetsList: AssetRecord[] = [
    {
      id: "AST-8812",
      name: "RSA-2048 Wildcard Ingress Certificate",
      status: "Active",
      risk: "PQC Migration Required",
      algorithm: "RSA",
      keySize: "2048",
      protocol: "TLS 1.2",
      location: "api.production.example",
      owner: "Payments Platform",
      firstObserved: "2026-08-21",
      lastObserved: "2026-09-19",
      evidenceId: "OBS-8F93A21"
    },
    {
      id: "AST-4419",
      name: "SWIFT Alliance Hardware Partition",
      status: "Active",
      risk: "Hybrid Ready",
      algorithm: "ECDSA",
      keySize: "256 (P-256)",
      protocol: "PKCS#11",
      location: "hsm-partition-4.sec.internal",
      owner: "Treasury Infrastructure",
      firstObserved: "2025-11-14",
      lastObserved: "2026-09-19",
      evidenceId: "OBS-7B21C44"
    },
    {
      id: "AST-1042",
      name: "Core Ledger Database Envelope DEK",
      status: "Active",
      risk: "Quantum Safe",
      algorithm: "AES-GCM",
      keySize: "256",
      protocol: "KMS Envelope",
      location: "rds-postgres-primary.vault",
      owner: "Data Engineering",
      firstObserved: "2026-01-10",
      lastObserved: "2026-09-19",
      evidenceId: "OBS-1A45F88"
    }
  ];

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      {/* 9. Asset Detail Page Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "24px", flexWrap: "wrap", gap: "16px" }}>
        <div>
          <div style={{ fontSize: "12px", fontFamily: "var(--mono)", color: "var(--cyan)", letterSpacing: "0.1em", textTransform: "uppercase" }}>
            Cryptographic Asset Record
          </div>
          <h1 style={{ fontSize: "26px", fontWeight: 700, margin: "4px 0 6px" }}>{selectedAsset.name}</h1>
          <p style={{ margin: 0, fontSize: "13.5px", color: "var(--dim)" }}>
            ID: <code style={{ fontFamily: "var(--mono)", color: "var(--cyan)" }}>{selectedAsset.id}</code> · Endpoint: <code style={{ fontFamily: "var(--mono)" }}>{selectedAsset.location}</code>
          </p>
        </div>

        <div style={{ display: "flex", gap: "10px" }}>
          <a href="#/whatif" className="btn primary" style={{ textDecoration: "none" }}>
            Simulate PQC Upgrade (CDT)
          </a>
          <a href="#/evidence" className="btn outline" style={{ textDecoration: "none" }}>
            Inspect Evidence Chain
          </a>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "340px 1fr", gap: "24px" }}>
        {/* Left Column: Asset Selection / Overview Panel (Section 9 Spec) */}
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          <div className="panel" style={{ padding: "20px" }}>
            <h3 style={{ margin: "0 0 16px", fontSize: "15px", fontWeight: 600 }}>Asset Metadata</h3>

            <div style={{ display: "flex", flexDirection: "column", gap: "12px", fontSize: "13px" }}>
              <div>
                <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Status</div>
                <div style={{ fontWeight: 600, color: "var(--green)", marginTop: "2px" }}>{selectedAsset.status}</div>
              </div>

              <div>
                <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Risk Rating</div>
                <Badge tone={selectedAsset.risk.includes("Required") ? "red" : selectedAsset.risk.includes("Hybrid") ? "orange" : "green"}>
                  {selectedAsset.risk}
                </Badge>
              </div>

              <div>
                <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Algorithm</div>
                <div style={{ fontFamily: "var(--mono)", fontWeight: 600, color: "var(--text)", marginTop: "2px" }}>{selectedAsset.algorithm}</div>
              </div>

              <div>
                <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Key Size</div>
                <div style={{ fontFamily: "var(--mono)", marginTop: "2px" }}>{selectedAsset.keySize}</div>
              </div>

              <div>
                <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Protocol</div>
                <div style={{ fontFamily: "var(--mono)", marginTop: "2px" }}>{selectedAsset.protocol}</div>
              </div>

              <div>
                <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Location</div>
                <div style={{ fontFamily: "var(--mono)", color: "var(--cyan)", marginTop: "2px", wordBreak: "break-all" }}>{selectedAsset.location}</div>
              </div>

              <div>
                <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Owner</div>
                <div style={{ marginTop: "2px" }}>{selectedAsset.owner}</div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", borderTop: "1px solid var(--line)", paddingTop: "12px" }}>
                <div>
                  <div style={{ fontSize: "11px", color: "var(--dim)" }}>First Observed</div>
                  <div style={{ fontFamily: "var(--mono)", fontSize: "12px" }}>{selectedAsset.firstObserved}</div>
                </div>
                <div>
                  <div style={{ fontSize: "11px", color: "var(--dim)" }}>Last Observed</div>
                  <div style={{ fontFamily: "var(--mono)", fontSize: "12px" }}>{selectedAsset.lastObserved}</div>
                </div>
              </div>
            </div>
          </div>

          {/* Quick Asset Switcher */}
          <div className="panel" style={{ padding: "16px" }}>
            <div style={{ fontSize: "12px", color: "var(--dim)", marginBottom: "8px" }}>Other In-Scope Assets</div>
            <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
              {assetsList.map((a) => (
                <button
                  key={a.id}
                  onClick={() => setSelectedAsset(a)}
                  style={{
                    background: selectedAsset.id === a.id ? "var(--panel-2)" : "transparent",
                    border: "1px solid",
                    borderColor: selectedAsset.id === a.id ? "var(--cyan)" : "transparent",
                    borderRadius: "6px",
                    padding: "8px 10px",
                    textAlign: "left",
                    cursor: "pointer",
                    fontSize: "12px",
                    color: "var(--text)"
                  }}
                >
                  <div style={{ fontWeight: 600 }}>{a.name}</div>
                  <div style={{ fontSize: "11px", color: "var(--faint)", fontFamily: "var(--mono)" }}>{a.id} · {a.algorithm}</div>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Right Column: Section 9 Tabs: Overview, Evidence, Dependencies, Usage, History, Policy, PQC */}
        <div className="panel" style={{ padding: "24px" }}>
          <Tabs tabs={tabNames} active={activeTab} onChange={setActiveTab} />

          <div style={{ marginTop: "20px" }}>
            {/* Tab 0: Overview */}
            {activeTab === 0 && (
              <div>
                <h3 style={{ margin: "0 0 8px", fontSize: "16px" }}>Component Overview & Architecture</h3>
                <p style={{ fontSize: "13px", color: "var(--dim)", lineHeight: 1.6, marginBottom: "20px" }}>
                  This cryptographic asset terminates external payment ingress traffic. Negotiates TLS 1.2 using an RSA-2048 leaf certificate. Evaluated against NIST SP 800-131A and FIPS 203 migration roadmaps.
                </p>

                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
                  <div style={{ padding: "14px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "8px" }}>
                    <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Deterministic Risk Score</div>
                    <div style={{ fontSize: "24px", fontWeight: 700, fontFamily: "var(--mono)", color: "var(--red)", margin: "4px 0" }}>98.2 / 100</div>
                    <div style={{ fontSize: "11.5px", color: "var(--dim)" }}>Technical: 0.25 · Business: 0.25 · Quantum: 0.10</div>
                  </div>

                  <div style={{ padding: "14px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "8px" }}>
                    <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Quantum Vulnerability</div>
                    <div style={{ fontSize: "24px", fontWeight: 700, fontFamily: "var(--mono)", color: "var(--red)", margin: "4px 0" }}>HIGH (HNDL)</div>
                    <div style={{ fontSize: "11.5px", color: "var(--dim)" }}>Subject to Harvest-Now-Decrypt-Later</div>
                  </div>
                </div>
              </div>
            )}

            {/* Tab 1: Evidence */}
            {activeTab === 1 && (
              <div>
                <h3 style={{ margin: "0 0 8px", fontSize: "16px" }}>Immutable Evidence Records</h3>
                <p style={{ fontSize: "13px", color: "var(--dim)", marginBottom: "16px" }}>
                  Observation signed and sealed in WORM audit pack.
                </p>
                <div style={{ padding: "14px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "8px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "8px" }}>
                    <span style={{ fontFamily: "var(--mono)", color: "var(--cyan)", fontWeight: 600 }}>{selectedAsset.evidenceId}</span>
                    <Badge tone="green">Verified Merkle Root</Badge>
                  </div>
                  <div style={{ fontSize: "12.5px", marginBottom: "8px" }}>
                    Observed active TLS handshake with RSA-2048 modulus.
                  </div>
                  <div style={{ fontFamily: "var(--mono)", fontSize: "11px", color: "var(--faint)", wordBreak: "break-all" }}>
                    SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
                  </div>
                </div>
              </div>
            )}

            {/* Tab 2: Dependencies */}
            {activeTab === 2 && (
              <div>
                <h3 style={{ margin: "0 0 8px", fontSize: "16px" }}>Cryptographic Dependency Graph</h3>
                <p style={{ fontSize: "13px", color: "var(--dim)", marginBottom: "16px" }}>
                  Connected services, underlying crypto libraries, and issuing CAs.
                </p>
                <div style={{ padding: "16px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "8px" }}>
                  <div style={{ fontFamily: "var(--mono)", fontSize: "13px", lineHeight: 2 }}>
                    API Gateway (NGINX)<br />
                    └── <b>RSA-2048 Leaf Certificate</b><br />
                    &nbsp;&nbsp;&nbsp;&nbsp;├── OpenSSL 1.1.1u (Deprecated)<br />
                    &nbsp;&nbsp;&nbsp;&nbsp;└── DigiCert Global Root G2 CA
                  </div>
                  <div style={{ marginTop: "14px" }}>
                    <a href="#/graph" style={{ fontSize: "12px", color: "var(--cyan)" }}>Open Interactive Graph View →</a>
                  </div>
                </div>
              </div>
            )}

            {/* Other tabs fallback cleanly */}
            {activeTab > 2 && (
              <div>
                <h3 style={{ margin: "0 0 8px", fontSize: "16px" }}>{tabNames[activeTab]} Analysis</h3>
                <p style={{ fontSize: "13px", color: "var(--dim)", marginBottom: "16px" }}>
                  Deterministic records and policy rules evaluated for {selectedAsset.name}.
                </p>
                <div style={{ padding: "16px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "8px", fontSize: "13px" }}>
                  ✓ Status: Evaluated against NIST FIPS 203 & PCI-DSS 4.0.<br />
                  ✓ Remediation: Swap to hybrid X25519MLKEM768 key exchange via Envoy Ingress.
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
