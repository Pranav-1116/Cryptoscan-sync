import React, { useState } from "react";
import { Badge, Stat, Row, Col, Button } from "../components/ui";
import { useRealtime } from "../hooks/useRealtime";
import LiveEventsPanel from "../components/realtime/LiveEventsPanel";
import LiveStatusBadge from "../components/realtime/LiveStatusBadge";
import RealtimeChart from "../components/realtime/RealtimeChart";

export default function CommandCenter() {
  const realtime = useRealtime("commandcenter", { historyLimit: 50 });
  const [activeTab, setActiveTab] = useState<"overview" | "assets" | "pqc" | "drift">("overview");
  const [selectedAsset, setSelectedAsset] = useState<any>(null);

  // High-level estate metrics (Command Center - Cryptographic Command Center)
  const metrics = {
    assets: 12482,
    algorithms: 87,
    pqcExposure: 31,
    violations: 24,
    drift: 7,
    certificates: 1823,
    p99Latency: "342ms",
    throughput: "100K+/s",
    evidenceIntegrity: "100% WORM"
  };

  const sampleAssets = [
    {
      id: "AST-9821",
      name: "Core Banking Transaction Switch (mTLS)",
      type: "Service / Ingress",
      algorithm: "RSA-2048",
      protocol: "TLS 1.2",
      risk: "CRITICAL",
      pqcStatus: "PQC Migration Required",
      owner: "Payments Platform",
      evidenceId: "OBS-8F93A21",
      lastObserved: "2 mins ago"
    },
    {
      id: "AST-4412",
      name: "SWIFT Gateway HSM Connector",
      type: "Hardware HSM",
      algorithm: "ECDSA P-256",
      protocol: "PKCS#11",
      risk: "HIGH",
      pqcStatus: "Hybrid Mode Ready",
      owner: "Treasury Infrastructure",
      evidenceId: "OBS-7B21C44",
      lastObserved: "5 mins ago"
    },
    {
      id: "AST-3190",
      name: "Customer Auth JWT Token Signer",
      type: "Application",
      algorithm: "ML-DSA-65 (Dual-Sign)",
      protocol: "FIPS 204",
      risk: "LOW",
      pqcStatus: "Quantum Safe",
      owner: "Identity & Access",
      evidenceId: "OBS-2D99E10",
      lastObserved: "Just now"
    },
    {
      id: "AST-1102",
      name: "Cardholder Vault Storage DEK",
      type: "KMS Envelope",
      algorithm: "AES-256-GCM",
      protocol: "AES-KW",
      risk: "LOW",
      pqcStatus: "Quantum Resistant",
      owner: "Data Security",
      evidenceId: "OBS-1A45F88",
      lastObserved: "12 mins ago"
    }
  ];

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      {/* 4. Dashboard — Top Area (Minimal Hero) */}
      <div style={{ padding: "32px 0 24px", borderBottom: "1px solid var(--line)", marginBottom: "28px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "20px" }}>
          <div>
            <div style={{ fontSize: "14px", color: "var(--dim)", marginBottom: "6px", fontFamily: "var(--sans)" }}>
              Good morning
            </div>
            <h1 style={{ fontSize: "28px", fontWeight: 700, margin: "0 0 10px", letterSpacing: "-0.02em", color: "var(--text)" }}>
              Your cryptographic estate<br />
              <span style={{ color: "var(--cyan)" }}>is under continuous observation.</span>
            </h1>
            <p style={{ margin: 0, fontSize: "13.5px", color: "var(--dim)", maxWidth: "540px", lineHeight: 1.5 }}>
              Deterministic discovery, PQC migration tracking, and WORM evidence chain enforcement across all payment switches, cloud services, and HSMs.
            </p>
          </div>

          <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
            <a href="#/scanners" className="btn primary lg" style={{ textDecoration: "none" }}>
              Start Scan
            </a>
            <a href="#/cbom" className="btn outline lg" style={{ textDecoration: "none" }}>
              View CBOM
            </a>
          </div>
        </div>
      </div>

      {/* 4. High-Level Metrics (Clean and Compact, No Huge Colorful Cards) */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "14px", marginBottom: "32px" }}>
        <div className="panel" style={{ padding: "16px 18px" }}>
          <div style={{ fontSize: "12px", color: "var(--dim)", fontWeight: 500, marginBottom: "6px" }}>Cryptographic Assets</div>
          <div style={{ fontSize: "28px", fontWeight: 700, fontFamily: "var(--mono)", color: "var(--text)" }}>{metrics.assets.toLocaleString()}</div>
          <div style={{ fontSize: "11px", color: "var(--green)", marginTop: "4px" }}>+12 discovered today</div>
        </div>

        <div className="panel" style={{ padding: "16px 18px" }}>
          <div style={{ fontSize: "12px", color: "var(--dim)", fontWeight: 500, marginBottom: "6px" }}>Algorithms</div>
          <div style={{ fontSize: "28px", fontWeight: 700, fontFamily: "var(--mono)", color: "var(--text)" }}>{metrics.algorithms}</div>
          <div style={{ fontSize: "11px", color: "var(--dim)", marginTop: "4px" }}>Classical + Post-Quantum</div>
        </div>

        <div className="panel" style={{ padding: "16px 18px" }}>
          <div style={{ fontSize: "12px", color: "var(--dim)", fontWeight: 500, marginBottom: "6px" }}>PQC Exposure</div>
          <div style={{ fontSize: "28px", fontWeight: 700, fontFamily: "var(--mono)", color: "var(--amber)" }}>{metrics.pqcExposure}%</div>
          <div style={{ fontSize: "11px", color: "var(--dim)", marginTop: "4px" }}>4,218 vulnerable assets</div>
        </div>

        <div className="panel" style={{ padding: "16px 18px" }}>
          <div style={{ fontSize: "12px", color: "var(--dim)", fontWeight: 500, marginBottom: "6px" }}>Policy Violations</div>
          <div style={{ fontSize: "28px", fontWeight: 700, fontFamily: "var(--mono)", color: "var(--red)" }}>{metrics.violations}</div>
          <div style={{ fontSize: "11px", color: "var(--dim)", marginTop: "4px" }}>3 critical (7d SLA)</div>
        </div>

        <div className="panel" style={{ padding: "16px 18px" }}>
          <div style={{ fontSize: "12px", color: "var(--dim)", fontWeight: 500, marginBottom: "6px" }}>Crypto Drift</div>
          <div style={{ fontSize: "28px", fontWeight: 700, fontFamily: "var(--mono)", color: "var(--cyan)" }}>{metrics.drift}</div>
          <div style={{ fontSize: "11px", color: "var(--dim)", marginTop: "4px" }}>Recorded in TimescaleDB</div>
        </div>

        <div className="panel" style={{ padding: "16px 18px" }}>
          <div style={{ fontSize: "12px", color: "var(--dim)", fontWeight: 500, marginBottom: "6px" }}>Certificates</div>
          <div style={{ fontSize: "28px", fontWeight: 700, fontFamily: "var(--mono)", color: "var(--text)" }}>{metrics.certificates.toLocaleString()}</div>
          <div style={{ fontSize: "11px", color: "var(--amber)", marginTop: "4px" }}>24 expiring &lt; 30d</div>
        </div>
      </div>

      {/* Main Content Area with Navigation Tabs */}
      <div style={{ display: "flex", gap: "16px", borderBottom: "1px solid var(--line)", marginBottom: "20px" }}>
        {[
          { id: "overview", label: "Active Estate" },
          { id: "assets", label: "Critical Findings" },
          { id: "pqc", label: "Post-Quantum Migration" },
          { id: "drift", label: "Realtime Telemetry" },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            style={{
              background: "none",
              border: "none",
              borderBottom: activeTab === tab.id ? "2px solid var(--cyan)" : "2px solid transparent",
              color: activeTab === tab.id ? "var(--text)" : "var(--dim)",
              fontWeight: activeTab === tab.id ? 600 : 400,
              fontSize: "13.5px",
              padding: "10px 4px",
              cursor: "pointer",
              transition: "all 0.15s ease"
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab 1: Active Estate */}
      {activeTab === "overview" && (
        <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: "24px" }}>
          <div>
            <div className="panel" style={{ padding: "20px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
                <div>
                  <h3 style={{ margin: 0, fontSize: "15px", fontWeight: 600 }}>Observed Cryptographic Assets</h3>
                  <div style={{ fontSize: "12px", color: "var(--dim)", marginTop: "2px" }}>Real-time inventory from passive network mirroring & eBPF daemon</div>
                </div>
                <a href="#/assets" style={{ fontSize: "12px", color: "var(--cyan)" }}>View all 12,482 →</a>
              </div>

              <div style={{ overflowX: "auto" }}>
                <table className="tbl" style={{ width: "100%" }}>
                  <thead>
                    <tr>
                      <th>Asset</th>
                      <th>Algorithm</th>
                      <th>Protocol</th>
                      <th>Risk</th>
                      <th>Evidence</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {sampleAssets.map((asset) => (
                      <tr key={asset.id} style={{ cursor: "pointer" }} onClick={() => setSelectedAsset(asset)}>
                        <td>
                          <div style={{ fontWeight: 600, color: "var(--text)" }}>{asset.name}</div>
                          <div style={{ fontSize: "11px", color: "var(--dim)" }}>{asset.type} · {asset.owner}</div>
                        </td>
                        <td>
                          <span style={{ fontFamily: "var(--mono)", fontSize: "12px" }}>{asset.algorithm}</span>
                        </td>
                        <td>
                          <span style={{ fontFamily: "var(--mono)", fontSize: "12px", color: "var(--dim)" }}>{asset.protocol}</span>
                        </td>
                        <td>
                          <Badge tone={asset.risk === "CRITICAL" ? "red" : asset.risk === "HIGH" ? "orange" : "green"}>
                            {asset.risk}
                          </Badge>
                        </td>
                        <td>
                          <span style={{ fontFamily: "var(--mono)", fontSize: "11.5px", color: "var(--cyan)" }}>{asset.evidenceId}</span>
                        </td>
                        <td style={{ textAlign: "right" }}>
                          <span style={{ fontSize: "12px", color: "var(--faint)" }}>Inspect</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Quick Summary Cards */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", marginTop: "16px" }}>
              <div className="panel" style={{ padding: "18px" }}>
                <div style={{ fontSize: "13px", fontWeight: 600, marginBottom: "8px" }}>PQC Transition Progress (NIST FIPS 203/204)</div>
                <p style={{ fontSize: "12px", color: "var(--dim)", margin: "0 0 12px" }}>
                  5,821 / 12,482 components successfully mapped to hybrid ML-KEM-768 or ML-DSA-65 algorithms.
                </p>
                <div className="bar thick">
                  <i className="cyan" style={{ width: "46%" }} />
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: "11px", color: "var(--dim)", marginTop: "6px" }}>
                  <span>46% Migration Ready</span>
                  <span>Target: 100% by 2030</span>
                </div>
              </div>

              <div className="panel" style={{ padding: "18px" }}>
                <div style={{ fontSize: "13px", fontWeight: 600, marginBottom: "8px" }}>Evidence Chain & Audit Integrity</div>
                <p style={{ fontSize: "12px", color: "var(--dim)", margin: "0 0 12px" }}>
                  All 16,923 cryptographic state changes sealed into SHA-256 HMAC Merkle WORM audit log.
                </p>
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <span style={{ color: "var(--green)", fontSize: "16px" }}>✓</span>
                  <span style={{ fontSize: "12px", fontFamily: "var(--mono)", color: "var(--text)" }}>Root: 0x9f4a...e12d (S3 Object Lock Active)</span>
                </div>
              </div>
            </div>
          </div>

          {/* Right Column: Live Feed & Selected Asset Detail */}
          <div>
            {selectedAsset ? (
              <div className="panel" style={{ padding: "20px", marginBottom: "16px", border: "1px solid var(--line-strong)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "12px" }}>
                  <h3 style={{ margin: 0, fontSize: "15px", fontWeight: 600 }}>Asset Detail</h3>
                  <button onClick={() => setSelectedAsset(null)} style={{ background: "none", border: "none", color: "var(--dim)", cursor: "pointer" }}>✕</button>
                </div>
                <div style={{ fontWeight: 600, color: "var(--text)", marginBottom: "4px" }}>{selectedAsset.name}</div>
                <div style={{ fontSize: "11px", color: "var(--cyan)", fontFamily: "var(--mono)", marginBottom: "16px" }}>{selectedAsset.id}</div>

                <div style={{ display: "flex", flexDirection: "column", gap: "10px", fontSize: "12.5px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <span style={{ color: "var(--dim)" }}>Algorithm:</span>
                    <span style={{ fontFamily: "var(--mono)", fontWeight: 600 }}>{selectedAsset.algorithm}</span>
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <span style={{ color: "var(--dim)" }}>Protocol:</span>
                    <span style={{ fontFamily: "var(--mono)" }}>{selectedAsset.protocol}</span>
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <span style={{ color: "var(--dim)" }}>PQC Status:</span>
                    <Badge tone={selectedAsset.pqcStatus.includes("Required") ? "red" : "green"}>{selectedAsset.pqcStatus}</Badge>
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <span style={{ color: "var(--dim)" }}>Owner:</span>
                    <span>{selectedAsset.owner}</span>
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <span style={{ color: "var(--dim)" }}>Evidence Observation:</span>
                    <span style={{ fontFamily: "var(--mono)", color: "var(--cyan)" }}>{selectedAsset.evidenceId}</span>
                  </div>
                </div>

                <div style={{ marginTop: "18px", display: "flex", gap: "8px" }}>
                  <a href="#/whatif" className="btn sm primary" style={{ textDecoration: "none", flex: 1, textAlign: "center" }}>
                    Simulate PQC
                  </a>
                  <a href="#/evidence" className="btn sm outline" style={{ textDecoration: "none", flex: 1, textAlign: "center" }}>
                    View Evidence
                  </a>
                </div>
              </div>
            ) : null}

            {/* Live Events Panel */}
            <div className="panel" style={{ padding: "18px" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "12px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "13px", fontWeight: 600 }}>
                  <span className="live-dot" style={{ width: 8, height: 8, borderRadius: "50%", background: "var(--green)" }} />
                  Continuous Event Stream
                </div>
                <LiveStatusBadge status={realtime.isConnected ? "connected" : "disconnected"} />
              </div>
              <LiveEventsPanel events={realtime.events} />
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Critical Findings */}
      {activeTab === "assets" && (
        <div className="panel" style={{ padding: "24px" }}>
          <h3 style={{ margin: "0 0 8px", fontSize: "16px" }}>Critical Cryptographic Findings & SLAs</h3>
          <p style={{ margin: "0 0 20px", fontSize: "13px", color: "var(--dim)" }}>
            Deterministic violations evaluated against NIST SP 800-131A, FIPS 203/204, and PCI-DSS v4.0.1.
          </p>

          <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
            {[
              {
                title: "Obsolete RSA-1024 / MD5 Signature in Legacy Payment Switch",
                desc: "Handshake negotiated with deprecated hashing algorithm. Immediate remediation required under PCI-DSS Requirement 12.3.3.",
                sla: "Critical · 7d SLA (4 days remaining)",
                evidence: "OBS-9921FA",
                tone: "red"
              },
              {
                title: "Expiring Wildcard TLS Certificate (*.production.internal)",
                desc: "X.509 certificate expires in 14 days without automated ACME renewal configuration.",
                sla: "High · 30d SLA",
                evidence: "OBS-4411BC",
                tone: "orange"
              },
              {
                title: "Harvest-Now-Decrypt-Later (HNDL) High-Exposure Circuit",
                desc: "Unencapsulated classical ECDH session keys detected on cross-border clearing wire.",
                sla: "Critical · 7d SLA",
                evidence: "OBS-1299EA",
                tone: "red"
              }
            ].map((finding, idx) => (
              <div key={idx} style={{ padding: "16px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "8px", borderLeft: `3px solid var(--${finding.tone})` }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "6px" }}>
                  <div style={{ fontWeight: 600, fontSize: "14px", color: "var(--text)" }}>{finding.title}</div>
                  <Badge tone={finding.tone}>{finding.sla}</Badge>
                </div>
                <p style={{ margin: "0 0 10px", fontSize: "12.5px", color: "var(--dim)" }}>{finding.desc}</p>
                <div style={{ display: "flex", alignItems: "center", gap: "12px", fontSize: "11.5px" }}>
                  <span style={{ color: "var(--faint)" }}>Deterministic Proof:</span>
                  <span style={{ fontFamily: "var(--mono)", color: "var(--cyan)" }}>{finding.evidence}</span>
                  <a href="#/evidence" style={{ marginLeft: "auto", color: "var(--cyan)" }}>Inspect Evidence Chain →</a>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 3: Post-Quantum Migration */}
      {activeTab === "pqc" && (
        <div className="panel" style={{ padding: "24px" }}>
          <h3 style={{ margin: "0 0 8px", fontSize: "16px" }}>Post-Quantum Migration Blueprint (6 Phases)</h3>
          <p style={{ margin: "0 0 20px", fontSize: "13px", color: "var(--dim)" }}>
            Deterministic migration planning to NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA). Zero guesswork.
          </p>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "16px" }}>
            {[
              { phase: "1. Assess", count: "12,482 components", status: "100% Completed", tone: "green", desc: "Automated discovery of all cryptographic assets, keys, and algorithms." },
              { phase: "2. Protect", count: "4,218 vulnerable", status: "In Progress (46%)", tone: "cyan", desc: "Dual-stack hybrid key exchange (ECDH-P256 + ML-KEM-768) rollout." },
              { phase: "3. Store", count: "KMS & Vaults", status: "Queued", tone: "slate", desc: "Upgrade data-at-rest encryption wrappers to AES-256 + ML-KEM encapsulation." },
              { phase: "4. Integrate", count: "HSM Firmware", status: "Planning", tone: "slate", desc: "Deploy FIPS 140-3 Level 3 quantum-ready firmware across HSM fleet." },
              { phase: "5. Operate", count: "24/7 Daemon", status: "Active", tone: "green", desc: "Continuous drift detection & TimescaleDB statistical baselining." },
              { phase: "6. Verify", count: "WORM Evidence", status: "Sealed", tone: "green", desc: "Immutable Merkle proofs for regulatory examinations." },
            ].map((p, idx) => (
              <div key={idx} style={{ padding: "16px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "8px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                  <div style={{ fontWeight: 600, fontSize: "13.5px" }}>{p.phase}</div>
                  <Badge tone={p.tone}>{p.status}</Badge>
                </div>
                <div style={{ fontSize: "12px", fontFamily: "var(--mono)", color: "var(--cyan)", marginBottom: "6px" }}>{p.count}</div>
                <p style={{ margin: 0, fontSize: "12px", color: "var(--dim)" }}>{p.desc}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 4: Realtime Telemetry */}
      {activeTab === "drift" && (
        <div className="panel" style={{ padding: "24px" }}>
          <h3 style={{ margin: "0 0 8px", fontSize: "16px" }}>Realtime Engine Telemetry & Latency</h3>
          <p style={{ margin: "0 0 20px", fontSize: "13px", color: "var(--dim)" }}>
            High-throughput event processing backbone with Redis pub/sub and exactly-once delivery.
          </p>

          <Row>
            <Col><Stat label="p99 Latency" value={metrics.p99Latency} sub="Measured via k6 (1000 VUs)" /></Col>
            <Col><Stat label="Throughput" value={metrics.throughput} sub="Single-writer Redis pub/sub" /></Col>
            <Col><Stat label="Evidence WORM" value={metrics.evidenceIntegrity} sub="S3 Object Lock Legal Hold" /></Col>
          </Row>

          <div style={{ marginTop: "24px" }}>
            <RealtimeChart data={realtime.events.map((_, i) => ({ timestamp: Date.now() - (10 - i) * 1000, value: 50 + Math.random() * 20 }))} />
          </div>
        </div>
      )}
    </div>
  );
}
