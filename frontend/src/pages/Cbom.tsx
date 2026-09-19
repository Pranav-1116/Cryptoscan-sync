import React, { useState } from "react";
import { Badge, Button, Input } from "../components/ui";

interface CbomComponent {
  id: string;
  algorithm: string;
  keySize: string;
  usage: string;
  location: string;
  owner: string;
  risk: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  status: string;
  pqcReady: boolean;
  subComponents?: { name: string; type: string; details: string }[];
}

export default function Cbom() {
  const [search, setSearch] = useState("");
  const [filterRisk, setFilterRisk] = useState<string>("ALL");
  const [expandedRow, setExpandedRow] = useState<string | null>("CBOM-01");

  const components: CbomComponent[] = [
    {
      id: "CBOM-01",
      algorithm: "RSA-2048",
      keySize: "2048-bit",
      usage: "mTLS Ingress Termination",
      location: "api-gateway.production.us-east-1",
      owner: "Payments Platform",
      risk: "CRITICAL",
      status: "PQC Migration Required",
      pqcReady: false,
      subComponents: [
        { name: "API Gateway NGINX Ingress", type: "Service", details: "TLS 1.2 / TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" },
        { name: "Core Payment Settlement Service", type: "Upstream Microservice", details: "HTTP/2 internal RPC with client auth" },
        { name: "Wildcard Production Certificate (*.bank.internal)", type: "X.509 Cert", details: "Expires in 184 days (DigiCert CA)" },
        { name: "OpenSSL 1.1.1u Legacy Crypto Lib", type: "Dependency", details: "Vulnerable to post-quantum Shor's algorithm" }
      ]
    },
    {
      id: "CBOM-02",
      algorithm: "ECDSA P-256",
      keySize: "256-bit",
      usage: "SWIFT Messaging Signing",
      location: "swift-connector.sec.internal",
      owner: "Treasury Infrastructure",
      risk: "HIGH",
      status: "Hybrid Mode Ready",
      pqcReady: true,
      subComponents: [
        { name: "SWIFT Alliance Gateway", type: "Service", details: "ISO 20022 message envelope signer" },
        { name: "Thales Luna 7 HSM Partition", type: "Hardware", details: "FIPS 140-2 Level 3 slot #4" },
        { name: "PKCS#11 v2.40 Driver", type: "Dependency", details: "Firmware version 7.8.1" }
      ]
    },
    {
      id: "CBOM-03",
      algorithm: "ML-KEM-768 (Dual-Key)",
      keySize: "FIPS 203 Level 3",
      usage: "Inter-Datacenter Wire Encapsulation",
      location: "mesh-router-east-west.infra",
      owner: "Core Network Operations",
      risk: "LOW",
      status: "Post-Quantum Ready",
      pqcReady: true,
      subComponents: [
        { name: "Envoy Proxy v1.31 Hybrid TLS", type: "Proxy", details: "X25519MLKEM768 key exchange negotiated" },
        { name: "Rustls PQC Crypto Provider", type: "Library", details: "Deterministic constant-time lattice primitives" }
      ]
    },
    {
      id: "CBOM-04",
      algorithm: "AES-256-GCM",
      keySize: "256-bit",
      usage: "Cardholder Database DEK",
      location: "rds-postgres-payments.vault",
      owner: "Data Security",
      risk: "LOW",
      status: "Quantum Resistant (Grover Safe)",
      pqcReady: true,
      subComponents: [
        { name: "PostgreSQL pgcrypto Table Encryption", type: "Database", details: "Column-level envelope with KMS KEK" },
        { name: "AWS KMS Customer Managed Key", type: "KMS", details: "Annual 365d key rotation enabled" }
      ]
    },
    {
      id: "CBOM-05",
      algorithm: "3DES / 2Key-Triple-DES",
      keySize: "112-bit effective",
      usage: "Legacy ATM Switch PIN Translation",
      location: "mainframe-gateway.dc2",
      owner: "Legacy Retail Banking",
      risk: "CRITICAL",
      status: "Deprecated / Immediate Sunset",
      pqcReady: false,
      subComponents: [
        { name: "ISO 8583 Message Translator", type: "Mainframe", details: "ANSI X9.52 3DES mode" },
        { name: "Hardware Security Module (SNA Link)", type: "Hardware", details: "Requires replacement before Dec 2026" }
      ]
    }
  ];

  const filtered = components.filter(c => {
    const matchesSearch =
      c.algorithm.toLowerCase().includes(search.toLowerCase()) ||
      c.location.toLowerCase().includes(search.toLowerCase()) ||
      c.owner.toLowerCase().includes(search.toLowerCase()) ||
      c.usage.toLowerCase().includes(search.toLowerCase());
    const matchesRisk = filterRisk === "ALL" || c.risk === filterRisk;
    return matchesSearch && matchesRisk;
  });

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      {/* 10. CBOM Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "24px", flexWrap: "wrap", gap: "16px" }}>
        <div>
          <div style={{ fontSize: "12px", fontFamily: "var(--mono)", color: "var(--cyan)", letterSpacing: "0.1em", textTransform: "uppercase" }}>
            CycloneDX 1.6 Cryptographic Specification
          </div>
          <h1 style={{ fontSize: "26px", fontWeight: 700, margin: "4px 0 6px" }}>Cryptographic Bill of Materials</h1>
          <p style={{ margin: 0, fontSize: "13.5px", color: "var(--dim)" }}>
            Living inventory of <b>12,482</b> verified cryptographic components across cloud, container, network, and hardware estates.
          </p>
        </div>

        <div style={{ display: "flex", gap: "10px" }}>
          <Button variant="outline" onClick={() => alert("Exporting CBOM as CycloneDX 1.6 JSON with Merkle proof...")}>
            Export CBOM (JSON/VEX)
          </Button>
          <a href="#/graph" className="btn primary" style={{ textDecoration: "none" }}>
            View Dependency Graph
          </a>
        </div>
      </div>

      {/* Search and Filters */}
      <div className="panel" style={{ padding: "16px", marginBottom: "20px", display: "flex", gap: "16px", flexWrap: "wrap", alignItems: "center" }}>
        <div style={{ flex: 1, minWidth: "260px" }}>
          <input
            type="text"
            placeholder="Search by algorithm (RSA, AES), location, usage, or owner..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="inp"
            style={{ fontSize: "13px" }}
          />
        </div>

        <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
          <span style={{ fontSize: "12px", color: "var(--dim)", marginRight: "4px" }}>Risk Filter:</span>
          {["ALL", "CRITICAL", "HIGH", "LOW"].map((r) => (
            <button
              key={r}
              onClick={() => setFilterRisk(r)}
              className="btn sm"
              style={{
                background: filterRisk === r ? "var(--cyan)" : undefined,
                color: filterRisk === r ? "#000" : undefined,
                fontWeight: filterRisk === r ? 700 : 500
              }}
            >
              {r}
            </button>
          ))}
        </div>
      </div>

      {/* CBOM Table with Expandable Rows */}
      <div className="panel" style={{ padding: "20px" }}>
        <div style={{ overflowX: "auto" }}>
          <table className="tbl" style={{ width: "100%" }}>
            <thead>
              <tr>
                <th style={{ width: "36px" }}></th>
                <th>Algorithm & Key</th>
                <th>Usage & Purpose</th>
                <th>Location / Service</th>
                <th>Owner</th>
                <th>PQC Status</th>
                <th>Risk</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((item) => {
                const isExpanded = expandedRow === item.id;
                return (
                  <React.Fragment key={item.id}>
                    <tr
                      onClick={() => setExpandedRow(isExpanded ? null : item.id)}
                      style={{ cursor: "pointer", background: isExpanded ? "rgba(0, 212, 255, 0.05)" : undefined }}
                    >
                      <td style={{ color: "var(--cyan)", fontWeight: 700, fontSize: "14px" }}>
                        {isExpanded ? "▼" : "▶"}
                      </td>
                      <td>
                        <div style={{ fontWeight: 600, color: "var(--text)", fontFamily: "var(--mono)", fontSize: "13px" }}>{item.algorithm}</div>
                        <div style={{ fontSize: "11px", color: "var(--dim)" }}>{item.keySize}</div>
                      </td>
                      <td>
                        <div style={{ fontSize: "13px" }}>{item.usage}</div>
                      </td>
                      <td>
                        <span style={{ fontFamily: "var(--mono)", fontSize: "12px", color: "var(--cyan)" }}>{item.location}</span>
                      </td>
                      <td>
                        <span style={{ fontSize: "12px" }}>{item.owner}</span>
                      </td>
                      <td>
                        <span style={{ fontSize: "12px", color: item.pqcReady ? "var(--green)" : "var(--amber)" }}>
                          {item.status}
                        </span>
                      </td>
                      <td>
                        <Badge tone={item.risk === "CRITICAL" ? "red" : item.risk === "HIGH" ? "orange" : "green"}>
                          {item.risk}
                        </Badge>
                      </td>
                    </tr>

                    {/* Expandable Sub-Component Tree */}
                    {isExpanded && item.subComponents && (
                      <tr>
                        <td colSpan={7} style={{ padding: "16px 20px 20px 48px", background: "var(--bg-2)", borderBottom: "1px solid var(--line)" }}>
                          <div style={{ fontSize: "12px", fontWeight: 600, color: "var(--faint)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "10px" }}>
                            Cryptographic Dependency Tree & Associated Assets
                          </div>
                          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                            {item.subComponents.map((sub, sIdx) => (
                              <div
                                key={sIdx}
                                style={{
                                  display: "flex",
                                  alignItems: "center",
                                  justifyContent: "space-between",
                                  padding: "8px 12px",
                                  background: "var(--panel)",
                                  border: "1px solid var(--line)",
                                  borderRadius: "6px",
                                  fontSize: "12.5px"
                                }}
                              >
                                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                                  <span style={{ color: "var(--dim)" }}>├──</span>
                                  <span style={{ fontWeight: 600, color: "var(--text)" }}>{sub.name}</span>
                                  <span style={{ fontSize: "11px", background: "var(--bg-2)", padding: "2px 6px", borderRadius: "4px", color: "var(--dim)" }}>{sub.type}</span>
                                </div>
                                <span style={{ fontFamily: "var(--mono)", fontSize: "11.5px", color: "var(--dim)" }}>{sub.details}</span>
                              </div>
                            ))}
                          </div>

                          <div style={{ display: "flex", gap: "10px", marginTop: "14px", justifyContent: "flex-end" }}>
                            <a href="#/whatif" className="btn sm primary" style={{ textDecoration: "none" }}>
                              Run PQC Migration Simulation
                            </a>
                            <a href="#/evidence" className="btn sm outline" style={{ textDecoration: "none" }}>
                              Inspect WORM Evidence Hash
                            </a>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
