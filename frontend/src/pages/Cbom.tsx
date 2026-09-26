import React, { useEffect, useState } from "react";
import { Badge, Button } from "../components/ui";
import { apiCbomCatalog, apiCbomCoverage } from "../lib/api";
import PortfolioDependencyPanel from "../components/PortfolioDependencyPanel";

interface CbomItem {
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
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [filterRisk, setFilterRisk] = useState<string>("ALL");
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [coverage, setCoverage] = useState<any>(null);
  const [components, setComponents] = useState<CbomItem[]>([]);

  useEffect(() => {
    let alive = true;
    async function loadCbom() {
      setLoading(true);
      try {
        const [catRes, covRes] = await Promise.all([
          apiCbomCatalog(1, 100),
          apiCbomCoverage(),
        ]);

        if (alive) {
          if (covRes.source === "live" && covRes.data) {
            setCoverage(covRes.data);
          }

          if (catRes.source === "live" && catRes.data) {
            const systems = catRes.data.systems || [];
            const mapped: CbomItem[] = [];

            systems.forEach((sys: any) => {
              const comps = sys.components || sys.crypto_assets || [];
              comps.forEach((c: any, idx: number) => {
                const alg = (c.algorithm || c.crypto_algorithm || "UNKNOWN").toUpperCase();
                const keyBits = c.key_length || c.key_size || c.keybits || 0;
                let risk: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" = "LOW";
                let pqc = false;

                if (alg.includes("RSA") || alg.includes("ECDSA") || alg.includes("DH")) {
                  risk = keyBits < 2048 ? "CRITICAL" : "HIGH";
                } else if (alg.includes("3DES") || alg.includes("DES") || alg.includes("RC4")) {
                  risk = "CRITICAL";
                } else if (alg.includes("ML-KEM") || alg.includes("ML-DSA") || alg.includes("SLH-DSA")) {
                  risk = "LOW";
                  pqc = true;
                } else if (alg.includes("AES")) {
                  risk = keyBits >= 256 ? "LOW" : "MEDIUM";
                  pqc = keyBits >= 256;
                }

                mapped.push({
                  id: c.id || `CBOM-${sys.id || 'SYS'}-${idx + 1}`,
                  algorithm: alg,
                  keySize: keyBits ? `${keyBits}-bit` : "Standard",
                  usage: c.purpose || c.usage || sys.name || "Cryptographic primitive",
                  location: c.location || sys.endpoint || sys.name || "Production host",
                  owner: sys.owner || "Engineering",
                  risk,
                  status: pqc ? "Quantum Ready" : "PQC Migration Target",
                  pqcReady: pqc,
                  subComponents: [
                    { name: sys.name || "System Parent", type: "System", details: `Environment: ${sys.environment || 'production'}` },
                    ...(c.file_path ? [{ name: c.file_path, type: "Artifact", details: "Observed file/binary" }] : [])
                  ]
                });
              });
            });

            setComponents(mapped);
          }
        }
      } catch (err) {
        console.error("Failed to load authoritative CBOM:", err);
      } finally {
        if (alive) setLoading(false);
      }
    }

    loadCbom();
    return () => { alive = false; };
  }, []);

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
      {/* CBOM Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "24px", flexWrap: "wrap", gap: "16px" }}>
        <div>
          <div style={{ fontSize: "12px", fontFamily: "var(--mono)", color: "var(--cyan)", letterSpacing: "0.1em", textTransform: "uppercase" }}>
            CycloneDX 1.5 Cryptographic Specification
          </div>
          <h1 style={{ fontSize: "26px", fontWeight: 700, margin: "4px 0 6px" }}>Cryptographic Bill of Materials</h1>
          <p style={{ margin: 0, fontSize: "13.5px", color: "var(--dim)" }}>
            Living cryptographic inventory derived directly from active scanners, containers, and network observations.
          </p>
        </div>

        <div style={{ display: "flex", gap: "10px" }}>
          <a
            href="/api/v1/cbom"
            target="_blank"
            rel="noreferrer"
            className="btn outline"
            style={{ textDecoration: "none", fontSize: "12px", padding: "8px 14px", borderRadius: "6px" }}
          >
            Export CycloneDX 1.5 JSON
          </a>
          <a
            href="#/graph"
            className="btn primary"
            style={{ textDecoration: "none", fontSize: "12px", padding: "8px 14px", borderRadius: "6px" }}
          >
            View Dependency Graph
          </a>
        </div>
      </div>

      {/* Stats bar */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "14px", marginBottom: "20px" }}>
        <div className="panel" style={{ padding: "16px" }}>
          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            Catalog Components
          </div>
          <div style={{ fontSize: "26px", fontWeight: 700, margin: "4px 0" }}>
            {loading ? "..." : components.length}
          </div>
          <div style={{ fontSize: "12px", color: "var(--dim)" }}>
            Observed across all systems
          </div>
        </div>

        <div className="panel" style={{ padding: "16px" }}>
          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            Coverage Percentage
          </div>
          <div style={{ fontSize: "26px", fontWeight: 700, color: "var(--cyan)", margin: "4px 0" }}>
            {loading ? "..." : `${coverage?.coverage_pct ?? 0}%`}
          </div>
          <div style={{ fontSize: "12px", color: "var(--dim)" }}>
            Systems with active CBOMs: {coverage?.with_cbom ?? 0} / {coverage?.systems ?? 0}
          </div>
        </div>

        <div className="panel" style={{ padding: "16px" }}>
          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            PQC Migration Targets
          </div>
          <div style={{ fontSize: "26px", fontWeight: 700, color: "var(--amber)", margin: "4px 0" }}>
            {loading ? "..." : components.filter(c => !c.pqcReady).length}
          </div>
          <div style={{ fontSize: "12px", color: "var(--dim)" }}>
            Quantum-vulnerable asymmetric keys
          </div>
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
              {filtered.length === 0 && !loading && (
                <tr>
                  <td colSpan={7} style={{ textAlign: "center", padding: "40px", color: "var(--dim)" }}>
                    <div style={{ fontSize: "15px", fontWeight: 600, color: "var(--text)", marginBottom: "4px" }}>
                      No CBOM components found
                    </div>
                    <div style={{ fontSize: "13px", maxWidth: "480px", margin: "0 auto 16px" }}>
                      {coverage?.message || "Register systems, then initiate network, host, or container discovery scans."}
                    </div>
                    <a href="#/scanners" className="btn primary" style={{ textDecoration: "none" }}>
                      Launch Discovery Scan
                    </a>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <PortfolioDependencyPanel />
    </div>
  );
}
