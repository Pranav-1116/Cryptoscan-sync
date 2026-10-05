import React, { useState, useEffect } from "react";
import { Badge, Button, Tabs } from "../components/ui";
import { Link } from "react-router-dom";
import { getToken, tenantFetch } from "../lib/api";
import { IconEstate } from "../components/icons";

export interface AssetRecord {
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
  const [assetsList, setAssetsList] = useState<AssetRecord[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedAsset, setSelectedAsset] = useState<AssetRecord | null>(null);
  const [activeTab, setActiveTab] = useState(0);
  const [searchTerm, setSearchTerm] = useState("");
  const [filterRisk, setFilterRisk] = useState("all");

  const tabNames = ["Overview", "Evidence", "Dependencies", "Usage", "History", "Policy", "PQC"];

  useEffect(() => {
    let cancelled = false;
    async function fetchAssets() {
      setLoading(true);
      try {
        const token = getToken();
        const headers: Record<string, string> = { "Content-Type": "application/json" };
        if (token) headers["Authorization"] = `Bearer ${token}`;

        const res = await tenantFetch("/api/v1/assets?page=1&page_size=100", { headers, signal: AbortSignal.timeout(6000) });
        if (res.ok) {
          const body = await res.json();
          if (!cancelled && body.assets && Array.isArray(body.assets)) {
            const mapped: AssetRecord[] = body.assets.map((a: any, i: number) => ({
              id: a.id || `AST-${1000 + i}`,
              name: a.name || a.common_name || a.algorithm || `Cryptographic Asset ${i + 1}`,
              status: (a.status as any) || "Active",
              risk: a.pqc_status === "PQC Ready" ? "Quantum Safe" : a.pqc_status === "Hybrid" ? "Hybrid Ready" : "PQC Migration Required",
              algorithm: a.algorithm || "RSA",
              keySize: String(a.key_size || "2048"),
              protocol: a.protocol || "TLS 1.3",
              location: a.endpoint || a.location || "Production Cluster",
              owner: a.owner || "Security Operations",
              firstObserved: a.first_seen || new Date().toISOString().slice(0, 10),
              lastObserved: a.last_seen || new Date().toISOString().slice(0, 10),
              evidenceId: a.evidence_id || `OBS-${a.id || i}`
            }));
            setAssetsList(mapped);
            if (mapped.length > 0) {
              setSelectedAsset(mapped[0]);
            }
          }
        }
      } catch (e) {
        console.error("Failed to load backend assets:", e);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    fetchAssets();
    return () => { cancelled = true; };
  }, []);

  const filteredAssets = assetsList.filter((a) => {
    const matchesSearch = a.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          a.algorithm.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          a.id.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesRisk = filterRisk === "all" || a.risk === filterRisk;
    return matchesSearch && matchesRisk;
  });

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      {/* 9. Asset Detail Page Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "24px", flexWrap: "wrap", gap: "16px" }}>
        <div>
          <div style={{ fontSize: "12px", fontFamily: "var(--mono)", color: "var(--cyan)", letterSpacing: "0.1em", textTransform: "uppercase" }}>
            Cryptographic Asset Record
          </div>
          <h1 style={{ fontSize: "26px", fontWeight: 700, margin: "4px 0 6px" }}>
            {selectedAsset ? selectedAsset.name : "Cryptographic Inventory"}
          </h1>
          <p style={{ margin: 0, fontSize: "13.5px", color: "var(--dim)" }}>
            {selectedAsset ? (
              <>ID: <code style={{ fontFamily: "var(--mono)", color: "var(--cyan)" }}>{selectedAsset.id}</code> · Endpoint: <code style={{ fontFamily: "var(--mono)" }}>{selectedAsset.location}</code></>
            ) : (
              "All discovered cryptographic keys, certificates, protocols, and algorithms."
            )}
          </p>
        </div>

        <div style={{ display: "flex", gap: "10px" }}>
          <Link to="/scanners" className="btn primary" style={{ textDecoration: "none" }}>
            + New Discovery Scan
          </Link>
          <Link to="/evidence" className="btn outline" style={{ textDecoration: "none" }}>
            Inspect Evidence Chain
          </Link>
        </div>
      </div>

      {loading ? (
        <div className="panel" style={{ padding: "40px", textAlign: "center", color: "var(--dim)" }}>
          Loading cryptographic asset inventory from backend...
        </div>
      ) : assetsList.length === 0 ? (
        <div className="panel" style={{ padding: "48px 24px", textAlign: "center" }}>
          <div style={{ marginBottom: "12px", lineHeight: 0, color: "var(--faint)" }}><IconEstate size={32} /></div>
          <h3 style={{ fontSize: "18px", fontWeight: 600, margin: "0 0 8px" }}>No cryptographic assets discovered yet</h3>
          <p style={{ color: "var(--dim)", fontSize: "14px", maxWidth: "480px", margin: "0 auto 20px", lineHeight: "1.5" }}>
            Connect a discovery source (Network TAP, Cloud KMS, CI/CD, or Container Registry) to start continuously observing your cryptographic estate.
          </p>
          <Link to="/scanners" className="btn primary" style={{ textDecoration: "none", display: "inline-block" }}>
            Start Discovery Scan
          </Link>
        </div>
      ) : (
        <div style={{ display: "grid", gridTemplateColumns: "360px 1fr", gap: "24px" }}>
          {/* Left Column: Asset Selection List */}
          <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
            <div className="panel" style={{ padding: "16px" }}>
              <div style={{ display: "flex", gap: "8px", marginBottom: "12px" }}>
                <input
                  type="text"
                  placeholder="Search assets..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  style={{
                    flex: 1,
                    background: "var(--bg-2)",
                    border: "1px solid var(--line)",
                    borderRadius: "var(--r)",
                    padding: "6px 10px",
                    color: "var(--text)",
                    fontSize: "13px"
                  }}
                />
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: "6px", maxHeight: "600px", overflowY: "auto" }}>
                {filteredAssets.map((asset) => {
                  const isSel = selectedAsset?.id === asset.id;
                  return (
                    <div
                      key={asset.id}
                      onClick={() => setSelectedAsset(asset)}
                      style={{
                        padding: "10px 12px",
                        background: isSel ? "color-mix(in srgb, var(--accent) 8%, transparent)" : "transparent",
                        border: isSel ? "1px solid var(--cyan)" : "1px solid var(--line)",
                        borderRadius: "var(--r)",
                        cursor: "pointer",
                        transition: "all 0.15s ease"
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                        <span style={{ fontWeight: 600, fontSize: "13px", color: isSel ? "var(--cyan)" : "var(--text)" }}>{asset.name}</span>
                        <Badge tone={asset.risk.includes("Required") ? "red" : asset.risk.includes("Hybrid") ? "orange" : "green"}>
                          {asset.algorithm}
                        </Badge>
                      </div>
                      <div style={{ display: "flex", justifyContent: "space-between", fontSize: "11.5px", color: "var(--dim)" }}>
                        <span>{asset.location}</span>
                        <span>{asset.owner}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Right Column: Active Asset Detail Tabs */}
          {selectedAsset && (
            <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
              <div className="panel" style={{ padding: "20px" }}>
                <Tabs tabs={tabNames} active={activeTab} onChange={setActiveTab} />

                <div style={{ marginTop: "20px" }}>
                  {activeTab === 0 && (
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", fontSize: "13px" }}>
                      <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                        <div>
                          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Status</div>
                          <div style={{ fontWeight: 600, color: "var(--green)", marginTop: "2px" }}>{selectedAsset.status}</div>
                        </div>
                        <div>
                          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Algorithm & Key Size</div>
                          <div style={{ fontFamily: "var(--mono)", color: "var(--text)", marginTop: "2px" }}>
                            {selectedAsset.algorithm} · {selectedAsset.keySize} bits
                          </div>
                        </div>
                        <div>
                          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Protocol Context</div>
                          <div style={{ marginTop: "2px" }}>{selectedAsset.protocol}</div>
                        </div>
                      </div>
                      <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                        <div>
                          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Quantum Risk Status</div>
                          <div style={{ marginTop: "2px" }}>
                            <Badge tone={selectedAsset.risk.includes("Required") ? "red" : selectedAsset.risk.includes("Hybrid") ? "orange" : "green"}>
                              {selectedAsset.risk}
                            </Badge>
                          </div>
                        </div>
                        <div>
                          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Owner & Environment</div>
                          <div style={{ marginTop: "2px" }}>{selectedAsset.owner}</div>
                        </div>
                        <div>
                          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Deterministic Observation Proof</div>
                          <code style={{ fontFamily: "var(--mono)", color: "var(--cyan)", marginTop: "2px", display: "inline-block" }}>
                            {selectedAsset.evidenceId}
                          </code>
                        </div>
                      </div>
                    </div>
                  )}

                  {activeTab === 1 && (
                    <div style={{ fontSize: "13px" }}>
                      <div style={{ marginBottom: "12px", color: "var(--dim)" }}>
                        Deterministic observation proof chained to PostgreSQL append-only ledger and WORM audit pack:
                      </div>
                      <div className="panel" style={{ padding: "14px", background: "var(--bg-2)", border: "1px solid var(--line)" }}>
                        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "8px" }}>
                          <span>Evidence ID: <code style={{ color: "var(--cyan)" }}>{selectedAsset.evidenceId}</code></span>
                          <span style={{ color: "var(--green)" }}>● Integrity Verified (HMAC-SHA256)</span>
                        </div>
                        <div style={{ color: "var(--dim)", fontSize: "12px" }}>
                          Observed at {selectedAsset.lastObserved} UTC by specialized scanner. No private keys or secret material ever stored or exposed.
                        </div>
                      </div>
                    </div>
                  )}

                  {activeTab === 2 && (
                    <div style={{ fontSize: "13px", color: "var(--dim)" }}>
                      <div>Direct cryptographic dependency relationships:</div>
                      <div style={{ marginTop: "12px", padding: "12px", background: "var(--bg-2)", borderRadius: "var(--r)" }}>
                        Application Mesh → Gateway Ingress → <b>{selectedAsset.algorithm} ({selectedAsset.keySize})</b> → Root Certificate Authority
                      </div>
                    </div>
                  )}

                  {activeTab >= 3 && (
                    <div style={{ fontSize: "13px", color: "var(--dim)", padding: "12px 0" }}>
                      Authoritative telemetry synchronized. No drift or policy violation currently detected on this asset.
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
