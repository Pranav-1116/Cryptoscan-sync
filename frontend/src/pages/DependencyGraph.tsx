import React, { useEffect, useState } from "react";
import { Badge, Button } from "../components/ui";
import { apiGraph, apiGraphStats, apiGraphBlastRadius } from "../lib/api";
import AuthenticatedDownload from "../components/AuthenticatedDownload";
import CodeCascadePanel from "../components/CodeCascadePanel";

export default function DependencyGraph() {
  const [loading, setLoading] = useState(true);
  const [graphData, setGraphData] = useState<any>({ nodes: [], edges: [] });
  const [graphStats, setGraphStats] = useState<any>(null);
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [blastRadius, setBlastRadius] = useState<any>(null);
  const [calculatingBlast, setCalculatingBlast] = useState(false);
  const [search, setSearch] = useState("");

  useEffect(() => {
    let alive = true;
    async function loadData() {
      setLoading(true);
      try {
        const [gRes, sRes] = await Promise.all([apiGraph(), apiGraphStats()]);
        if (alive) {
          if (gRes.source === "live" && gRes.data) {
            setGraphData(gRes.data);
          }
          if (sRes.source === "live" && sRes.data) {
            setGraphStats(sRes.data);
          }
        }
      } catch (err) {
        console.error("Failed to load graph data:", err);
      } finally {
        if (alive) setLoading(false);
      }
    }
    loadData();
    return () => { alive = false; };
  }, []);

  const handleSelectNode = async (node: any) => {
    setSelectedNode(node);
    if (node.kind === "system" || node.id) {
      setCalculatingBlast(true);
      try {
        const bRes = await apiGraphBlastRadius(node.id, 2);
        if (bRes.source === "live" && bRes.data) {
          setBlastRadius(bRes.data);
        } else {
          setBlastRadius(null);
        }
      } catch {
        setBlastRadius(null);
      } finally {
        setCalculatingBlast(false);
      }
    }
  };

  const nodes = graphData.nodes || [];
  const edges = graphData.edges || [];

  const filteredNodes = nodes.filter((n: any) =>
    (n.label || n.id || "").toLowerCase().includes(search.toLowerCase()) ||
    (n.kind || "").toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "24px", flexWrap: "wrap", gap: "16px" }}>
        <div>
          <div style={{ fontSize: "12px", fontFamily: "var(--mono)", color: "var(--cyan)", letterSpacing: "0.1em", textTransform: "uppercase" }}>
            Deterministic Topology & Impact
          </div>
          <h1 style={{ fontSize: "26px", fontWeight: 700, margin: "4px 0 6px" }}>Cryptographic Dependency Graph</h1>
          <p style={{ margin: 0, fontSize: "13.5px", color: "var(--dim)" }}>
            Observed relationships between systems, services, cryptographic libraries, HSMs, and digital certificates.
          </p>
        </div>

        <div style={{ display: "flex", gap: "10px" }}>
          <AuthenticatedDownload
            path="/api/v1/graph"
            filename="cryptoscan-graph.json"
            className="btn outline"
            style={{ fontSize: "12px", padding: "8px 14px", borderRadius: "6px" }}
          >
            Export Graph JSON
          </AuthenticatedDownload>
          <a
            href="#/scanners"
            className="btn primary"
            style={{ textDecoration: "none", fontSize: "12px", padding: "8px 14px", borderRadius: "6px" }}
          >
            Discover Topology
          </a>
        </div>
      </div>

      {/* Stats bar */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "14px", marginBottom: "24px" }}>
        <div className="panel" style={{ padding: "16px" }}>
          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            Graph Nodes
          </div>
          <div style={{ fontSize: "26px", fontWeight: 700, margin: "4px 0" }}>
            {loading ? "..." : (graphStats?.nodes ?? nodes.length)}
          </div>
          <div style={{ fontSize: "12px", color: "var(--dim)" }}>
            Systems, libraries, certificates & HSMs
          </div>
        </div>

        <div className="panel" style={{ padding: "16px" }}>
          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            Observed Edges
          </div>
          <div style={{ fontSize: "26px", fontWeight: 700, color: "var(--cyan)", margin: "4px 0" }}>
            {loading ? "..." : (graphStats?.edges ?? edges.length)}
          </div>
          <div style={{ fontSize: "12px", color: "var(--dim)" }}>
            mTLS calls, imports, key bindings
          </div>
        </div>

        <div className="panel" style={{ padding: "16px" }}>
          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            Graph Backend Engine
          </div>
          <div style={{ fontSize: "20px", fontWeight: 700, margin: "7px 0" }}>
            {loading ? "..." : (graphData.backend === "memory" ? "Deterministic Memory Engine" : "Neo4j Cluster")}
          </div>
          <div style={{ fontSize: "12px", color: "var(--green)" }}>
            Fail-closed BFS traversal ready
          </div>
        </div>
      </div>

      {/* Main Workspace Layout */}
      <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: "20px" }}>
        {/* Left: Node Explorer / Visual Map */}
        <div className="panel" style={{ padding: "20px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px", gap: "10px" }}>
            <h3 style={{ margin: 0, fontSize: "16px", fontWeight: 600 }}>Topology Elements</h3>
            <input
              type="text"
              placeholder="Filter nodes..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="inp sm"
              style={{ width: "180px", fontSize: "12px" }}
            />
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "8px", maxHeight: "550px", overflowY: "auto" }}>
            {filteredNodes.map((n: any) => {
              const isSelected = selectedNode?.id === n.id;
              return (
                <div
                  key={n.id}
                  onClick={() => handleSelectNode(n)}
                  style={{
                    padding: "10px 14px",
                    background: isSelected ? "rgba(0, 212, 255, 0.08)" : "var(--bg-2)",
                    border: `1px solid ${isSelected ? "var(--cyan)" : "var(--line)"}`,
                    borderRadius: "6px",
                    cursor: "pointer",
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center"
                  }}
                >
                  <div>
                    <div style={{ fontSize: "13px", fontWeight: 600, color: "var(--text)" }}>
                      {n.label || n.id}
                    </div>
                    <div style={{ fontSize: "11px", color: "var(--dim)" }}>
                      Kind: {n.kind || "system"} · In-Degree: {n.in_degree ?? 0} · Out-Degree: {n.out_degree ?? 0}
                    </div>
                  </div>
                  <Badge variant={n.kind === "hardware" ? "warning" : n.kind === "certificate" ? "info" : "neutral"}>
                    {(n.kind || "node").toUpperCase()}
                  </Badge>
                </div>
              );
            })}

            {filteredNodes.length === 0 && !loading && (
              <div style={{ textAlign: "center", padding: "40px", color: "var(--dim)" }}>
                <div style={{ fontSize: "14px", fontWeight: 600, color: "var(--text)", marginBottom: "4px" }}>
                  No topology nodes in graph
                </div>
                <p style={{ margin: "0 0 14px", fontSize: "12.5px" }}>
                  Register backend systems and complete network discovery to populate dependency links.
                </p>
                <a href="#/scanners" className="btn sm primary" style={{ textDecoration: "none" }}>
                  Launch Scanners
                </a>
              </div>
            )}
          </div>
        </div>

        {/* Right: Selected Node Details & Blast Radius Calculator */}
        <div className="panel" style={{ padding: "20px" }}>
          <h3 style={{ margin: "0 0 4px", fontSize: "16px", fontWeight: 600 }}>Blast Radius & Impact Analysis</h3>
          <p style={{ margin: "0 0 16px", fontSize: "12px", color: "var(--dim)" }}>
            Exact BFS traversal calculating downstream cascading compromise exposure.
          </p>

          {selectedNode ? (
            <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
              <div style={{ padding: "12px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "6px" }}>
                <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Selected Asset</div>
                <div style={{ fontSize: "15px", fontWeight: 700, color: "var(--cyan)", margin: "3px 0" }}>{selectedNode.label || selectedNode.id}</div>
                <div style={{ fontSize: "12px", color: "var(--text)" }}>ID: {selectedNode.id}</div>
                {selectedNode.source === "cryptoscan-systems.yml" && (
                  <div style={{ fontSize: "11px", color: "var(--dim)", marginTop: 4 }}>Declared in code (cryptoscan-systems.yml), not in the CMDB</div>
                )}
              </div>

              {selectedNode.code_cascade && (
                <div style={{ padding: "12px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "6px" }}>
                  <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Code-level crypto (latest scan)</div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8, margin: "6px 0" }}>
                    <div><div style={{ fontSize: 11, color: "var(--dim)" }}>Providers</div><div style={{ fontWeight: 700 }}>{selectedNode.code_cascade.providers}</div></div>
                    <div><div style={{ fontSize: 11, color: "var(--dim)" }}>Weak sizes</div><div style={{ fontWeight: 700, color: selectedNode.code_cascade.weak_parameters ? "var(--red)" : undefined }}>{selectedNode.code_cascade.weak_parameters}</div></div>
                    <div><div style={{ fontSize: 11, color: "var(--dim)" }}>Earliest wave</div><div style={{ fontWeight: 700 }}>{selectedNode.code_cascade.earliest_wave ?? "—"}</div></div>
                  </div>
                  <div style={{ fontSize: 12 }}>{(selectedNode.code_cascade.algorithms || []).slice(0, 8).join(", ") || "—"}</div>
                  {selectedNode.code_cascade.depends_on_systems?.length > 0 && (
                    <div style={{ fontSize: 11, color: "var(--dim)", marginTop: 4 }}>imports crypto from: {selectedNode.code_cascade.depends_on_systems.join(", ")}</div>
                  )}
                  <div style={{ fontSize: 11, color: "var(--dim)", marginTop: 4 }}>scan {selectedNode.code_cascade.scan_id}</div>
                </div>
              )}

              {calculatingBlast ? (
                <div style={{ textAlign: "center", padding: "20px", color: "var(--dim)", fontSize: "13px" }}>
                  Traversing dependency graph hops...
                </div>
              ) : blastRadius ? (
                <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
                    <div style={{ padding: "10px", background: "var(--bg-2)", borderRadius: "6px" }}>
                      <div style={{ fontSize: "11px", color: "var(--dim)" }}>Impacted Systems</div>
                      <div style={{ fontSize: "20px", fontWeight: 700, color: "var(--red)" }}>
                        {blastRadius.affected_systems?.length ?? 0}
                      </div>
                    </div>
                    <div style={{ padding: "10px", background: "var(--bg-2)", borderRadius: "6px" }}>
                      <div style={{ fontSize: "11px", color: "var(--dim)" }}>Max Traversal Depth</div>
                      <div style={{ fontSize: "20px", fontWeight: 700 }}>
                        {blastRadius.hops || 2} hops
                      </div>
                    </div>
                  </div>

                  {blastRadius.affected_systems && blastRadius.affected_systems.length > 0 && (
                    <div>
                      <div style={{ fontSize: "12px", fontWeight: 600, marginBottom: "6px", color: "var(--faint)" }}>
                        Downstream Dependents:
                      </div>
                      <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                        {blastRadius.affected_systems.map((s: string, idx: number) => (
                          <div key={idx} style={{ fontSize: "12px", padding: "6px 8px", background: "var(--bg-2)", borderRadius: "4px" }}>
                            ↳ {s}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div style={{ padding: "14px", background: "var(--bg-2)", borderRadius: "6px", fontSize: "12.5px", color: "var(--dim)" }}>
                  No downstream dependencies detected for this node at 2-hop radius.
                </div>
              )}

              <div style={{ marginTop: "12px" }}>
                <a href="#/whatif" className="btn sm primary" style={{ textDecoration: "none", display: "block", textAlign: "center" }}>
                  Simulate Node Outage in Digital Twin
                </a>
              </div>
            </div>
          ) : (
            <div style={{ textAlign: "center", padding: "40px", color: "var(--dim)", fontSize: "13px" }}>
              Select a node from the topology list on the left to calculate blast radius and upstream dependencies.
            </div>
          )}
        </div>
      </div>
      <CodeCascadePanel />
    </div>
  );
}
