import { Link, useSearchParams } from "react-router-dom";
import React, { useEffect, useState } from "react";
import { Badge, Button, Bar, Ring } from "../components/ui";
import { apiGraph, apiGraphStats, apiGraphBlastRadius, apiGraphBlastRadiusFromAsset } from "../lib/api";
import AuthenticatedDownload from "../components/AuthenticatedDownload";
import { IconComponent, IconSearch, IconTarget, IconSecurity, IconCloud, IconHardware } from "../components/icons";
import CodeCascadePanel from "../components/CodeCascadePanel";
import UnifiedCascadePanel from "../components/UnifiedCascadePanel";
import EdgeManagerPanel from "../components/EdgeManagerPanel";

export default function DependencyGraph() {
  const [loading, setLoading] = useState(true);
  const [graphData, setGraphData] = useState<any>({ nodes: [], edges: [] });
  const [graphStats, setGraphStats] = useState<any>(null);
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [blastRadius, setBlastRadius] = useState<any>(null);
  const [calculatingBlast, setCalculatingBlast] = useState(false);
  const [search, setSearch] = useState("");
  /* §5 (round 64): /dependency-graph?asset=<id> deep-links from the asset
   * inventory — the blast panel starts from that crypto asset instead of
   * waiting for a node click. */
  const [searchParams] = useSearchParams();
  const assetParam = searchParams.get("asset");

  useEffect(() => {
    if (!assetParam) return;
    let alive = true;
    setSelectedNode({ id: assetParam, kind: "asset", label: `Crypto asset ${assetParam}` });
    setCalculatingBlast(true);
    apiGraphBlastRadiusFromAsset(assetParam, 5).then((res) => {
      if (!alive) return;
      // 404 = the endpoint's "asset not linked to any system" answer —
      // rendered below as the honest unknown, never as zero impact.
      setBlastRadius(res.source === "live" && res.data ? res.data : null);
      setCalculatingBlast(false);
    });
    return () => { alive = false; };
  }, [assetParam]);

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

  // §4.5 (r43): an edge count alone implies every line is an observed
  // relationship. The provenance breakdown says which are operator
  // declarations, which are scanner-derived from evidence, and which have
  // unknown origin — computed from the API's per-edge provenance field.
  const edgeProvenance: Record<string, number> = {};
  for (const e of edges as Array<Record<string, unknown>>) {
    const key = String(e?.provenance || "UNATTRIBUTED").toUpperCase();
    edgeProvenance[key] = (edgeProvenance[key] || 0) + 1;
  }
  const provenanceSummary = Object.entries(edgeProvenance)
    .sort((a, b) => b[1] - a[1])
    .map(([k, v]) => `${v} ${k.toLowerCase().replace(/_/g, "-")}`)
    .join(" · ");

  const filteredNodes = nodes.filter((n: any) =>
    (n.label || n.id || "").toLowerCase().includes(search.toLowerCase()) ||
    (n.kind || "").toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "14px 16px", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: "var(--r)", marginBottom: 16, flexWrap: "wrap", gap: 12 }}>
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--accent) 14%, transparent)", border: "1px solid var(--accent)" }}><IconComponent size={16} style={{ color: "var(--accent)" }} /></span>
          <div>
            <div style={{ fontSize: 10, letterSpacing: .12, fontFamily: "var(--mono)", color: "var(--accent)" }}>DETERMINISTIC TOPOLOGY · LIVE BFS · NO INFERENCE</div>
            <h1 style={{ fontSize: 22, fontWeight: 700, margin: "2px 0 2px", lineHeight: 1 }}>Cryptographic Dependency Graph</h1>
            <div style={{ fontSize: 12, color: "var(--dim)" }}>Systems → libraries → certs → HSMs — observed edges with provenance</div>
          </div>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          {!loading && nodes.length > 0 && <div style={{ display: "flex", alignItems: "center", gap: 8 }}><Ring pct={edges.length ? Math.min(1, edges.length / Math.max(1, nodes.length * 1.5)) : 0} label={nodes.length} sub="nodes" tone="cyan" /><div style={{ fontSize: 11, color: "var(--dim)", lineHeight: 1.3 }}>{edges.length} edges<br />{provenanceSummary ? <span style={{ color: "var(--accent)" }}>{provenanceSummary.split(" · ")[0]}</span> : <span>no edges yet</span>}</div></div>}
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <AuthenticatedDownload path="/api/v1/graph" filename="cryptoscan-graph.json" className="btn outline" style={{ fontSize: 12, padding: "7px 12px", borderRadius: "var(--r)" }}>Export Graph JSON</AuthenticatedDownload>
            <Link to="/scanners" className="btn primary" style={{ textDecoration: "none", fontSize: 12, padding: "7px 12px", borderRadius: "var(--r)", textAlign: "center" }}>Discover Topology</Link>
          </div>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 12, marginBottom: 16 }}>
        <div className="panel" style={{ padding: "12px 14px", borderTop: "2px solid var(--accent)" }}>
          <div style={{ fontSize: 10, color: "var(--dim)", letterSpacing: .08, display: "flex", gap: 6, alignItems: "center" }}><span className="dot" style={{ background: "var(--accent)", width: 6, height: 6, borderRadius: 99 }} />NODES</div>
          <div style={{ fontSize: 22, fontWeight: 800, margin: "4px 0 2px" }}>{loading ? "…" : (graphStats?.nodes ?? nodes.length)}</div>
          <div style={{ fontSize: 11, color: "var(--dim)" }}>Systems · libs · certs · HSMs</div>
          {!loading && <Bar value={1} tone="cyan" />}
        </div>
        <div className="panel" style={{ padding: "12px 14px", borderTop: "2px solid var(--cyan)" }}>
          <div style={{ fontSize: 10, color: "var(--dim)", letterSpacing: .08, display: "flex", gap: 6, alignItems: "center" }}><span className="dot" style={{ background: "var(--cyan)", width: 6, height: 6, borderRadius: 99 }} />EDGES</div>
          <div style={{ fontSize: 22, fontWeight: 800, color: "var(--cyan)", margin: "4px 0 2px" }}>{loading ? "…" : (graphStats?.edges ?? edges.length)}</div>
          <div style={{ fontSize: 11, color: "var(--dim)" }}>{loading ? "…" : (provenanceSummary || "no edges yet")}</div>
          {!loading && edges.length > 0 && <Bar value={Math.min(1, edges.length / Math.max(1, (graphStats?.nodes ?? nodes.length)))} tone="cyan" />}
          <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 4 }}>declared = operator · scanner-derived = evidence</div>
        </div>
        <div className="panel" style={{ padding: "12px 14px", borderTop: loading || graphData.backend ? "2px solid var(--green)" : "2px solid var(--line-strong)" }}>
          <div style={{ fontSize: 10, color: "var(--dim)", letterSpacing: .08, display: "flex", gap: 6, alignItems: "center" }}><span className="dot" style={{ background: loading || graphData.backend ? "var(--green)" : "var(--slate)", width: 6, height: 6, borderRadius: 99 }} />ENGINE</div>
          <div style={{ fontSize: 14, fontWeight: 700, margin: "6px 0 2px", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{loading ? "…" : graphData.backend === "memory" ? "Deterministic Memory" : graphData.backend ? `Neo4j (${graphData.backend})` : "Not reported"}</div>
          <div style={{ fontSize: 11, color: loading || graphData.backend ? "var(--green)" : "var(--dim)" }}>{loading || graphData.backend ? "Fail-closed BFS ready" : "Backend not reported"}</div>
        </div>
      </div>

      {/* Main Workspace Layout */}
      <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: "20px" }}>
        {/* Left: Node Explorer / Visual Map */}
        <div className="panel" style={{ padding: "14px 16px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10, flexWrap: "wrap", marginBottom: 10, padding: "8px 10px", background: "var(--bg-2)", borderRadius: "var(--r)", border: "1px solid var(--line)" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}><IconComponent size={14} style={{ color: "var(--accent)" }} /><span style={{ fontSize: 12, fontWeight: 700 }}>Topology Elements</span><Badge tone={nodes.length ? "cyan" : "slate"}>{filteredNodes.length} / {nodes.length}</Badge></div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, flex: "1", minWidth: 160, maxWidth: 220 }}><IconSearch size={13} style={{ color: "var(--faint)" }} /><input type="text" placeholder="Filter nodes…" value={search} onChange={(e) => setSearch(e.target.value)} className="inp sm" style={{ flex: 1, fontSize: 12 }} /></div>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "8px", maxHeight: "550px", overflowY: "auto" }}>
            {filteredNodes.map((n: any) => {
              const isSelected = selectedNode?.id === n.id;
              return (
                <div
                  key={n.id}
                  onClick={() => handleSelectNode(n)}
                  style={{
                    padding: "9px 12px",
                    background: isSelected ? "color-mix(in srgb, var(--accent) 10%, transparent)" : "var(--panel-2)",
                    border: `1px solid ${isSelected ? "var(--accent)" : "var(--line)"}`,
                    borderLeft: `3px solid ${isSelected ? "var(--accent)" : n.kind === "certificate" ? "var(--green)" : n.kind === "hardware" ? "var(--orange)" : "var(--line-strong)"}`,
                    borderRadius: "var(--r)",
                    cursor: "pointer",
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center"
                  }}
                >
                  <div>
                    <div style={{ fontSize: "13px", fontWeight: 600, color: "var(--text)", fontFamily: "var(--mono)" }}>
                      [<span style={{ color: isSelected ? "var(--accent)" : "var(--text)" }}>{n.label || n.id}</span>]
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
                <Link to="/scanners" className="btn sm primary" style={{ textDecoration: "none" }}>
                  Launch Scanners
                </Link>
              </div>
            )}
          </div>
        </div>

        {/* Right: Selected Node Details & Blast Radius Calculator */}
        <div className="panel" style={{ padding: "14px 16px", borderTop: "2px solid var(--red)" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, flexWrap: "wrap", marginBottom: 8, padding: "8px 10px", background: "var(--bg-2)", borderRadius: "var(--r)", border: "1px solid var(--line)" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}><IconTarget size={14} style={{ color: "var(--red)" }} /><span style={{ fontSize: 12, fontWeight: 700 }}>Blast Radius & Impact</span><Badge tone={blastRadius ? "red" : "slate"}>{blastRadius ? `${blastRadius.systems?.length ?? 0} impacted` : "select node"}</Badge></div>
            <span style={{ fontSize: 11, color: "var(--dim)" }}>Exact BFS · downstream exposure</span>
          </div>

          {selectedNode ? (
            <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
              {selectedNode.kind === "asset" && (
                <div style={{ fontSize: "12px", color: "var(--dim)", lineHeight: 1.5 }}>
                  Asset start — loaded from an inventory cross-link. The walk fans out from every system that
                  uses this crypto asset (declared or adopted SystemAsset links, not observed traffic).{" "}
                  <Link to="/assets" style={{ color: "var(--cyan)" }}>Back to the asset inventory</Link>
                  {blastRadius?.owning_systems?.length ? ` · shared across ${blastRadius.owning_systems.length} owning system(s)` : ""}
                </div>
              )}
              <div style={{ padding: "12px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>
                <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Selected Asset</div>
                <div style={{ fontSize: "15px", fontWeight: 700, color: "var(--cyan)", margin: "3px 0" }}>{selectedNode.label || selectedNode.id}</div>
                <div style={{ fontSize: "12px", color: "var(--text)" }}>ID: {selectedNode.id}</div>
                {selectedNode.source === "cryptoscan-systems.yml" && (
                  <div style={{ fontSize: "11px", color: "var(--dim)", marginTop: 4 }}>Declared in code (cryptoscan-systems.yml), not in the CMDB</div>
                )}
              </div>

              {selectedNode.code_cascade && (
                <div style={{ padding: "12px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>
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
                    <div style={{ padding: "10px", background: "var(--bg-2)", borderRadius: "var(--r)" }}>
                      <div style={{ fontSize: "11px", color: "var(--dim)" }}>Impacted Systems</div>
                      <div style={{ fontSize: "20px", fontWeight: 700, color: "var(--red)" }}>
                        {blastRadius.systems?.length ?? 0}
                      </div>
                    </div>
                    <div style={{ padding: "10px", background: "var(--bg-2)", borderRadius: "var(--r)" }}>
                      <div style={{ fontSize: "11px", color: "var(--dim)" }}>Max Traversal Depth</div>
                      <div style={{ fontSize: "20px", fontWeight: 700 }}>
                        {(blastRadius.systems || []).length > 0
                          ? `${Math.max(...(blastRadius.systems || []).map((s: any) => s.hops ?? 0))} hops`
                          : "0 hops"}
                      </div>
                    </div>
                  </div>

                  {blastRadius.provenance_counts && (
                    <div style={{ fontSize: "11px", color: "var(--dim)", lineHeight: 1.5 }}>
                      Path edges:{" "}
                      {Object.entries(blastRadius.provenance_counts as Record<string, number>)
                        .filter(([, v]) => Number(v) > 0)
                        .map(([k, v]) => `${Number(v)} ${String(k).toLowerCase().replace(/_/g, "-")}`)
                        .join(" · ") || "none"}
                      {" "}— declared edges are operator statements, not observed traffic.
                    </div>
                  )}

                  {blastRadius.owning_systems && blastRadius.owning_systems.length > 0 && (
                    <div style={{ fontSize: "11px", color: "var(--dim)" }}>
                      Shared across {blastRadius.owning_systems.length} owning system{blastRadius.owning_systems.length === 1 ? "" : "s"} (asset start).
                    </div>
                  )}

                  {blastRadius.systems && blastRadius.systems.length > 0 && (
                    <div>
                      <div style={{ fontSize: "12px", fontWeight: 600, marginBottom: "6px", color: "var(--faint)" }}>
                        Downstream Dependents:
                      </div>
                      <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                        {blastRadius.systems.map((s: any, idx: number) => (
                          <div key={idx} style={{ fontSize: "12px", padding: "6px 8px", background: "var(--bg-2)", borderRadius: "var(--r)" }}>
                            ↳ {s.name || s.id} <span style={{ color: "var(--dim)" }}>· {s.hops} hop{s.hops === 1 ? "" : "s"}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div style={{ padding: "14px", background: "var(--bg-2)", borderRadius: "var(--r)", fontSize: "12.5px", color: "var(--dim)" }}>
                  {selectedNode.kind === "asset"
                    ? "No traversal result — this asset is not linked to any system (no SystemAsset rows), or the graph is unavailable. Blast radius is unknown, not zero; nothing is claimed."
                    : "Blast radius unavailable for this node — no traversal result was returned, so nothing is claimed."}
                </div>
              )}

              <div style={{ marginTop: "12px" }}>
                <Link to="/what-if" className="btn sm primary" style={{ textDecoration: "none", display: "block", textAlign: "center" }}>
                  Explore What-If Migration
                </Link>
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
      <UnifiedCascadePanel />
      <EdgeManagerPanel />
    </div>
  );
}
