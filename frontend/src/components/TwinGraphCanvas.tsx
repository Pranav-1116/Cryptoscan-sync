import React, { useEffect, useMemo, useState } from "react";
import { Panel, Badge } from "./ui.jsx";
import { apiEstateTwinGraph, apiEstateTwinWhy, type EstateTwinGraphExport, type EstateTwinWhy } from "../lib/api.js";
import { useConsoleStore } from "../lib/appStore.js";

/** Union of two bounded exports: expanding a neighbourhood merges into the
 *  picture without refetching what is already drawn. Dedupe by node id and
 *  by (type, from, to). */
export function mergeTwinExport(
  prev: EstateTwinGraphExport | null,
  next: EstateTwinGraphExport,
): EstateTwinGraphExport {
  if (!prev) return next;
  const nodes = [...prev.nodes];
  const seen = new Set(nodes.map((n) => n.id));
  for (const node of next.nodes) {
    if (!seen.has(node.id)) {
      seen.add(node.id);
      nodes.push(node);
    }
  }
  const relationships = [...prev.relationships];
  const edgeSeen = new Set(relationships.map((e) => `${e.type}|${e.from}|${e.to}`));
  for (const edge of next.relationships) {
    const key = `${edge.type}|${edge.from}|${edge.to}`;
    if (!edgeSeen.has(key)) {
      edgeSeen.add(key);
      relationships.push(edge);
    }
  }
  return {
    ...prev,
    ...next,
    nodes,
    relationships,
    // The disclosure still covers everything NOT loaded anywhere.
    omitted_nodes: next.omitted_nodes ?? prev.omitted_nodes,
    omitted_edges: next.omitted_edges ?? prev.omitted_edges,
    frontier: next.frontier ?? prev.frontier,
    bounded: true,
  };
}

/* ─── The twin's own graph, drawn ─────────────────────────────────────────────
   §9's footnote has been the same for a while: the picture on `/graph` is drawn
   from the legacy eight-label `cypher_writes` projection, so clicking a line on it
   does not open twin evidence — the edge-first panel *beside* the picture does.

   This canvas closes that by drawing the twin's own export. Every line here is a
   relationship the twin holds with the twin's ids, so selecting one asks
   `GET …/twin/why` about *that* subject/predicate/object and prints the evidence
   or the refusal underneath.

   Three decisions worth naming:

   * the layout is layered and deterministic — placement levels above the assets
     they contain, evidence below the asset it supports. No physics, no random
     seed, so the same projection draws the same picture twice, and a screenshot
     is comparable with the next one;
   * refused candidates are counted, never drawn. An unproven relationship drawn
     as a line is an assumption with a border;
   * the drawing is capped and says when it is capped. A graph that silently drops
     nodes is a picture that reads as a complete estate.
──────────────────────────────────────────────────────────────────────────── */

const MAX_NODES = 120;
const WIDTH = 960;
const LAYER_HEIGHT = 118;
const MARGIN = 54;

/** The specification's vertical order: organisation down to the evidence under it. */
const LAYERS = ["ORGANIZATION", "REGION", "DATA_CENTER", "ENVIRONMENT", "ASSET", "EVIDENCE"] as const;
type LayerName = (typeof LAYERS)[number];

interface Placed {
  id: string;
  name: string;
  layer: LayerName;
  kind: string;
  x: number;
  y: number;
  evidenceCount: number;
  degree: number;
}

interface DrawnEdge {
  key: string;
  type: string;
  from: Placed;
  to: Placed;
  predicate: string;
}

function layerOf(labels: string[]): LayerName {
  const upper = labels.map((label) => label.toUpperCase());
  if (upper.includes("EVIDENCE")) return "EVIDENCE";
  if (upper.includes("PLACEMENT")) {
    for (const level of ["ORGANIZATION", "REGION", "DATA_CENTER", "ENVIRONMENT"] as const) {
      if (upper.includes(level)) return level;
    }
    return "ENVIRONMENT";
  }
  return "ASSET";
}

function kindOf(labels: string[]): string {
  // the second label is the type: Asset/APPLICATION, Evidence/RUNTIME_OBSERVED,
  // PLACEMENT/DATA_CENTER — the first is the family.
  return labels.length > 1 ? String(labels[labels.length - 1]) : String(labels[0] ?? "UNKNOWN");
}

export default function TwinGraphCanvas() {
  const [exported, setExported] = useState<EstateTwinGraphExport | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [answer, setAnswer] = useState<{ key: string; data: EstateTwinWhy | null } | null>(null);
  const [asking, setAsking] = useState(false);
  const [expanding, setExpanding] = useState<string | null>(null);
  const expandNode = useConsoleStore((s) => s.expandNode);

  useEffect(() => {
    let live = true;
    void (async () => {
      // The bank rule: the server returns a BOUNDED subgraph (best-connected
      // overview). The estate is never downloaded whole; neighbourhoods load
      // on demand through expandNeighborhood.
      const result = await apiEstateTwinGraph({ limit: MAX_NODES });
      if (!live) return;
      if (result.ok) setExported(result.data as EstateTwinGraphExport);
      // a failed read is a fact about the read, not an empty graph
      else setLoadError("the twin's graph export is unavailable — this is not 'no relationships'");
    })();
    return () => { live = false; };
  }, []);

  const expandNeighborhood = async (nodeId: string) => {
    if (expanding) return;
    setExpanding(nodeId);
    const result = await apiEstateTwinGraph({ seed: nodeId, depth: 1 });
    if (result.ok) {
      setExported((prev) => mergeTwinExport(prev, result.data as EstateTwinGraphExport));
      expandNode(nodeId, true);
    } else {
      setLoadError("the neighbourhood could not be loaded — the picture is unchanged, not empty");
    }
    setExpanding(null);
  };

  const { placed, drawn, omittedNodes, omittedEdges } = useMemo(() => {
    const nodes = exported?.nodes ?? [];
    const relationships = exported?.relationships ?? [];

    const degree = new Map<string, number>();
    for (const edge of relationships) {
      degree.set(edge.from, (degree.get(edge.from) ?? 0) + 1);
      degree.set(edge.to, (degree.get(edge.to) ?? 0) + 1);
    }

    // keep the best-connected nodes when the projection is too big to draw, and
    // keep the choice deterministic: degree desc, then id.
    const kept = [...nodes]
      .sort((a, b) => (degree.get(b.id) ?? 0) - (degree.get(a.id) ?? 0) || a.id.localeCompare(b.id))
      .slice(0, MAX_NODES);
    const keptIds = new Set(kept.map((node) => node.id));

    const byLayer = new Map<LayerName, typeof kept>();
    for (const node of kept) {
      const layer = layerOf(node.labels ?? []);
      const bucket = byLayer.get(layer) ?? [];
      bucket.push(node);
      byLayer.set(layer, bucket);
    }

    const positions = new Map<string, Placed>();
    LAYERS.forEach((layer, index) => {
      const bucket = (byLayer.get(layer) ?? [])
        .slice()
        .sort((a, b) => String((a.properties as Record<string, unknown>)?.name ?? a.id)
          .localeCompare(String((b.properties as Record<string, unknown>)?.name ?? b.id)));
      bucket.forEach((node, position) => {
        const properties = (node.properties ?? {}) as Record<string, unknown>;
        positions.set(node.id, {
          id: node.id,
          name: String(properties.name ?? node.id),
          layer,
          kind: kindOf(node.labels ?? []),
          x: ((position + 0.5) * WIDTH) / Math.max(bucket.length, 1),
          y: MARGIN + index * LAYER_HEIGHT,
          evidenceCount: Number(properties.evidence_count ?? 0),
          degree: degree.get(node.id) ?? 0,
        });
      });
    });

    const edges: DrawnEdge[] = [];
    let dropped = 0;
    for (const edge of relationships) {
      const from = positions.get(edge.from);
      const to = positions.get(edge.to);
      if (!from || !to) { dropped += 1; continue; }
      edges.push({
        key: `${edge.type}|${edge.from}|${edge.to}`,
        type: edge.type,
        from,
        to,
        predicate: String(edge.type).toLowerCase(),
      });
    }

    return {
      placed: [...positions.values()],
      drawn: edges,
      omittedNodes: nodes.length - kept.length,
      omittedEdges: dropped,
    };
  }, [exported]);

  const askWhy = async (edge: DrawnEdge) => {
    setSelected(edge.key);
    setAsking(true);
    setAnswer({ key: edge.key, data: null });
    const result = await apiEstateTwinWhy({
      subject: edge.from.id, predicate: edge.predicate, object: edge.to.id,
    });
    setAnswer({
      key: edge.key,
      data: result.ok
        ? (result.data as EstateTwinWhy)
        : {
            schema: "", status: "NO_SUCH_RELATIONSHIP",
            detail: "the why route could not be read — that is not 'this edge has no evidence'",
          },
    });
    setAsking(false);
  };

  const current = answer && answer.key === selected ? answer.data : null;
  const activeEdge = drawn.find((edge) => edge.key === selected) ?? null;
  const height = MARGIN + (LAYERS.length - 1) * LAYER_HEIGHT + MARGIN;

  return (
    <Panel
      title="The twin's own graph, drawn"
      sub="every line is a relationship the twin holds — select one and read its evidence, or the reason it was refused"
      style={{ padding: "12px 14px" }}
    >
      {loadError && <div style={{ fontSize: 11, color: "var(--dim)" }}>{loadError}</div>}
      {!exported && !loadError && <div style={{ fontSize: 11, color: "var(--dim)" }}>loading the twin's graph…</div>}

      {exported && (
        <>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center", marginBottom: 8 }}>
            <Badge tone="violet">{placed.length} nodes drawn</Badge>
            <Badge tone="slate">{drawn.length} relationships</Badge>
            <Badge tone="slate">{exported.counts?.unresolved ?? 0} refused candidates, not drawn</Badge>
            {exported.projection_id && (
              <Badge tone="green">projection {String(exported.projection_id).slice(0, 8)}…</Badge>
            )}
          </div>

          <div style={{ overflowX: "auto", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>
            <svg
              viewBox={`0 0 ${WIDTH} ${height}`}
              width="100%"
              height={height}
              role="img"
              aria-label="The twin's relationship graph"
              style={{ display: "block", minWidth: 520 }}
            >
              <defs>
                <marker id="twin-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--faint)" />
                </marker>
              </defs>

              {LAYERS.map((layer, index) => (
                <text
                  key={layer}
                  x={8}
                  y={MARGIN + index * LAYER_HEIGHT - 26}
                  fontSize={9}
                  fill="var(--faint)"
                  style={{ fontFamily: "var(--mono)", letterSpacing: ".08em" }}
                >
                  {layer}
                </text>
              ))}

              {drawn.map((edge) => {
                const isActive = edge.key === selected;
                return (
                  <g key={edge.key}>
                    <line
                      x1={edge.from.x} y1={edge.from.y} x2={edge.to.x} y2={edge.to.y}
                      stroke={isActive ? "var(--violet)" : "var(--line)"}
                      strokeWidth={isActive ? 2.4 : 1}
                      markerEnd="url(#twin-arrow)"
                    />
                    {/* a 12px transparent hit area: a 1px line is not clickable in practice */}
                    <line
                      x1={edge.from.x} y1={edge.from.y} x2={edge.to.x} y2={edge.to.y}
                      stroke="transparent"
                      strokeWidth={12}
                      role="button"
                      tabIndex={0}
                      aria-label={`${edge.predicate}: ${edge.from.name} → ${edge.to.name}`}
                      style={{ cursor: "pointer" }}
                      onClick={() => void askWhy(edge)}
                      onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") void askWhy(edge); }}
                    />
                  </g>
                );
              })}

              {placed.map((node) => (
                <g key={node.id}>
                  <circle
                    cx={node.x} cy={node.y} r={node.layer === "ASSET" ? 13 : 9}
                    fill={node.layer === "EVIDENCE" ? "var(--amber)" : node.layer === "ASSET" ? "var(--violet)" : "var(--slate)"}
                    opacity={0.9}
                    role="button"
                    tabIndex={0}
                    aria-label={`Load the neighbourhood of ${node.name}`}
                    style={{ cursor: "pointer" }}
                    onClick={() => void expandNeighborhood(node.id)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === " ") void expandNeighborhood(node.id);
                    }}
                  />
                  <text
                    x={node.x} y={node.y + (node.layer === "ASSET" ? 28 : 22)}
                    fontSize={10} textAnchor="middle" fill="var(--dim)"
                  >
                    {node.name.length > 20 ? `${node.name.slice(0, 19)}…` : node.name}
                  </text>
                </g>
              ))}

              {placed.length === 0 && (
                <text x={WIDTH / 2} y={height / 2} fontSize={12} textAnchor="middle" fill="var(--faint)">
                  the export holds no nodes
                </text>
              )}
            </svg>
          </div>

          {(omittedNodes > 0 || omittedEdges > 0) && (
            <div style={{ marginTop: 8, fontSize: 11, color: "var(--amber)" }}>
              {omittedNodes > 0 && <>{omittedNodes} further node(s) are not drawn (the canvas holds {MAX_NODES}). </>}
              {omittedEdges > 0 && <>{omittedEdges} relationship(s) connect nodes this canvas did not draw. </>}
              This is a drawing limit, not the edge of the estate.
            </div>
          )}

          {exported.bounded && (
            <div style={{ marginTop: 6, fontSize: 11, color: "var(--dim)" }}>
              {Number(exported.omitted_nodes ?? 0) > 0 && (
                <>{exported.omitted_nodes} further node(s) are not loaded — the picture is a bounded subgraph. </>
              )}
              Select a node to load its neighbourhood (progressive expansion).
              {expanding && <> Loading {expanding}…</>}
            </div>
          )}

          {activeEdge && (
            <div style={{ marginTop: 10, borderTop: "1px solid var(--line)", paddingTop: 10 }}>
              <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", marginBottom: 6 }}>
                <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--violet)" }}>
                  {activeEdge.predicate}
                </span>
                <span style={{ fontSize: 11 }}>{activeEdge.from.name} → {activeEdge.to.name}</span>
                {asking && <Badge tone="slate">asking why…</Badge>}
                {current && <Badge tone={current.status === "ESTABLISHED" ? "green" : "amber"}>{current.status}</Badge>}
              </div>
              {current && current.status === "ESTABLISHED" && (
                <div style={{ overflowX: "auto" }}>
                  <table className="tbl" style={{ width: "100%" }}>
                    <thead><tr><th>Evidence</th><th>Collector</th><th>Source</th><th>Observed</th><th>Hash</th></tr></thead>
                    <tbody>
                      {(current.matches ?? []).flatMap((match) => match.evidence ?? []).map((record, index) => (
                        <tr key={`${record.evidence_id}-${index}`}>
                          <td style={{ fontSize: 11 }}>{record.evidence_type}</td>
                          <td style={{ fontSize: 11, color: "var(--faint)" }}>{record.collector ?? "—"}</td>
                          <td style={{ fontSize: 11 }}>{record.source ?? "—"}</td>
                          <td style={{ fontSize: 11 }}>{record.observed_at ? new Date(record.observed_at).toLocaleString() : "—"}</td>
                          <td style={{ fontFamily: "var(--mono)", fontSize: 10.5 }} title={record.hash}>
                            {String(record.hash ?? "").slice(0, 12)}…
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              {current && current.status !== "ESTABLISHED" && (
                <div style={{ fontSize: 11, color: "var(--dim)", lineHeight: 1.5 }}>
                  {current.detail ?? "the twin gave no reason"}
                  {current.refused && current.refused.length > 0 && <> — {current.refused[0].reason}</>}
                  {" "}That is not the same as &ldquo;no evidence exists&rdquo;.
                </div>
              )}
            </div>
          )}

          {!selected && drawn.length > 0 && (
            <div style={{ marginTop: 8, fontSize: 11, color: "var(--faint)" }}>
              Select a line to ask why the twin believes it. {placed.filter((node) => node.layer === "EVIDENCE").length} evidence
              record(s) are drawn under the assets they support.
            </div>
          )}
        </>
      )}
    </Panel>
  );
}
