import React, { useMemo, useState } from "react";
import type { TechBomComponent, TechBomState } from "../lib/api.js";

/* Technology BOM dependency graph.

   Columns by BOM layer (software → crypto → hardware → vendors → certificates),
   one row per component, so a few hundred components stay readable. Rows are ordered
   to keep connected components near each other.
   Only the edges the BOM records (`state.dependencies`) are drawn — nothing is
   inferred from counts. An edge end that is not a BOM component is shown in its own
   "Referenced only" column, never dropped and never guessed into a component. */

export const LAYERS = [
  { key: "sbom", label: "Software", short: "SBOM", color: "var(--violet)" },
  { key: "cbom", label: "Crypto", short: "CBOM", color: "var(--accent)" },
  { key: "hbom", label: "Hardware", short: "HBOM", color: "var(--amber)" },
  { key: "vendor", label: "Vendors", short: "VBOM", color: "var(--slate)" },
  { key: "certificates", label: "Certificates", short: "Certs", color: "var(--green)" },
  { key: "external", label: "Referenced only", short: "not in BOM", color: "var(--faint)" },
] as const;
export type LayerKey = typeof LAYERS[number]["key"];

export interface DepNode {
  id: string;
  label: string;
  sub: string;
  layer: LayerKey;
  degree: number;
}
export interface DepEdge { source: string; target: string; type: string }
export interface DepGraph {
  nodes: DepNode[];
  edges: DepEdge[];
  recorded: number;      // edges the BOM records
  external: number;      // edge ends that are not BOM components
  selfLoops: number;
}

const BOM_LAYERS = ["sbom", "cbom", "hbom", "vendor", "certificates"] as const;

function componentLabel(c: TechBomComponent & Record<string, unknown>): string {
  const name = String(c.name ?? c.subject ?? c.algorithm ?? c["bom-ref"] ?? c.fingerprint ?? "unnamed");
  return c.version && c.version !== "unknown" ? `${name} ${c.version}` : name;
}

/** Turn the BOM state into a graph of real components and recorded edges. */
export function buildDependencyGraph(state: Pick<TechBomState, "layers" | "dependencies">): DepGraph {
  const nodes = new Map<string, DepNode>();
  const keys = new Map<string, string>();         // lookup key -> node id
  const nameCount = new Map<string, number>();
  const byName = new Map<string, string>();

  for (const layer of BOM_LAYERS) {
    const comps = (state.layers?.[layer]?.components ?? []) as Array<TechBomComponent & Record<string, unknown>>;
    comps.forEach((c, i) => {
      const ref = String(c["bom-ref"] ?? c.fingerprint ?? `${layer}:${i}`);
      const id = `${layer}|${ref}`;
      if (nodes.has(id)) return;
      nodes.set(id, {
        id, layer, degree: 0,
        label: componentLabel(c),
        sub: String(c.type ?? (layer === "certificates" ? "certificate" : "")),
      });
      const candidates = [ref, ref.includes(":") ? ref.slice(ref.indexOf(":") + 1) : "",
        c.asset, c.fingerprint, c.id as string | undefined];
      // crypto refs are "crypto:<id>:<asset>" — the id alone is how edges name it
      if (layer === "cbom" && ref.startsWith("crypto:")) candidates.push(ref.split(":")[1]);
      for (const k of candidates) if (k && !keys.has(String(k))) keys.set(String(k), id);
      const name = String(c.name ?? "").toLowerCase();
      if (name) { nameCount.set(name, (nameCount.get(name) ?? 0) + 1); byName.set(name, id); }
    });
  }

  const resolve = (endpoint: string): string => {
    const direct = keys.get(endpoint);
    if (direct) return direct;
    const lower = endpoint.toLowerCase();
    if (nameCount.get(lower) === 1) return byName.get(lower)!;   // a unique name only
    const id = `external|${endpoint}`;
    if (!nodes.has(id)) nodes.set(id, { id, layer: "external", degree: 0, label: endpoint, sub: "not a BOM component" });
    return id;
  };

  const seen = new Set<string>();
  const edges: DepEdge[] = [];
  let selfLoops = 0;
  const raw = state.dependencies ?? [];
  for (const dep of raw) {
    if (!Array.isArray(dep) || dep.length < 2 || !dep[0] || !dep[1]) continue;
    const source = resolve(String(dep[0]));
    const target = resolve(String(dep[1]));
    if (source === target) { selfLoops += 1; continue; }
    const type = String(dep[2] ?? "") || "depends on";
    const key = `${source}→${target}→${type}`;
    if (seen.has(key)) continue;
    seen.add(key);
    edges.push({ source, target, type: type.replace(/_/g, " ") });
    nodes.get(source)!.degree += 1;
    nodes.get(target)!.degree += 1;
  }
  const external = [...nodes.values()].filter((n) => n.layer === "external").length;
  return { nodes: [...nodes.values()], edges, recorded: raw.length, external, selfLoops };
}

/** Rows per column, ordered so neighbours line up (two barycentre sweeps). */
export function orderColumns(nodes: DepNode[], edges: DepEdge[]): Map<LayerKey, DepNode[]> {
  const columns = new Map<LayerKey, DepNode[]>();
  for (const layer of LAYERS) columns.set(layer.key, []);
  for (const n of nodes) columns.get(n.layer)!.push(n);
  for (const list of columns.values()) {
    list.sort((a, b) => b.degree - a.degree || a.label.localeCompare(b.label));
  }
  const neighbours = new Map<string, string[]>();
  for (const e of edges) {
    (neighbours.get(e.source) ?? neighbours.set(e.source, []).get(e.source)!).push(e.target);
    (neighbours.get(e.target) ?? neighbours.set(e.target, []).get(e.target)!).push(e.source);
  }
  for (let sweep = 0; sweep < 2; sweep++) {
    const pos = new Map<string, number>();
    for (const list of columns.values()) list.forEach((n, i) => pos.set(n.id, i / Math.max(1, list.length - 1)));
    for (const list of columns.values()) {
      const score = new Map<string, number>();
      list.forEach((n, i) => {
        const ns = (neighbours.get(n.id) ?? []).map((m) => pos.get(m)).filter((v): v is number => v !== undefined);
        score.set(n.id, ns.length ? ns.reduce((a, b) => a + b, 0) / ns.length : i / Math.max(1, list.length - 1));
      });
      list.sort((a, b) => score.get(a.id)! - score.get(b.id)! || a.label.localeCompare(b.label));
    }
  }
  return columns;
}

const EDGE_COLORS = ["var(--accent)", "var(--green)", "var(--amber)", "var(--violet)", "var(--orange)", "var(--slate)"];
const ROW = 22;
const TOP = 34;
const WIDTH = 1100;

export default function TechBomDependencyGraph({ state }: { state: TechBomState }) {
  const graph = useMemo(() => buildDependencyGraph(state), [state]);
  const [connectedOnly, setConnectedOnly] = useState(true);
  const [hidden, setHidden] = useState<Set<LayerKey>>(new Set());
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [hover, setHover] = useState<string | null>(null);

  const hasEdges = graph.edges.length > 0;
  const showAll = !connectedOnly || !hasEdges;

  const visibleNodes = useMemo(() => graph.nodes.filter((n) =>
    !hidden.has(n.layer) && (showAll || n.degree > 0)), [graph, hidden, showAll]);
  const visibleIds = useMemo(() => new Set(visibleNodes.map((n) => n.id)), [visibleNodes]);
  const visibleEdges = useMemo(() => graph.edges.filter((e) =>
    visibleIds.has(e.source) && visibleIds.has(e.target)), [graph, visibleIds]);
  const columns = useMemo(() => orderColumns(visibleNodes, visibleEdges), [visibleNodes, visibleEdges]);
  const activeColumns = LAYERS.filter((l) => (columns.get(l.key)?.length ?? 0) > 0);
  const edgeTypes = useMemo(() => [...new Set(graph.edges.map((e) => e.type))].sort(), [graph]);
  const edgeColor = (type: string) => EDGE_COLORS[edgeTypes.indexOf(type) % EDGE_COLORS.length];

  const q = query.trim().toLowerCase();
  const matches = useMemo(() => new Set(q ? visibleNodes.filter((n) => n.label.toLowerCase().includes(q)).map((n) => n.id) : []), [q, visibleNodes]);
  const focus = hover ?? selected;
  const focusSet = useMemo(() => {
    if (!focus) return null;
    const set = new Set([focus]);
    for (const e of visibleEdges) {
      if (e.source === focus) set.add(e.target);
      if (e.target === focus) set.add(e.source);
    }
    return set;
  }, [focus, visibleEdges]);

  const colWidth = activeColumns.length ? WIDTH / activeColumns.length : WIDTH;
  const boxWidth = Math.max(120, colWidth - 46);
  // room for the left stripe and the dependency count on the right
  const maxChars = Math.floor((boxWidth - 14 - 26) / 6.7);
  const place = new Map<string, { x: number; y: number; col: number }>();
  activeColumns.forEach((layer, ci) => {
    columns.get(layer.key)!.forEach((n, ri) => place.set(n.id, { x: ci * colWidth + 6, y: TOP + ri * ROW, col: ci }));
  });
  const rows = Math.max(1, ...activeColumns.map((l) => columns.get(l.key)!.length));
  const height = TOP + rows * ROW + 10;
  const hiddenUnconnected = connectedOnly && hasEdges
    ? graph.nodes.filter((n) => n.degree === 0 && !hidden.has(n.layer)).length : 0;

  const path = (e: DepEdge) => {
    const a = place.get(e.source)!, b = place.get(e.target)!;
    const ay = a.y + ROW / 2 - 2, by = b.y + ROW / 2 - 2;
    if (a.col === b.col) {   // same column: an arc on the right of the column
      const x = a.x + boxWidth;
      const bulge = 14 + Math.min(26, Math.abs(by - ay) / 10);
      return `M${x},${ay} C${x + bulge},${ay} ${x + bulge},${by} ${x},${by}`;
    }
    const leftToRight = a.col < b.col;
    const x1 = leftToRight ? a.x + boxWidth : a.x;
    const x2 = leftToRight ? b.x : b.x + boxWidth;
    const mid = (x1 + x2) / 2;
    return `M${x1},${ay} C${mid},${ay} ${mid},${by} ${x2},${by}`;
  };

  const selectedNode = selected ? graph.nodes.find((n) => n.id === selected) : null;
  const nodeById = useMemo(() => new Map(graph.nodes.map((n) => [n.id, n])), [graph]);
  const outgoing = selected ? graph.edges.filter((e) => e.source === selected) : [];
  const incoming = selected ? graph.edges.filter((e) => e.target === selected) : [];

  if (graph.nodes.length === 0) {
    return <div className="empty">No components yet — run a scan to populate the Technology BOM.</div>;
  }

  return (
    <div className="depgraph">
      <div className="depgraph-toolbar">
        <input
          aria-label="Find a component"
          placeholder="Find a component…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          style={{ minWidth: 200 }}
        />
        <div className="depgraph-chips" role="group" aria-label="Layers">
          {LAYERS.filter((l) => graph.nodes.some((n) => n.layer === l.key)).map((l) => {
            const on = !hidden.has(l.key);
            const count = graph.nodes.filter((n) => n.layer === l.key).length;
            return (
              <button
                key={l.key}
                type="button"
                className={`depgraph-chip${on ? " on" : ""}`}
                aria-pressed={on}
                onClick={() => setHidden((h) => { const next = new Set(h); if (on) next.add(l.key); else next.delete(l.key); return next; })}
              >
                <i style={{ background: l.color }} />{l.label} <span>{count}</span>
              </button>
            );
          })}
        </div>
        {hasEdges && (
          <label className="depgraph-toggle">
            <input type="checkbox" checked={connectedOnly} onChange={(e) => setConnectedOnly(e.target.checked)} />
            connected only
          </label>
        )}
      </div>

      <div className="depgraph-stats">
        <span><b>{visibleNodes.length}</b> components shown</span>
        <span><b>{visibleEdges.length}</b> of {graph.edges.length} dependencies drawn</span>
        {hiddenUnconnected > 0 && <span>{hiddenUnconnected} with no recorded dependency hidden</span>}
        {graph.external > 0 && <span>{graph.external} edge ends are not BOM components</span>}
        {!hasEdges && <span className="warn">No dependency edges recorded in this BOM — components only.</span>}
      </div>

      {edgeTypes.length > 0 && (
        <div className="depgraph-legend">
          {edgeTypes.map((t) => <span key={t}><i style={{ background: edgeColor(t) }} />{t}</span>)}
        </div>
      )}

      <div className="depgraph-canvas">
        <svg viewBox={`0 0 ${WIDTH} ${height}`} width="100%" role="img"
          aria-label={`Dependency graph: ${visibleNodes.length} components, ${visibleEdges.length} dependencies`}
          style={{ minWidth: activeColumns.length * 190, display: "block" }}
          onMouseLeave={() => setHover(null)}>
          {activeColumns.map((l, ci) => (
            <g key={l.key}>
              <text x={ci * colWidth + 6} y={16} className="depgraph-colhead">
                {l.label.toUpperCase()} <tspan className="depgraph-colsub">· {l.short} · {columns.get(l.key)!.length}</tspan>
              </text>
              <line x1={ci * colWidth + 6} x2={ci * colWidth + 6 + boxWidth} y1={23} y2={23} stroke="var(--line)" />
            </g>
          ))}
          <g fill="none">
            {visibleEdges.map((e, i) => {
              const on = !focusSet || (focusSet.has(e.source) && focusSet.has(e.target) && (e.source === focus || e.target === focus));
              return (
                <path key={i} d={path(e)} stroke={edgeColor(e.type)}
                  strokeOpacity={focusSet ? (on ? 0.95 : 0.05) : 0.35}
                  strokeWidth={focusSet && on ? 1.8 : 1} />
              );
            })}
          </g>
          {activeColumns.map((l) => columns.get(l.key)!.map((n) => {
            const p = place.get(n.id)!;
            const dim = (focusSet && !focusSet.has(n.id)) || (q && !matches.has(n.id));
            const isSel = n.id === selected;
            const text = n.label.length > maxChars ? `${n.label.slice(0, maxChars - 1)}…` : n.label;
            return (
              <g key={n.id} transform={`translate(${p.x},${p.y})`} opacity={dim ? 0.25 : 1}
                style={{ cursor: "pointer" }}
                onMouseEnter={() => setHover(n.id)}
                onClick={() => setSelected(isSel ? null : n.id)}
                data-testid={`depnode-${n.id}`}>
                <title>{`${n.label}${n.sub ? ` · ${n.sub}` : ""} · ${n.degree} dependenc${n.degree === 1 ? "y" : "ies"}`}</title>
                <rect width={boxWidth} height={ROW - 4} rx={4}
                  fill={isSel ? "color-mix(in srgb, var(--accent) 22%, var(--panel-2))" : "var(--panel-2)"}
                  stroke={isSel || matches.has(n.id) ? "var(--accent)" : "var(--line)"} />
                <rect width={3} height={ROW - 4} rx={1.5} fill={l.color} />
                <text x={10} y={ROW / 2 + 2} className="depgraph-label">{text}</text>
                {n.degree > 0 && (
                  <text x={boxWidth - 6} y={ROW / 2 + 2} textAnchor="end" className="depgraph-degree">{n.degree}</text>
                )}
              </g>
            );
          }))}
        </svg>
      </div>

      {selectedNode && (
        <div className="depgraph-detail" aria-label="Selected component">
          <div className="depgraph-detail-head">
            <b>{selectedNode.label}</b>
            <span>{LAYERS.find((l) => l.key === selectedNode.layer)?.label}{selectedNode.sub ? ` · ${selectedNode.sub}` : ""}</span>
            <button type="button" className="btn ghost sm" onClick={() => setSelected(null)}>Clear</button>
          </div>
          <div className="depgraph-detail-cols">
            <div>
              <div className="kicker">Depends on · {outgoing.length}</div>
              {outgoing.length ? outgoing.map((e, i) => (
                <div key={i} className="depgraph-rel"><i style={{ background: edgeColor(e.type) }} />{nodeById.get(e.target)?.label} <span>{e.type}</span></div>
              )) : <div className="faint">nothing recorded</div>}
            </div>
            <div>
              <div className="kicker">Used by · {incoming.length}</div>
              {incoming.length ? incoming.map((e, i) => (
                <div key={i} className="depgraph-rel"><i style={{ background: edgeColor(e.type) }} />{nodeById.get(e.source)?.label} <span>{e.type}</span></div>
              )) : <div className="faint">nothing recorded</div>}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
