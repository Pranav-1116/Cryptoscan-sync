import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Panel, Badge, Kpi, Tabs } from "../components/ui.jsx";
import { useApi } from "../lib/apiUi.jsx";
import { useRealtime, isSystemEvent, type RealtimeState } from "../lib/realtime.js";
import {
  apiGraph,
  apiGraphStats,
  apiGraphBlastRadius,
  apiGraphDependents,
  apiGraphSimulate,
  apiGraphExplain,
  apiGraphMigrationPlan,
  apiGraphSnapshot,
  apiGraphTimeline,
  apiGraphCompare,
  apiGraphVendorChains,
  type MigrationPlanResult,
  type GraphTimeline,
  type GraphCompare,
  type GraphNode,
  type GraphEdge,
  type GraphStats,
  type BlastRadiusResult,
  type SimulateResult,
  type ExplainResult,
  type VendorChains,
  type VendorChain,
} from "../lib/api.js";

/* ZELNX Dependency Graph (flagship) — a CISO can start from any node and trace
   what depends on what. The backend produces the graph (GET /api/v1/graph) and
   the blast radius / trace / simulate / explain results; the frontend only
   renders it (it never discovers relationships). Honest empty state when the
   store is unprovisioned. */

const GROUP_TYPES: Record<string, { label: string; icon: string; color: string }> = {
  System:            { label: "Application", icon: "💻", color: "#3b82f6" },
  BusinessProcess:   { label: "Business",    icon: "🏢", color: "#8b5cf6" },
  BusinessOwner:     { label: "Owner",       icon: "🧑‍💼", color: "#8b5cf6" },
  Certificate:       { label: "Certificate", icon: "🔐", color: "#f59e0b" },
  CryptoAsset:       { label: "Crypto",      icon: "🧬", color: "#10b981" },
  CloudResource:     { label: "Cloud",       icon: "☁️", color: "#06b6d4" },
  Vendor:            { label: "Vendor",      icon: "🏭", color: "#64748b" },
  ComplianceScope:   { label: "Compliance",  icon: "📋", color: "#94a3b8" },
  NetworkResource:   { label: "Network",     icon: "🛰️", color: "#0ea5e9" },
  Algorithm:         { label: "Algorithm",   icon: "🧮", color: "#22c55e" },
  Key:               { label: "Key",         icon: "🗝️", color: "#f97316" },
};

const RISK_COLOR: Record<string, string> = {
  CRITICAL: "#ef4444", HIGH: "#ef4444", "TIER-1": "#ef4444",
  MEDIUM: "#f59e0b", LOW: "#10b981",
};
const PQC_COLOR: Record<string, string> = { vulnerable: "#ef4444", ready: "#10b981", unknown: "#94a3b8" };

function groupMeta(node: GraphNode) {
  return GROUP_TYPES[node.group] ?? { label: node.group, icon: "◈", color: "#64748b" };
}

function riskOf(node: GraphNode): string {
  const c = String(node.criticality || node.confidence || "").toUpperCase();
  if (["CRITICAL", "HIGH", "TIER-1", "TIER-1"].includes(c)) return "CRITICAL";
  if (c === "MEDIUM" || c === "MED") return "MEDIUM";
  if (node.group === "CryptoAsset" || c === "LOW") return "LOW";
  return "LOW";
}
function pqcOf(node: GraphNode): "vulnerable" | "ready" | "unknown" {
  const alg = String(node.algorithm || "").toUpperCase();
  if (/(RSA|ECDSA|DSA|DH|ED25519|X25519|P-256|P-384|P-521|KE$)/.test(alg)) return "vulnerable";
  if (/(ML-KEM|ML-DSA|KYBER|DILITHIUM|AES-256-GCM|SHA-3)/.test(alg)) return "ready";
  return "unknown";
}

export default function DependencyGraph() {
  // Live state: the SSE stream (backend-published, no simulated events) drives
  // refreshes; the graph/stats load once and refresh when the estate changes.
  const rt = useRealtime();
  const graph = useApi(() => apiGraph(), []);
  const stats = useApi(() => apiGraphStats(), []);
  const nodes = graph.data?.nodes ?? [];
  const edges = graph.data?.edges ?? [];
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [selKind, setSelKind] = useState<string[]>(Object.keys(GROUP_TYPES));
  const [overlay, setOverlay] = useState<"risk" | "pqc" | "none">("risk");
  const [layout, setLayout] = useState<"force" | "radial">("force");
  const [viewMode, setViewMode] = useState("All");
  const [vendorChains, setVendorChains] = useState<VendorChains | null>(null);
  const [zoom, setZoom] = useState(1);
  const [focus, setFocus] = useState<string | null>(null);
  const [tab, setTab] = useState(0);
  const [blast, setBlast] = useState<BlastRadiusResult | null>(null);
  const [sim, setSim] = useState<SimulateResult | null>(null);
  const [explain, setExplain] = useState<ExplainResult | null>(null);
  const [trace, setTrace] = useState<BlastRadiusResult | null>(null);
  const [running, setRunning] = useState<string | null>(null);
  const [timeline, setTimeline] = useState<GraphTimeline | null>(null);
  const [compare, setCompare] = useState<GraphCompare | null>(null);
  const [cmpFrom, setCmpFrom] = useState(0);
  const [cmpTo, setCmpTo] = useState(0);
  const [offset, setOffset] = useState({ x: 0, y: 0 });
  const [revealed, setRevealed] = useState<Set<string>>(new Set());   // nodes currently loaded into view
  const [expanded, setExpanded] = useState<Set<string>>(new Set());   // nodes whose neighbors are loaded
  const [initialized, setInitialized] = useState(false);
  const dragRef = useRef<{ x: number; y: number } | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  // For expand/collapse animation: remember the previously-rendered node ids so
  // we can apply a "pop-in" animation to nodes that are newly revealed and let
  // already-rendered nodes glide to their new layout positions.
  const prevRendered = useRef<Set<string>>(new Set());

  // filter: node-type checkboxes + view mode
  const visibleNodes = useMemo(() => nodes.filter((n) => {
    if (selKind.length && !selKind.includes(n.group)) return false;
    if (viewMode === "Crypto") return n.group === "CryptoAsset" || n.group === "System";
    if (viewMode === "Infrastructure") return n.group === "System" || n.group === "CloudResource" || n.group === "Certificate";
    if (viewMode === "Business") return n.group === "BusinessProcess" || n.group === "System";
    if (viewMode === "Cloud") return n.group === "CloudResource" || n.group === "System";
    if (viewMode === "Network") return n.group === "System" || n.group === "Vendor";
    return true;
  }), [nodes, selKind, viewMode]);
  const visibleEdges = useMemo(() => {
    const ids = new Set(visibleNodes.map((n) => n.id));
    return edges.filter((e) => ids.has(e.from) && ids.has(e.to));
  }, [edges, visibleNodes]);

  const visibleIdSet = useMemo(() => new Set(visibleNodes.map((n) => n.id)), [visibleNodes]);

  // neighbor adjacency (both directions) over the currently-filtered graph.
  const neighbors = useMemo(() => {
    const m = new Map<string, Set<string>>();
    for (const e of visibleEdges) {
      if (!m.has(e.from)) m.set(e.from, new Set());
      if (!m.has(e.to)) m.set(e.to, new Set());
      m.get(e.from)!.add(e.to);
      m.get(e.to)!.add(e.from);
    }
    return m;
  }, [visibleEdges]);

  // ── Level 0 roots: the "start anywhere" entry points. These are the business
  // ── services + the systems, so a CISO begins at a real anchor and lazily
  // ── expands inward (never painting 40k nodes at once).
  const roots = useMemo(
    () => visibleNodes.filter((n) => ["System", "BusinessProcess", "BusinessOwner"].includes(n.group)).map((n) => n.id),
    [visibleNodes]
  );
  useEffect(() => {
    if (!initialized && roots.length > 0) {
      setRevealed(new Set(roots));
      setInitialized(true);
    }
  }, [initialized, roots]);

  // Load the vendor → product → assets → crypto chains for the dedicated view,
  // only when that view is active (so the graph still loads fast by default).
  useEffect(() => {
    if (viewMode !== "VendorChain") return;
    let alive = true;
    apiGraphVendorChains()
      .then((res) => { if (alive && res.data) setVendorChains(res.data); })
      .catch(() => { /* offline: keep previous */ });
    return () => { alive = false; };
  }, [viewMode]);

  // ── Realtime: the graph/stats refresh when the backend changes. ──────────
  // While the SSE stream is live we refresh on real (non-system) events and
  // deliberately drop the polling interval; when SSE is unavailable (proxy that
  // buffers, signed-out, backend down) we fall back to a slow poll so the page
  // still reflects real state. Throttled so a burst of events never hammers the
  // API — at most one re-fetch run per REFRESH_THROTTLE_MS.
  const lastGraphRefresh = useRef(0);
  const refreshTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const REFRESH_THROTTLE_MS = 5000;
  const refreshGraph = useCallback(() => {
    const now = Date.now();
    if (now - lastGraphRefresh.current < REFRESH_THROTTLE_MS) return;
    lastGraphRefresh.current = now;
    if (refreshTimer.current) clearTimeout(refreshTimer.current);
    refreshTimer.current = setTimeout(() => {
      void graph.run();
      void stats.run();
    }, 200);
  }, [graph, stats]);

  // Slow poll safety net when not streaming (honest offline/fallback state).
  useEffect(() => {
    if (rt.connected) return;
    const t = setInterval(() => { void graph.run(); void stats.run(); }, 60000);
    return () => clearInterval(t);
  }, [rt.connected, graph, stats]);

  // Trigger a refresh whenever a real platform/monitor event lands on the bus.
  useEffect(() => {
    const last = rt.events[0];
    if (!last || !rt.connected) return;
    if (isSystemEvent(last.type)) return;
    refreshGraph();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rt.events, rt.connected]);

  const toggleExpand = (id: string) => {
    const nb = neighbors.get(id);
    if (!nb || nb.size === 0) return;
    if (expanded.has(id)) {
      // collapse: drop the neighbors this node loaded (keep nodes that are also
      // roots or that are loaded by another still-expanded parent).
      const nextExpanded = new Set(expanded); nextExpanded.delete(id);
      const keep = new Set<string>();
      for (const p of nextExpanded) for (const x of (neighbors.get(p) || [])) keep.add(x);
      for (const r of roots) keep.add(r);
      setRevealed(keep);
      setExpanded(nextExpanded);
    } else {
      const nextRevealed = new Set(revealed);
      nb.forEach((x) => nextRevealed.add(x));
      setRevealed(nextRevealed);
      setExpanded(new Set(expanded).add(id));
    }
  };

  // ── render only what has been lazily loaded (revealed) + their edges ──
  const renderedNodes = useMemo(
    () => visibleNodes.filter((n) => revealed.has(n.id)),
    [visibleNodes, revealed]
  );
  // Nodes that just entered the view (for the expand pop-in animation).
  const renderedIdSet = useMemo(() => new Set(renderedNodes.map((n) => n.id)), [renderedNodes]);
  const newIds = useMemo(() => {
    const s = new Set<string>();
    renderedIdSet.forEach((id) => { if (!prevRendered.current.has(id)) s.add(id); });
    return s;
  }, [renderedIdSet]);
  useEffect(() => { prevRendered.current = new Set(renderedIdSet); }, [renderedIdSet]);
  const renderedEdges = useMemo(() => {
    const ids = new Set(renderedNodes.map((n) => n.id));
    return visibleEdges.filter((e) => ids.has(e.from) && ids.has(e.to));
  }, [visibleEdges, renderedNodes]);
  const positions = useMemo(() => layoutNodes(renderedNodes, renderedEdges, layout), [renderedNodes, renderedEdges, layout]);
  // count of neighbours not yet revealed (for the expand badge)
  const hiddenCount = (id: string) => {
    const nb = neighbors.get(id); if (!nb) return 0;
    let c = 0; nb.forEach((x) => { if (!revealed.has(x) && visibleIdSet.has(x)) c++; }); return c;
  };
  const expandable = (id: string) => expanded.has(id) || hiddenCount(id) > 0;

  const select = (n: GraphNode) => {
    setSelected(n);
    setFocus(n.id);
    setTab(0);
    setBlast(null); setSim(null); setExplain(null); setTrace(null);
  };

  const rawId = (id: string) => id.split(":").pop() ?? id;

  const runBlast = async (n: GraphNode, dir: "down" | "up") => {
    setRunning(dir);
    setTab(dir === "down" ? 1 : 2);
    try {
      const res = dir === "down"
        ? await apiGraphBlastRadius(rawId(n.id), 6)
        : await apiGraphDependents(rawId(n.id), 6);
      if (res.data) { if (dir === "down") setBlast(res.data); else setTrace(res.data); }
    } catch { /* offline */ }
    setRunning(null);
  };
  const runSim = async (n: GraphNode) => {
    setRunning("sim"); setTab(4);
    const res = await apiGraphSimulate(rawId(n.id));
    if (res.data) setSim(res.data);
    setRunning(null);
  };
  const runExplain = async (n: GraphNode) => {
    setRunning("why"); setTab(3);
    const res = await apiGraphExplain(rawId(n.id));
    if (res.data) setExplain(res.data);
    setRunning(null);
  };

  const kindCounts = stats.data?.nodes_by_kind ?? {};

  return (
    <>
      <PageHead
        crumb="platform / dependency graph"
        title="ZELNX Dependency Graph"
        sub="Start from any node and trace what depends on what — impact, evidence, risk & PQC, from the backend knowledge graph"
        right={<Badge tone={graph.source === "live" ? "green" : "amber"}>{(stats.data?.nodes ?? 0)} nodes · {(stats.data?.edges ?? 0)} edges</Badge>}
      />

      {/* Controls bar */}
      <div className="toolbar" style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center", marginBottom: 10 }}>
        <span className="dim" style={{ fontSize: 12 }}>Layout</span>
        <select value={layout} onChange={(e) => setLayout(e.target.value as "force" | "radial")} className="inp">
          <option value="force">Force</option><option value="radial">Radial</option>
        </select>
        <span className="dim" style={{ fontSize: 12 }}>View</span>
        <select value={viewMode} onChange={(e) => setViewMode(e.target.value)} className="inp">
          {["All", "Crypto", "Infrastructure", "Cloud", "Network", "Business", "VendorChain"].map((v) => <option key={v} value={v}>{v === "VendorChain" ? "Vendor chain" : v}</option>)}
        </select>
        <span className="dim" style={{ fontSize: 12 }}>Overlay</span>
        {(["risk", "pqc", "none"] as const).map((o) => (
          <button key={o} className={`chip ${overlay === o ? "chip-on" : ""}`} onClick={() => setOverlay(o)}>{o.toUpperCase()}</button>
        ))}
        <span style={{ flex: 1 }} />
        <RealtimeBadge rt={rt} />
        <button className="btn" onClick={() => setZoom((z) => Math.max(0.5, z - 0.15))}>−</button>
        <button className="btn" onClick={() => setZoom((z) => Math.min(2.5, z + 0.15))}>+</button>
        <button className="btn" onClick={() => setZoom(1)}>⛶ reset</button>
      </div>

      <div className="grid" style={{ gridTemplateColumns: "240px 1fr 320px", gap: 12 }}>
        {/* LEFT: filters */}
        <Panel title="Graph filters" sub="node types · risk">
          <div className="mono-list">
            {Object.keys(GROUP_TYPES).map((k) => (
              <label key={k} className="spread" style={{ fontSize: 13, padding: "4px 0" }}>
                <span>
                  <input type="checkbox" checked={selKind.includes(k)}
                    onChange={() => setSelKind((v) => v.includes(k) ? v.filter((x) => x !== k) : [...v, k])} />{" "}
                  {GROUP_TYPES[k].icon} {GROUP_TYPES[k].label}
                </span>
                <span className="dim mono">{kindCounts[k] ?? 0}</span>
              </label>
            ))}
          </div>
          <div style={{ marginTop: 12 }}>
            <div className="dim" style={{ fontSize: 12, marginBottom: 6 }}>Legend / risk</div>
            {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((r) => (
              <div key={r} className="spread" style={{ fontSize: 12, padding: "2px 0" }}>
                <span><span className="dot" style={{ background: RISK_COLOR[r] }} /> {r}</span>
              </div>
            ))}
          </div>
          <div style={{ marginTop: 12 }}>
            <div className="dim" style={{ fontSize: 12, marginBottom: 6 }}>PQC</div>
            {["vulnerable", "ready", "unknown"].map((r) => (
              <div key={r} className="spread" style={{ fontSize: 12, padding: "2px 0" }}>
                <span><span className="dot" style={{ background: PQC_COLOR[r] }} /> {r}</span>
              </div>
            ))}
          </div>
        </Panel>

        {/* CENTER: canvas */}
        <Panel title="Graph canvas" sub={graph.source === "live" ? "backend-produced knowledge graph · click a node" : "backend offline"}>
          {nodes.length === 0 && (
            <div style={{ padding: "40px 16px", textAlign: "center" }}>
              <div style={{ fontSize: 34 }}>🗺️</div>
              <div style={{ fontSize: 15, marginTop: 8 }}>The dependency graph is empty</div>
              <div className="dim" style={{ fontSize: 13, marginTop: 6 }}>
                No systems / crypto assets have been discovered yet. Run a source scan or discovery to populate the graph.
              </div>
            </div>
          )}
          {viewMode === "VendorChain" && (
            <VendorChainView chains={vendorChains?.chains ?? []} loading={vendorChains === null} />
          )}
          {viewMode !== "VendorChain" && (
          <div style={{ position: "relative", border: "1px solid var(--line)", borderRadius: 8, overflow: "hidden" }}>
            <svg
              ref={svgRef}
              viewBox="0 0 900 560"
              style={{ width: "100%", height: "auto", background: "transparent", cursor: dragRef.current ? "grabbing" : "grab" }}
              onMouseDown={(e) => { dragRef.current = { x: e.clientX, y: e.clientY }; }}
              onMouseUp={() => { dragRef.current = null; }}
              onMouseMove={(e) => {
                if (!dragRef.current) return;
                const dx = e.clientX - dragRef.current.x, dy = e.clientY - dragRef.current.y;
                dragRef.current = { x: e.clientX, y: e.clientY };
                setOffset((o) => ({ x: o.x + dx, y: o.y + dy }));
              }}
            >
              <style>{`
                .g-node { transition: transform .55s cubic-bezier(.22,1,.36,1); }
                .g-pop { transform-origin: center; transform-box: fill-box; animation: gNodePop .5s cubic-bezier(.22,1,.36,1) both; }
                @keyframes gNodePop {
                  0% { opacity: 0; transform: scale(0); }
                  55% { opacity: 1; }
                  100% { opacity: 1; transform: scale(1); }
                }
                .g-edge { transition: opacity .35s ease; }
              `}</style>
              <g transform={`translate(${450 + offset.x} ${280 + offset.y}) scale(${zoom})`}>
                {renderedEdges.map((e, i) => {
                  const p = positions.get(e.from), q = positions.get(e.to);
                  if (!p || !q) return null;
                  return (
                    <line key={i} className="g-edge" x1={p.x} y1={p.y} x2={q.x} y2={q.y}
                      stroke="var(--line)" strokeWidth={1.3} strokeDasharray={focus && (focus === e.from || focus === e.to) ? "0" : "3 3"}
                      opacity={focus && (focus === e.from || focus === e.to) ? 0.9 : 0.35} />
                  );
                })}
                {renderedNodes.map((n) => {
                  const p = positions.get(n.id);
                  if (!p) return null;
                  const meta = groupMeta(n);
                  const fill = overlay === "risk" ? RISK_COLOR[riskOf(n)] : overlay === "pqc" ? PQC_COLOR[pqcOf(n)] : meta.color;
                  const isSel = selected?.id === n.id;
                  const r = n.group === "System" ? 18 : 12;
                  const hc = hiddenCount(n.id);
                  const isExpanded = expanded.has(n.id);
                  // CSS transform (not the attribute) so the node *glides* when
                  // the layout re-settles on expand/collapse; new nodes pop in.
                  const delay = newIds.has(n.id) ? `${Math.min((renderedNodes.indexOf(n) % 24) * 35, 640)}ms` : "0ms";
                  return (
                    <g key={n.id}
                      className="g-node"
                      style={{ transform: `translate(${p.x}px, ${p.y}px)`, cursor: "pointer" }}>
                      <g className={newIds.has(n.id) ? "g-pop" : undefined} style={{ animationDelay: delay }}>
                        <circle r={r + (isSel ? 5 : 0)} fill={fill} stroke={isSel ? "#fff" : "transparent"} strokeWidth={isSel ? 2.5 : 0} opacity={0.92}
                          onClick={() => select(n)} />
                        <text y={r + 13} textAnchor="middle" fontSize={10.5} fill="var(--text)">{friendly(n) ? truncate(friendly(n), 16) : ""}</text>
                        <title>{`${groupMeta(n).label} · ${n.label}${n.algorithm ? ` · ${n.algorithm}` : ""}${n.confidence ? ` · ${n.confidence}` : ""}${hc ? `\n${hc} hidden neighbours — click ⊕ to expand` : ""}`}</title>
                        {expandable(n.id) && (
                          <g transform={`translate(${r + 2} ${-r - 2})`} onClick={(e) => { e.stopPropagation(); toggleExpand(n.id); }} style={{ cursor: "pointer" }}>
                            <circle r={8} fill={isExpanded ? "var(--line)" : "#fff"} stroke="var(--line)" strokeWidth={1} />
                            <text textAnchor="middle" dy={3} fontSize={10} fill={isExpanded ? "var(--bg)" : "var(--text)"} style={{ userSelect: "none" }}>
                              {isExpanded ? "−" : `+${hc > 0 ? hc : ""}`}
                            </text>
                          </g>
                        )}
                      </g>
                    </g>
                  );
                })}
              </g>
              {nodes.length > 0 && (
                <div style={{ position: "absolute", top: 8, left: 10, fontSize: 11.5 }} className="dim">
                  {renderedNodes.length} of {nodes.length} nodes loaded (lazy) · ⊕ expands neighbours · drag to pan · +/− to zoom
                </div>
              )}
            </svg>
          </div>
          )}
          <LiveActivity rt={rt} />
        </Panel>

        {/* RIGHT: details */}
        <Panel title={selected ? "Node details" : "Node details"} sub={selected ? groupMeta(selected).label : "click a node to inspect"}>
          {!selected && <div className="dim" style={{ fontSize: 13 }}>Select a node to see its dependencies, evidence, risk and PQC status.</div>}
          {selected && (
            <>
              <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 4 }}>{groupMeta(selected).icon} {selected.name || selected.algorithm || truncate(selected.label, 40)}</div>
              <div className="mono-list">
                <Row k="type" v={<Badge tone="cyan">{groupMeta(selected).label}</Badge>} />
                {selected.algorithm && <Row k="algorithm" v={<span className="mono">{selected.algorithm}</span>} />}
                {selected.confidence && <Row k="confidence" v={<Badge tone={selected.confidence === "HIGH" ? "green" : "amber"}>{selected.confidence}</Badge>} />}
                {selected.criticality && <Row k="criticality" v={<Badge tone="red">{selected.criticality}</Badge>} />}
                {selected.environment && <Row k="environment" v={selected.environment} />}
                {selected.owner && <Row k="owner" v={selected.owner} />}
                {selected.purpose && <Row k="purpose" v={selected.purpose} />}
                {selected.subject && selected.subject !== selected.name && <Row k="subject" v={truncate(String(selected.subject), 30)} />}
                {selected.issuer && <Row k="issuer" v={truncate(String(selected.issuer), 30)} />}
                {selected.expiry_status && <Row k="expiry" v={<Badge tone={selected.expiry_status === "EXPIRED" ? "red" : selected.expiry_status === "NOT_YET_VALID" ? "amber" : "green"}>{String(selected.expiry_status)}</Badge>} />}
                {selected.days_until_expiry != null && <Row k="days to expiry" v={selected.days_until_expiry} />}
                {selected.file_path && <Row k="file" v={<span className="mono" style={{ fontSize: 11 }}>{truncate(String(selected.file_path), 28)}</span>} />}
                <Row k="risk" v={<Badge tone={riskOf(selected) === "CRITICAL" ? "red" : riskOf(selected) === "MEDIUM" ? "amber" : "green"}>{riskOf(selected)}</Badge>} />
                <Row k="pqc" v={<Badge tone={pqcOf(selected) === "vulnerable" ? "red" : pqcOf(selected) === "ready" ? "green" : "amber"}>{pqcOf(selected)}</Badge>} />
              </div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 10 }}>
                <button className="btn" onClick={() => select(selected)} disabled={running !== null}>⨯</button>
                <button className="btn" onClick={() => void runBlast(selected, "down")} disabled={running !== null}>Blast Radius ↓</button>
                <button className="btn" onClick={() => void runBlast(selected, "up")} disabled={running !== null}>Trace ↑</button>
                <button className="btn" onClick={() => void runExplain(selected)} disabled={running !== null}>Why risky?</button>
                <button className="btn" onClick={() => void runSim(selected)} disabled={running !== null}>Simulate Change</button>
              </div>

              <Tabs tabs={["Details", "Blast radius", "Trace", "Why risky", "Simulate", "Versions"]} active={tab} onChange={setTab} />
              <div style={{ marginTop: 10 }}>
                {tab === 0 && <ProofPanel selected={selected} />}
                {tab === 1 && <ResultList title="Blast radius (downstream)" rows={blast?.systems ?? []} note={blast ? `${blast.nodes_visited} nodes visited` : "run blast radius"} />}
                {tab === 2 && <ResultList title="Dependents / trace (upstream)" rows={trace?.systems ?? []} note={trace ? `${trace.nodes_visited} nodes visited` : "run trace"} />}
                {tab === 3 && <ExplainPanel explain={explain} />}
                {tab === 4 && <SimulatePanel sim={sim} nodeId={selected ? rawId(selected.id) : undefined} />}
                {tab === 5 && (
                  <VersionsPanel
                    timeline={timeline}
                    compare={compare}
                    from={cmpFrom} to={cmpTo}
                    onFrom={setCmpFrom} onTo={setCmpTo}
                    onSnapshot={async () => { setRunning("snap"); const r = await apiGraphSnapshot(); const t = await apiGraphTimeline(); setTimeline(t.data); setRunning(null); return r; }}
                    onCompare={async (f, t2) => { setCompare(null); const r = await apiGraphCompare(f, t2); setCompare(r.data); }}
                    refreshing={running === "snap"}
                  />
                )}
              </div>
            </>
          )}
        </Panel>
      </div>
    </>
  );
}

/* ── tiny force / radial layout (no external lib, deterministic) ── */
function layoutNodes(nodes: GraphNode[], edges: GraphEdge[], mode: "force" | "radial") {
  const W = 900, H = 560;
  const pos = new Map<string, { x: number; y: number }>();
  if (mode === "radial" || nodes.length === 0) {
    const groups = [...new Set(nodes.map((n) => n.group))];
    nodes.forEach((n, i) => {
      const gi = Math.max(0, groups.indexOf(n.group));
      const a = (2 * Math.PI * i) / Math.max(1, nodes.length);
      const r = Math.min(W, H) * (0.28 + gi * 0.12);
      pos.set(n.id, { x: W / 2 + r * Math.cos(a), y: H / 2 + r * Math.sin(a) });
    });
    return pos;
  }
  // force: init on a circle
  nodes.forEach((n, i) => {
    const a = (2 * Math.PI * i) / Math.max(1, nodes.length);
    const r = Math.min(W, H) * 0.32;
    pos.set(n.id, { x: W / 2 + r * Math.cos(a), y: H / 2 + r * Math.sin(a) });
  });
  for (let iter = 0; iter < 140; iter++) {
    const arr = [...pos.entries()];
    for (let a = 0; a < arr.length; a++) {
      for (let b = a + 1; b < arr.length; b++) {
        const p = arr[a][1], q = arr[b][1];
        let dx = p.x - q.x, dy = p.y - q.y;
        const d2 = dx * dx + dy * dy || 1;
        if (d2 < 42000) { const f = 9000 / d2; dx *= f; dy *= f; p.x += dx; p.y += dy; q.x -= dx; q.y -= dy; }
      }
    }
    for (const e of edges) {
      const p = pos.get(e.from), q = pos.get(e.to);
      if (!p || !q) continue;
      let dx = q.x - p.x, dy = q.y - p.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 1;
      const target = 120, f = (d - target) * 0.05;
      dx /= d; dy /= d;
      p.x += dx * f; p.y += dy * f; q.x -= dx * f; q.y -= dy * f;
    }
    for (const p of pos.values()) { p.x += (W / 2 - p.x) * 0.02; p.y += (H / 2 - p.y) * 0.02; }
  }
  return pos;
}

function PageHead({ crumb, title, sub, right }: { crumb: string; title: string; sub?: string; right?: React.ReactNode }) {
  return (
    <div className="pageHead" style={{ marginBottom: 14 }}>
      <div>
        <div className="dim" style={{ fontSize: 12 }}>{crumb}</div>
        <h1 style={{ margin: "2px 0", fontSize: 22, fontWeight: 800 }}>{title}</h1>
        {sub && <div className="dim" style={{ fontSize: 13 }}>{sub}</div>}
      </div>
      {right && <div style={{ alignSelf: "center" }}>{right}</div>}
    </div>
  );
}

function ResultList({ title, rows, note }: { title: string; rows: { id: string; name?: string; criticality?: string | null; hops: number }[]; note: string }) {
  return (
    <div>
      <div className="spread"><span style={{ fontSize: 13 }}>{title}</span><span className="dim mono" style={{ fontSize: 11 }}>{note}</span></div>
      {rows.length === 0 && <div className="dim" style={{ fontSize: 12, marginTop: 6 }}>No nodes in this region.</div>}
      {rows.length > 0 && (
        <div className="mono-list" style={{ marginTop: 6 }}>
          {rows.map((r) => (
            <Row key={r.id} k={`${"·".repeat(Math.max(1, r.hops))} ${r.name || truncate(r.id, 12)}`} v={<Badge tone={r.criticality === "TIER-1" || r.criticality === "CRITICAL" ? "red" : "amber"}>{r.hops}</Badge>} />
          ))}
        </div>
      )}
    </div>
  );
}

function ProofPanel({ selected }: { selected: GraphNode }) {
  const evidence = String((selected.extra as Record<string, unknown> | undefined)?.detection ?? "");
  const band = String((selected.extra as Record<string, unknown> | undefined)?.band ?? "");
  return (
    <div>
      <div className="mono-list">
        <Row k="confidence" v={selected.confidence ?? "—"} />
        {band && <Row k="band" v={band} />}
      </div>
      <div className="dim" style={{ fontSize: 12, marginTop: 8 }}>Evidence</div>
      <div style={{ fontSize: 12.5, marginTop: 4 }}>
        {evidence ? evidence : <span className="dim">No scanned evidence attached to this node yet.</span>}
      </div>
      {selected.algorithm && (
        <>
          <div className="dim" style={{ fontSize: 12, marginTop: 10 }}>Relationship evidence</div>
          <div style={{ fontSize: 12.5, marginTop: 4 }}>
            {selected.algorithm} — detected by the crypto scanner · confidence {selected.confidence ?? "unknown"}.
          </div>
        </>
      )}
    </div>
  );
}

function ExplainPanel({ explain }: { explain: ExplainResult | null }) {
  if (!explain) return <div className="dim" style={{ fontSize: 12.5 }}>Run "Why risky?" to see the evidence-backed chain.</div>;
  return (
    <div>
      <div className="spread" style={{ fontSize: 13 }}>
        <span>{explain.title}</span>
        <Badge tone={explain.quantum_vulnerable ? "red" : "green"}>{explain.quantum_vulnerable ? "Q-VULNERABLE" : "PQC OK"}</Badge>
      </div>
      <div className="step-list" style={{ marginTop: 8, borderLeft: "2px solid var(--line)", paddingLeft: 12 }}>
        {explain.steps.map((s, i) => (
          <div key={i} style={{ marginBottom: 8, fontSize: 12.5 }}>
            <div><b>{s.label}</b> <span className="dim">· {s.kind}</span></div>
            {s.detail && <div className="dim">{s.detail}</div>}
            {s.evidence && <div className="mono" style={{ fontSize: 11, opacity: 0.7 }}>evidence: {truncate(s.evidence, 90)}</div>}
          </div>
        ))}
      </div>
    </div>
  );
}

function SimulatePanel({ sim, nodeId }: { sim: SimulateResult | null; nodeId?: string }) {
  const [plan, setPlan] = useState<MigrationPlanResult | null>(null);
  const [sending, setSending] = useState(false);
  if (!sim) return <div className="dim" style={{ fontSize: 12.5 }}>Run "Simulate Change" to see what breaks / needs migration.</div>;
  const send = async () => {
    if (!nodeId) return;
    setSending(true);
    const res = await apiGraphMigrationPlan(nodeId, sim.change);
    if (res.data) setPlan(res.data);
    setSending(false);
  };
  return (
    <div>
      <div className="kpi-strip" style={{ marginTop: 6 }}>
        <Kpi k="assets" v={sim.affected.assets} tone={sim.affected.assets ? "red" : "green"} />
        <Kpi k="applications" v={sim.affected.applications} tone={sim.affected.applications ? "amber" : "green"} />
        <Kpi k="certificates" v={sim.affected.certificates} tone={sim.affected.certificates ? "red" : "green"} />
        <Kpi k="services" v={sim.affected.services} tone={sim.affected.services ? "amber" : "green"} />
      </div>
      <div style={{ marginTop: 10 }}>
        <div className="spread" style={{ fontSize: 13 }}><span>Migration tasks</span><span className="mono">{sim.migration_tasks}</span></div>
        <div className="spread" style={{ fontSize: 13 }}><span>Compatibility issues</span><span className="mono">{sim.compatibility_issues}</span></div>
        <div className="spread" style={{ fontSize: 13 }}><span>Revenue at risk</span><span className="mono">{sim.total_revenue_at_risk}</span></div>
      </div>
      {sim.systems.length > 0 && (
        <div style={{ marginTop: 8 }}>
          <div className="dim" style={{ fontSize: 12 }}>Affected systems</div>
          {sim.systems.map((s) => <Row key={s.id} k={s.name || truncate(s.id, 12)} v={<span className="mono">{s.crypto_assets} crypto</span>} />)}
        </div>
      )}
      <div style={{ marginTop: 10 }}>
        {!plan && (
          <button className="btn" onClick={() => void send()} disabled={sending}>
            {sending ? "Creating migration plan…" : "Send to migration plan"}
          </button>
        )}
        {plan && (
          <div className="mono-list">
            <Row k="project" v={<span className="mono">{plan.project_id ? truncate(plan.project_id, 12) : "—"}</span>} />
            <Row k="tasks" v={plan.tasks_created} />
            <Row k="status" v={<Badge tone={plan.created ? "green" : "amber"}>{plan.created ? "created" : "no changes"}</Badge>} />
          </div>
        )}
      </div>
    </div>
  );
}

function VersionsPanel({ timeline, compare, from, to, onFrom, onTo, onSnapshot, onCompare, refreshing }: {
  timeline: GraphTimeline | null; compare: GraphCompare | null;
  from: number; to: number; onFrom: (n: number) => void; onTo: (n: number) => void;
  onSnapshot: () => Promise<unknown>; onCompare: (f: number, t: number) => Promise<void>; refreshing: boolean;
}) {
  const versions = timeline?.versions ?? [];
  const latest = timeline?.latest_version ?? 0;
  useEffect(() => {
    // auto-select the two newest versions when the timeline loads.
    if (versions.length >= 2) { onTo(versions[0].version); onFrom(versions[1].version); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [timeline?.total_count]);
  return (
    <div>
      <div className="spread">
        <span style={{ fontSize: 13 }}>Graph versions</span>
        <button className="btn" onClick={() => void onSnapshot()} disabled={refreshing}>{refreshing ? "snapshotting…" : "Snapshot graph"}</button>
      </div>
      <div className="dim" style={{ fontSize: 12, marginTop: 4 }}>
        Content-addressed snapshots of the real graph. A new version is recorded only when the state changes.
      </div>
      {timeline !== null && versions.length === 0 && (
        <div className="dim" style={{ fontSize: 12.5, marginTop: 8 }}>No versions yet — press "Snapshot graph".</div>
      )}
      {versions.length > 0 && (
        <div className="mono-list" style={{ marginTop: 8 }}>
          {versions.map((v) => (
            <Row key={v.version} k={`v${v.version}`}
              v={<span className="mono" style={{ fontSize: 11 }}>{v.node_count} nodes · {v.edge_count} edges{v.new_quantum_vulnerable?.length ? ` · ⚠ ${v.new_quantum_vulnerable.length} QV` : ""}</span>} />
          ))}
        </div>
      )}
      {versions.length >= 2 && (
        <>
          <div style={{ display: "flex", gap: 6, marginTop: 10 }}>
            <select value={from} onChange={(e) => onFrom(Number(e.target.value))} className="inp">
              {versions.map((v) => <option key={v.version} value={v.version}>v{v.version}</option>)}
            </select>
            <span className="dim" style={{ alignSelf: "center" }}>→</span>
            <select value={to} onChange={(e) => onTo(Number(e.target.value))} className="inp">
              {versions.map((v) => <option key={v.version} value={v.version}>v{v.version}</option>)}
            </select>
            <button className="btn" onClick={() => void onCompare(from, to)}>Compare</button>
          </div>
          {compare && <CompareView compare={compare} />}
        </>
      )}
    </div>
  );
}

function CompareView({ compare }: { compare: GraphCompare }) {
  const change = (n: number) => n > 0 ? <Badge tone="red">{`+${n}`}</Badge> : n < 0 ? <Badge tone="green">{n}</Badge> : <span className="mono dim">0</span>;
  return (
    <div style={{ marginTop: 10 }}>
      <div className="spread" style={{ fontSize: 12.5 }}><span>{`v${compare.from.version} (${compare.from.node_count} nodes) → v${compare.to.version} (${compare.to.node_count} nodes)`}</span></div>
      <div className="mono-list" style={{ marginTop: 4 }}>
        <Row k="nodes added / removed" v={<span>{change(compare.added_nodes.length)} / {change(-compare.removed_nodes.length)}</span>} />
        <Row k="relationships added / removed" v={<span>{change(compare.added_edges.length)} / {change(-compare.removed_edges.length)}</span>} />
        {compare.new_quantum_vulnerable?.length > 0 && (
          <Row k="new quantum-vulnerable" v={<Badge tone="red">{compare.new_quantum_vulnerable.length}</Badge>} />
        )}
      </div>
      {compare.added_nodes.length > 0 && (
        <>
          <div className="dim" style={{ fontSize: 12, marginTop: 8 }}>New nodes</div>
          <div className="mono-list">
            {compare.added_nodes.slice(0, 12).map((n) => (
              <Row key={n.id} k={truncate(String(n.kind || ""), 14)} v={<span className="mono" style={{ fontSize: 11 }}>{n.algorithm || truncate(n.id.split(":").pop() || n.id, 12)}</span>} />
            ))}
          </div>
        </>
      )}
      <button className="btn" style={{ marginTop: 8 }} disabled>Open v{compare.to.version} in canvas</button>
    </div>
  );
}

/* ── Realtime connection indicator + live event activity ── */
function timeAgo(iso: string): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "";
  const s = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  return `${Math.floor(m / 60)}h ago`;
}

function RealtimeBadge({ rt }: { rt: RealtimeState }) {
  const last = rt.events.find((e) => !isSystemEvent(e.type));
  const tone = rt.connected ? "green" : rt.backend === false ? "red" : "amber";
  const label = rt.connected
    ? `SSE live · ${rt.subscribers} sub${rt.eps ? ` · ${rt.eps} ev/s` : ""}${last ? ` · ${last.type} ${timeAgo(last.ts)}` : ""}`
    : rt.backend === false ? "backend offline"
    : "SSE offline (polling fallback)";
  return <Badge tone={tone}>{label}</Badge>;
}

function LiveActivity({ rt }: { rt: RealtimeState }) {
  const activity = rt.events.filter((e) => !isSystemEvent(e.type)).slice(0, 6);
  if (activity.length === 0) {
    if (!rt.connected) {
      return (
        <div className="dim" style={{ fontSize: 11.5, padding: "8px 10px", borderTop: "1px solid var(--line)" }}>
          No live events — connect via SSE to see platform + monitor activity here.
        </div>
      );
    }
    return (
      <div className="dim" style={{ fontSize: 11.5, padding: "8px 10px", borderTop: "1px solid var(--line)" }}>
        ● Connected — waiting for the next platform / monitor event.
      </div>
    );
  }
  return (
    <div style={{ borderTop: "1px solid var(--line)", padding: "6px 10px" }}>
      <div className="dim" style={{ fontSize: 11, marginBottom: 4 }}>Live activity (SSE)</div>
      {activity.map((e) => (
        <div key={e.id} className="spread" style={{ fontSize: 11.5, padding: "2px 0" }}>
          <span className="mono dim">{e.type}</span>
          <span className="dim">{timeAgo(e.ts)}</span>
        </div>
      ))}
    </div>
  );
}

/* ── Dedicated vendor → product → assets → crypto path view ── */
function VendorChainView({ chains, loading }: { chains: VendorChain[]; loading: boolean }) {
  if (loading) return <div className="dim" style={{ padding: "40px 16px", textAlign: "center" }}>Loading vendor chains…</div>;
  if (chains.length === 0) {
    return (
      <div style={{ padding: "40px 16px", textAlign: "center" }}>
        <div style={{ fontSize: 34 }}>🏭</div>
        <div style={{ fontSize: 15, marginTop: 8 }}>No vendor chains yet</div>
        <div className="dim" style={{ fontSize: 13, marginTop: 6 }}>
          Vendors appear here once a system depends on a real library. Run a source scan to populate vendor dependents.
        </div>
      </div>
    );
  }
  return (
    <div className="vendor-chain" style={{ maxHeight: 560, overflow: "auto", padding: "6px 2px" }}>
      {chains.map((c) => (
        <div key={c.vendor?.id ?? c.start} className="vc-vendor" style={{ marginBottom: 12, border: "1px solid var(--line)", borderRadius: 8, padding: "10px 12px" }}>
          <div className="spread">
            <span style={{ fontSize: 14, fontWeight: 700 }}>
              <span style={{ color: GROUP_TYPES.Vendor.color }}>🏭</span> {c.vendor?.name || c.start}
            </span>
            <Badge tone={c.total_assets ? "amber" : "green"}>{c.total_assets} assets</Badge>
          </div>
          <div className="dim" style={{ fontSize: 11.5, margin: "2px 0 8px" }}>
            product · {c.product || "—"} → {" "}
            {c.count} {c.count === 1 ? "system" : "systems"} · {c.systems.reduce((n, s) => n + s.asset_count, 0)} crypto findings
          </div>
          <div style={{ marginLeft: 8, borderLeft: "2px solid var(--line)", paddingLeft: 10 }}>
            {c.systems.length === 0 && <div className="dim" style={{ fontSize: 12 }}>No system depends on this vendor.</div>}
            {c.systems.map((sys) => (
              <div key={sys.id} style={{ marginBottom: 8 }}>
                <div className="spread">
                  <span style={{ fontSize: 12.5, fontWeight: 600 }}>💻 {sys.name || sys.id}</span>
                  <span className="mono dim" style={{ fontSize: 11 }}>{sys.criticality || ""} · {sys.asset_count} crypto</span>
                </div>
                {sys.processes.length > 0 && (
                  <div className="dim" style={{ fontSize: 11.5, margin: "2px 0 4px" }}>
                    🏢 supports {sys.processes.map((p) => p.id).join(", ")}
                  </div>
                )}
                {sys.assets.length === 0 && <div className="dim" style={{ fontSize: 12 }}>No detected crypto in this system.</div>}
                {sys.assets.length > 0 && (
                  <div className="mono-list" style={{ marginTop: 4 }}>
                    {sys.assets.slice(0, 12).map((a) => (
                      <Row
                        key={a.id}
                        k={a.algorithm || truncate(a.id, 12)}
                        v={
                          <span style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
                            <span className="dim" style={{ fontSize: 11 }}>{a.purpose || truncate(a.file_path || "", 14)}</span>
                            {a.risk === "vulnerable" ? <Badge tone="red">Q-V</Badge> : a.risk === "ready" ? <Badge tone="green">PQC</Badge> : null}
                          </span>
                        }
                      />
                    ))}
                    {sys.assets.length > 12 && <div className="dim" style={{ fontSize: 11, padding: "3px 0" }}>+ {sys.assets.length - 12} more…</div>}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="spread" style={{ fontSize: 12.5, padding: "5px 0", borderBottom: "1px solid var(--line)" }}>
      <span className="dim">{k}</span><span style={{ textAlign: "right" }}>{v}</span>
    </div>
  );
}

function friendly(n: GraphNode): string {
  return n.name || n.subject || n.algorithm || (n.label && n.label !== n.id ? n.label : "");
}
function truncate(s: string, n: number): string { return s.length > n ? s.slice(0, n - 1) + "…" : s; }
