import { Link } from "react-router-dom";
import React, { useEffect, useMemo, useState } from "react";
import { Panel, Badge, Table, PageHead, Code } from "../components/ui.jsx";
import { apiBlast, LiveBadge, ApiResult } from "../lib/api.js";
import { useLive, LiveStatus } from "../lib/useLive.js";
import { motion } from "framer-motion";
import { EASE, useMotionOK } from "../lib/motion";

/* Dependency graph (spec §17) — renders the REAL crypto dependency graph from
   the control plane (/graph). Nodes/edges are auto-laid-out in a circle; a
   node is empty until discovery/scan builds the CBOM graph. Click a node to
   compute its blast radius from the live engine. */

interface RawNode { id: string; label?: string; name?: string; group?: string; kind?: string; [k: string]: unknown; }
interface RawEdge { from?: string; to?: string; source?: string; target?: string; label?: string; relationship?: string; }

interface GNode { id: string; label: string; sub: string; x: number; y: number; kind: string; }

const KIND_TONE: Record<string, string> = {
  system: "violet", cert: "cyan", certificate: "green", infra: "blue", network: "blue",
  cloud: "cyan", app: "violet", application: "violet", process: "violet",
  lib: "cyan", library: "cyan", algo: "red", algorithm: "red", vendor: "slate", owner: "green",
  hardware: "orange", risk: "red",
};

/* Node stroke colors per spec graph key (kept dark/subtle on navy). */
const KIND_COLOR: Record<string, string> = {
  network: "var(--accent)", infra: "var(--accent)",
  cloud: "var(--accent)",
  app: "var(--violet)", application: "var(--violet)", process: "var(--violet)",
  crypto: "var(--accent)",
  cert: "var(--green)", certificate: "var(--green)",
  hardware: "var(--orange)",
  algo: "var(--red)", algorithm: "var(--red)",
  // Libraries were amber. In this design system amber means "warning /
  // medium risk" and nothing else, so a library node was telling the
  // operator something was wrong with it when the colour only meant
  // "this is a library". Node *type* is not a status, so it does not get
  // to spend a status colour: libraries now share the cryptography
  // family, which is what they are -- the code that performs the crypto.
  lib: "var(--accent)", library: "var(--accent)",
  risk: "var(--red)",
  vendor: "var(--slate)", owner: "var(--text)", system: "var(--text)",
};
const graphColor = (kind: string) => KIND_COLOR[String(kind).toLowerCase()] ?? "var(--line-strong)";

function layout(nodes: RawNode[]): GNode[] {
  const cx = 400, cy = 190, r = nodes.length > 1 ? 145 : 40;
  return nodes.map((n, i) => {
    const ang = (i / Math.max(1, nodes.length)) * Math.PI * 2 - Math.PI / 2;
    return {
      id: n.id,
      label: n.label ?? n.name ?? n.id,
      sub: String(n.group ?? n.kind ?? ""),
      kind: String(n.group ?? n.kind ?? "app"),
      x: nodes.length === 1 ? cx : cx + r * Math.cos(ang),
      y: nodes.length === 1 ? cy : cy + r * Math.sin(ang) * 0.7,
    };
  });
}

export default function Graph() {
  const graph = useLive<{ nodes: RawNode[]; edges: RawEdge[]; backend?: string }>("/api/v1/graph", { nodes: [], edges: [] });
  const stats = useLive<any>("/api/v1/graph/stats", {});
  const [sel, setSel] = useState<string | null>(null);
  const [zoom, setZoom] = useState(1);
  const motionOK = useMotionOK();
  const [live, setLive] = useState<ApiResult<Record<string, unknown>> | null>(null);
  const [busy, setBusy] = useState(false);

  const NODES = useMemo(() => layout(graph.data.nodes ?? []), [graph.data.nodes]);
  const EDGES: { from: string; to: string }[] = useMemo(
    () => (graph.data.edges ?? []).map((e) => ({ from: e.from ?? e.source ?? "", to: e.to ?? e.target ?? "" })).filter((e) => e.from && e.to),
    [graph.data.edges]
  );

  const byId = useMemo(() => new Map(NODES.map((n) => [n.id, n])), [NODES]);

  const descendants = (from: string) => {
    const out = new Set<string>();
    const walk = (id: string) => EDGES.filter((e) => e.from === id).forEach((e) => { if (!out.has(e.to)) { out.add(e.to); walk(e.to); } });
    walk(from); return out;
  };
  const ancestors = (from: string) => {
    const out = new Set<string>();
    const walk = (id: string) => EDGES.filter((e) => e.to === id).forEach((e) => { if (!out.has(e.from)) { out.add(e.from); walk(e.from); } });
    walk(from); return out;
  };

  const blast = sel ? descendants(sel) : new Set<string>();
  const upline = sel ? ancestors(sel) : new Set<string>();

  const runLiveBlast = async () => {
    if (!sel) return;
    setBusy(true);
    const seed = byId.get(sel)?.label ?? sel;
    setLive(await apiBlast(seed, 10));
    setBusy(false);
  };
  useEffect(() => { if (sel) void runLiveBlast(); /* eslint-disable-next-line */ }, [sel]);

  const selNode = sel ? byId.get(sel) : null;
  const statCounts = stats.data ?? {};

  return (
    <>
      <PageHead
        crumb="boms / dependency graph"
        title="Dependency graph"
        sub="Systems → certificates → infrastructure → applications → libraries → algorithms. Click a node for its live blast radius."
        right={
          <div className="row">
            {sel ? <Badge tone="amber">{blast.size} NODES IN BLAST RADIUS</Badge> : <Badge tone="cyan">{NODES.length} NODES</Badge>}
            <LiveStatus loading={graph.loading} error={graph.error} />
          </div>
        }
      />

      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        {[["nodes", statCounts.nodes ?? NODES.length, "cyan"], ["edges", statCounts.edges ?? EDGES.length, "cyan"],
          ["systems", statCounts.systems ?? 0, "green"], ["orphan systems", statCounts.orphan_system_count ?? 0, (statCounts.orphan_system_count ?? 0) ? "amber" : "green"]]
          .map(([k, v, tone]) => (
            <div className="kpi" key={k as string}><span className="k">{k}</span><span className="v" style={{ color: `var(--${tone})` }}>{v}</span></div>
          ))}
      </div>

      {live?.data && (
        <Panel title="Blast radius — engine response" sub={`seed: ${selNode?.label ?? sel}`} className="mt">
          <Code>{JSON.stringify(live.data, null, 2)}</Code>
        </Panel>
      )}

      <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8, flexWrap: "wrap" }}>
        <div style={{ display: "flex", gap: 6, alignItems: "center", padding: "6px 10px", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>
          <span style={{ fontSize: 10, color: "var(--dim)", letterSpacing: .08, display: "flex", alignItems: "center", gap: 6 }}>[<span style={{ color: "var(--accent)", fontWeight: 700 }}>G</span>]RAPH VISUAL</span>
          <button className="btn sm" onClick={() => setZoom(z => Math.min(1.6, +(z + 0.1).toFixed(1)))} style={{ fontSize: 12, padding: "4px 8px", minWidth: 28 }}>+</button>
          <button className="btn sm outline" onClick={() => setZoom(z => Math.max(0.7, +(z - 0.1).toFixed(1)))} style={{ fontSize: 12, padding: "4px 8px", minWidth: 28 }}>−</button>
          <button className="btn sm outline" onClick={() => setZoom(1)} style={{ fontSize: 11, padding: "4px 8px" }}>[ ]</button>
          <span style={{ fontSize: 11, color: "var(--dim)", fontFamily: "var(--mono)" }}>{Math.round(zoom*100)}%</span>
          <span style={{ fontSize: 10, color: "var(--faint)" }}>+/− zoom · [ ] reset · click node → blast</span>
        </div>
        {sel && <Badge tone="amber">[ {byId.get(sel)?.label ?? sel} ] SELECTED</Badge>}
      </div>
      <Panel title="Graph" sub={NODES.length ? `edges are dependency edges from the CBOM · backend: ${graph.data.backend ?? "—"} · ${NODES.length} nodes · ${EDGES.length} edges` : "no CBOM yet — run discovery and a scan to build the crypto dependency graph"}>
        {NODES.length === 0 ? (
          <div style={{ minHeight: 200, display: "grid", placeItems: "center" }}>
            <div className="frame" style={{ border: "1px dashed var(--line-strong)", borderRadius: "var(--r)", padding: "34px 40px", textAlign: "center", color: "var(--faint)", fontSize: 13.5, maxWidth: 440 }}>
              No dependency graph yet.<br />
              <span className="dim">Configure your estate in <Link to="/onboarding">Onboarding</Link>, then run a scan. The graph renders systems → certificates → infrastructure → applications → libraries → algorithms from the real CBOM.</span>
            </div>
          </div>
        ) : (
          <div className="graphwrap" style={{ overflow: "auto", border: "1px solid var(--line)", borderRadius: "var(--r)", background: "var(--bg-2)" }}>
            <div style={{ transform: `scale(${zoom})`, transformOrigin: "top center", transition: "transform 160ms ease" }}>
            <svg viewBox="0 0 800 380" width="100%" style={{ minWidth: 700, background: "var(--panel)" }}>
              {EDGES.map((e, i) => {
                const a = byId.get(e.from); const b = byId.get(e.to);
                if (!a || !b) return null;
                const cls = sel === null ? "edge" : blast.has(e.to) && blast.has(e.from) ? "edge blast" : e.to === sel || e.from === sel ? "edge hit" : "edge";
                const d = `M${a.x} ${a.y + 24} L${b.x} ${b.y - 20}`;
                if (!motionOK) return <path key={`${e.from}-${e.to}-${i}`} className={cls} d={d} />;
                // Edges draw themselves from source to target, so the
                // direction of the dependency is visible as it appears.
                return (
                  <motion.path
                    key={`${e.from}-${e.to}-${i}`}
                    className={cls}
                    d={d}
                    initial={{ pathLength: 0, opacity: 0 }}
                    animate={{ pathLength: 1, opacity: 1 }}
                    transition={{ duration: 0.45, ease: EASE, delay: Math.min(i * 0.012, 0.3) }}
                  />
                );
              })}
              {NODES.map((n, nodeIndex) => {
                const isSel = sel === n.id;
                const isBlast = sel && blast.has(n.id);
                const isUp = sel && upline.has(n.id);
                return (
                  <motion.g
                    key={n.id}
                    className={`gnode ${isSel ? "sel" : ""}`}
                    onClick={() => setSel(isSel ? null : n.id)}
                    initial={motionOK ? { opacity: 0, scale: 0.96 } : false}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ duration: 0.22, ease: EASE, delay: Math.min(nodeIndex * 0.02, 0.35) }}
                    style={{ transformOrigin: `${n.x}px ${n.y + 21}px` }}
                  >
                    <rect
                      x={n.x - 80} y={n.y} width={160} height={42} rx={8}
                      opacity={sel && !isSel && !isBlast && !isUp ? 0.35 : 1}
                      style={{ stroke: isSel ? "var(--red)" : graphColor(n.kind), strokeWidth: isSel ? 2 : 1.5 }}
                    />
                    <rect x={n.x - 80} y={n.y} width={160} height={4} rx={2}
                      style={{ fill: graphColor(n.kind), stroke: "none", opacity: sel && !isSel && !isBlast && !isUp ? 0.2 : 0.85 }} />
                    <text x={n.x} y={n.y + 18} textAnchor="middle" style={{ fontWeight: 600, fontSize: 12 }}>{n.label.length > 22 ? n.label.slice(0, 21) + "…" : n.label}</text>
                    <text x={n.x} y={n.y + 32} textAnchor="middle" className="gsub">{n.kind}</text>
                  </motion.g>
                );
              })}
            </svg>
            </div>
          </div>
        )}
      </Panel>

      <div className="grid cols-2 mt">
        <Panel title={selNode ? `Blast radius — ${selNode.label}` : "Blast radius"} sub="every downstream dependent of the selection">
          {sel ? (
            <Table
              head={["node", "kind"]}
              rows={[...blast].map((id) => {
                const n = byId.get(id);
                return [<span className="mono" key="n">{n?.label ?? id}</span>, <Badge key="k" tone={KIND_TONE[n?.kind ?? ""] ?? ""}>{n?.kind ?? "—"}</Badge>];
              })}
            />
          ) : (
            <div className="dim" style={{ fontSize: 13.5 }}>Select a node to compute its blast radius — every application, library and certificate that depends on it, from the live graph engine.</div>
          )}
        </Panel>
        <Panel title="Impact analysis" sub="evidence-linked dependencies of the selection">
          {sel ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <div className="kpi"><span className="k">nodes in blast radius</span><span className="v">{blast.size}</span></div>
              <div className="kpi"><span className="k">upstream (ancestors)</span><span className="v">{upline.size}</span></div>
              {busy && <LiveBadge source="live" label="QUERYING ENGINE…" />}
              <Link to="/what-if" className="btn sm" style={{ alignSelf: "flex-start" }}>Run migration analysis →</Link>
            </div>
          ) : (
            <div className="dim" style={{ fontSize: 13.5 }}>Impact analysis appears once a node is selected.</div>
          )}
        </Panel>
      </div>
    </>
  );
}
