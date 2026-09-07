import React, { useEffect, useMemo, useState } from "react";
import { Panel, Badge, Table, PageHead, Code } from "../components/ui.jsx";
import { apiBlast, LiveBadge, ApiResult } from "../lib/api.js";
import { useLive, LiveStatus } from "../lib/useLive.js";

/* Dependency graph (spec §17) — renders the REAL crypto dependency graph from
   the control plane (/graph). Nodes/edges are auto-laid-out in a circle; a
   node is empty until discovery/scan builds the CBOM graph. Click a node to
   compute its blast radius from the live engine. */

interface RawNode { id: string; label?: string; name?: string; group?: string; kind?: string; [k: string]: unknown; }
interface RawEdge { from?: string; to?: string; source?: string; target?: string; label?: string; relationship?: string; }

interface GNode { id: string; label: string; sub: string; x: number; y: number; kind: string; }

const KIND_TONE: Record<string, string> = {
  system: "violet", cert: "cyan", certificate: "cyan", infra: "cyan", network: "cyan",
  cloud: "cyan", app: "green", application: "green", process: "green",
  lib: "amber", library: "amber", algo: "red", algorithm: "red", vendor: "violet", owner: "green",
};

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

      <Panel title="Graph" sub={NODES.length ? `edges are dependency edges from the CBOM · backend: ${graph.data.backend ?? "—"}` : "no CBOM yet — run discovery and a scan to build the crypto dependency graph"}>
        {NODES.length === 0 ? (
          <div style={{ minHeight: 200, display: "grid", placeItems: "center" }}>
            <div className="frame" style={{ border: "1px dashed var(--line-strong)", borderRadius: 12, padding: "34px 40px", textAlign: "center", color: "var(--faint)", fontSize: 13.5, maxWidth: 440 }}>
              No dependency graph yet.<br />
              <span className="dim">Configure your estate in <a href="#/onboarding">Onboarding</a>, then run a scan. The graph renders systems → certificates → infrastructure → applications → libraries → algorithms from the real CBOM.</span>
            </div>
          </div>
        ) : (
          <div className="graphwrap">
            <svg viewBox="0 0 800 380" width="100%" style={{ minWidth: 700 }}>
              {EDGES.map((e, i) => {
                const a = byId.get(e.from); const b = byId.get(e.to);
                if (!a || !b) return null;
                const cls = sel === null ? "edge" : blast.has(e.to) && blast.has(e.from) ? "edge blast" : e.to === sel || e.from === sel ? "edge hit" : "edge";
                return <path key={`${e.from}-${e.to}-${i}`} className={cls} d={`M${a.x} ${a.y + 24} L${b.x} ${b.y - 20}`} />;
              })}
              {NODES.map((n) => {
                const isSel = sel === n.id;
                const isBlast = sel && blast.has(n.id);
                const isUp = sel && upline.has(n.id);
                return (
                  <g key={n.id} className={`gnode ${isSel ? "sel" : ""}`} onClick={() => setSel(isSel ? null : n.id)}>
                    <rect x={n.x - 80} y={n.y} width={160} height={42} rx={8} opacity={sel && !isSel && !isBlast && !isUp ? 0.35 : 1} />
                    <text x={n.x} y={n.y + 18} textAnchor="middle" style={{ fontWeight: 600, fontSize: 12 }}>{n.label.length > 22 ? n.label.slice(0, 21) + "…" : n.label}</text>
                    <text x={n.x} y={n.y + 32} textAnchor="middle" className="gsub">{n.kind}</text>
                  </g>
                );
              })}
            </svg>
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
              <a href="#/whatif" className="btn sm" style={{ alignSelf: "flex-start" }}>Run migration analysis →</a>
            </div>
          ) : (
            <div className="dim" style={{ fontSize: 13.5 }}>Impact analysis appears once a node is selected.</div>
          )}
        </Panel>
      </div>
    </>
  );
}
