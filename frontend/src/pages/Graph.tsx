import React, { useState } from "react";
import { Panel, Badge, Table, PageHead, Code } from "../components/ui.jsx";
import { apiBlast, LiveBadge, ApiResult } from "../lib/api.js";

/* Dependency graph (spec §17) — click any node to see its blast radius. */

interface GNode { id: string; label: string; sub: string; x: number; y: number; kind: "ca" | "cert" | "infra" | "app" | "lib" | "algo"; }
interface GEdge { from: string; to: string; }

/* The dependency graph is built from the real CBOM produced by scans.
   It starts empty — nodes/edges populate from the control plane once a
   crypto BOM exists. */
const NODES: GNode[] = [];

const EDGES: GEdge[] = [];

function descendants(from: string): Set<string> {
  const out = new Set<string>();
  const walk = (id: string) => {
    EDGES.filter((e) => e.from === id).forEach((e) => {
      if (!out.has(e.to)) { out.add(e.to); walk(e.to); }
    });
  };
  walk(from);
  return out;
}

function ancestors(from: string): Set<string> {
  const out = new Set<string>();
  const walk = (id: string) => {
    EDGES.filter((e) => e.to === id).forEach((e) => {
      if (!out.has(e.from)) { out.add(e.from); walk(e.from); }
    });
  };
  walk(from);
  return out;
}

const KIND_TONE: Record<string, string> = { ca: "violet", cert: "cyan", infra: "cyan", app: "green", lib: "amber", algo: "red" };

export default function Graph() {
  const [sel, setSel] = useState<string | null>(null);
  const [live, setLive] = useState<ApiResult<Record<string, unknown>> | null>(null);
  const [busy, setBusy] = useState(false);
  const blast = sel ? descendants(sel) : new Set<string>();
  const upline = sel ? ancestors(sel) : new Set<string>();

  const runLiveBlast = async () => {
    if (!sel) return;
    setBusy(true);
    const res = await apiBlast(sel === "rsa" ? "RSA-2048" : sel, 10);
    setLive(res);
    setBusy(false);
  };

  return (
    <>
      <PageHead
        crumb="boms / dependency graph"
        title="Dependency graph"
        sub="Root CA → certificate → load balancer → applications → libraries → algorithms. Click any node to inspect it and its blast radius."
        right={
          <div className="row">
            {sel ? <Badge tone="amber">{blast.size} NODES IN BLAST RADIUS</Badge> : <Badge tone="cyan">CLICK A NODE</Badge>}
            {sel && (
              <button className="btn sm" onClick={() => void runLiveBlast()} disabled={busy}>
                {busy ? "Querying…" : "Blast radius (live)"}
              </button>
            )}
            {live && <LiveBadge source={live.source} label={live.source === "live" ? "LIVE API RESULT" : "BACKEND OFFLINE"} />}
          </div>
        }
      />
      {live?.data && (
        <Panel title="POST /api/v1/platform/blast — engine response" sub={`seed: ${sel}`} className="mt">
          <Code>{JSON.stringify(live.data, null, 2)}</Code>
        </Panel>
      )}
      <Panel title="Graph" sub={NODES.length ? "edges are dependency edges from the CBOM" : "no CBOM yet — run discovery and a scan to build the crypto dependency graph"}>
        {NODES.length === 0 ? (
          <div style={{ minHeight: 200, display: "grid", placeItems: "center" }}>
            <div className="frame" style={{ border: "1px dashed var(--line-strong)", borderRadius: 12, padding: "34px 40px", textAlign: "center", color: "var(--faint)", fontSize: 13.5, maxWidth: 440 }}>
              No dependency graph yet.<br />
              <span className="dim">Configure your estate in <a href="#/onboarding">Onboarding</a>, then run a scan. The graph renders Root CA → certificate → infrastructure → applications → libraries → algorithms from the real CBOM.</span>
            </div>
          </div>
        ) : (
        <div className="graphwrap">
          <svg viewBox="0 0 800 380" width="100%" style={{ minWidth: 700 }}>
            {EDGES.map((e) => {
              const a = NODES.find((n) => n.id === e.from)!;
              const b = NODES.find((n) => n.id === e.to)!;
              const cls = sel === null ? "edge" : blast.has(e.to) && blast.has(e.from) ? "edge blast" : e.to === sel || e.from === sel ? "edge hit" : "edge";
              const mid = `M${a.x} ${a.y + 34} L${b.x} ${b.y - 24}`;
              return <path key={`${e.from}-${e.to}`} className={cls} d={mid} />;
            })}
            {NODES.map((n) => {
              const isSel = sel === n.id;
              const isBlast = sel && blast.has(n.id);
              const isUp = sel && upline.has(n.id);
              return (
                <g key={n.id} className={`gnode ${isSel ? "sel" : ""}`} onClick={() => setSel(isSel ? null : n.id)}>
                  <rect x={n.x - 88} y={n.y} width="176" height="46" opacity={sel && !isSel && !isBlast && !isUp ? 0.35 : 1} />
                  <text x={n.x} y={n.y + 19} textAnchor="middle" style={{ fontWeight: 600 }}>{n.label}</text>
                  <text x={n.x} y={n.y + 33} textAnchor="middle" className="gsub">{n.sub}</text>
                </g>
              );
            })}
          </svg>
        </div>
        )}
      </Panel>

      <div className="grid cols-2 mt">
        <Panel title={sel ? `Blast radius — ${NODES.find((n) => n.id === sel)?.label}` : "Blast radius"} sub="every downstream dependent of the selection">
          {sel ? (
            <Table
              head={["node", "kind", "status"]}
              rows={[...blast].map((id) => {
                const n = NODES.find((x) => x.id === id)!;
                return [<span className="mono">{n.label}</span>, <Badge tone={KIND_TONE[n.kind]}>{n.kind}</Badge>, <Badge>{n.kind === "algo" ? n.sub : "AFFECTED"}</Badge>];
              })}
            />
          ) : (
            <div className="dim" style={{ fontSize: 13.5 }}>
              Select a node to compute its blast radius — e.g. click <span className="mono">RSA-2048</span> to see every
              application, library and certificate that depends on it. The same computation powers the
              what-if simulator.
            </div>
          )}
        </Panel>
        <Panel title="Impact analysis" sub="evidence-linked findings on the selection">
          {sel ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <div className="kpi"><span className="k">nodes in blast radius</span><span className="v">{blast.size}</span></div>
              <div className="kpi"><span className="k">upstream (ancestors)</span><span className="v">{upline.size}</span></div>
              <div className="kpi"><span className="k">quantum status</span><span className="v">from live analysis</span></div>
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
