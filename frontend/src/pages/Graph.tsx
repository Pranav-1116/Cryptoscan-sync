import React, { useState } from "react";
import { Panel, Badge, Table, PageHead, Code } from "../components/ui.jsx";
import { apiBlast, LiveBadge, ApiResult } from "../lib/api.js";

/* Dependency graph (spec §17) — click any node to see its blast radius. */

interface GNode { id: string; label: string; sub: string; x: number; y: number; kind: "ca" | "cert" | "infra" | "app" | "lib" | "algo"; }
interface GEdge { from: string; to: string; }

const NODES: GNode[] = [
  { id: "rootca", label: "ROOT CA", sub: "root-ca.internal", x: 400, y: 24, kind: "ca" },
  { id: "cert", label: "Certificate", sub: "payments.internal", x: 400, y: 96, kind: "cert" },
  { id: "lb", label: "Load balancer", sub: "lb-pay-01", x: 400, y: 168, kind: "infra" },
  { id: "appa", label: "App A", sub: "payments-svc", x: 250, y: 246, kind: "app" },
  { id: "appb", label: "App B", sub: "authentication-service", x: 550, y: 246, kind: "app" },
  { id: "openssl", label: "OpenSSL", sub: "3.5.1", x: 150, y: 322, kind: "lib" },
  { id: "bouncy", label: "BouncyCastle", sub: "1.78", x: 350, y: 322, kind: "lib" },
  { id: "rsa", label: "RSA-2048", sub: "QUANTUM VULNERABLE", x: 500, y: 322, kind: "algo" },
  { id: "ecdsa", label: "ECDSA-P-256", sub: "QUANTUM VULNERABLE", x: 660, y: 322, kind: "algo" },
];

const EDGES: GEdge[] = [
  { from: "rootca", to: "cert" },
  { from: "cert", to: "lb" },
  { from: "lb", to: "appa" },
  { from: "lb", to: "appb" },
  { from: "appa", to: "openssl" },
  { from: "appa", to: "bouncy" },
  { from: "appb", to: "openssl" },
  { from: "openssl", to: "rsa" },
  { from: "bouncy", to: "ecdsa" },
  { from: "appb", to: "ecdsa" },
];

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
      <Panel title="Graph" sub="edges are dependency edges from the CBOM">
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
              <div className="kpi"><span className="k">applications affected</span><span className="v">{sel === "rsa" ? 184 : Math.max(2, blast.size - 1)}</span></div>
              <div className="kpi"><span className="k">certificates affected</span><span className="v">{sel === "rsa" ? 17 : 1}</span></div>
              <div className="kpi"><span className="k">libraries affected</span><span className="v">{sel === "rsa" ? 6 : 1}</span></div>
              <div className="kpi"><span className="k">quantum status</span><span className="v">{sel === "rsa" || sel === "ecdsa" ? "VULNERABLE" : "SAFE"}</span></div>
              <a href="#/whatif" className="btn sm" style={{ alignSelf: "flex-start" }}>Simulate migration →</a>
            </div>
          ) : (
            <div className="dim" style={{ fontSize: 13.5 }}>Impact analysis appears once a node is selected.</div>
          )}
        </Panel>
      </div>
    </>
  );
}
