import React, { useMemo, useState } from "react";
import { Panel, Badge, Table, PageHead, Drawer } from "../components/ui.jsx";
import { usePollingApi, LiveBadge } from "../lib/apiUi.jsx";
import { apiLiveInventory, LiveNetworkAsset } from "../lib/api.js";

/* Network — live TLS endpoints from the network scanner via
   GET /api/v1/live-scan/inventory. The topology is derived DETERMINISTICALLY
   from observed inventory (never fabricated): assets group into /24 subnets by
   IP, each distinct host IP is a node, and each TLS service on that host is a
   child node. Posture colors follow the semantic risk ladder. Until a real
   network scan returns endpoints, the graph shows an honest empty state. */

interface TopoNode {
  id: string; label: string; sub: string; x: number; y: number;
  kind: "subnet" | "host" | "service"; tone: string; asset?: LiveNetworkAsset;
}
interface TopoEdge { from: string; to: string; hit: boolean; }
interface Topo { nodes: TopoNode[]; edges: TopoEdge[]; width: number; height: number; }

const NODE_W = 176;
const NODE_H = 50;
const SUBNET_Y = 64;
const HOST_Y = 220;
const SVC_Y0 = 360;
const SVC_GAP = 96;
const HOST_GAP_X = 236;

function toneOf(asset: LiveNetworkAsset): string {
  if (asset.status === "OK" && asset.chain_valid !== false) return "green";
  if (/REFUSED|FAILED|EXPIRED|CLOSED|TIMEOUT/.test(asset.status) || asset.chain_valid === false) return "red";
  return "amber";
}

function ipToInt(ip: string): number {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n))) return 0;
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}
function subnetOf(ip: string): string {
  const p = ip.split(".");
  return p.length === 4 ? `${p[0]}.${p[1]}.${p[2]}.0/24` : "unknown";
}

/* Deterministic layered layout: one block per subnet — subnet node on top,
   host nodes in a row beneath, each host's TLS services stacked below it.
   Positions are a pure function of observed assets, so the same inventory
   always draws the same topology. */
function buildTopology(assets: LiveNetworkAsset[]): Topo {
  const nodes: TopoNode[] = [];
  const edges: TopoEdge[] = [];

  const subnets = new Map<string, LiveNetworkAsset[]>();
  for (const a of assets) {
    const sub = subnetOf(a.ip || "0.0.0.0");
    if (!subnets.has(sub)) subnets.set(sub, []);
    subnets.get(sub)!.push(a);
  }

  let cursorX = 160;
  let maxY = SVC_Y0;
  for (const [sub, list] of [...subnets.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    const hosts = new Map<string, LiveNetworkAsset[]>();
    for (const a of list) {
      if (!hosts.has(a.ip)) hosts.set(a.ip, []);
      hosts.get(a.ip)!.push(a);
    }
    const hostEntries = [...hosts.entries()].sort((a, b) => ipToInt(a[0]) - ipToInt(b[0]));
    const subId = `subnet:${sub}`;
    const colCenterX = cursorX + ((hostEntries.length - 1) * HOST_GAP_X) / 2;
    nodes.push({ id: subId, label: sub, sub: `${hostEntries.length} host${hostEntries.length === 1 ? "" : "s"}`,
      x: colCenterX, y: SUBNET_Y, kind: "subnet", tone: "blue" });

    hostEntries.forEach(([ip, svcs], hi) => {
      const hostX = cursorX + hi * HOST_GAP_X;
      const hostId = `host:${ip}`;
      const hostHasIssue = svcs.some((s) => toneOf(s) === "red");
      nodes.push({ id: hostId, label: ip, sub: `${svcs.length} svc`,
        x: hostX, y: HOST_Y, kind: "host", tone: hostHasIssue ? "red" : "cyan" });
      edges.push({ from: subId, to: hostId, hit: hostHasIssue });

      svcs.forEach((s, j) => {
        const svcY = SVC_Y0 + j * SVC_GAP;
        maxY = Math.max(maxY, svcY);
        const tone = toneOf(s);
        const port = s.id && s.id.includes(":") ? s.id.slice(s.id.lastIndexOf(":")) : "";
        nodes.push({
          id: s.id,
          label: s.tls ? s.tls.split(" ")[0] : s.kind,
          sub: `${s.kind}${port}`,
          x: hostX, y: svcY, kind: "service", tone, asset: s,
        });
        edges.push({ from: hostId, to: s.id, hit: tone === "red" });
      });
    });

    cursorX += hostEntries.length * HOST_GAP_X + 130;
  }

  return { nodes, edges, width: Math.max(860, cursorX + 40), height: maxY + 120 };
}

function statusTone(status: string): "green" | "red" | "amber" | "" {
  if (status === "OK") return "green";
  if (/REFUSED|FAILED|EXPIRED|CLOSED|TIMEOUT/.test(status)) return "red";
  if (status && status !== "discovered" && status !== "open") return "amber";
  return "";
}

const NODE_TONE_COLOR: Record<string, string> = {
  blue: "#3b82f6", cyan: "#00d4ff", green: "#22c55e", amber: "#f59e0b", red: "#ef4444",
};

export default function Network() {
  const [sel, setSel] = useState<string | null>(null);
  const inv = usePollingApi(apiLiveInventory, 8000);
  const live = inv.source === "live";
  const assets: LiveNetworkAsset[] = (inv.data as { network?: LiveNetworkAsset[] } | null)?.network ?? [];
  const detail = assets.find((n) => n.id === sel);

  const tlsEndpoints = assets.filter((n) => n.kind === "tls_endpoint");
  const withIssues = tlsEndpoints.filter((n) => n.status !== "OK").length;
  const chainValid = tlsEndpoints.filter((n) => n.chain_valid === true).length;
  const discovered = assets.filter((n) => n.kind === "discovered").length;
  const c = { endpoints: tlsEndpoints.length, policyIssues: withIssues, chainValid, discovered };

  const topo = useMemo<Topo>(() => buildTopology(assets), [assets]);
  const subnets = new Set(assets.map((a) => subnetOf(a.ip || ""))).size;
  const hostIps = new Set(assets.map((a) => a.ip)).size;
  const nodeById = useMemo(() => new Map(topo.nodes.map((n) => [n.id, n])), [topo.nodes]);

  return (
    <>
      <PageHead
        crumb="discovery / network"
        title="Network topology"
        sub="Observed TLS endpoints grouped into subnets · host → service posture (network scanner, passive-safe)"
        right={
          <>
            {live && <LiveBadge source="live" label="LIVE" />}
            <Badge tone={assets.length ? "green" : ""}><span className="dot" /> {subnets} subnets · {hostIps} hosts</Badge>
          </>
        }
      />
      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        {[["TLS endpoints", c.endpoints], ["with policy issues", c.policyIssues], ["valid chain", c.chainValid], ["discovered (open)", c.discovered]].map(([k, v]) => (
          <div className="kpi" key={k as string}><span className="k">{k}</span>
            <span className="v" style={{ color: k === "with policy issues" && Number(v) ? "var(--red)" : undefined }}>{v}</span>
          </div>
        ))}
      </div>

      <Panel
        title="Observed network topology"
        sub={assets.length ? "subnet → host → TLS service · click a service node for detail · red = policy/chain issue" : "populates after a live network scan"}
      >
        {assets.length === 0 ? (
          <div className="dim" style={{ fontSize: 13, padding: "30px 6px", textAlign: "center" }}>
            No network data yet — run a live network scan (set a host:port target) in
            Operations → Realtime scanners. The topology is drawn from observed endpoints only;
            nothing is inferred or fabricated.
          </div>
        ) : (
          <div className="graphwrap">
            <svg viewBox={`0 0 ${topo.width} ${topo.height}`} width="100%" style={{ minWidth: 720 }}>
              {topo.edges.map((e, i) => {
                const a = nodeById.get(e.from);
                const b = nodeById.get(e.to);
                if (!a || !b) return null;
                return (
                  <line key={i}
                    x1={a.x} y1={a.y + NODE_H / 2} x2={b.x} y2={b.y - NODE_H / 2}
                    className={`edge ${e.hit ? "hit" : ""}`} />
                );
              })}
              {topo.nodes.map((n) => {
                const col = NODE_TONE_COLOR[n.tone] ?? "#1e3a52";
                const isSel = sel === n.id;
                const clickable = n.kind === "service";
                return (
                  <g key={n.id} className={`gnode ${isSel ? "sel" : ""}`}
                     onClick={() => clickable && setSel(isSel ? null : n.id)}
                     style={{ cursor: clickable ? "pointer" : "default" }}>
                    <rect
                      x={n.x - NODE_W / 2} y={n.y - NODE_H / 2} width={NODE_W} height={NODE_H}
                      rx={9}
                      fill={n.kind === "subnet" ? "rgba(59,130,246,0.10)" : "var(--panel)"}
                      stroke={col} strokeWidth={n.kind === "subnet" ? 1.4 : 1.6}
                    />
                    <text x={n.x} y={n.y - 2} textAnchor="middle"
                      style={{ fontWeight: 700, fontSize: 13, fill: "var(--text)" }}>
                      {n.label}
                    </text>
                    <text x={n.x} y={n.y + 16} textAnchor="middle" className="gsub"
                      style={{ fontSize: 10.5, fill: col }}>
                      {n.sub}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>
        )}
      </Panel>

      <Panel title="TLS endpoints" sub="version · cipher · certificate · chain · policy posture (live scan)" className="mt">
        <Table
          head={["kind", "id", "ip", "tls / cipher", "certificate", "chain", "status"]}
          rows={assets.map((n) => [
            <Badge tone="cyan">{n.kind}</Badge>,
            <span className="mono">{n.id}</span>,
            <span className="num">{n.ip}</span>,
            n.tls,
            n.certs.length ? n.certs.join(", ") : <span className="faint">—</span>,
            n.chain_valid === undefined ? <span className="faint">—</span>
              : n.chain_valid ? <Badge tone="green">valid</Badge> : <Badge tone="red">invalid</Badge>,
            <Badge tone={statusTone(n.status)}>
              {n.status}{n.cert_expiry_days != null ? ` · ${n.cert_expiry_days}d` : ""}
            </Badge>,
          ])}
        />
        {!assets.length && (
          <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>
            No network data yet — run a live network scan (set a host:port target) in Operations → Realtime scanners.
          </div>
        )}
      </Panel>

      {detail && (
        <Drawer title={detail.id} sub={`${detail.kind} · ${detail.ip}`} onClose={() => setSel(null)}>
          <div className="row" style={{ marginBottom: 16 }}>
            <Badge tone="cyan">{detail.kind}</Badge>
            <Badge tone={statusTone(detail.status)}>{detail.status}</Badge>
            {detail.cert_expiry_days != null && <Badge>cert {detail.cert_expiry_days}d</Badge>}
          </div>
          <div className="tree" style={{ marginBottom: 16 }}>
            Crypto posture:<br />
            {" └── "}{detail.tls}
          </div>
          <Panel title="Certificates" sub="served by this endpoint" frame>
            {detail.certs.length ? detail.certs.map((cc) => <Badge key={cc} tone="cyan">{cc}</Badge>) : <span className="faint" style={{ fontSize: 13 }}>none observed</span>}
          </Panel>
          <Panel title="Evidence" sub="linked artifacts" frame className="mt">
            <a href="#/evidence" className="mono" style={{ fontSize: 12 }}>open evidence chain →</a>
          </Panel>
        </Drawer>
      )}
    </>
  );
}
