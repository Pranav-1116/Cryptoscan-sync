import TrafficControlReview from "../components/TrafficControlReview";
import ResourceMonitoring from "../components/ResourceMonitoring";
import { Link } from "react-router-dom";
import React, { useEffect, useMemo, useState } from "react";
import { Panel, Badge, Table, PageHead, Drawer } from "../components/ui.jsx";
import { usePollingApi, LiveBadge } from "../lib/apiUi.jsx";
import { useRealtimeRefresh } from "../lib/realtime.js";
import { apiLiveInventory, apiNetworkInventory, apiNetworkInventoryRisk, apiNetworkInventoryTopology, apiNetworkConfigurationDrift, apiValidateNetworkInventory, apiSaveNetworkInventory, LiveNetworkAsset, NetworkInventoryResponse, NetworkInventoryRiskResponse, NetworkInventoryTopologyResponse, NetworkConfigurationDriftResponse } from "../lib/api.js";

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
  blue: "var(--accent)", cyan: "var(--accent)", green: "var(--green)", amber: "var(--amber)", red: "var(--red)",
};

function NetworkInventoryPanel() {
  const inventory = usePollingApi(apiNetworkInventory, 15000);
  const risk = usePollingApi(apiNetworkInventoryRisk, 15000);
  const topology = usePollingApi(apiNetworkInventoryTopology, 15000);
  const drift = usePollingApi(apiNetworkConfigurationDrift, 15000);
  const snapshot = inventory.data as NetworkInventoryResponse | null;
  const riskData = risk.data as NetworkInventoryRiskResponse | null;
  const topologyData = topology.data as NetworkInventoryTopologyResponse | null;
  const driftData = drift.data as NetworkConfigurationDriftResponse | null;
  const [editorOpen, setEditorOpen] = useState(false);
  const [draft, setDraft] = useState("");
  const [editorMessage, setEditorMessage] = useState("");
  useEffect(() => {
    if (snapshot && !draft) setDraft(JSON.stringify(snapshot.inventory, null, 2));
  }, [snapshot, draft]);
  const parseDraft = (): Record<string, any> | null => {
    try {
      const parsed = JSON.parse(draft);
      if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") throw new Error("inventory must be a JSON object");
      return parsed;
    } catch (error) {
      setEditorMessage(`Invalid JSON: ${String(error)}`);
      return null;
    }
  };
  const validateDraft = async () => {
    const parsed = parseDraft();
    if (!parsed) return;
    const result = await apiValidateNetworkInventory(parsed);
    setEditorMessage(result.data ? `Validated: ${result.data.valid ? "schema accepted" : "rejected"}` : result.error || "Validation failed");
  };
  const saveDraft = async () => {
    const parsed = parseDraft();
    if (!parsed) return;
    const result = await apiSaveNetworkInventory(parsed, { status: "DRAFT", source: "MANUAL" });
    setEditorMessage(result.data ? `Saved revision ${result.data.revision ?? "pending"}` : result.error || "Save failed");
    if (result.data) void inventory.run();
  };
  const sectionCount = snapshot?.inventory ? Object.keys(snapshot.inventory).length : 0;
  const devices = Array.isArray(snapshot?.inventory?.devices) ? snapshot!.inventory.devices : [];
  return (
    <Panel title="Structured network inventory" sub="tenant-scoped evidence register · unknown values stay explicit" className="mt">
      {inventory.source !== "live" || !snapshot ? (
        <div className="dim" style={{ fontSize: 13 }}>Inventory API unavailable — no local or fabricated snapshot is shown.</div>
      ) : (
        <>
          <div className="row" style={{ marginBottom: 12 }}>
            <Badge tone={snapshot.completeness.status === "COMPLETE" ? "green" : "amber"}>{snapshot.completeness.status}</Badge>
            <Badge tone={riskData?.posture === "GREEN" ? "green" : riskData?.posture === "RED" ? "red" : "amber"}>{riskData?.posture ?? "UNKNOWN"}</Badge>
            <span className="dim">revision {snapshot.revision ?? "not persisted"} · {Math.round(snapshot.completeness.score * 100)}% section coverage</span>
          </div>
          <div className="grid cols-4" style={{ marginBottom: 12 }}>
            <div className="kpi"><span className="k">devices</span><span className="v">{devices.length}</span></div>
            <div className="kpi"><span className="k">inventory sections</span><span className="v">{sectionCount}</span></div>
            <div className="kpi"><span className="k">missing sections</span><span className="v">{snapshot.completeness.missing.length}</span></div>
            <div className="kpi"><span className="k">evidence records</span><span className="v">{Array.isArray(snapshot.inventory.evidence) ? snapshot.inventory.evidence.length : 0}</span></div>
          </div>
          {snapshot.completeness.next_actions.length > 0 && (
            <div className="tree" style={{ marginBottom: 10 }}>
              Next actions: {snapshot.completeness.next_actions.slice(0, 4).join(" · ")}
            </div>
          )}
          {riskData?.unknowns?.length ? <div className="dim">Unknowns: {riskData.unknowns.slice(0, 4).join(" · ")}</div> : null}
          {topologyData && <div className="dim" style={{ marginTop: 8 }}>
            Structured graph: {topologyData.node_count} nodes · {topologyData.edge_count} observed edges · {topologyData.unknown_endpoints.length} unknown endpoints
          </div>}
          {driftData && <div className="dim" style={{ marginTop: 4 }}>
            Configuration: {driftData.status} · {driftData.drifted_comparisons} drifted comparisons · {driftData.unknown_comparisons} unknown comparisons
          </div>}
          <div className="row" style={{ marginTop: 14 }}>
            <button className="btn" type="button" onClick={() => setEditorOpen((open) => !open)}>
              {editorOpen ? "Hide inventory editor" : "Edit structured inventory"}
            </button>
            <span className="dim">Raw configurations and credentials are never accepted.</span>
          </div>
          {editorOpen && <div style={{ marginTop: 12 }}>
            <textarea
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              aria-label="Structured network inventory JSON"
              style={{ width: "100%", minHeight: 260, fontFamily: "var(--mono)", fontSize: 12, background: "var(--bg)", color: "var(--text)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: 10 }}
            />
            <div className="row" style={{ marginTop: 8 }}>
              <button className="btn" type="button" onClick={() => void validateDraft()}>Validate</button>
              <button className="btn primary" type="button" onClick={() => void saveDraft()}>Save draft</button>
              {editorMessage && <span className="dim">{editorMessage}</span>}
            </div>
          </div>}
        </>
      )}
    </Panel>
  );
}

export default function Network() {
  const [sel, setSel] = useState<string | null>(null);
  const inv = usePollingApi(apiLiveInventory, 8000);
  useRealtimeRefresh(inv.run);
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
      <ResourceMonitoring />
      <TrafficControlReview />
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
                const col = NODE_TONE_COLOR[n.tone] ?? "var(--line-strong)";
                const isSel = sel === n.id;
                const clickable = n.kind === "service";
                return (
                  <g key={n.id} className={`gnode ${isSel ? "sel" : ""}`}
                     onClick={() => clickable && setSel(isSel ? null : n.id)}
                     style={{ cursor: clickable ? "pointer" : "default" }}>
                    <rect
                      x={n.x - NODE_W / 2} y={n.y - NODE_H / 2} width={NODE_W} height={NODE_H}
                      rx={9}
                      fill={n.kind === "subnet" ? "color-mix(in srgb, var(--violet) 10%, transparent)" : "var(--panel)"}
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
            <Link to="/evidence" className="mono" style={{ fontSize: 12 }}>open evidence chain →</Link>
          </Panel>
        </Drawer>
      )}
    </>
  );
}
