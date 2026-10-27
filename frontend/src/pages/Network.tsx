import TrafficControlReview from "../components/TrafficControlReview";
import ResourceMonitoring from "../components/ResourceMonitoring";
import { Link } from "react-router-dom";
import React, { useEffect, useMemo, useState } from "react";
import { Panel, Badge, Table, PageHead, Drawer } from "../components/ui.jsx";
import { usePollingApi, LiveBadge } from "../lib/apiUi.jsx";
import { useRealtimeRefresh } from "../lib/realtime.js";
import { IconNetwork, IconCloud, IconHardware, IconSecurity, IconTarget, IconSatellite } from "../components/icons";
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
  const posturePct = tlsEndpoints.length ? Math.round((chainValid / tlsEndpoints.length) * 100) : 0;

  return (
    <>
      <PageHead
        crumb="discovery / network"
        title="Network topology"
        sub="Live TLS posture mapped from observed endpoints — subnet → host → service, no inference"
        right={
          <>
            {live && <LiveBadge source="live" label="LIVE" />}
            <Badge tone={assets.length ? "green" : ""}><span className="dot pulse" /> {subnets} subnets · {hostIps} hosts</Badge>
            <Badge tone={tlsEndpoints.length ? "cyan" : ""}>{tlsEndpoints.length} TLS endpoints</Badge>
          </>
        }
      />

      {/* ── hero KPI strip — visual, not theory ── */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 10, marginBottom: 14 }}>
        {[
          { k: "TLS endpoints", v: c.endpoints, icon: IconNetwork, tone: "cyan", sub: `${hostIps} hosts in ${subnets} subnets` },
          { k: "Policy issues", v: c.policyIssues, icon: IconSecurity, tone: c.policyIssues ? "red" : "green", sub: c.policyIssues ? "requires review" : "no open issues" },
          { k: "Valid chains", v: c.chainValid, icon: IconHardware, tone: "green", sub: `${posturePct}% of endpoints` },
          { k: "Discovered", v: c.discovered, icon: IconTarget, tone: "violet", sub: "open services" },
        ].map((item) => {
          const Ico = item.icon;
          return <div key={item.k} className="panel" style={{ padding: "12px 14px", display: "flex", justifyContent: "space-between", alignItems: "center", borderTop: `2px solid var(--${item.tone === "cyan" ? "accent" : item.tone})`, background: "var(--panel-2)" }}>
            <div>
              <div style={{ display: "flex", gap: 6, alignItems: "center", fontSize: 10, letterSpacing: ".07em", textTransform: "uppercase", color: "var(--faint)", fontFamily: "var(--mono)" }}><Ico size={12} /> {item.k}</div>
              <div style={{ fontFamily: "var(--mono)", fontWeight: 700, fontSize: 20, marginTop: 4, color: item.k === "Policy issues" && item.v ? "var(--red)" : "var(--text)" }}>{item.v}</div>
              <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 2 }}>{item.sub}</div>
            </div>
            <div style={{ width: 36, height: 36, borderRadius: "var(--r)", display: "grid", placeItems: "center", background: `color-mix(in srgb, var(--${item.tone === "cyan" ? "accent" : item.tone}) 10%, var(--panel))`, border: `1px solid var(--${item.tone === "cyan" ? "accent" : item.tone})`, color: `var(--${item.tone === "cyan" ? "accent" : item.tone})` }}><Ico size={16} /></div>
          </div>;
        })}
      </div>

      {/* ── posture overview — visual bar ── */}
      {tlsEndpoints.length > 0 && <div className="panel" style={{ padding: "12px 16px", marginBottom: 14, display: "flex", gap: 16, alignItems: "center", flexWrap: "wrap", background: "var(--panel-2)" }}>
        <b style={{ fontSize: 12, fontFamily: "var(--mono)", letterSpacing: ".06em", textTransform: "uppercase", color: "var(--faint)" }}>Posture</b>
        <div style={{ flex: "1 1 300px", minWidth: 220 }}>
          <div style={{ display: "flex", height: 8, borderRadius: 999, overflow: "hidden", background: "var(--bg-2)", border: "1px solid var(--line)" }}>
            <i style={{ width: `${tlsEndpoints.length ? (chainValid / tlsEndpoints.length) * 100 : 0}%`, background: "var(--green)" }} />
            <i style={{ width: `${tlsEndpoints.length ? (withIssues / tlsEndpoints.length) * 100 : 0}%`, background: "var(--red)" }} />
            <i style={{ flex: 1, background: "var(--line)" }} />
          </div>
          <div style={{ display: "flex", gap: 12, marginTop: 6, fontSize: 11, color: "var(--dim)", fontFamily: "var(--mono)" }}>
            <span style={{ color: "var(--green)" }}>● {chainValid} valid chains</span>
            <span style={{ color: "var(--red)" }}>● {withIssues} policy issues</span>
            <span style={{ color: "var(--faint)" }}>● {tlsEndpoints.length - chainValid - withIssues} unknown</span>
            <span style={{ marginLeft: "auto", color: "var(--dim)" }}>{posturePct}% healthy</span>
          </div>
        </div>
        <div style={{ display: "flex", gap: 8, flexShrink: 0 }}>
          <Badge tone="green">LIVE SCAN</Badge>
          <Badge tone="">passive-safe</Badge>
        </div>
      </div>}

      {/* ── hero topology — visual first, not theory ── */}
      <div className="panel" style={{ padding: 0, overflow: "hidden", border: "1px solid var(--line)", background: "var(--panel)" }}>
        <div style={{ padding: "14px 16px", borderBottom: "1px solid var(--line)", background: "var(--bg-2)", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10 }}>
          <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
            <span className="brandmark" style={{ width: 32, height: 32, display: "grid", placeItems: "center" }}><IconNetwork size={16} /></span>
            <div>
              <div style={{ fontWeight: 700, fontSize: 13 }}>Observed network topology</div>
              <div style={{ fontSize: 11, color: "var(--dim)" }}>{assets.length ? "Subnet → host → TLS service · click service for detail · red = policy/chain issue" : "Awaiting live scan — no fabric inference"}</div>
            </div>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <span className="badge slate" style={{ fontFamily: "var(--mono)" }}>{subnets} subnets</span>
            <span className="badge slate" style={{ fontFamily: "var(--mono)" }}>{hostIps} hosts</span>
            <span className="badge cyan">{assets.length} endpoints</span>
          </div>
        </div>
        {assets.length === 0 ? (
          <div className="dim" style={{ fontSize: 13, padding: "40px 20px", textAlign: "center", background: "repeating-linear-gradient(45deg, var(--panel) 0 8px, var(--panel-2) 8px 16px)" }}>
            <div style={{ maxWidth: 480, margin: "0 auto" }}>
              <div style={{ width: 48, height: 48, borderRadius: "var(--r)", background: "var(--bg-2)", border: "1px solid var(--line)", display: "grid", placeItems: "center", margin: "0 auto 14px" }}><IconSatellite size={22} style={{ color: "var(--faint)" }} /></div>
              <b style={{ color: "var(--text)" }}>No network data yet</b><br />
              <span>Run a live network scan (set a host:port target) in Operations → Realtime scanners.<br />The topology is drawn from observed endpoints only; nothing is inferred or fabricated.</span>
            </div>
          </div>
        ) : (
          <div className="graphwrap" style={{ background: "radial-gradient(1200px 400px at 20% 0%, color-mix(in srgb, var(--accent) 5%, transparent), transparent 60%), var(--panel)", padding: 8 }}>
            <svg viewBox={`0 0 ${topo.width} ${topo.height}`} width="100%" style={{ minWidth: 720, display: "block" }}>
              {/* subtle grid */}
              <defs><pattern id="net-grid" width={40} height={40} patternUnits="userSpaceOnUse"><path d="M 40 0 L 0 0 0 40" fill="none" stroke="var(--line)" strokeWidth={0.4} opacity={0.5} /></pattern></defs>
              <rect x={0} y={0} width={topo.width} height={topo.height} fill="url(#net-grid)" opacity={0.35} />
              {topo.edges.map((e, i) => {
                const a = nodeById.get(e.from);
                const b = nodeById.get(e.to);
                if (!a || !b) return null;
                return (
                  <line key={i}
                    x1={a.x} y1={a.y + NODE_H / 2} x2={b.x} y2={b.y - NODE_H / 2}
                    className={`edge ${e.hit ? "hit" : ""}`} style={{ strokeWidth: e.hit ? 2.2 : 1.3 }} />
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
                      rx={10}
                      fill={n.kind === "subnet" ? "color-mix(in srgb, var(--violet) 12%, var(--panel))" : isSel ? "color-mix(in srgb, var(--accent) 12%, var(--panel))" : "var(--panel-2)"}
                      stroke={col} strokeWidth={isSel ? 2 : n.kind === "subnet" ? 1.6 : 1.4}
                      style={{ filter: isSel ? "drop-shadow(0 2px 8px color-mix(in srgb, var(--accent) 20%, transparent))" : undefined }}
                    />
                    {n.kind === "subnet" && <rect x={n.x - NODE_W / 2} y={n.y - NODE_H / 2} width={NODE_W} height={4} rx={4} fill={col} opacity={0.9} />}
                    <text x={n.x} y={n.y - 3} textAnchor="middle"
                      style={{ fontWeight: 700, fontSize: 12.5, fill: "var(--text)", fontFamily: "var(--sans)" }}>
                      {n.label}
                    </text>
                    <text x={n.x} y={n.y + 14} textAnchor="middle" className="gsub"
                      style={{ fontSize: 10, fill: col, fontFamily: "var(--mono)", letterSpacing: ".04em" }}>
                      {n.sub}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>
        )}
        <div style={{ padding: "10px 16px", borderTop: "1px solid var(--line)", background: "var(--bg-2)", display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center", fontSize: 11, color: "var(--faint)", fontFamily: "var(--mono)" }}>
          <span style={{ display: "inline-flex", gap: 6, alignItems: "center" }}><span style={{ width: 8, height: 8, borderRadius: 2, background: "var(--accent)" }} /> subnet</span>
          <span style={{ display: "inline-flex", gap: 6, alignItems: "center" }}><span style={{ width: 8, height: 8, borderRadius: 2, background: "var(--cyan)" }} /> host</span>
          <span style={{ display: "inline-flex", gap: 6, alignItems: "center" }}><span style={{ width: 8, height: 8, borderRadius: 999, background: "var(--green)" }} /> service OK</span>
          <span style={{ display: "inline-flex", gap: 6, alignItems: "center" }}><span style={{ width: 8, height: 8, borderRadius: 999, background: "var(--red)" }} /> policy / chain fail</span>
          <span style={{ marginLeft: "auto", color: "var(--dim)" }}>Deterministic layout — same inventory always draws the same graph</span>
        </div>
      </div>

      <div className="panel" style={{ marginTop: 14, padding: 0, overflow: "hidden" }}>
        <div style={{ padding: "14px 16px", borderBottom: "1px solid var(--line)", background: "var(--bg-2)", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10 }}>
          <div>
            <div style={{ fontWeight: 700, fontSize: 13, display: "flex", gap: 8, alignItems: "center" }}><IconSecurity size={14} style={{ color: "var(--accent)" }} /> TLS endpoints</div>
            <div style={{ fontSize: 11, color: "var(--dim)", marginTop: 2 }}>Version · cipher · certificate · chain · policy posture (live scan)</div>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <Badge tone="cyan">{tlsEndpoints.length} endpoints</Badge>
            <Badge tone={withIssues ? "red" : "green"}>{withIssues ? `${withIssues} issues` : "no issues"}</Badge>
          </div>
        </div>
        <div style={{ padding: "0 16px 16px" }}>
          <Table
            head={["kind", "id", "ip", "tls / cipher", "certificate", "chain", "status"]}
            rows={assets.map((n) => [
              <Badge tone="cyan">{n.kind}</Badge>,
              <span className="mono" style={{ fontSize: 11 }}>{n.id}</span>,
              <span className="num" style={{ fontFamily: "var(--mono)" }}>{n.ip}</span>,
              <span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{n.tls || "—"}</span>,
              n.certs.length ? <span style={{ display: "inline-flex", gap: 4, flexWrap: "wrap" }}>{n.certs.slice(0, 2).map(c => <Badge key={c} tone="cyan" >{c}</Badge>)}{n.certs.length > 2 ? <span className="faint">+{n.certs.length - 2}</span> : null}</span> : <span className="faint">—</span>,
              n.chain_valid === undefined ? <span className="faint">—</span>
                : n.chain_valid ? <Badge tone="green">valid</Badge> : <Badge tone="red">invalid</Badge>,
              <Badge tone={statusTone(n.status)}>
                {n.status}{n.cert_expiry_days != null ? ` · ${n.cert_expiry_days}d` : ""}
              </Badge>,
            ])}
          />
          {!assets.length && (
            <div className="dim" style={{ fontSize: 13, marginTop: 12, textAlign: "center", padding: "16px 0" }}>
              No network data yet — run a live network scan (set a host:port target) in Operations → Realtime scanners.
            </div>
          )}
        </div>
      </div>

      {/* ── operational telemetry — visual panels below the primary graph ── */}
      <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr)", gap: 0, marginTop: 18 }}>
        <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 10, paddingLeft: 2 }}>
          <IconCloud size={14} style={{ color: "var(--faint)" }} />
          <span style={{ fontSize: 11, letterSpacing: ".12em", textTransform: "uppercase", color: "var(--faint)", fontFamily: "var(--mono)" }}>Operational telemetry</span>
          <span style={{ flex: 1, height: 1, background: "var(--line)", marginLeft: 10 }} />
        </div>
        <ResourceMonitoring />
        <TrafficControlReview />
      </div>

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
