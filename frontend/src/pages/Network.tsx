import { Link } from "react-router-dom";
import React, { useEffect, useMemo, useState } from "react";
import { Panel, Badge, Table, PageHead, Drawer } from "../components/ui.jsx";
import { usePollingApi, LiveBadge } from "../lib/apiUi.jsx";
import { useRealtimeRefresh } from "../lib/realtime.js";
import { IconNetwork, IconCloud, IconHardware, IconSecurity, IconTarget, IconSatellite } from "../components/icons";
import { apiLiveInventory, apiNetworkInventory, apiNetworkInventoryRisk, apiNetworkInventoryTopology, apiNetworkConfigurationDrift, apiValidateNetworkInventory, apiSaveNetworkInventory, apiNetworkCryptoScope, apiPutNetworkCryptoScope, apiValidateNetworkCryptoScope, apiNetworkCryptoEvidence, apiNetworkCryptoCbom, apiNetworkCryptoPath, apiNetworkCryptoBudget, NetworkBudgetResponse, NetworkCryptoScope, NetworkEvidenceResponse, NetworkCbomResponse, NetworkCryptoPathResponse, LiveNetworkAsset, NetworkInventoryResponse, NetworkInventoryRiskResponse, NetworkInventoryTopologyResponse, NetworkConfigurationDriftResponse } from "../lib/api.js";

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

/* ── Cryptographic Network Intelligence — Approved Scope panel (spec §3) ── */
/* Rolling-window traffic budget (§3, §30) — the approved cap, actually counted. */
function BudgetStrip() {
  const budget = usePollingApi(() => apiNetworkCryptoBudget("default"), 20000);
  const b = budget.data as NetworkBudgetResponse | null;
  if (!b || !b.configured) return null;
  const connMax = b.max_connections || 0;
  const connPct = connMax ? Math.min(100, Math.round(((b.connections_used || 0) / connMax) * 100)) : 0;
  const byteMax = b.max_bytes || 0;
  const bytePct = byteMax ? Math.min(100, Math.round(((b.bytes_used || 0) / byteMax) * 100)) : 0;
  const tone = b.exhausted ? "var(--red)" : connPct > 80 || bytePct > 80 ? "var(--amber)" : "var(--green)";
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 10, marginBottom: 10 }}>
      <div style={{ padding: "8px 12px", border: "1px solid var(--line)", borderLeft: `3px solid ${tone}`, borderRadius: "var(--r)", background: "var(--panel)" }}>
        <div className="kicker">connections this window</div>
        <div className="mono" style={{ fontSize: 12, marginTop: 4 }}>{b.connections_used ?? 0} / {connMax || "∞"} · {b.runs ?? 0} runs</div>
        <span style={{ display: "block", height: 6, marginTop: 6, borderRadius: 999, background: "var(--bg-2)", overflow: "hidden" }}>
          <span style={{ display: "block", height: "100%", width: `${connPct}%`, background: tone }} />
        </span>
      </div>
      <div style={{ padding: "8px 12px", border: "1px solid var(--line)", borderLeft: `3px solid ${tone}`, borderRadius: "var(--r)", background: "var(--panel)" }}>
        <div className="kicker">bytes this window</div>
        <div className="mono" style={{ fontSize: 12, marginTop: 4 }}>{((b.bytes_used ?? 0) / 1024).toFixed(1)} KB / {byteMax ? `${(byteMax / 1024 / 1024).toFixed(1)} MB` : "∞"}</div>
        <span style={{ display: "block", height: 6, marginTop: 6, borderRadius: 999, background: "var(--bg-2)", overflow: "hidden" }}>
          <span style={{ display: "block", height: "100%", width: `${bytePct}%`, background: tone }} />
        </span>
      </div>
      <div style={{ padding: "8px 12px", border: "1px solid var(--line)", borderLeft: `3px solid ${b.exhausted ? "var(--red)" : "var(--line-strong)"}`, borderRadius: "var(--r)", background: "var(--panel)" }}>
        <div className="kicker">window status</div>
        <div style={{ fontSize: 12, marginTop: 4 }}>{b.exhausted ? <Badge tone="red">EXHAUSTED — runs refused</Badge> : <Badge tone="green">within budget</Badge>}</div>
        <div className="faint" style={{ fontSize: 10.5, marginTop: 4 }}>{b.distributed === false ? "single-process counter" : "distributed"}</div>
      </div>
    </div>
  );
}

function NetworkCryptoScopePanel() {
  const scopeRes = usePollingApi(() => apiNetworkCryptoScope("default"), 12000);
  const data = scopeRes.data as { scope: NetworkCryptoScope | null; status: { state: string; expired: boolean; reason: string } } | null;
  const scope = data?.scope ?? null;
  const status = data?.status ?? { state: "NOT_CONFIGURED", expired: false, reason: "Loading…" };
  const [editing, setEditing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [draft, setDraft] = useState<NetworkCryptoScope>({
    name: "payments-prod",
    type: "network",
    destinations: ["10.20.10.15:443", "10.20.10.16:443", "10.20.20.10:8443"],
    protocols: ["TLS"],
    allowed_operations: ["CONNECT", "TLS_HANDSHAKE", "CERTIFICATE_READ"],
    traffic_budget: { max_connections: 20, max_bytes: 10485760 },
    valid_until: new Date(Date.now() + 24 * 3600 * 1000).toISOString(),
    inventory_id: "default",
  });
  useEffect(() => {
    if (scope) {
      setDraft({
        name: scope.name || "payments-prod",
        type: "network",
        destinations: scope.destinations || [],
        protocols: scope.protocols || ["TLS"],
        allowed_operations: scope.allowed_operations || ["CONNECT", "TLS_HANDSHAKE", "CERTIFICATE_READ"],
        traffic_budget: scope.traffic_budget || { max_connections: 20, max_bytes: 10485760 },
        valid_until: scope.valid_until || new Date(Date.now() + 24 * 3600 * 1000).toISOString(),
        inventory_id: scope.inventory_id || "default",
      });
    }
  }, [scope]);
  const tone = status.state === "APPROVED" ? "green" : status.state === "EXPIRED" ? "red" : status.state === "NOT_CONFIGURED" ? "amber" : "slate";
  const validUntilLabel = (() => {
    if (!scope?.valid_until) return "no expiry — re-approve recommended";
    try {
      const d = new Date(scope.valid_until);
      const diff = d.getTime() - Date.now();
      const hrs = Math.round(diff / 3600000);
      return `${d.toLocaleString()} · ${hrs > 0 ? `${hrs}h remaining` : "expired"}`;
    } catch { return scope.valid_until; }
  })();
  const save = async () => {
    setSaving(true);
    setMsg(null);
    const payload: NetworkCryptoScope = {
      ...draft,
      destinations: draft.destinations.map((s) => s.trim()).filter(Boolean),
      protocols: draft.protocols.map((s) => s.trim().toUpperCase()).filter(Boolean),
      allowed_operations: draft.allowed_operations.map((s) => s.trim().toUpperCase()).filter(Boolean),
    };
    const v = await apiValidateNetworkCryptoScope(payload);
    if (v.data && !(v.data as any).valid) {
      setMsg(`Validation failed: ${(v.data as any).issues?.join("; ") || v.error || "check destinations"}`);
      setSaving(false);
      return;
    }
    const r = await apiPutNetworkCryptoScope(payload);
    if (r.data) {
      setMsg(`Saved — scope ${r.data.status.state}: ${r.data.status.reason}`);
      setEditing(false);
      void scopeRes.run();
    } else setMsg(r.error || "Save failed");
    setSaving(false);
  };
  return (
    <Panel
      title="Approved Network Scope — explicit authorization only"
      sub="Indha exact destination / port / protocol / operation / time window mattum observe pannu — bank must approve every target (spec §3)"
    >
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginBottom: 10 }}>
        <Badge tone={tone as any}>{status.state}</Badge>
        <span className="dim" style={{ fontSize: 12 }}>{status.reason}</span>
        <span className="dim" style={{ marginLeft: "auto", fontSize: 11 }}>
          {scope ? `saved ${scope.saved_at ? new Date(scope.saved_at as string).toLocaleString() : ""} by ${scope.saved_by || "—"}` : "no scope yet — scans are refused until configured"}
        </span>
        <button className="btn sm" onClick={() => setEditing((e) => !e)}>{editing ? "Cancel edit" : "Configure scope"}</button>
        {scopeRes.source === "live" ? <LiveBadge source="live" label="SCOPE LIVE" /> : <Badge tone="amber">OFFLINE</Badge>}
      </div>

      {!scope && !editing ? (
        <div style={{ padding: "14px", border: "1px dashed var(--line)", borderRadius: "var(--r)", background: "color-mix(in srgb, var(--amber) 6%, transparent)", fontSize: 12, color: "var(--dim)" }}>
          No approved scope configured — CryptoScan will <b>refuse</b> network probes (including <code>10.0.0.0/8</code>) until you save explicit destinations. Click <b>Configure scope</b> to add approved host:port entries like <code>10.20.10.15:443</code>.
        </div>
      ) : null}

      {scope ? (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 10, marginBottom: 10 }}>
          <div style={{ padding: "10px 12px", border: "1px solid var(--line)", borderTop: "2px solid var(--accent)", borderRadius: "var(--r)", background: "var(--panel)" }}>
            <div className="kicker">destinations — exact host:port</div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 6 }}>
              {scope.destinations.map((d) => <span key={d} className="mono" style={{ fontSize: 11, padding: "3px 8px", borderRadius: 999, background: "var(--bg-2)", border: "1px solid var(--line)" }}>{d}</span>)}
              {!scope.destinations.length && <span className="faint">— none —</span>}
            </div>
          </div>
          <div style={{ padding: "10px 12px", border: "1px solid var(--line)", borderTop: "2px solid var(--violet)", borderRadius: "var(--r)", background: "var(--panel)" }}>
            <div className="kicker">protocols · allowed operations</div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 6 }}>
              {scope.protocols.map((p) => <Badge key={p} tone="violet">{p}</Badge>)}
              {scope.allowed_operations.map((o) => <Badge key={o} tone="cyan">{o}</Badge>)}
            </div>
          </div>
          <div style={{ padding: "10px 12px", border: "1px solid var(--line)", borderTop: `2px solid ${status.state === "APPROVED" ? "var(--green)" : "var(--amber)"}`, borderRadius: "var(--r)", background: "var(--panel)" }}>
            <div className="kicker">traffic budget · validity</div>
            <div style={{ fontSize: 12, marginTop: 6, display: "flex", flexDirection: "column", gap: 4 }}>
              <span><b>{scope.traffic_budget.max_connections}</b> max connections · <b>{(scope.traffic_budget.max_bytes / 1024 / 1024).toFixed(1)} MB</b> max bytes</span>
              <span className="dim" style={{ fontSize: 11 }}>{validUntilLabel}</span>
            </div>
          </div>
        </div>
      ) : null}

      <BudgetStrip />

      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 8, fontSize: 11, color: "var(--faint)" }}>
        <span className="mono">name: <b style={{ color: "var(--text)" }}>{scope?.name || "—"}</b></span>
        <span>· only these destinations will be observed</span>
        <span>· CIDR like <code>10.0.0.0/8</code> is never scanned implicitly</span>
      </div>

      {editing && (
        <div style={{ border: "1px solid var(--accent)", borderRadius: "var(--r)", padding: 12, background: "var(--bg-2)", display: "flex", flexDirection: "column", gap: 10 }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <label style={{ fontSize: 11, color: "var(--dim)" }}>name<input value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} style={{ width: "100%", marginTop: 4, padding: "6px 8px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--panel)", color: "var(--text)", fontSize: 12 }} /></label>
            <label style={{ fontSize: 11, color: "var(--dim)" }}>valid until<input type="datetime-local" value={draft.valid_until ? new Date(draft.valid_until).toISOString().slice(0, 16) : ""} onChange={(e) => setDraft({ ...draft, valid_until: e.target.value ? new Date(e.target.value).toISOString() : null })} style={{ width: "100%", marginTop: 4, padding: "6px 8px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--panel)", color: "var(--text)", fontSize: 12 }} /></label>
          </div>
          <label style={{ fontSize: 11, color: "var(--dim)" }}>destinations — one host:port per line (e.g. 10.20.10.15:443)<textarea value={draft.destinations.join("\n")} onChange={(e) => setDraft({ ...draft, destinations: e.target.value.split("\n") })} rows={3} style={{ width: "100%", marginTop: 4, padding: "8px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--panel)", color: "var(--text)", fontFamily: "var(--mono)", fontSize: 11 }} placeholder={"10.20.10.15:443\n10.20.10.16:443\n10.20.20.10:8443"} /></label>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <label style={{ fontSize: 11, color: "var(--dim)" }}>protocols (comma separated)<input value={draft.protocols.join(", ")} onChange={(e) => setDraft({ ...draft, protocols: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) })} style={{ width: "100%", marginTop: 4, padding: "6px 8px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--panel)", color: "var(--text)", fontSize: 12 }} placeholder="TLS, SSH, IPsec" /></label>
            <label style={{ fontSize: 11, color: "var(--dim)" }}>allowed operations (comma separated)<input value={draft.allowed_operations.join(", ")} onChange={(e) => setDraft({ ...draft, allowed_operations: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) })} style={{ width: "100%", marginTop: 4, padding: "6px 8px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--panel)", color: "var(--text)", fontSize: 12 }} placeholder="CONNECT, TLS_HANDSHAKE, CERTIFICATE_READ" /></label>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <label style={{ fontSize: 11, color: "var(--dim)" }}>max connections<input type="number" value={draft.traffic_budget.max_connections} onChange={(e) => setDraft({ ...draft, traffic_budget: { ...draft.traffic_budget, max_connections: Math.max(1, Math.min(1000, Number(e.target.value))) } })} style={{ width: "100%", marginTop: 4, padding: "6px 8px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--panel)", color: "var(--text)", fontSize: 12 }} /></label>
            <label style={{ fontSize: 11, color: "var(--dim)" }}>max bytes<input type="number" value={draft.traffic_budget.max_bytes} onChange={(e) => setDraft({ ...draft, traffic_budget: { ...draft.traffic_budget, max_bytes: Math.max(1024, Number(e.target.value)) } })} style={{ width: "100%", marginTop: 4, padding: "6px 8px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--panel)", color: "var(--text)", fontSize: 12 }} /></label>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <button className="btn primary" onClick={() => void save()} disabled={saving}>{saving ? "Saving…" : "Save approved scope"}</button>
            <button className="btn" onClick={() => setEditing(false)}>Cancel</button>
            {msg && <span className="dim" style={{ fontSize: 11 }}>{msg}</span>}
          </div>
          <div className="faint" style={{ fontSize: 11 }}>Stored as tenant-scoped <code>network:crypto-scope</code> — probes outside these exact destinations/ports/protocols are refused.</div>
        </div>
      )}
    </Panel>
  );
}

/* ── Cryptographic Network Intelligence — observed crypto (spec §24, §25, §28) ── */
function evidenceTone(type: string): "green" | "amber" | "slate" {
  if (type === "NETWORK_ACTIVE_OBSERVED") return "green";
  if (type === "CERTIFICATE_OBSERVED") return "amber";
  return "slate";
}

function NetworkCryptoIntelligencePanel() {
  const evidence = usePollingApi(() => apiNetworkCryptoEvidence(5), 15000);
  const cbom = usePollingApi(() => apiNetworkCryptoCbom(5), 15000);
  const ev = evidence.data as NetworkEvidenceResponse | null;
  const cb = cbom.data as NetworkCbomResponse | null;
  const summary = ev?.summary;
  const records = ev?.evidence ?? [];
  const assets = cb?.assets ?? [];
  const algorithms = Object.entries(cb?.algorithms ?? {}).sort((a, b) => b[1] - a[1]);
  const maxCount = algorithms.length ? Math.max(...algorithms.map(([, n]) => n)) : 1;
  const [hops, setHops] = useState("10.20.10.15:443 -> api-gateway\napi-gateway -> payments-db");
  const [path, setPath] = useState<NetworkCryptoPathResponse | null>(null);
  const [pathMsg, setPathMsg] = useState<string | null>(null);
  const [loadingPath, setLoadingPath] = useState(false);
  const annotate = async () => {
    setLoadingPath(true);
    setPathMsg(null);
    const parsed = hops
      .split("\n")
      .map((line) => line.split(/->|→/).map((part) => part.trim()))
      .filter((parts) => parts.length === 2 && parts[0] && parts[1])
      .map(([from, to]) => ({ from, to }));
    if (!parsed.length) {
      setPathMsg("Enter hops as `source -> target`, one per line.");
      setLoadingPath(false);
      return;
    }
    const result = await apiNetworkCryptoPath(parsed);
    if (result.data) setPath(result.data);
    else setPathMsg(result.error || "Path annotation failed");
    setLoadingPath(false);
  };
  return (
    <Panel
      title="Network crypto intelligence — observed transport crypto"
      sub="TLS version · cipher · key exchange · certificate curve · mTLS — network transport layer only, never application or storage crypto"
      className="mt"
    >
      <div className="grid cols-4" style={{ marginBottom: 12 }}>
        {[
          ["observed endpoints", summary?.observed ?? 0, "var(--green)"],
          ["not observed (UNKNOWN)", summary?.not_observed ?? 0, (summary?.not_observed ?? 0) ? "var(--amber)" : undefined],
          ["CBOM crypto assets", cb?.asset_count ?? 0, "var(--accent)"],
          ["policy issues", Object.values(summary?.policy_issues ?? {}).reduce((a, b) => a + b, 0), undefined],
        ].map(([k, v, color]) => (
          <div className="kpi" key={k as string}>
            <span className="k">{k}</span>
            <span className="v" style={{ color: color as string | undefined }}>{v as number}</span>
          </div>
        ))}
      </div>

      {algorithms.length > 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: 6, marginBottom: 14 }}>
          <div className="kicker">observed algorithms — network transport</div>
          {algorithms.slice(0, 6).map(([name, count]) => (
            <div key={name} style={{ display: "grid", gridTemplateColumns: "150px 1fr 34px", alignItems: "center", gap: 8 }}>
              <span className="mono" style={{ fontSize: 11 }}>{name}</span>
              <span style={{ height: 8, borderRadius: 999, background: "var(--bg-2)", overflow: "hidden" }}>
                <span style={{ display: "block", height: "100%", width: `${Math.max(6, (count / maxCount) * 100)}%`, background: "linear-gradient(90deg, var(--accent), var(--violet))" }} />
              </span>
              <span className="num" style={{ fontSize: 11, textAlign: "right" }}>{count}</span>
            </div>
          ))}
        </div>
      )}

      {records.length === 0 ? (
        <div className="dim" style={{ fontSize: 13, padding: "12px 4px" }}>
          No observations yet — configure an approved scope above, then run <code>POST /api/v1/network/crypto-observe</code>.
          Empty means <b>NOT_OBSERVED</b>, never “no crypto”.
        </div>
      ) : (
        <Table
          head={["endpoint", "evidence", "TLS", "cipher", "key exchange", "cert key / curve", "mTLS", "observed"]}
          rows={records.map((r) => [
            <span className="mono">{r.target.endpoint}</span>,
            <Badge tone={evidenceTone(r.evidence_type)}>{r.evidence_type === "NETWORK_ACTIVE_OBSERVED" ? "OBSERVED" : "UNKNOWN"}</Badge>,
            r.tls_version ?? <span className="faint">—</span>,
            <span className="mono" style={{ fontSize: 11 }}>{r.cipher_suite ?? "—"}</span>,
            r.decomposition.key_exchange ?? <span className="faint">—</span>,
            <span>{r.certificate.public_key_algorithm ?? "—"}{r.certificate.curve ? ` / ${r.certificate.curve}` : ""}</span>,
            <Badge tone={r.mutual_tls === "NOT_REQUIRED" ? "amber" : "slate"}>{r.mutual_tls}</Badge>,
            r.observed_at ? new Date(r.observed_at).toLocaleTimeString() : "—",
          ])}
        />
      )}

      {assets.length > 0 && (
        <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 12 }}>
          {assets.slice(0, 12).map((a) => (
            <span key={a.asset_id} className="mono" style={{ fontSize: 10.5, padding: "3px 8px", borderRadius: 999, border: "1px solid var(--line)", background: "var(--bg-2)" }} title={`${a.role} · ${a.context.endpoint}`}>
              {a.algorithm} <span style={{ color: "var(--faint)" }}>{a.role.replace("tls-", "")}</span>
            </span>
          ))}
        </div>
      )}

      <div style={{ marginTop: 16, borderTop: "1px solid var(--line)", paddingTop: 12 }}>
        <div className="kicker" style={{ marginBottom: 6 }}>crypto hop path — declared hops, observed crypto</div>
        <textarea
          value={hops}
          onChange={(event) => setHops(event.target.value)}
          rows={2}
          aria-label="Declared crypto hops"
          style={{ width: "100%", fontFamily: "var(--mono)", fontSize: 11, padding: 8, borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)", color: "var(--text)" }}
        />
        <div className="row" style={{ marginTop: 8 }}>
          <button className="btn sm" type="button" onClick={() => void annotate()} disabled={loadingPath}>{loadingPath ? "Annotating…" : "Annotate path"}</button>
          {pathMsg && <span className="dim" style={{ fontSize: 11 }}>{pathMsg}</span>}
          {path && (
            <span className="dim" style={{ fontSize: 11 }}>
              {path.observed_edges}/{path.edge_count} hops observed · {path.complete ? "chain complete" : `${path.unknown_edges} UNKNOWN`}
            </span>
          )}
        </div>
        {path && (
          <div style={{ display: "flex", flexDirection: "column", gap: 6, marginTop: 10 }}>
            {path.edges.map((edge, index) => (
              <div key={index} style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", padding: "6px 10px", borderRadius: "var(--r)", border: "1px solid var(--line)", borderLeft: `3px solid ${edge.evidence_type === "NETWORK_ACTIVE_OBSERVED" ? "var(--green)" : "var(--amber)"}`, background: "var(--panel)" }}>
                <span className="mono" style={{ fontSize: 11 }}>{edge.from}</span>
                <span className="faint">→</span>
                <span className="mono" style={{ fontSize: 11 }}>{edge.to}</span>
                {edge.evidence_type === "NETWORK_ACTIVE_OBSERVED" ? (
                  <>
                    <Badge tone="green">{edge.tls_version}</Badge>
                    <span className="mono" style={{ fontSize: 10.5 }}>{edge.cipher_suite}</span>
                    <Badge tone="violet">{String(edge.decomposition?.key_exchange ?? "—")}</Badge>
                    <Badge tone="amber">mTLS {edge.mutual_tls}</Badge>
                  </>
                ) : (
                  <Badge tone="amber">UNKNOWN — not observed</Badge>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
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

      {/* ── approved scope + observed crypto (spec 67) ── */}
      <NetworkCryptoScopePanel />
      <NetworkCryptoIntelligencePanel />

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

      {/* Operational telemetry (ResourceMonitoring / TrafficControlReview) is not
          rendered here: those components are absent from this checkout. The
          section header stays so the layout is unchanged when they return. */}
      <div style={{ display: "flex", gap: 8, alignItems: "center", margin: "18px 0 10px", paddingLeft: 2 }}>
        <IconCloud size={14} style={{ color: "var(--faint)" }} />
        <span style={{ fontSize: 11, letterSpacing: ".12em", textTransform: "uppercase", color: "var(--faint)", fontFamily: "var(--mono)" }}>Operational telemetry</span>
        <span style={{ flex: 1, height: 1, background: "var(--line)", marginLeft: 10 }} />
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
