import { Link } from "react-router-dom";
import React, { useEffect, useMemo, useState } from "react";
import { Panel, Badge, Table, PageHead, Drawer } from "../components/ui.jsx";
import { usePollingApi, LiveBadge } from "../lib/apiUi.jsx";
import { useRealtimeRefresh } from "../lib/realtime.js";
import { IconNetwork, IconCloud, IconHardware, IconSecurity, IconTarget, IconSatellite } from "../components/icons";
import { apiLiveInventory, apiNetworkInventory, apiNetworkInventoryRisk, apiNetworkInventoryTopology, apiNetworkConfigurationDrift, apiValidateNetworkInventory, apiSaveNetworkInventory, apiNetworkCryptoScope, apiPutNetworkCryptoScope, apiValidateNetworkCryptoScope, apiNetworkCryptoEvidence, apiNetworkCryptoCbom, apiNetworkCryptoPath, apiNetworkCryptoBudget, NetworkBudgetResponse, apiImportNetworkScope, ScopeImportResponse, apiNetworkCryptoWatch, apiStartNetworkCryptoWatch, apiStopNetworkCryptoWatch, apiTickNetworkCryptoWatch, NetworkWatchStatus, NetworkCryptoScope, NetworkEvidenceResponse, NetworkCbomResponse, NetworkCryptoPathResponse, LiveNetworkAsset, NetworkInventoryResponse, NetworkInventoryRiskResponse, NetworkInventoryTopologyResponse, NetworkConfigurationDriftResponse, apiNetworkCryptoIntegrity, NetworkEvidenceIntegrity, apiNetworkMessageLayer, apiObserveNetworkMessageLayer, MessageLayerResponse, MessageLayerRecord, apiNetworkCryptoCorrelate, NetworkCorrelationResponse, apiNetworkCryptoProbe, CryptoProbeResponse, ProtocolDetection, apiNetworkCryptoSafety, apiNetworkCryptoStop, NetworkSafetyState, apiNetworkCryptoRisk, NetworkRiskReport, NetworkRiskFinding, apiNetworkAnchorStatus, apiNetworkCreateAnchor, apiNetworkVerifyAnchor, apiNetworkWatchLease, NetworkAnchorStatus, NetworkAnchorReceipt, NetworkAnchorVerification, NetworkWatchLease } from "../lib/api.js";

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

/* §4 declared/imported candidates — an import is a declaration, never a probe. */
function ScopeImportPanel() {
  const [source, setSource] = useState("CMDB");
  const [text, setText] = useState("");
  const [result, setResult] = useState<ScopeImportResponse | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async (apply: boolean) => {
    if (!text.trim()) {
      setMessage("Paste a CMDB/load-balancer export first (CSV, TSV, JSON or one host per line).");
      return;
    }
    setBusy(true);
    setMessage(null);
    const response = await apiImportNetworkScope({ source, text, apply });
    if (response.data) {
      setResult(response.data);
      setMessage(
        apply
          ? response.data.applied
            ? `Applied — ${response.data.merge?.added.length ?? 0} destination(s) added to the approved scope`
            : response.data.apply_blocked || "Apply blocked"
          : `Preview — ${response.data.preview.accepted_count} accepted, ${response.data.preview.rejected.length} rejected (nothing probed)`
      );
    } else {
      setMessage(response.error || "Import failed");
    }
    setBusy(false);
  };
  return (
    <Panel
      title="Import declared destinations"
      sub="CMDB · load balancer · Kubernetes · cloud export — declarations only, no probing, approval still required"
      className="mt"
    >
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginBottom: 8 }}>
        <select value={source} onChange={(e) => setSource(e.target.value)} style={{ padding: "6px 8px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--panel)", color: "var(--text)", fontSize: 12 }}>
          {["CMDB", "LOAD_BALANCER", "KUBERNETES", "CLOUD", "FIREWALL", "DNS", "MANUAL"].map((option) => <option key={option} value={option}>{option}</option>)}
        </select>
        <span className="dim" style={{ fontSize: 11 }}>nothing is probed; imported rows are CONFIG_IMPORTED candidates</span>
      </div>
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        rows={3}
        aria-label="Declared destinations export"
        placeholder={"host,port\n10.20.10.15,443\n10.20.10.16,8443"}
        style={{ width: "100%", fontFamily: "var(--mono)", fontSize: 11, padding: 8, borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)", color: "var(--text)" }}
      />
      <div className="row" style={{ marginTop: 8 }}>
        <button className="btn sm" type="button" disabled={busy} onClick={() => void run(false)}>Preview import</button>
        <button className="btn sm primary" type="button" disabled={busy} onClick={() => void run(true)}>Apply to scope</button>
        {message && <span className="dim" style={{ fontSize: 11 }}>{message}</span>}
      </div>
      {result && (
        <div style={{ marginTop: 10, display: "flex", flexDirection: "column", gap: 6 }}>
          <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
            <Badge tone="cyan">{result.preview.source}</Badge>
            <Badge tone="green">{result.preview.accepted_count} accepted</Badge>
            {result.preview.rejected.length > 0 && <Badge tone="red">{result.preview.rejected.length} rejected</Badge>}
            {result.preview.duplicate_count > 0 && <Badge tone="amber">{result.preview.duplicate_count} duplicate</Badge>}
            {result.preview.truncated && <Badge tone="amber">truncated</Badge>}
            <span className="faint" style={{ fontSize: 10.5 }}>probing performed: {String(result.probing_performed)}</span>
          </div>
          {result.preview.candidates.slice(0, 8).map((candidate) => (
            <span key={candidate.endpoint} className="mono" style={{ fontSize: 11 }}>{candidate.endpoint} <span className="faint">· {candidate.evidence_type}</span></span>
          ))}
          {result.preview.rejected.slice(0, 5).map((row) => (
            <span key={row.endpoint} className="mono" style={{ fontSize: 10.5, color: "var(--red)" }}>{row.endpoint} — {row.reason}</span>
          ))}
        </div>
      )}
    </Panel>
  );
}

/* 24/7 scope-bound observation worker (§3, §30). */
function CryptoWatchPanel() {
  const watch = usePollingApi(apiNetworkCryptoWatch, 10000);
  const status = watch.data as NetworkWatchStatus | null;
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const act = async (fn: () => Promise<{ data: unknown; error?: string }>, label: string) => {
    setBusy(true);
    const response = await fn();
    setMessage(response.error ? `${label} failed: ${response.error}` : `${label} ok`);
    void watch.run();
    setBusy(false);
  };
  const last = status?.last_result;
  return (
    <Panel
      title="24/7 observation worker"
      sub="Re-reads the approved scope every tick · reserves traffic budget · skipped ticks are reported, never counted as observations"
      className="mt"
    >
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginBottom: 10 }}>
        <Badge tone={status?.running ? "green" : "slate"}>{status?.running ? "RUNNING" : "STOPPED"}</Badge>
        <Badge tone={status?.scope?.state === "APPROVED" ? "green" : "amber"}>scope {status?.scope?.state ?? "—"}</Badge>
        <span className="mono" style={{ fontSize: 11 }}>every {status?.interval_seconds ?? 900}s</span>
        <span className="dim" style={{ fontSize: 11 }}>ticks {status?.ticks ?? 0} · observed {status?.observed_ticks ?? 0} · skipped {status?.skipped_ticks ?? 0} · failed {status?.failed_ticks ?? 0}</span>
        <div style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
          <button className="btn sm" type="button" disabled={busy || status?.running} onClick={() => void act(() => apiStartNetworkCryptoWatch(300), "Start")}>Start</button>
          <button className="btn sm" type="button" disabled={busy || !status?.running} onClick={() => void act(() => apiStopNetworkCryptoWatch(), "Stop")}>Stop</button>
          <button className="btn sm" type="button" disabled={busy} onClick={() => void act(() => apiTickNetworkCryptoWatch(), "Tick")}>Tick now</button>
        </div>
      </div>
      {last && (
        <div className="dim" style={{ fontSize: 11 }}>
          last tick: <b style={{ color: last.status === "OBSERVED" ? "var(--green)" : last.status === "SKIPPED" ? "var(--amber)" : "var(--red)" }}>{last.status}</b>
          {last.reason ? ` — ${last.reason}` : ""}
          {typeof last.observed === "number" ? ` · ${last.observed} observed` : ""}
        </div>
      )}
      {message && <div className="dim" style={{ fontSize: 11, marginTop: 6 }}>{message}</div>}
      {status?.boundary && <div className="faint" style={{ fontSize: 10.5, marginTop: 6 }}>{status.boundary}</div>}
    </Panel>
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

/* ── Safety: the operator STOP switch (spec §30) ── */
function SafetyStopPanel() {
  const safety = usePollingApi(() => apiNetworkCryptoSafety(), 15000);
  const state = safety.data as NetworkSafetyState | null;
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const toggle = async () => {
    setBusy(true);
    setMsg(null);
    const result = await apiNetworkCryptoStop(!state?.engaged, !state?.engaged ? "operator emergency stop" : undefined);
    if (result.data) {
      setMsg(result.data.engaged ? "active observation stopped" : "active observation released");
      safety.run();
    } else {
      setMsg(result.error || "safety switch failed");
    }
    setBusy(false);
  };
  return (
    <Panel
      title="Observation safety — emergency stop"
      sub="IDS alert → STOP, never disable the IDS: active probes are refused before any socket opens; passive ingest and config import keep running"
      className="mt"
    >
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <Badge tone={state?.engaged ? "red" : "green"}>{state?.engaged ? "STOPPED" : "ACTIVE OBSERVATION PERMITTED"}</Badge>
        {state?.engaged && <span className="dim" style={{ fontSize: 11 }}>{state.reason} · {state.engaged_by}</span>}
        <button className={state?.engaged ? "btn sm primary" : "btn sm"} type="button" onClick={() => void toggle()} disabled={busy}>
          {busy ? "…" : state?.engaged ? "Release stop" : "Stop observation"}
        </button>
        {msg && <span className="dim" style={{ fontSize: 11 }}>{msg}</span>}
      </div>
      <div className="faint" style={{ fontSize: 10.5, marginTop: 8 }}>
        One local switch per tenant · passive metadata ingest stays available · not a distributed kill switch
      </div>
    </Panel>
  );
}

/* ── Port ≠ protocol: detect what the endpoint actually speaks (spec §5) ── */
function protocolTone(protocol: string): string {
  if (protocol === "TLS") return "green";
  if (protocol === "SSH" || protocol === "POSTGRESQL" || protocol === "MYSQL") return "violet";
  return "slate";
}

function ProtocolProbePanel() {
  const [endpoints, setEndpoints] = useState("");
  const [detectOnly, setDetectOnly] = useState(true);
  const [result, setResult] = useState<CryptoProbeResponse | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async () => {
    setBusy(true);
    setMsg(null);
    const list = endpoints.split(/[\n,]/).map((item) => item.trim()).filter(Boolean);
    if (!list.length) {
      setMsg("Add at least one approved endpoint (host:port).");
      setBusy(false);
      return;
    }
    const response = await apiNetworkCryptoProbe(list, { detect_only: detectOnly });
    if (response.data) setResult(response.data);
    else setMsg(response.error || "probe refused");
    setBusy(false);
  };

  const detections: ProtocolDetection[] = result?.detections ?? [];
  const summary = result?.detection_summary;
  return (
    <Panel
      title="Service discovery — port ≠ protocol"
      sub="detection reads only what the endpoint answers; the protocol-specific observation is checked again against the approved operations"
      className="mt"
    >
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <input
          value={endpoints}
          onChange={(event) => setEndpoints(event.target.value)}
          aria-label="Approved endpoints"
          placeholder="10.20.10.15:443, 10.20.10.30:22"
          style={{ flex: "1 1 260px", fontSize: 11, padding: "6px 8px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)", color: "var(--text)" }}
        />
        <label className="dim" style={{ fontSize: 11, display: "flex", gap: 6, alignItems: "center" }}>
          <input type="checkbox" checked={detectOnly} onChange={(event) => setDetectOnly(event.target.checked)} />
          detection only
        </label>
        <button className="btn sm" type="button" onClick={() => void run()} disabled={busy}>{busy ? "Probing…" : "Detect + observe"}</button>
        {msg && <span className="dim" style={{ fontSize: 11 }}>{msg}</span>}
      </div>

      {summary && (
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 10 }}>
          {Object.entries(summary.by_protocol).map(([protocol, count]) => (
            <Badge key={protocol} tone={protocolTone(protocol)}>{protocol} · {count}</Badge>
          ))}
          {summary.unknown > 0 && <Badge tone="amber">{summary.unknown} UNKNOWN</Badge>}
          {summary.port_protocol_mismatches.length > 0 && <Badge tone="cyan">{summary.port_protocol_mismatches.length} port/protocol mismatch</Badge>}
        </div>
      )}

      {detections.length > 0 && (
        <div style={{ marginTop: 10 }}>
          <Table
            head={["endpoint", "detected", "method", "port guess", "TLS", "attempts"]}
            rows={detections.map((item) => [
              <span className="mono" style={{ fontSize: 11 }}>{item.endpoint ?? `${item.host}:${item.port}`}</span>,
              <Badge tone={protocolTone(item.detected)}>{item.detected}</Badge>,
              <span className="faint" style={{ fontSize: 10 }}>{item.detection_method}</span>,
              <span style={{ fontSize: 10.5 }}>
                {item.service_guess.name}
                {item.port_matches_protocol === false && <span style={{ color: "var(--cyan)" }}> · mismatch</span>}
              </span>,
              <span className="mono" style={{ fontSize: 10 }}>{item.tls?.tls_version ?? "—"}</span>,
              <span className="faint" style={{ fontSize: 10 }}>{item.attempts.map((attempt) => attempt.probe).join(" → ") || "—"}</span>,
            ])}
          />
        </div>
      )}

      {result && (
        <div style={{ marginTop: 10, display: "flex", gap: 6, flexWrap: "wrap" }}>
          <Badge tone="green">{result.network_summary.observed} observed</Badge>
          <Badge tone="amber">{result.network_summary.not_observed} not observed</Badge>
          <Badge tone="violet">{result.cbom.asset_count} CBOM assets</Badge>
          {result.scope_refusals.map((refusal) => (
            <Badge key={`${refusal.endpoint}-${refusal.protocol}`} tone="red">{refusal.protocol} not approved · {refusal.error}</Badge>
          ))}
        </div>
      )}
    </Panel>
  );
}

/* ── Policy, risk and PQC readiness over what was observed (spec §28–§31) ── */
function severityTone(severity: string): string {
  if (severity === "critical") return "red";
  if (severity === "high") return "amber";
  if (severity === "medium") return "cyan";
  return "slate";
}

function verdictTone(verdict: string): string {
  if (verdict === "FAIL") return "red";
  if (verdict === "PASS") return "green";
  return "amber";
}

function RiskFindingList({ findings }: { findings: NetworkRiskFinding[] }) {
  if (!findings.length) return <div className="dim" style={{ fontSize: 11 }}>no failed rule</div>;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6, marginTop: 8 }}>
      {findings.map((finding) => (
        <div key={`${finding.rule_id}-${finding.endpoint}-${finding.evidence_id}`} style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
          <Badge tone={severityTone(finding.severity)}>{finding.severity}</Badge>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 11 }}>
              <span className="mono" style={{ color: "var(--cyan)" }}>{finding.rule_id}</span>
              <span className="dim"> · {finding.endpoint ?? "—"}</span>
            </div>
            <div className="dim" style={{ fontSize: 11 }}>{finding.message}</div>
          </div>
        </div>
      ))}
    </div>
  );
}

function NetworkRiskPanel() {
  const risk = usePollingApi(() => apiNetworkCryptoRisk({}), 30000);
  const report = risk.data as NetworkRiskReport | null;
  const pqc = report?.pqc;
  return (
    <Panel
      title="Crypto risk & PQC readiness — network transport"
      sub="only negotiated parameters are judged; an endpoint nobody observed stays UNKNOWN and is never counted as compliant"
      className="mt"
    >
      {!report && <div className="dim" style={{ fontSize: 12 }}>{risk.error ? risk.error : "evaluating stored observations…"}</div>}
      {report && (
        <>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
            <Badge tone={verdictTone(report.verdict)}>{report.verdict}</Badge>
            <Badge tone="slate">{report.summary.endpoints} endpoints</Badge>
            <Badge tone="red">{report.summary.failed} failed</Badge>
            <Badge tone="amber">{report.summary.unknown} UNKNOWN</Badge>
            <span className="faint" style={{ fontSize: 10.5 }}>
              baseline {report.policy.policy_id} v{report.policy.version} · TLS ≥ {report.policy.min_tls_version}
              {report.policy.require_forward_secrecy ? " · forward secrecy required" : ""}
            </span>
          </div>

          <RiskFindingList findings={report.failed.slice(0, 12)} />

          {pqc && (
            <div style={{ marginTop: 12 }}>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
                <span className="dim" style={{ fontSize: 11 }}>post-quantum readiness</span>
                <Badge tone={pqc.verdict === "HYBRID_KEX_PRESENT" ? "green" : pqc.verdict === "NOT_OBSERVED" ? "slate" : "amber"}>
                  {pqc.verdict}
                </Badge>
                <Badge tone="violet">{pqc.summary.hybrid_kex} hybrid</Badge>
                <Badge tone="slate">{pqc.summary.classical_only} classical</Badge>
                <Badge tone="amber">{pqc.summary.not_observed} not observed</Badge>
              </div>
              <div className="faint" style={{ fontSize: 10.5, marginTop: 6 }}>
                classical key agreement only → recorded traffic is harvest-now-decrypt-later exposed; certificates are judged separately
              </div>
            </div>
          )}

          {report.coverage_gaps.length > 0 && (
            <div className="faint" style={{ fontSize: 10.5, marginTop: 10 }}>
              {report.coverage_gaps.length} coverage gap(s): declared or unobserved endpoints whose crypto is UNKNOWN, not clean
            </div>
          )}
        </>
      )}
    </Panel>
  );
}


/* ── Evidence integrity: chain verification, anchor receipts, single-writer lease ── */
function EvidenceIntegrityPanel() {
  const integrity = usePollingApi(() => apiNetworkCryptoIntegrity(), 30000);
  const [anchorStatus, setAnchorStatus] = useState<NetworkAnchorStatus | null>(null);
  const [receipt, setReceipt] = useState<NetworkAnchorReceipt | null>(null);
  const [verification, setVerification] = useState<NetworkAnchorVerification | null>(null);
  const [lease, setLease] = useState<NetworkWatchLease | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const report = integrity.data as NetworkEvidenceIntegrity | null;

  const loadStatus = () => {
    apiNetworkAnchorStatus().then((result) => {
      if (result.ok) setAnchorStatus(result.data as NetworkAnchorStatus);
    });
    apiNetworkWatchLease().then((result) => {
      if (result.ok) setLease(result.data as NetworkWatchLease);
    });
  };
  useEffect(loadStatus, []);

  const createAnchor = async () => {
    setBusy(true);
    setNotice(null);
    const result = await apiNetworkCreateAnchor("operator anchor from dashboard");
    setBusy(false);
    if (!result.ok) {
      setNotice(result.error ?? "anchor refused");
      return;
    }
    const created = (result.data as { receipt: NetworkAnchorReceipt }).receipt;
    setReceipt(created);
    const verified = await apiNetworkVerifyAnchor(created);
    if (verified.ok) setVerification(verified.data as NetworkAnchorVerification);
    loadStatus();
  };

  const anchorTone = (status?: string) =>
    status === "HEAD_INTACT" || status === "ADVANCED" ? "green" : status === "HISTORY_REWRITTEN" || status === "SIGNATURE_INVALID" ? "red" : "amber";

  return (
    <Panel
      title="Evidence integrity — chain, anchor, single writer"
      sub="the chain detects a rewritten record inside this database; an exported anchor receipt detects a rewritten database"
      className="mt"
    >
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
        {report ? (
          <Badge tone={report.verified ? "green" : "red"}>
            {report.verified ? "CHAIN VERIFIED" : report.reason ?? "CHAIN BROKEN"}
          </Badge>
        ) : (
          <Badge tone="slate">chain: {integrity.error ? "unavailable" : "checking…"}</Badge>
        )}
        {report && <Badge tone="slate">{report.entries} entries</Badge>}
        {report && report.tampered_records.length > 0 && <Badge tone="red">{report.tampered_records.length} tampered</Badge>}
        {report && report.unverifiable_entries.length > 0 && <Badge tone="amber">{report.unverifiable_entries.length} unverifiable</Badge>}
        <Badge tone={anchorStatus?.key.configured ? "cyan" : "amber"}>
          anchor key {anchorStatus?.key.configured ? anchorStatus.key.source : "NOT CONFIGURED"}
        </Badge>
        {anchorStatus && <Badge tone="violet">{anchorStatus.anchors} anchor receipt(s)</Badge>}
        {lease && (
          <Badge tone={lease.lease.held ? "green" : "slate"}>
            lease {lease.lease.held ? lease.lease.holder : "free"} · {lease.mode}
          </Badge>
        )}
      </div>

      <div style={{ display: "flex", gap: 8, marginTop: 10, alignItems: "center", flexWrap: "wrap" }}>
        <button className="btn btn-sm" disabled={busy || !anchorStatus?.key.configured} onClick={createAnchor}>
          {busy ? "signing…" : "sign chain head"}
        </button>
        {verification && (
          <Badge tone={anchorTone(verification.status)}>{verification.status}</Badge>
        )}
        {receipt && (
          <span className="mono faint" style={{ fontSize: 10.5 }}>
            seq {receipt.chain.seq} · {receipt.chain.head.slice(0, 16)}… · {receipt.signature_scheme}
          </span>
        )}
      </div>

      {notice && <div style={{ color: "var(--red, #f87171)", fontSize: 11, marginTop: 8 }}>{notice}</div>}
      {anchorStatus && !anchorStatus.key.configured && (
        <div className="faint" style={{ fontSize: 10.5, marginTop: 8 }}>
          anchoring refused until CRYPTOSCAN_ANCHOR_KEY is set outside the database — an unsigned anchor is a claim, not evidence
        </div>
      )}
      {verification && (
        <div className="dim" style={{ fontSize: 11, marginTop: 8 }}>{verification.reason}</div>
      )}
      <div className="faint" style={{ fontSize: 10.5, marginTop: 8 }}>
        {report?.boundary ?? "the chain is local to this database; export the receipt to make it external"}
      </div>
    </Panel>
  );
}

/* ── Hop attribution: where TLS terminates (spec §15–§17) ── */
function AttributionStrip({ path }: { path: NetworkCryptoPathResponse | null }) {
  const attr = path?.attribution;
  if (!attr) return null;
  const verdictTone = (verdict: string) =>
    verdict === "TERMINATES_AND_REORIGINATES" ? "cyan" : verdict === "PASS_THROUGH" ? "green" : "amber";
  return (
    <div style={{ marginTop: 10, display: "flex", flexDirection: "column", gap: 6 }}>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
        <span className="kicker">hop roles</span>
        {Object.entries(attr.roles).map(([node, role]) => (
          <span
            key={node}
            className="mono"
            style={{ fontSize: 10, padding: "2px 7px", borderRadius: 999, border: "1px solid var(--line)", background: "var(--bg-2)" }}
            title={`${node} · ${attr.role_sources[node] || "UNDECLARED"}`}
          >
            {role}
            {attr.role_sources[node] === "INFERRED_FROM_LABEL" && <span style={{ color: "var(--amber)" }}> ·inferred</span>}
          </span>
        ))}
      </div>
      {attr.termination_points.length > 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {attr.termination_points.map((point) => (
            <div
              key={point.node}
              style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", padding: "6px 10px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--panel)" }}
            >
              <Badge tone={verdictTone(point.verdict)}>{point.verdict.replace(/_/g, " ")}</Badge>
              <span className="mono" style={{ fontSize: 11 }}>{point.node}</span>
              <span className="dim" style={{ fontSize: 11 }}>
                {point.client_side_from ?? "client"} → <b>{point.node}</b> → {point.internal_side_to ?? "?"}
              </span>
              <span className="faint" style={{ fontSize: 10.5 }}>{point.reason}</span>
            </div>
          ))}
        </div>
      )}
      {attr.sidecars.length > 0 && (
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          {attr.sidecars.map((sidecar) => (
            <Badge key={sidecar.node} tone="violet">sidecar {sidecar.node} — not app crypto</Badge>
          ))}
        </div>
      )}
      {attr.unattributed_nodes.length > 0 && (
        <span className="faint" style={{ fontSize: 10.5 }}>role UNKNOWN: {attr.unattributed_nodes.join(", ")}</span>
      )}
    </div>
  );
}

/* ── Evidence integrity: tamper-evident hash chain (spec §24) ── */
function EvidenceIntegrityStrip() {
  const integrity = usePollingApi(() => apiNetworkCryptoIntegrity(), 30000);
  const data = integrity.data as NetworkEvidenceIntegrity | null;
  if (!data) return null;
  const tone = data.verified ? "green" : data.entries === 0 ? "slate" : "red";
  return (
    <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", marginBottom: 12, padding: "8px 12px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--panel)" }}>
      <Badge tone={tone}>{data.verified ? "CHAIN VERIFIED" : data.entries === 0 ? "NO EVIDENCE YET" : "CHAIN BROKEN"}</Badge>
      <span className="dim" style={{ fontSize: 11 }}>{data.entries} chained · {data.checked_records} re-hashed</span>
      <span className="mono faint" style={{ fontSize: 10 }}>head {data.head_hash.slice(0, 16)}…</span>
      {data.tampered_records.length > 0 && <Badge tone="red">{data.tampered_records.length} tampered</Badge>}
      {data.unverifiable_entries.length > 0 && <Badge tone="amber">{data.unverifiable_entries.length} unverifiable</Badge>}
      <span className="faint" style={{ fontSize: 10 }}>{data.anchoring} · not distributed</span>
    </div>
  );
}

/* ── Message layer: Kafka/MQ transport crypto vs message crypto (spec §19) ── */
function MessageLayerPanel() {
  const layer = usePollingApi(() => apiNetworkMessageLayer(5), 20000);
  const data = layer.data as MessageLayerResponse | null;
  const summary = data?.summary;
  const records: MessageLayerRecord[] = data?.evidence ?? [];
  const [endpoint, setEndpoint] = useState("kafka-01.bank:9093");
  const [listener, setListener] = useState("SASL_SSL");
  const [mechanism, setMechanism] = useState("SCRAM-SHA-512");
  const [payloadClaim, setPayloadClaim] = useState("");
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  const submit = async () => {
    setSaving(true);
    setMsg(null);
    const broker: Record<string, unknown> = {
      endpoint,
      protocol: "KAFKA",
      listener_security: listener,
      sasl_mechanism: mechanism,
      client_authentication: "mTLS",
      authorization_model: "ACL",
    };
    if (payloadClaim.trim()) {
      broker.payload_encryption = payloadClaim.trim();
      broker.payload_encryption_source = "BANK_DECLARATION";
    }
    const result = await apiObserveNetworkMessageLayer([broker]);
    if (result.data) {
      setMsg(`stored ${result.data.stored} listener · ${result.data.active_packets} active packets`);
      layer.run();
    } else {
      setMsg(result.error || "ingest failed");
    }
    setSaving(false);
  };

  return (
    <Panel
      title="Message layer — Kafka / MQ crypto"
      sub="transport TLS and SASL are not message encryption: a TLS listener says nothing about whether payloads are encrypted"
      className="mt"
    >
      <div className="grid cols-4" style={{ marginBottom: 12 }}>
        {[
          ["listeners", summary?.records ?? 0, undefined],
          ["transport encrypted", summary?.transport_encrypted ?? 0, "var(--green)"],
          ["transport plaintext", summary?.transport_plaintext ?? 0, (summary?.transport_plaintext ?? 0) ? "var(--red)" : undefined],
          ["payload DECLARED / UNKNOWN", `${summary?.payload_encryption_states?.DECLARED ?? 0} / ${summary?.payload_encryption_states?.UNKNOWN ?? 0}`, "var(--amber)"],
        ].map(([k, v, color]) => (
          <div className="kpi" key={k as string}>
            <span className="k">{k}</span>
            <span className="v" style={{ fontSize: 20, color: color as string | undefined }}>{v as string | number}</span>
          </div>
        ))}
      </div>

      {records.length === 0 ? (
        <div className="dim" style={{ fontSize: 13, padding: "8px 4px" }}>
          No broker declared — an unobserved listener is <b>UNKNOWN</b>, not “no encryption”.
        </div>
      ) : (
        <Table
          head={["endpoint", "listener", "SASL", "client auth", "transport", "message payload", "issues"]}
          rows={records.map((r) => [
            <span className="mono" style={{ fontSize: 11 }}>{r.target.endpoint}</span>,
            <Badge tone={r.listener.security === "SASL_SSL" || r.listener.security === "SSL" ? "green" : r.listener.security === "UNKNOWN" ? "slate" : "red"}>
              {r.listener.security}
            </Badge>,
            <span className="mono" style={{ fontSize: 10.5 }}>{r.sasl.mechanism}</span>,
            <span style={{ fontSize: 11 }}>{r.client_authentication}</span>,
            <Badge tone={r.listener.transport_encrypted ? "green" : r.listener.transport_encrypted === false ? "red" : "slate"}>
              {r.listener.transport_encrypted ? "TLS" : r.listener.transport_encrypted === false ? "CLEARTEXT" : "UNKNOWN"}
            </Badge>,
            <Badge tone={r.payload_encryption.status === "DECLARED" ? "violet" : "slate"}>
              {r.payload_encryption.status}{r.payload_encryption.algorithm ? ` · ${r.payload_encryption.algorithm}` : ""}
            </Badge>,
            <span className="faint" style={{ fontSize: 10 }}>{r.policy_issues.length ? r.policy_issues.join(", ") : "—"}</span>,
          ])}
        />
      )}

      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginTop: 12 }}>
        <input
          value={endpoint}
          onChange={(event) => setEndpoint(event.target.value)}
          aria-label="Broker endpoint"
          placeholder="broker:port"
          style={{ flex: "1 1 160px", fontSize: 11, padding: "6px 8px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)", color: "var(--text)" }}
        />
        <select value={listener} onChange={(event) => setListener(event.target.value)} aria-label="Listener security" className="input" style={{ fontSize: 11 }}>
          {["SASL_SSL", "SSL", "SASL_PLAINTEXT", "PLAINTEXT"].map((option) => <option key={option} value={option}>{option}</option>)}
        </select>
        <select value={mechanism} onChange={(event) => setMechanism(event.target.value)} aria-label="SASL mechanism" className="input" style={{ fontSize: 11 }}>
          {["SCRAM-SHA-512", "SCRAM-SHA-256", "GSSAPI", "OAUTHBEARER", "PLAIN", "NONE"].map((option) => <option key={option} value={option}>{option}</option>)}
        </select>
        <input
          value={payloadClaim}
          onChange={(event) => setPayloadClaim(event.target.value)}
          aria-label="Declared payload encryption"
          placeholder="declared payload crypto (optional)"
          style={{ flex: "1 1 180px", fontSize: 11, padding: "6px 8px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)", color: "var(--text)" }}
        />
        <button className="btn sm" type="button" onClick={() => void submit()} disabled={saving}>
          {saving ? "Recording…" : "Record listener"}
        </button>
        {msg && <span className="dim" style={{ fontSize: 11 }}>{msg}</span>}
      </div>
      <div className="faint" style={{ fontSize: 10.5, marginTop: 6 }}>
        A declared payload algorithm is stored as <b>DECLARED</b> with its source — network telemetry cannot observe message encryption.
      </div>
    </Panel>
  );
}

/* ── Cross-layer correlation: STATIC + RUNTIME + NETWORK (spec §26, §27) ── */
function CrossLayerCorrelationPanel() {
  const [service, setService] = useState("payments-api");
  const [host, setHost] = useState("payments.bank");
  const [declaredTls, setDeclaredTls] = useState("TLS1.2");
  const [report, setReport] = useState<NetworkCorrelationResponse | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async () => {
    setBusy(true);
    setMsg(null);
    const result = await apiNetworkCryptoCorrelate({
      services: [{ name: service, hosts: [host], endpoints: [`${host}:443`] }],
      static: declaredTls.trim()
        ? [{ service, kind: "tls_version", role: "network-transport", value: declaredTls.trim(), source: "declared policy" }]
        : [],
      use_latest_network_evidence: true,
    });
    if (result.data) setReport(result.data);
    else setMsg(result.error || "correlation failed");
    setBusy(false);
  };

  const layerTone = (present: boolean) => (present ? "green" : "amber");

  return (
    <Panel
      title="Cross-layer correlation — static + runtime + network"
      sub="each layer keeps its own facts; only the same artifact (TLS policy, certificate identity) is compared — transport crypto never stands in for application crypto"
      className="mt"
    >
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginBottom: 12 }}>
        <input value={service} onChange={(event) => setService(event.target.value)} aria-label="Service name" placeholder="service" style={{ flex: "1 1 140px", fontSize: 11, padding: "6px 8px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)", color: "var(--text)" }} />
        <input value={host} onChange={(event) => setHost(event.target.value)} aria-label="Service host" placeholder="host" style={{ flex: "1 1 140px", fontSize: 11, padding: "6px 8px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)", color: "var(--text)" }} />
        <input value={declaredTls} onChange={(event) => setDeclaredTls(event.target.value)} aria-label="Declared TLS version" placeholder="declared TLS (e.g. TLS1.2)" style={{ flex: "0 1 150px", fontSize: 11, padding: "6px 8px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)", color: "var(--text)" }} />
        <button className="btn sm" type="button" onClick={() => void run()} disabled={busy}>{busy ? "Correlating…" : "Correlate"}</button>
        {msg && <span className="dim" style={{ fontSize: 11 }}>{msg}</span>}
      </div>

      {report && (
        <>
          <div className="grid cols-4" style={{ marginBottom: 12 }}>
            {[
              ["match", report.summary.matches, "var(--green)"],
              ["mismatch (review)", report.summary.mismatches, report.summary.mismatches ? "var(--amber)" : undefined],
              ["not comparable", report.summary.not_comparable, undefined],
              ["no network evidence", report.summary.services_without_network_evidence, report.summary.services_without_network_evidence ? "var(--amber)" : undefined],
            ].map(([k, v, color]) => (
              <div className="kpi" key={k as string}>
                <span className="k">{k}</span>
                <span className="v" style={{ color: color as string | undefined }}>{v as number}</span>
              </div>
            ))}
          </div>
          {report.services.map((item) => (
            <div key={item.service} style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
                <span className="mono" style={{ fontSize: 12 }}>{item.service}</span>
                {["STATIC", "RUNTIME", "NETWORK"].map((layer) => (
                  <Badge key={layer} tone={layerTone(item.layers_present.includes(layer))}>
                    {layer}{item.layers_present.includes(layer) ? "" : " · NOT_OBSERVED"}
                  </Badge>
                ))}
              </div>
              {item.comparisons.length === 0 ? (
                <span className="faint" style={{ fontSize: 11 }}>no comparable facts yet — supply a declared policy or run a network observation</span>
              ) : (
                item.comparisons.map((comparison, index) => (
                  <div key={index} style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", padding: "6px 10px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--panel)" }}>
                    <Badge tone={comparison.result === "MATCH" ? "green" : comparison.result === "MISMATCH" ? "amber" : "slate"}>{comparison.result}</Badge>
                    <span className="mono" style={{ fontSize: 11 }}>{comparison.kind}</span>
                    <span className="dim" style={{ fontSize: 11 }}>{comparison.left.layer} {String(comparison.left.value)}</span>
                    <span className="faint">↔</span>
                    <span className="dim" style={{ fontSize: 11 }}>{comparison.right.layer} {String(comparison.right.value)}</span>
                    {comparison.reason && <span className="faint" style={{ fontSize: 10 }}>{comparison.reason}</span>}
                  </div>
                ))
              )}
            </div>
          ))}
          <div className="faint" style={{ fontSize: 10.5, marginTop: 8 }}>{report.boundary}</div>
        </>
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
      <EvidenceIntegrityStrip />
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
          No observations yet — approve a scope above, then start the observation worker or record a listener.
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
        {path && <AttributionStrip path={path} />}
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
      <SafetyStopPanel />
      <NetworkCryptoIntelligencePanel />
      <ProtocolProbePanel />
      <NetworkRiskPanel />
      <EvidenceIntegrityPanel />
      <MessageLayerPanel />
      <CrossLayerCorrelationPanel />
      <ScopeImportPanel />
      <CryptoWatchPanel />

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
