import React, { useEffect, useMemo, useState } from "react";
import {
  Badge, Feed, Kpi, PageHead, Panel, Stat, Table, Tabs, Code,
} from "../components/ui.jsx";
import { useRealtime, useRealtimeRefresh, severityOf } from "../lib/realtime.js";
import { usePollingApi } from "../lib/apiUi.jsx";
import {
  apiTechBomLive, apiTechBomSnapshot, apiTechBomVersions, apiTechBomCompare,
  apiTechBomExport, apiTechBomExportCsv, apiTechBomExportRaw, fmtSnapshotId,
  apiTechBomSchedules, apiTechBomScheduleCreate, apiTechBomScheduleDelete,
  apiTechBomScheduleRun, apiTechBomRunDue, apiTechBomExportRuns,
  apiTechBomEvidence, apiTechBomVendor,
  apiTechBomAssurance, apiTechBomAdmission, apiTechBomVex, apiTechBomXbom, apiTechBomRuntimeVerify,
  TechBomState, TechBomDiff, TechBomVersion, TechBomComponent, TechBomExport,
  TechBomSchedule, TechBomRun, TechBomEvidence, TechBomVendorInventory,
  TechBomAssurance, TechBomAdmission, TechBomVex, TechBomXbom, TechBomRuntimeVerify,
} from "../lib/api.js";

/* Live Asset Intelligence — one asset model materialized into SBOM / CBOM /
   HBOM / Vendor views (the unified Technology BOM). Top counts, an interactive
   dependency graph, a live event feed, version history + compare, and the full
   Export Service (JSON/CSV/CycloneDX/XML/SPDX/PDF, with filters), scheduled
   exports, an evidence package, and a vendor inventory. */

const VIEWS = ["Overview", "Components", "Compare", "Export", "Schedules", "Assurance", "Evidence & Vendor"];

const LAYER_LABELS: Record<string, string> = {
  sbom: "SBOM — Application",
  cbom: "CBOM — Crypto",
  hbom: "HBOM — Hardware",
  vendor: "VBOM — Vendor",
  certificates: "TLS Certificates",
};
const LAYER_TONE: Record<string, string> = {
  sbom: "cyan", cbom: "amber", hbom: "orange", vendor: "violet", certificates: "green",
};

function download(filename: string, text: string, mime: string) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}

/* Simple radial dependency graph from the live layers' components + deps. */
interface GraphNode extends TechBomComponent { layer: string; x: number; y: number }

function BomGraph({ state }: { state: TechBomState }) {
  const components = useMemo<Array<GraphNode>>(() => {
    const all: Array<GraphNode> = [];
    for (const layer of ["sbom", "cbom", "hbom", "vendor", "certificates"] as const) {
      const L = state.layers?.[layer];
      for (const c of L?.components ?? []) all.push({ ...c, layer, x: 0, y: 0 });
    }
    const cx = 420, cy = 250, r = Math.min(210, Math.max(90, all.length * 16));
    return all.map((c, i) => {
      const ang = all.length === 1 ? -Math.PI / 2 : (i / all.length) * Math.PI * 2 - Math.PI / 2;
      return { ...c, x: cx + r * Math.cos(ang), y: cy + r * Math.sin(ang) * 0.68 };
    });
  }, [state.layers]);

  const edges = useMemo<Array<{ a: GraphNode; b: GraphNode }>>(() => {
    const map = new Map(components.map((c) => [c["bom-ref"], c]));
    const deps = state.dependency_count ?? 0;
    const pairs: Array<[string, string]> = [];
    const names: string[] = components.map((c) => c["bom-ref"] ?? "").filter((x): x is string => Boolean(x));
    for (let i = 0; i < deps && i < names.length - 1; i++) pairs.push([names[i], names[i + 1]]);
    const edges: Array<{ a: GraphNode; b: GraphNode }> = [];
    for (const [a, b] of pairs) {
      const na = map.get(a), nb = map.get(b);
      if (na && nb) edges.push({ a: na, b: nb });
    }
    return edges;
  }, [components, state.dependency_count]);

  const color = (layer: string) =>
    ({ sbom: "#00d4ff", cbom: "#f59e0b", hbom: "#f97316", vendor: "#8b7cf6", certificates: "#22c55e" }[layer] || "#64748b");

  if (components.length === 0) return <div className="empty">No components — run a scan to populate the BOM.</div>;
  return (
    <svg viewBox="0 0 840 500" width="100%">
      {edges.map((e, i) => (
        <line key={i} x1={e.a.x} y1={e.a.y} x2={e.b.x} y2={e.b.y}
          stroke="rgba(120,140,170,.35)" strokeWidth="1.4" />
      ))}
      {components.map((c, i) => (
        <g key={i}>
          <circle cx={c.x} cy={c.y} r={14} fill={color(c.layer)} fillOpacity={0.85} />
          <text x={c.x} y={c.y + 4} textAnchor="middle" fontSize="9" fill="#0b1220" fontWeight="600">
            {(c.name || c["bom-ref"] || "").slice(0, 3).toUpperCase()}
          </text>
          <text x={c.x} y={c.y + 30} textAnchor="middle" fontSize="9.5" fill="#e5e7eb">
            {c.name || c["bom-ref"] || ""}
          </text>
        </g>
      ))}
    </svg>
  );
}

function Comparison({ from, to, diff }: { from: TechBomVersion | null; to: TechBomVersion | null; diff: TechBomDiff | null }) {
  if (!from || !to) return <div className="empty">Pick two versions, then run Compare.</div>;
  if (!diff) return <div className="empty">No difference computed.</div>;
  return (
    <div>
      <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 12 }}>
        <Badge tone="cyan">v{from.version} → v{to.version}</Badge>
        {diff.changed ? <Badge tone="amber">changed</Badge> : <Badge tone="green">identical</Badge>}
      </div>
      <Table
        head={["Layer", "Added", "Removed", "From", "To"]}
        rows={Object.entries(diff.layers).map(([layer, d]) => [
          <span key={layer}>{LAYER_LABELS[layer] || layer}</span>,
          <span key="a" style={{ color: d.added_count ? "var(--green)" : undefined }}>{d.added_count}</span>,
          <span key="r" style={{ color: d.removed_count ? "var(--red)" : undefined }}>{d.removed_count}</span>,
          d.from_count, d.to_count,
        ])}
      />
      {(Object.values(diff.layers).some((d) => d.added.length || d.removed.length)) && (
        <div style={{ marginTop: 12 }}>
          {Object.entries(diff.layers).map(([layer, d]) => (
            (d.added.length || d.removed.length) ? (
              <div key={layer} style={{ marginBottom: 8 }}>
                <div className="kicker">{LAYER_LABELS[layer] || layer}</div>
                {d.added.map((c, i) => <code key={`a${i}`} className="badge">+ {c["bom-ref"] || c.name}</code>)}
                {d.removed.map((c, i) => <code key={`r${i}`} className="badge">− {c["bom-ref"] || c.name}</code>)}
              </div>
            ) : null
          ))}
        </div>
      )}
    </div>
  );
}

function vexTone(status: string): string {
  return ({ not_affected: "green", fixed: "cyan", affected: "red", under_review: "amber" } as Record<string, string>)[status] || "default";
}
function prioTone(p: string): string {
  return ({ P0: "red", P1: "amber", P2: "cyan", P3: "default" } as Record<string, string>)[p] || "default";
}

function AssuranceTab({ data }: { data: TechBomAssurance | null }) {
  if (!data) return <div className="empty">Loading Assurance & Control…</div>;

  const vex = data.vex;
  const xbom = data.xbom;
  const admission = data.admission;
  const runtime = data.runtime_verify;
  const admitTone = admission?.decision === "FAIL" ? "red" : admission?.decision === "WARN" ? "amber" : "green";

  return (
    <div style={{ display: "grid", gap: 18 }}>
      {/* Admission gate */}
      <Panel title="Pre-Deploy Admission Gate" sub="PASS / WARN / FAIL over the materialized BOM" frame>
        {admission ? (
          <div>
            <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 10, flexWrap: "wrap" }}>
              <Badge tone={admitTone}>{admission.decision}</Badge>
              <Stat label="Blocking" value={admission.blocking_count} tone="red" />
              <Stat label="Warnings" value={admission.warn_count} tone="amber" />
              <Stat label="Admitted" value={admission.admitted ? "yes" : "no"} />
            </div>
            <Table
              head={["BOM-Ref", "Algorithm", "Purpose", "Reason", "Verdict"]}
              rows={[
                ...(admission.blocking ?? []).map((b) => [
                  <code key="r">{b.bom_ref || "—"}</code>, b.algorithm || "—", b.purpose || "—", b.reason,
                  <Badge key="v" tone="red">BLOCK</Badge>,
                ]),
                ...(admission.warnings ?? []).map((w) => [
                  <code key="r">{w.bom_ref || "—"}</code>, w.algorithm || "—", w.purpose || "—", w.reason,
                  <Badge key="v" tone="amber">WARN</Badge>,
                ]),
              ]}
            />
          </div>
        ) : <div className="empty">No admission decision yet.</div>}
      </Panel>

      {/* VEX */}
      <Panel title="VEX — Vulnerability Prioritization" sub="CycloneDX VEX lifecycle + exploitability-weighted priority" frame>
        {vex ? (
          <div>
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 10 }}>
              <Stat label="Total" value={vex.total} tone="cyan" />
              <Stat label="Affected" value={vex.affected} tone="red" />
              <Stat label="Not affected" value={vex.not_affected} tone="green" />
              <Stat label="Fixed" value={vex.fixed} tone="cyan" />
              <Stat label="Under review" value={vex.under_review} tone="amber" />
            </div>
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 10 }}>
              {(Object.entries(vex.by_priority)).map(([p, n]) => <Badge key={p} tone={prioTone(p)}>{p}: {n}</Badge>)}
            </div>
            <Table
              head={["CVE", "Package", "Severity", "Exploitability", "VEX", "Priority", ""]}
              rows={vex.findings.slice(0, 30).map((f) => [
                <code key="c">{f.cve}</code>,
                f.package || "—",
                <Badge key="s" tone={f.severity === "CRITICAL" ? "red" : f.severity === "HIGH" ? "amber" : "cyan"}>{f.severity || "UNKNOWN"}</Badge>,
                `${(f.exploitability * 100).toFixed(0)}%`,
                <Badge key="v" tone={vexTone(f.vex_status)}>{f.vex_status}</Badge>,
                <Badge key="p" tone={prioTone(f.priority)}>{f.priority}</Badge>,
                f.component_is_blocking ? <Badge key="b" tone="red">blocking</Badge> : f.component_is_weak ? <Badge key="w" tone="amber">weak</Badge> : <span key="n">—</span>,
              ])}
            />
          </div>
        ) : <div className="empty">No vulnerabilities recorded — run a scan that populates the CVE table.</div>}
      </Panel>

      {/* xBOM correlation */}
      <Panel title="xBOM Correlation" sub="CBOM crypto → SBOM app → HBOM hardware → VBOM vendor → business process" frame>
        {xbom && xbom.count ? (
          <div>
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 10 }}>
              <Stat label="Crypto traces" value={xbom.count} tone="amber" />
              <Stat label="Deploy-relevant" value={xbom.deploy_relevant} tone="red" />
              <Stat label="Highest impact (processes)" value={xbom.highest_impact} />
            </div>
            <Table
              head={["Crypto", "Applications", "Hardware", "Vendor", "Processes"]}
              rows={xbom.traces.slice(0, 20).map((t) => [
                <span key="c">
                  <Badge tone={t.crypto.blocking ? "red" : t.crypto.weak ? "amber" : "green"}>{t.crypto.algorithm || "—"}</Badge>
                  {t.crypto.asset ? <span style={{ fontSize: 11, marginLeft: 6 }}>{t.crypto.asset}</span> : null}
                </span>,
                t.applications.length ? t.applications.slice(0, 3).map((a) => <code key={a.name}>{a.name}</code>).reduce<React.ReactNode[]>((acc, el, i) => [...acc, ...(i ? [", "] : []), el], []) : "—",
                t.hardware ? <code key="h">{t.hardware.model}</code> : "—",
                t.vendor ? <code key="v">{t.vendor.name}</code> : "—",
                t.business_processes.length ? t.business_processes.slice(0, 2).map((b) => <code key={b.name}>{b.name}</code>) : "—",
              ])}
            />
          </div>
        ) : <div className="empty">No xBOM correlation yet.</div>}
      </Panel>

      {/* Runtime verification */}
      <Panel title="Runtime Verification" sub="Live runtime observations vs the BOM baseline (continuous drift)" frame>
        {runtime ? (
          <div>
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 10 }}>
              <Stat label="Observed" value={runtime.observed} tone="cyan" />
              <Stat label="Drifted" value={runtime.drifted} tone="red" />
              <Stat label="Runtime-only" value={runtime.runtime_only} tone="amber" />
              <Stat label="Weak at runtime" value={runtime.weak_at_runtime} tone="red" />
              <Stat label="TLS < 1.2" value={runtime.tls_below_1_2} tone="amber" />
            </div>
            <Table
              head={["Host", "Algorithm", "TLS", "Cipher", "Weak", "Drift"]}
              rows={runtime.drift_rows.slice(0, 30).map((r) => [
                <code key="h">{r.hostname || "—"}</code>,
                r.algorithm || "—",
                r.tls_version || "—",
                <code key="c">{(r.cipher_suite || "").slice(0, 40) || "—"}</code>,
                r.weak ? <Badge key="w" tone="red">weak</Badge> : <Badge key="w" tone="green">ok</Badge>,
                r.drift ? <Badge key="d" tone="amber">{r.drift_reason}</Badge> : <Badge key="d" tone="green">baseline</Badge>,
              ])}
            />
          </div>
        ) : <div className="empty">No runtime observations recorded — run a runtime scanner.</div>}
      </Panel>
    </div>
  );
}

export default function LiveAssetIntelligence() {
  const [view, setView] = useState(0);
  const live = usePollingApi(apiTechBomLive, 15000);
  const versions = usePollingApi(apiTechBomVersions, 30000);
  const schedules = usePollingApi(apiTechBomSchedules, 30000);
  const vendor = usePollingApi(apiTechBomVendor, 60000);
  const runs = usePollingApi(apiTechBomExportRuns, 30000);
  const assurance = usePollingApi(apiTechBomAssurance, 30000);
  const rt = useRealtime();

  const [compare, setCompare] = useState<{ from: number; to: number; diff: TechBomDiff | null; loading: boolean }>({ from: 0, to: 0, diff: null, loading: false });
  const [snapshotMsg, setSnapshotMsg] = useState<string | null>(null);
  const [exportFilters, setExportFilters] = useState<{ risk_level: string; key_size_min: string; search: string }>({ risk_level: "", key_size_min: "", search: "" });
  const [evidence, setEvidence] = useState<TechBomEvidence | null>(null);
  const [evidenceMsg, setEvidenceMsg] = useState<string | null>(null);
  const [scheduleForm, setScheduleForm] = useState<{ name: string; frequency: string; fmt: string; layer: string }>({ name: "", frequency: "weekly", fmt: "json", layer: "all" });

  useRealtimeRefresh(live.run, versions.run, schedules.run, runs.run, vendor.run, assurance.run);

  const state: TechBomState | null = (live.data as TechBomState) ?? null;

  useEffect(() => {
    const list = (versions.data as { versions?: TechBomVersion[] })?.versions ?? [];
    if ((!compare.from || !compare.to) && list.length >= 2) {
      setCompare((c) => ({ ...c, from: list[1].version, to: list[0].version }));
    } else if ((!compare.from || !compare.to) && list.length === 1) {
      setCompare((c) => ({ ...c, from: list[0].version, to: list[0].version }));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [versions.data]);

  async function runCompare() {
    if (!compare.from || !compare.to) return;
    setCompare((c) => ({ ...c, loading: true }));
    const r = await apiTechBomCompare(compare.from, compare.to);
    setCompare((c) => ({ ...c, diff: (r.data as TechBomDiff) ?? null, loading: false }));
  }

  async function captureSnapshot() {
    const r = await apiTechBomSnapshot();
    setSnapshotMsg(r.ok && r.data?.recorded
      ? `Snapshot recorded: ${fmtSnapshotId(r.data.snapshot?.snapshot_id)} (v${r.data.snapshot?.version})`
      : r.data?.note || `Snapshot request ${r.ok ? "returned unchanged" : "failed"}`);
    live.run(); versions.run(); schedules.run(); runs.run();
  }

  function exportNow(fmt: string, layer: string, version?: number) {
    void (async () => {
      try {
        const rawFmts = ["csv", "xml", "pdf"];
        if (rawFmts.includes(fmt)) {
          const resp = await apiTechBomExportRaw({ fmt, layer, version, filters: exportFilters });
          const buf = await resp.arrayBuffer();
          download(`technology-bom-${layer}-${version ?? "live"}.${fmt}`, String.fromCharCode(...new Uint8Array(buf)), resp.headers.get("content-type") || "application/octet-stream");
          return;
        }
        const r = await apiTechBomExport({ fmt, layer, version });
        const data = (r.data as TechBomExport) ?? null;
        if (!data) return;
        const payload = typeof data.data === "string" ? data.data : JSON.stringify(data.data, null, 2);
        download(`${data.snapshot_id}-${layer}-${fmt}.json`, payload, data.mime_type || "application/json");
      } catch { /* export failure is non-fatal */ }
    })();
  }

  async function loadEvidence() {
    const r = await apiTechBomEvidence();
    if (r instanceof Response) return;
    if (r.ok && r.data) { setEvidence(r.data as TechBomEvidence); setEvidenceMsg(null); }
    else setEvidenceMsg("Evidence package unavailable");
  }

  async function createSchedule() {
    if (!scheduleForm.name.trim()) return;
    const r = await apiTechBomScheduleCreate({ name: scheduleForm.name.trim(), frequency: scheduleForm.frequency, fmt: scheduleForm.fmt, layer: scheduleForm.layer, recipients: [] });
    if (r.ok) { scheduleForm.name = ""; schedules.run(); }
  }

  async function runSchedule(id: string) { await apiTechBomScheduleRun(id); schedules.run(); runs.run(); }
  async function deleteSchedule(id: string) { await apiTechBomScheduleDelete(id); schedules.run(); }
  async function runDue() { await apiTechBomRunDue(); schedules.run(); runs.run(); }

  const total = state?.total_components ?? 0;
  const counts = state?.components_by_layer ?? {};
  const liveEvents = useMemo(() => rt.events.filter((e) => severityOf(e.type) !== "LOW").slice(0, 12), [rt.events]);

  const layersTable = useMemo(() => {
    const order = ["sbom", "cbom", "hbom", "vendor", "certificates"] as const;
    return order.map((layer) => {
      const L = state?.layers?.[layer];
      return [
        <span key="n" style={{ color: `var(--${LAYER_TONE[layer]})` }}>{LAYER_LABELS[layer]}</span>,
        L?.count ?? 0,
        <Badge key="t" tone={LAYER_TONE[layer]}>{layer.toUpperCase()}</Badge>,
        <code key="r">{(state?.fingerprint ?? "").slice(0, 12) || "—"}</code>,
      ];
    });
  }, [state]);

  const componentRows = useMemo(() => {
    if (!state) return [];
    const out: Array<[string, string, string, string]> = [];
    for (const layer of ["sbom", "cbom", "hbom", "vendor", "certificates"] as const) {
      for (const c of state.layers?.[layer]?.components ?? []) {
        out.push([c.name || c["bom-ref"] || "—", (c as { type?: string }).type || layer, c.version || "—", c["bom-ref"] || "—"]);
      }
    }
    return out.slice(0, 500).map((r) => [
      <span key="n">{r[0]}</span>,
      <Badge key="t" tone={LAYER_TONE[r[1].toLowerCase()] || "default"}>{r[1]}</Badge>,
      r[2], <code key="r">{r[3]}</code>,
    ]);
  }, [state]);

  const schedulesList = (schedules.data as { schedules?: TechBomSchedule[] })?.schedules ?? [];
  const runsList = (runs.data as { runs?: TechBomRun[] })?.runs ?? [];
  const vendorData = (vendor.data as TechBomVendorInventory) ?? null;
  const assuranceData = (assurance.data as TechBomAssurance) ?? null;

  return (
    <div>
      <PageHead
        crumb="Intelligence / Technology BOM"
        title="Live Asset Intelligence"
        sub={`Unified SBOM · CBOM · HBOM · Vendor — one asset model, four materialized views. Snapshot v${state?.state_version ?? 0} · ${fmtSnapshotId(state?.snapshot_id)}`}
        right={
          <div style={{ display: "flex", gap: 8 }}>
            <Badge tone={rt.connected ? "green" : "amber"}>
              {rt.connected ? "SSE LIVE" : rt.backend === false ? "OFFLINE" : "POLLING"}
            </Badge>
            <button className="btn" onClick={captureSnapshot}>Capture snapshot</button>
          </div>
        }
      />

      <div className="grid" style={{ gridTemplateColumns: "repeat(5, 1fr)", gap: 12, marginBottom: 16 }}>
        <Kpi k="Assets" v={total} tone="cyan" />
        <Kpi k="SBOM" v={counts.sbom ?? 0} tone="cyan" />
        <Kpi k="CBOM" v={counts.cbom ?? 0} tone="amber" />
        <Kpi k="HBOM" v={counts.hbom ?? 0} tone="orange" />
        <Kpi k="Vendors" v={counts.vendor ?? 0} tone="violet" />
      </div>

      {state?.scan_in_progress && (
        <div className="notice" style={{ marginBottom: 12, borderColor: "var(--amber)", color: "var(--amber)" }}>
          <strong>⚠ LIVE SCAN IN PROGRESS</strong> — the BOM is partially updated. Use <em>Capture snapshot</em> or wait for the scan to finish for a stable export.
        </div>
      )}
      {snapshotMsg && <div className="notice" style={{ marginBottom: 12 }}>{snapshotMsg}</div>}
      {evidenceMsg && <div className="notice" style={{ marginBottom: 12 }}>{evidenceMsg}</div>}

      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8, flexWrap: "wrap", gap: 8 }}>
        <Tabs tabs={VIEWS} active={view} onChange={setView} />
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          <button className="btn" onClick={() => exportNow("json", "all")}>JSON</button>
          <button className="btn" onClick={() => exportNow("csv", "all")}>CSV</button>
          <button className="btn" onClick={() => exportNow("cyclonedx", "all")}>CycloneDX</button>
          <button className="btn" onClick={() => exportNow("xml", "all")}>XML</button>
          <button className="btn" onClick={() => exportNow("spdx", "sbom")}>SPDX</button>
          <button className="btn" onClick={() => exportNow("pdf", "all")}>PDF</button>
        </div>
      </div>

      {view === 0 && (
        <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 14 }}>
          <Panel title="Dependency Graph" sub={`${total} components · ${state?.dependency_count ?? 0} edges`} frame>
            <BomGraph state={state!} />
          </Panel>
          <Panel title="Live Event Feed" sub="Platform events from the SSE stream" frame>
            {liveEvents.length ? (
              <Feed items={liveEvents.map((e) => ({
                t: e.ts ? new Date(e.ts).toLocaleTimeString() : "—",
                tag: e.type.replace(/^platform\./, "").replace(/_/g, " "),
                text: String((e.payload as { detail?: string })?.detail ?? ""),
              }))} />
            ) : <div className="empty">Waiting for platform events…</div>}
          </Panel>
        </div>
      )}

      {view === 1 && (
        <div style={{ display: "grid", gap: 14 }}>
          <Panel title="Materialized Layers" sub="SBOM / CBOM / HBOM / Vendor / Certificates from one model" frame>
            <Table head={["Layer", "Components", "Type", "Fingerprint"]} rows={layersTable} />
          </Panel>
          <Panel title="Components" sub={`${componentRows.length} shown`} frame>
            <Table head={["Name", "Type", "Version", "BOM-Ref"]} rows={componentRows} />
          </Panel>
        </div>
      )}

      {view === 2 && (
        <div style={{ display: "grid", gap: 14 }}>
          <Panel title="Compare Versions" sub="Per-layer added / removed components" frame>
            <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 12, flexWrap: "wrap" }}>
              <select value={compare.from} onChange={(e) => setCompare((c) => ({ ...c, from: Number(e.target.value) }))}>
                {(versions.data as { versions?: TechBomVersion[] })?.versions?.map?.((v) => (
                  <option key={v.version} value={v.version}>v{v.version} · {fmtSnapshotId(v.snapshot_id)}</option>
                ))}
              </select>
              <span>→</span>
              <select value={compare.to} onChange={(e) => setCompare((c) => ({ ...c, to: Number(e.target.value) }))}>
                {(versions.data as { versions?: TechBomVersion[] })?.versions?.map?.((v) => (
                  <option key={v.version} value={v.version}>v{v.version} · {fmtSnapshotId(v.snapshot_id)}</option>
                ))}
              </select>
              <button className="btn" onClick={runCompare} disabled={compare.loading}>
                {compare.loading ? "Comparing…" : "Run Compare"}
              </button>
            </div>
            <Comparison
              from={(versions.data as { versions?: TechBomVersion[] })?.versions?.find?.((v) => v.version === compare.from) ?? null}
              to={(versions.data as { versions?: TechBomVersion[] })?.versions?.find?.((v) => v.version === compare.to) ?? null}
              diff={compare.diff}
            />
          </Panel>
        </div>
      )}

      {view === 3 && (
        <div style={{ display: "grid", gap: 14 }}>
          <Panel title="Export Service" sub="Validate → filter → generate → sign(HMAC) → audit. JSON / CSV / CycloneDX / XML / SPDX / PDF" frame>
            <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 12, alignItems: "center" }}>
              <input className="input" placeholder="search…" value={exportFilters.search}
                onChange={(e) => setExportFilters((f) => ({ ...f, search: e.target.value }))} />
              <select value={exportFilters.risk_level} onChange={(e) => setExportFilters((f) => ({ ...f, risk_level: e.target.value }))}>
                <option value="">risk: any</option><option value="LOW">LOW</option>
                <option value="MEDIUM">MEDIUM</option><option value="HIGH">HIGH</option><option value="CRITICAL">CRITICAL</option>
              </select>
              <input className="input" type="number" placeholder="key size ≥" value={exportFilters.key_size_min}
                onChange={(e) => setExportFilters((f) => ({ ...f, key_size_min: e.target.value }))} />
            </div>
            <Table
              head={["Format", "Layer", "Integrity / Signature", ""]}
              rows={[
                ["JSON", "Full / filtered", <span key="i">{state?.fingerprint.slice(0, 12) || "—"}</span>, <button key="b" className="btn" onClick={() => exportNow("json", "all")}>Export</button>],
                ["CSV", "Full / filtered", "text/csv", <button key="b" className="btn" onClick={() => exportNow("csv", "all")}>Export</button>],
                ["CycloneDX 1.5", "SBOM/CBOM/HBOM/Vendor", "JSON or XML", <button key="b" className="btn" onClick={() => exportNow("cyclonedx", "all")}>Export</button>],
                ["XML (CycloneDX)", "Full / filtered", "application/xml", <button key="b" className="btn" onClick={() => exportNow("xml", "all")}>Export</button>],
                ["SPDX 2.3", "SBOM", "application/json", <button key="b" className="btn" onClick={() => exportNow("spdx", "sbom")}>Export</button>],
                ["PDF", "Full summary", "application/pdf", <button key="b" className="btn" onClick={() => exportNow("pdf", "all")}>Export</button>],
              ]}
            />
            <div style={{ marginTop: 12 }}>
              <Stat label="Integrity" value={<code>{state?.fingerprint ? state.fingerprint.slice(0, 32) + "…" : "—"}</code>} tone="cyan" />
              <Stat label="Environment" value={state?.environment || "—"} />
              <Stat label="State version" value={state?.state_version ?? "—"} />
            </div>
            {state?.scan_in_progress && <div className="notice" style={{ marginTop: 10 }}>Exports reflect a partially-updated BOM while a scan is running.</div>}
          </Panel>
        </div>
      )}

      {view === 4 && (
        <div style={{ display: "grid", gap: 14 }}>
          <Panel title="Scheduled Exports" sub="Daily / weekly / monthly / after scan / after major change" frame>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
              <input className="input" placeholder="schedule name…" value={scheduleForm.name}
                onChange={(e) => setScheduleForm((f) => ({ ...f, name: e.target.value }))} />
              <select value={scheduleForm.frequency} onChange={(e) => setScheduleForm((f) => ({ ...f, frequency: e.target.value }))}>
                <option value="daily">daily</option><option value="weekly">weekly</option><option value="monthly">monthly</option>
                <option value="after_scan">after scan</option><option value="after_major_change">after major change</option>
              </select>
              <select value={scheduleForm.fmt} onChange={(e) => setScheduleForm((f) => ({ ...f, fmt: e.target.value }))}>
                <option value="json">json</option><option value="csv">csv</option><option value="cyclonedx">cyclonedx</option>
                <option value="spdx">spdx</option><option value="pdf">pdf</option>
              </select>
              <select value={scheduleForm.layer} onChange={(e) => setScheduleForm((f) => ({ ...f, layer: e.target.value }))}>
                <option value="all">all</option><option value="sbom">sbom</option><option value="cbom">cbom</option>
                <option value="hbom">hbom</option><option value="vendor">vendor</option>
              </select>
              <button className="btn" onClick={createSchedule}>Create</button>
              <button className="btn" onClick={runDue}>Run due</button>
            </div>
            <Table
              head={["Name", "Frequency", "Format/Layer", "Last run", "Next run", ""]}
              rows={schedulesList.map((s) => [
                <span key="n">{s.name}</span>,
                <Badge key="f" tone="cyan">{s.frequency}</Badge>,
                <span key="d">{s.fmt}/{s.layer}</span>,
                s.last_run_at ? new Date(s.last_run_at).toLocaleString() : "—",
                s.next_run_at ? new Date(s.next_run_at).toLocaleString() : "event-driven",
                <span key="a" style={{ display: "flex", gap: 6 }}>
                  <button className="btn" onClick={() => runSchedule(s.id)}>Run</button>
                  <button className="btn" onClick={() => deleteSchedule(s.id)}>Delete</button>
                </span>,
              ])}
            />
          </Panel>
          <Panel title="Export Runs" sub="Immutable scheduled artifacts (hash + HMAC signature)" frame>
            <Table
              head={["Snapshot", "Format", "Components", "Content SHA-256", "Trigger"]}
              rows={runsList.map((r) => [
                <code key="s">{fmtSnapshotId(r.snapshot_id)}</code>,
                <Badge key="f" tone="cyan">{r.fmt}</Badge>,
                r.total_components,
                <code key="h">{r.content_sha256.slice(0, 16)}…</code>,
                r.trigger || "—",
              ])}
            />
          </Panel>
        </div>
      )}

      {view === 5 && (
        <div style={{ display: "grid", gap: 14 }}>
          <Panel title="Assurance & Control" sub="VEX prioritization · xBOM correlation · admission gate · runtime verification" frame>
            <AssuranceTab data={assuranceData} />
          </Panel>
        </div>
      )}

      {view === 6 && (
        <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 14 }}>
          <Panel title="Evidence Package" sub="Compliance / audit — BOM + certificate posture, content hashed & HMAC-signed" frame>
            <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
              <button className="btn" onClick={loadEvidence}>Generate & view</button>
              <button className="btn" onClick={() => void (async () => { const r = await apiTechBomEvidence(undefined, "pdf"); if (r instanceof Response) { const b = await r.arrayBuffer(); download("evidence-package.pdf", String.fromCharCode(...new Uint8Array(b)), "application/pdf"); } })()}>Download PDF</button>
            </div>
            {evidence ? (
              <div>
                <Stat label="Snapshot" value={<code>{fmtSnapshotId(evidence.snapshot_id)}</code>} tone="cyan" />
                <Stat label="Components" value={evidence.bom.total_components} />
                <div style={{ display: "flex", gap: 12, marginTop: 10 }}>
                  {Object.entries(evidence.certificates).map(([k, v]) => <Kpi key={k} k={k} v={v} tone="green" />)}
                </div>
                <div style={{ marginTop: 12 }}>
                  <Stat label="Content SHA-256" value={<code>{evidence.content_sha256.slice(0, 24)}…</code>} />
                  <Stat label="Signature (HMAC)" value={<code>{evidence.signature_hmac.slice(0, 24)}…</code>} tone="amber" />
                </div>
              </div>
            ) : <div className="empty">Generate an evidence package to see the compliance summary + hash.</div>}
          </Panel>
          <Panel title="Vendor BOM (VBOM)" sub="Vendor inventory + the systems each vendor supplies" frame>
            {vendorData && vendorData.vendors.length ? (
              <div>
                <Stat label="Vendors" value={vendorData.vendor_count} tone="violet" />
                <Table
                  head={["Vendor", "Type", "Criticality", "Systems", ""]}
                  rows={vendorData.vendors.map((v) => [
                    <span key="n">{v.name}</span>,
                    v.vendor_type || "—",
                    <Badge key="c" tone={v.criticality === "HIGH" ? "amber" : "cyan"}>{v.criticality || "—"}</Badge>,
                    `${v.system_count} · ${v.systems.slice(0, 2).join(", ")}${v.system_count > 2 ? "…" : ""}`,
                    <code key="i">{v.contract_end_date ? new Date(v.contract_end_date).toLocaleDateString() : "—"}</code>,
                  ])}
                />
              </div>
            ) : <div className="empty">No vendor inventory recorded.</div>}
          </Panel>
        </div>
      )}
    </div>
  );
}
