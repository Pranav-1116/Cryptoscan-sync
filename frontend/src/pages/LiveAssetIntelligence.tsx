import React, { useEffect, useMemo, useState } from "react";
import {
  Badge, Feed, Kpi, PageHead, Panel, Stat, Table, Tabs, Code, Bar, Ring, Drawer,
} from "../components/ui.jsx";
import { useRealtime, useRealtimeRefresh, severityOf } from "../lib/realtime.js";
import { usePollingApi, useApi } from "../lib/apiUi.jsx";
import { useSearchParams } from "react-router-dom";
import { ICON_MD, ICON_SM, IconCalendar, IconClose, IconWarn, IconClock, IconCrypto, IconHardware, IconTarget, IconSecurity, IconInfo, IconSearch, IconComponent, IconCertificate } from "../components/icons";
import {
  apiTechBomLive, apiTechBomSnapshot, apiTechBomVersions, apiTechBomCompare,
  apiTechBomExport, apiTechBomExportCsv, apiTechBomExportRaw, fmtSnapshotId,
  apiTechBomSchedules, apiTechBomScheduleCreate, apiTechBomScheduleDelete,
  apiTechBomScheduleRun, apiTechBomRunDue, apiTechBomExportRuns,
  apiTechBomEvidence, apiTechBomVendor,
  apiTechBomAssurance, apiTechBomAdmission, apiTechBomVex, apiTechBomXbom, apiTechBomRuntimeVerify,
  apiBankingOverview, apiBankingHndl, apiBankingRoadmap, apiBankingHsm,
  apiBankingActionPlan, apiBankingMainframe, apiBankingMainframeIngest,
  apiBankingMainframeAnalyze, apiBankingHsmParse, apiBankingFipsLookup, downloadBankingArtifact,
  apiBankingJurisdictions, apiBankingKeys, apiBankingSwiftCsp, apiBankingActionPlanJurisdiction, downloadBankingArtifactIntl,
  apiGroupEntities, apiGroupEntityAdd, apiGroupEntityDelete, apiGroupRollup, downloadDoraRegister,
  apiTechBomWorkspaceOverview, apiTechBomWorkspaceInventory, apiTechBomWorkspaceAssetDetail,
  apiTechBomWorkspaceApplications, apiTechBomWorkspaceInfrastructure, apiTechBomWorkspaceLayers,
  apiTechBomWorkspaceReconciliation, apiTechBomWorkspaceRelationships, apiTechBomWorkspaceLifecycle,
  apiTechBomWorkspaceEvidence, apiTechBomWorkspaceHistory, apiTechBomWorkspaceExport,
  type TechbomInventoryRow,
  downloadGroupRoadmap,
  downloadSupervisorPack,
  BankJurisdictionPack, BankKeyLifecycle, BankSwiftCsp, GroupEntityRec, GroupRollup,
  TechBomState, TechBomDiff, TechBomVersion, TechBomComponent, TechBomExport,
  TechBomSchedule, TechBomRun, TechBomEvidence, TechBomVendorInventory,
  TechBomAssurance, TechBomAdmission, TechBomVex, TechBomXbom, TechBomRuntimeVerify,
  BankOverview, BankHndl, BankRoadmap, BankHsmFleet, BankActionPlan, BankMainframeInventory, BankIngestResult,
} from "../lib/api.js";

/* Live Asset Intelligence — one asset model materialized into SBOM / CBOM /
   HBOM / Vendor views (the unified Technology BOM). Top counts, an interactive
   dependency graph, a live event feed, version history + compare, and the full
   Export Service (JSON/CSV/CycloneDX/XML/SPDX/PDF, with filters), scheduled
   exports, an evidence package, and a vendor inventory. */

const VIEWS = ["Overview", "Components", "Compare", "Export", "Schedules", "Assurance", "Banking", "Evidence & Vendor"];

const LAYER_LABELS: Record<string, string> = {
  sbom: "SBOM — Application",
  cbom: "CBOM — Crypto",
  hbom: "HBOM — Hardware",
  vendor: "VBOM — Vendor",
  certificates: "TLS Certificates",
};
// BOM layer is a *type*, not a verdict, so none of these may borrow a
// status colour. cbom was amber and hbom was orange -- "warning" and
// "high risk" -- which told an operator the cryptography and hardware
// inventories were in trouble when the colour only meant "this is the
// crypto one". Cryptography now shares the accent used for crypto nodes
// in the dependency graph, so one subject reads the same colour
// everywhere in the product.
const LAYER_TONE: Record<string, string> = {
  sbom: "violet", cbom: "cyan", hbom: "slate", vendor: "slate", certificates: "green",
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
    ({ sbom: "var(--violet)", cbom: "var(--accent)", hbom: "var(--slate)", vendor: "var(--slate)", certificates: "var(--green)" }[layer] || "var(--slate)");

  if (components.length === 0) return <div className="empty">No components — run a scan to populate the BOM.</div>;
  return (
    <svg viewBox="0 0 840 500" width="100%">
      {edges.map((e, i) => (
        <line key={i} x1={e.a.x} y1={e.a.y} x2={e.b.x} y2={e.b.y}
          stroke="color-mix(in srgb, var(--violet) 35%, transparent)" strokeWidth="1.4" />
      ))}
      {components.map((c, i) => (
        <g key={i}>
          <circle cx={c.x} cy={c.y} r={14} fill={color(c.layer)} fillOpacity={0.85} />
          <text x={c.x} y={c.y + 4} textAnchor="middle" fontSize="9" fill="var(--bg)" fontWeight="600">
            {(c.name || c["bom-ref"] || "").slice(0, 3).toUpperCase()}
          </text>
          <text x={c.x} y={c.y + 30} textAnchor="middle" fontSize="9.5" fill="var(--text)">
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
              total={vex.findings.length} rows={vex.findings.slice(0, 30).map((f) => [
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
              total={xbom.traces.length} rows={xbom.traces.slice(0, 20).map((t) => [
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
              total={runtime.drift_rows.length} rows={runtime.drift_rows.slice(0, 30).map((r) => [
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

function deadlineTone(yearsLeft: number | null | undefined): string {
  if (yearsLeft === null || yearsLeft === undefined) return "default";
  if (yearsLeft <= 1) return "red";
  if (yearsLeft <= 4) return "amber";
  return "green";
}

function BankingTab({ overview }: { overview: BankOverview | null }) {
  const [hndl, setHndl] = useState<BankHndl | null>(null);
  const [roadmap, setRoadmap] = useState<BankRoadmap | null>(null);
  const [hsm, setHsm] = useState<BankHsmFleet | null>(null);
  const [plan, setPlan] = useState<BankActionPlan | null>(null);
  const [mainframe, setMainframe] = useState<BankMainframeInventory | null>(null);
  const [framework, setFramework] = useState("ecb");
  const [institution, setInstitution] = useState("");
  const [mfKind, setMfKind] = useState("racdcert");
  const [mfText, setMfText] = useState("");
  const [mfResult, setMfResult] = useState<BankIngestResult | null>(null);
  const [mfErr, setMfErr] = useState<string | null>(null);
  const [deepKind, setDeepKind] = useState("db2_tls");
  const [deepText, setDeepText] = useState("");
  const [deepOut, setDeepOut] = useState<Record<string, unknown> | null>(null);
  const [fipsMod, setFipsMod] = useState("");
  const [fipsOut, setFipsOut] = useState<Record<string, unknown> | null>(null);
  const [jurisdictions, setJurisdictions] = useState<BankJurisdictionPack[]>([]);
  const [jurisdiction, setJurisdiction] = useState("eu");
  const [exportLang, setExportLang] = useState("en");
  const [keys, setKeys] = useState<BankKeyLifecycle | null>(null);
  const [cscf, setCscf] = useState<BankSwiftCsp["cscf"] | null>(null);
  const [group, setGroup] = useState<GroupRollup | null>(null);
  const [groupEntities, setGroupEntities] = useState<GroupEntityRec[]>([]);
  const [newEntity, setNewEntity] = useState("");

  useEffect(() => {
    apiBankingHndl().then((r) => r.ok && setHndl(r.data as BankHndl));
    apiBankingRoadmap().then((r) => r.ok && setRoadmap(r.data as BankRoadmap));
    apiBankingHsm().then((r) => r.ok && setHsm((r.data as { fleet: BankHsmFleet }).fleet));
    apiBankingMainframe().then((r) => r.ok && setMainframe(r.data as BankMainframeInventory));
    apiBankingActionPlan(framework, institution).then((r) => r.ok && setPlan(r.data as BankActionPlan));
    apiBankingJurisdictions().then((r) => r.ok && setJurisdictions((r.data as { jurisdictions: BankJurisdictionPack[] }).jurisdictions));
    apiBankingKeys().then((r) => r.ok && setKeys(r.data as BankKeyLifecycle));
    apiBankingSwiftCsp().then((r) => r.ok && setCscf((r.data as BankSwiftCsp).cscf ?? null));
    apiGroupEntities().then((r) => r.ok && setGroupEntities((r.data as { entities: GroupEntityRec[] }).entities));
    apiGroupRollup().then((r) => r.ok && setGroup(r.data as GroupRollup));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const a = plan?.assessment;

  async function generatePlan() {
    const r = await apiBankingActionPlan(framework, institution);
    if (r.ok) setPlan(r.data as BankActionPlan);
  }
  async function addEntity() {
    const code = newEntity.trim().toLowerCase();
    if (!code) return;
    const juris = jurisdiction || "eu";
    const r = await apiGroupEntityAdd({ code, name: code, jurisdiction: juris });
    if (r.ok) {
      setNewEntity("");
      const list = await apiGroupEntities();
      if (list.ok) setGroupEntities((list.data as { entities: GroupEntityRec[] }).entities);
      const roll = await apiGroupRollup();
      if (roll.ok) setGroup(roll.data as GroupRollup);
    }
  }
  async function removeEntity(code: string) {
    const r = await apiGroupEntityDelete(code);
    if (r.ok) {
      setGroupEntities((prev) => prev.filter((e) => e.code !== code));
      const roll = await apiGroupRollup();
      if (roll.ok) setGroup(roll.data as GroupRollup);
    }
  }
  function loadJurisdiction(code: string) {
    setJurisdiction(code);
    apiBankingActionPlanJurisdiction(code, institution).then((r) => r.ok && setPlan(r.data as BankActionPlan));
  }
  async function ingestMainframe() {
    setMfErr(null);
    const r = await apiBankingMainframeIngest(mfKind, mfText);
    if (r.ok) {
      setMfResult(r.data as BankIngestResult);
      const inv = await apiBankingMainframe();
      if (inv.ok) setMainframe(inv.data as BankMainframeInventory);
    } else {
      setMfErr((r as { error?: string }).error || "ingest failed");
    }
  }

  async function deepAnalyze() {
    setMfErr(null);
    const r = await apiBankingMainframeAnalyze(deepKind, deepText);
    if (r.ok) setDeepOut(r.data as Record<string, unknown>);
    else setMfErr((r as { error?: string }).error || "analyze failed");
  }
  async function lookupFips() {
    const r = await apiBankingFipsLookup(fipsMod);
    if (r.ok) setFipsOut(r.data as Record<string, unknown>);
  }

  return (
    <div style={{ display: "grid", gap: 18 }}>
      <Panel title="Supervisor Action Plan" sub="assessment → register → phased roadmap (ECB / RBI / FCA shaped)" frame>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", marginBottom: 10 }}>
          {["ecb", "rbi", "fca", "generic"].map((f) => (
            <button key={f} className={f === framework ? "active" : ""} onClick={() => setFramework(f)}
              style={{ padding: "4px 12px", textTransform: "uppercase" }}>{f}</button>
          ))}
          <input placeholder="institution (optional)" value={institution}
            onChange={(e) => setInstitution(e.target.value)}
            style={{ background: "none", border: "1px solid #233047", color: "inherit", padding: "4px 8px", borderRadius: "var(--r)" }} />
          <button onClick={generatePlan} style={{ padding: "4px 14px" }}>Generate</button>
          {jurisdictions.length ? (
            <select value={jurisdiction} onChange={(e) => loadJurisdiction(e.target.value)}
              style={{ background: "var(--bg)", color: "inherit", border: "1px solid #233047", padding: "4px 8px", borderRadius: "var(--r)" }}>
              {jurisdictions.map((j) => <option key={j.code} value={j.code}>{j.display}</option>)}
            </select>
          ) : null}
          <select value={exportLang} onChange={(e) => setExportLang(e.target.value)}
            style={{ background: "var(--bg)", color: "inherit", border: "1px solid #233047", padding: "4px 8px", borderRadius: "var(--r)" }}>
            {["en", "de", "fr", "es", "it", "ar"].map((l) => <option key={l} value={l}>{l.toUpperCase()}</option>)}
          </select>
          <button onClick={() => downloadBankingArtifactIntl("action-plan", { format: "html", lang: exportLang, jurisdiction })}
            style={{ padding: "4px 14px" }}>Download ({exportLang.toUpperCase()})</button>
        </div>
        {plan?.milestones?.length ? (
          <div style={{ marginBottom: 10 }}>
            {(plan.milestones as Array<{ label: string; date?: string | null; note?: string }>).slice(0, 5).map((m, i) => (
              <div key={i} style={{ fontSize: 11, opacity: 0.75 }}>
                <IconCalendar className="ico" size={ICON_MD} /> <strong>{m.label}</strong>{m.date ? ` — ${m.date}` : ""}{m.note ? ` · ${m.note}` : ""}
              </div>
            ))}
          </div>
        ) : null}
        {a ? (
          <div>
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 10 }}>
              <Badge tone={a.admission?.decision === "FAIL" ? "red" : a.admission?.decision === "WARN" ? "amber" : "green"}>
                admission {a.admission?.decision}
              </Badge>
              <Stat label="HNDL exposed" value={a.hndl?.total ?? 0} tone={a.hndl?.at_risk ? "red" : "green"} />
              <Stat label="HSM PQC gap" value={a.hsm_fleet?.pqc_gap ?? 0} tone={(a.hsm_fleet?.pqc_gap ?? 0) ? "amber" : "green"} />
              <Stat label="Mainframe assets" value={a.mainframe_inventory?.total ?? 0} tone="cyan" />
              <Stat label="BOM snapshot" value={plan?.evidence?.snapshot_id?.slice(0, 16) || "—"} />
            </div>
            {(plan?.references ?? []).map((ref, i) => (
              <div key={i} style={{ fontSize: 11, opacity: 0.75, marginBottom: 3 }}>§ {ref}</div>
            ))}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12, marginTop: 12 }}>
              {(plan?.phases ?? []).map((p) => (
                <div key={p.phase} style={{ border: "1px solid #1b2740", borderRadius: "var(--r)", padding: 10 }}>
                  <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 6 }}>
                    <Badge tone={p.phase === "P1" ? "red" : p.phase === "P2" ? "amber" : "cyan"}>{p.phase}</Badge>
                    <strong style={{ fontSize: 12 }}>{p.title}</strong>
                    {p.deadline ? <Badge tone={deadlineTone((p.deadline ?? 0) - new Date().getFullYear())}>by {p.deadline}</Badge> : null}
                  </div>
                  <div style={{ fontSize: 11, opacity: 0.7, marginBottom: 6 }}>{p.action}</div>
                  {(p.items ?? []).slice(0, 6).map((it, i) => (
                    <div key={i} style={{ fontSize: 11, display: "flex", gap: 6, alignItems: "center" }}>
                      <code>{it.family}{it.key_size ? `-${it.key_size}` : ""}</code>
                      <span>×{it.instances}</span>
                      {it.overdue ? <Badge tone="red">overdue</Badge> : null}
                      {it.applications?.length ? <span style={{ opacity: 0.6 }}>{it.applications.slice(0, 2).join(", ")}</span> : null}
                    </div>
                  ))}
                </div>
              ))}
            </div>
          </div>
        ) : <div className="empty">Generating action plan…</div>}
      </Panel>

      <div className="grid" style={{ gridTemplateColumns: "3fr 2fr", gap: 14 }}>
        <Panel title="HNDL — Harvest Now, Decrypt Later" sub="quantum-vulnerable public-key crypto over long-horizon data" frame>
          {hndl && hndl.total ? (
            <Table
              head={["Algorithm", "Purpose", "Horizon", "Deadline", "Exposure", "Reason"]}
              rows={(hndl.entries ?? []).slice(0, 20).map((e) => [
                <code key="a">{e.algorithm}{e.key_size ? `-${e.key_size}` : ""}</code>,
                e.purpose || "—",
                `${e.confidentiality_years ?? "?"}y`,
                <Badge key="d" tone={deadlineTone(e.years_to_deadline)}>{e.deadline}</Badge>,
                <Badge key="e" tone={e.exposure === "critical" ? "red" : "amber"}>{e.exposure}</Badge>,
                <span key="r" style={{ fontSize: 11, opacity: 0.75 }}>{e.reason}</span>,
              ])}
            />
          ) : <div className="empty">{hndl ? "No HNDL exposure in the current BOM." : "Loading HNDL register…"}</div>}
        </Panel>

        <Panel title="HSM Fleet Readiness" sub="PQC + FIPS posture from the hardware inventory" frame>
          {hsm && hsm.total ? (
            <div>
              <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 10 }}>
                <Stat label="Fleet" value={hsm.total} />
                <Stat label="PQC ready" value={hsm.pqc_ready} tone={hsm.pqc_gap ? "amber" : "green"} />
                <Stat label="FIPS family" value={hsm.fips_validated_family} tone="cyan" />
              </div>
              <Table
                head={["HSM", "Firmware", "FIPS", "PQC"]}
                rows={(hsm.hsms ?? []).map((h) => [
                  <code key="h">{h.model || h.asset_id}</code>,
                  String(typeof h.firmware === "object" ? h.firmware?.version : (h.firmware ?? "—")).slice(0, 12),
                  <Badge key="f" tone={h.fips?.status === "validated" ? "green" : "default"}>{h.fips?.status}</Badge>,
                  <Badge key="p" tone={h.pqc_status === "ready" ? "green" : h.pqc_status === "not_declared" ? "amber" : "default"}>{h.pqc_status}</Badge>,
                ])}
              />
            </div>
          ) : <div className="empty">{hsm ? "No HSMs in the hardware inventory." : "Loading HSM fleet…"}</div>}
        </Panel>
      </div>

      <Panel title="Mainframe Ingest — z/OS into the unified BOM" sub="RACF RACDCERT LIST text or ICSF key CSV → same crypto_assets as every scanner" frame>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", marginBottom: 8 }}>
          <select value={mfKind} onChange={(e) => setMfKind(e.target.value)}
            style={{ background: "var(--bg)", color: "inherit", border: "1px solid #233047", padding: "4px 8px", borderRadius: "var(--r)" }}>
            <option value="racdcert">RACDCERT LIST</option>
            <option value="icsf_csv">ICSF CSV</option>
          </select>
          <button onClick={ingestMainframe} disabled={!mfText.trim()} style={{ padding: "4px 14px" }}>Ingest</button>
          {mfResult ? (
            <span style={{ fontSize: 12 }}>
              parsed <strong>{mfResult.parsed}</strong> · inserted <strong>{mfResult.inserted}</strong> · duplicates <strong>{mfResult.duplicates}</strong>
            </span>
          ) : null}
          {mfErr ? <Badge tone="red">{mfErr}</Badge> : null}
          {mainframe ? <span style={{ fontSize: 12, opacity: 0.7 }}>inventory: {mainframe.total} mainframe assets</span> : null}
        </div>
        <textarea value={mfText} onChange={(e) => setMfText(e.target.value)} rows={5}
          placeholder={mfKind === "racdcert"
            ? "Digital certificate information for site certificate PAYGW:\n    Status: TRUST\n    Certificate Key Size: 2048\n    Algorithm Signature: SHA256WithRSA"
            : "LABEL,ALGORITHM,KEYBITS,USAGE,STATUS\nPAY.ZEK.2026,AES,256,CIPHER,ACTIVE"}
          style={{ width: "100%", background: "var(--bg)", color: "var(--text)", border: "1px solid #233047", borderRadius: "var(--r)", padding: 8, fontFamily: "monospace", fontSize: 11 }} />
        {mainframe && mainframe.total ? (
          <div style={{ marginTop: 8 }}>
            <Table
              head={["Algorithm", "Key", "Usage", "Location", "Quantum"]}
              rows={(mainframe.assets ?? []).slice(0, 12).map((m, i) => [
                <code key="a">{m.algorithm}</code>, m.key_size ?? "—", m.purpose || "—",
                <code key="l">{m.location}</code>,
                <Badge key="q" tone={m.quantum?.deadline ? "amber" : "green"}>{m.quantum?.transition || "—"}</Badge>,
              ])}
            />
          </div>
        ) : null}
      </Panel>

      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 14 }}>
        <Panel title="z/OS Deep Analysis" sub="DB2 SSL config · CICS TCPIPSERVICE · RACDCERT · ICSF — assessed inline" frame>
          <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8 }}>
            <select value={deepKind} onChange={(e) => setDeepKind(e.target.value)}
              style={{ background: "var(--bg)", color: "inherit", border: "1px solid #233047", padding: "4px 8px", borderRadius: "var(--r)" }}>
              <option value="db2_tls">DB2 TLS config</option>
              <option value="cics_tcpservice">CICS TCPIPSERVICE</option>
              <option value="racdcert">RACDCERT LIST</option>
              <option value="icsf_csv">ICSF CSV</option>
            </select>
            <button onClick={deepAnalyze} disabled={!deepText.trim()} style={{ padding: "4px 14px" }}>Analyze</button>
          </div>
          <textarea value={deepText} onChange={(e) => setDeepText(e.target.value)} rows={4}
            placeholder={deepKind === "db2_tls"
              ? "[database PAYDB]\nSSL_VERSIONS = TLSv1.2\nSSL_CIPHERSPECS = TLS_AES_256_GCM_SHA384"
              : "TCPIPSERVICE(PAYMENTS) PORTNUMBER(9443) PROTOCOL(https) CIPHERS(...)"}
            style={{ width: "100%", background: "var(--bg)", color: "var(--text)", border: "1px solid #233047", borderRadius: "var(--r)", padding: 8, fontFamily: "monospace", fontSize: 11 }} />
          {deepOut ? (
            <pre style={{ fontSize: 11, background: "var(--bg)", padding: 8, borderRadius: "var(--r)", overflowX: "auto", maxHeight: 180 }}>
              {JSON.stringify((deepOut as { assessment?: unknown }).assessment ?? deepOut, null, 2).slice(0, 1600)}
            </pre>
          ) : null}
        </Panel>

        <Panel title="Regulator Exports & Integrations" sub="one-click downloads for supervisors, CMDB sync and GRC tooling" frame>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
            <button onClick={() => downloadBankingArtifact("action-plan", "html")} style={{ padding: "6px 10px" }}>Action Plan (HTML→PDF)</button>
            <button onClick={() => downloadBankingArtifact("action-plan", "csv")} style={{ padding: "6px 10px" }}>HNDL Register (CSV)</button>
            <button onClick={() => downloadBankingArtifact("servicenow")} style={{ padding: "6px 10px" }}>ServiceNow CMDB (JSON)</button>
            <button onClick={() => downloadBankingArtifact("qualys")} style={{ padding: "6px 10px" }}>Qualys Detections (CSV)</button>
          </div>
          <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
            <input placeholder="FIPS 140 module lookup (CMVP registry)" value={fipsMod}
              onChange={(e) => setFipsMod(e.target.value)}
              style={{ flex: 1, background: "none", border: "1px solid #233047", color: "inherit", padding: "4px 8px", borderRadius: "var(--r)" }} />
            <button onClick={lookupFips} disabled={fipsMod.trim().length < 2} style={{ padding: "4px 14px" }}>Lookup</button>
          </div>
          {fipsOut ? (
            <pre style={{ fontSize: 11, background: "var(--bg)", padding: 8, borderRadius: "var(--r)", overflowX: "auto", marginTop: 8 }}>
              {JSON.stringify(fipsOut, null, 2).slice(0, 800)}
            </pre>
          ) : null}
        </Panel>
      </div>

      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 14 }}>
        <Panel title="Key Lifecycle" sub="NIST SP 800-57 states over the unified inventory" frame>
          {keys && keys.total ? (
            <div>
              <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 10 }}>
                <Stat label="Keys" value={keys.total} />
                <Stat label="Compromised" value={keys.compromised} tone={keys.compromised ? "red" : "green"} />
                <Stat label="Expired" value={keys.expired} tone={keys.expired ? "red" : "green"} />
                <Stat label="Rotation overdue" value={keys.rotation_overdue} tone={keys.rotation_overdue ? "amber" : "green"} />
              </div>
              <Table
                head={["Key", "State", "Rotation", "Detail"]}
                rows={(keys.keys ?? []).slice(0, 12).map((k, i) => [
                  <code key="k">{k.label || k.location}</code>,
                  <Badge key="s" tone={k.state === "compromised" ? "red" : k.state === "expired" ? "red" : k.state === "active" ? "green" : "default"}>{k.state}</Badge>,
                  <Badge key="r" tone={k.rotation_status === "overdue" ? "red" : k.rotation_status === "within_policy" ? "green" : "default"}>{k.rotation_status}</Badge>,
                  <span key="d" style={{ fontSize: 11, opacity: 0.75 }}>{k.detail}</span>,
                ])}
              />
            </div>
          ) : <div className="empty">{keys ? "No keys in the inventory yet — ingest ICSF/RACF extracts." : "Loading key lifecycle…"}</div>}
        </Panel>

        <Panel title="Group — Legal Entities & Rollup" sub="cross-entity posture; systems inherit via assignment" frame>
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", marginBottom: 8 }}>
            <input placeholder="new entity code (e.g. sg-ops)" value={newEntity}
              onChange={(e) => setNewEntity(e.target.value)}
              style={{ background: "none", border: "1px solid #233047", color: "inherit", padding: "4px 8px", borderRadius: "var(--r)" }} />
            <button onClick={addEntity} disabled={!newEntity.trim()} style={{ padding: "4px 12px" }}>Add</button>
            <button onClick={() => downloadDoraRegister("csv", groupEntities[0]?.code || "")} style={{ padding: "4px 12px" }}>DORA register (CSV)</button>
            <button onClick={() => downloadDoraRegister("json", groupEntities[0]?.code || "")} style={{ padding: "4px 12px" }}>DORA (JSON)</button>
            <button onClick={() => downloadGroupRoadmap().catch(() => undefined)} style={{ padding: "4px 12px" }}>Roadmap (CSV)</button>
            <button onClick={() => downloadSupervisorPack().catch(() => undefined)} style={{ padding: "4px 12px" }}>Supervisor pack (JSON)</button>
          </div>
          {group && groupEntities.length ? (
            <div>
              <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 8 }}>
                <Stat label="Entities" value={group.group?.totals?.entities ?? 0} />
                <Stat label="Systems" value={group.group?.totals?.systems ?? 0} />
                <Stat label="Weak (group)" value={group.group?.totals?.weak_legacy_instances ?? 0} tone={(group.group?.totals?.weak_legacy_instances ?? 0) ? "red" : "green"} />
                <Stat label="Quantum-exposed" value={group.group?.totals?.quantum_vulnerable_public_key ?? 0} tone="amber" />
              </div>
              <Table
                head={["Entity", "Jurisdiction", "Systems", "Crypto", "Weak", "Quantum", ""]}
                rows={(group.entities ?? []).map((e) => [
                  <code key="c">{e.entity.code}</code>, e.entity.jurisdiction,
                  e.systems, e.crypto_instances,
                  <Badge key="w" tone={e.weak_legacy_instances ? "red" : "green"}>{e.weak_legacy_instances}</Badge>,
                  <Badge key="q" tone={e.quantum_vulnerable_public_key ? "amber" : "green"}>{e.quantum_vulnerable_public_key}</Badge>,
                  <button key="d" onClick={() => removeEntity(e.entity.code)} style={{ padding: "2px 8px" }} aria-label="Remove"><IconClose size={ICON_SM} /></button>,
                ])}
              />
              {(group.group?.recurring_weak_families ?? []).length ? (
                <div style={{ fontSize: 11, opacity: 0.8, marginTop: 8 }}>
                  ↻ shared across entities:
                  {(group.group?.recurring_weak_families ?? []).slice(0, 4).map((f) => (
                    <Badge key={f.family} tone="amber">{f.family} ×{f.entity_count}</Badge>
                  ))}
                </div>
              ) : null}
            </div>
          ) : <div className="empty">No legal entities registered — add one to start the group rollup.</div>}
        </Panel>

        <Panel title="SWIFT CSP — CSCF Evidence" sub="control themes → platform evidence (pin IDs from your CSCF version)" frame>
          {cscf ? (
            <div>
              <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 10 }}>
                <Stat label="Controls" value={cscf.controls.length} />
                <Stat label="Gaps" value={cscf.gaps} tone={cscf.gaps ? "red" : "green"} />
                <Stat label="Unknown" value={cscf.unknown} tone={cscf.unknown ? "amber" : "green"} />
                <Badge tone={cscf.attestation_ready ? "green" : "amber"}>
                  {cscf.attestation_ready ? "attestation-ready" : "evidence in progress"}
                </Badge>
              </div>
              <Table
                head={["Control theme", "Status", "Evidence"]}
                rows={cscf.controls.map((c) => [
                  <span key="t" style={{ fontSize: 11 }}>{c.theme}</span>,
                  <Badge key="s" tone={c.status === "satisfied" ? "green" : c.status === "gap" ? "red" : "default"}>{c.status}</Badge>,
                  <span key="e" style={{ fontSize: 11, opacity: 0.75 }}>{c.evidence}</span>,
                ])}
              />
            </div>
          ) : <div className="empty">Loading SWIFT CSP evidence…</div>}
        </Panel>
      </div>
    </div>
  );
}

const TECHBOM_TABS: Array<{ id: string; label: string }> = [
  { id: "overview", label: "TechBOM Overview" },
  { id: "inventory", label: "Technology Inventory" },
  { id: "applications", label: "Application & Service Registry" },
  { id: "infrastructure", label: "Infrastructure Inventory" },
  { id: "layers", label: "Technology Layers" },
  { id: "reconciliation", label: "Six-BOM Reconciliation" },
  { id: "relationships", label: "Technology Relationships" },
  { id: "lifecycle", label: "Lifecycle Intelligence" },
  { id: "evidence", label: "Evidence & Provenance" },
  { id: "history", label: "TechBOM History" },
  { id: "export", label: "Export & Validation" },
];

/* A read that did not return is never an inventory of zero records. */
function WsState({ read, noun, children }: {
  read: { data: Record<string, unknown> | null; running: boolean; source: string; detail?: string | null };
  noun: string;
  children: React.ReactNode;
}) {
  if (read.running && !read.data) return <p className="faint" style={{ fontSize: 12 }}>Reading the {noun}…</p>;
  if (read.source !== "live" || read.data == null)
    return (
      <Panel title={`${noun} not read`} sub={read.source === "live" ? "the read returned nothing" : "the control plane did not answer"}>
        <p role="status" style={{ margin: 0, fontSize: 12, color: "var(--amber)" }}>
          {read.source === "live"
            ? `The ${noun} read returned nothing — nothing is claimed here.`
            : `The ${noun} could not be read${read.detail ? ` — ${read.detail}` : ""}. An unread inventory is not an empty one.`}
        </p>
      </Panel>
    );
  return <>{children}</>;
}

function WsTable({ head, rows, colSpan }: { head: string[]; rows: React.ReactNode[]; colSpan: number }) {
  return (
    <div style={{ overflowX: "auto" }}>
      <table className="tbl" style={{ width: "100%" }}>
        <thead><tr>{head.map((h) => <th key={h}>{h}</th>)}</tr></thead>
        <tbody>
          {rows.length ? rows : (
            <tr><td colSpan={colSpan} style={{ padding: 26, textAlign: "center", color: "var(--dim)", fontSize: 12 }}>
              <div style={{ fontWeight: 600, color: "var(--text)" }}>Nothing stored yet</div>
              <div style={{ fontSize: 11.5, marginTop: 4 }}>Empty rows here mean no stored observations — not a healthy zero.</div>
            </td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

/* Cross-BOM relationship states (spec §7 vocabulary): primary record /
 * linked / not established / unknown — never conflated. */
function RelatedBadge({ state }: { state: string }) {
  const tone = state === "PRIMARY_RECORD" ? "pass" : state === "LINKED" ? "cyan" : state === "UNKNOWN" ? "slate" : "default";
  const label = state === "PRIMARY_RECORD" ? "primary record" : state === "LINKED" ? "linked" : state === "NOT_ESTABLISHED" ? "not established" : "unknown";
  return <Badge tone={tone}>{label}</Badge>;
}

function EvidenceBadge({ evidence }: { evidence: { state: string; freshness: string } }) {
  const tone = evidence.state === "MEASURED" ? "pass" : evidence.state === "IMPORTED" ? "cyan"
    : evidence.state === "INFERRED" ? "amber" : evidence.state === "CONTRADICTED" ? "red" : "slate";
  return (
    <span style={{ display: "inline-flex", gap: 4, flexWrap: "wrap" }}>
      <Badge tone={tone}>{evidence.state}</Badge>
      <Badge tone={evidence.freshness === "CURRENT" ? "green" : evidence.freshness === "STALE" ? "amber" : "slate"}>{evidence.freshness}</Badge>
    </span>
  );
}

export default function LiveAssetIntelligence() {
  const [wsParams, setWsParams] = useSearchParams();
  const wsActive = TECHBOM_TABS.some((t) => t.id === wsParams.get("tab")) ? wsParams.get("tab") as string : "overview";
  const [view, setView] = useState(0);
  const live = usePollingApi(apiTechBomLive, 15000);
  const versions = usePollingApi(apiTechBomVersions, 30000);
  const schedules = usePollingApi(apiTechBomSchedules, 30000);
  const vendor = usePollingApi(apiTechBomVendor, 60000);
  const runs = usePollingApi(apiTechBomExportRuns, 30000);
  const assurance = usePollingApi(apiTechBomAssurance, 30000);
  const banking = usePollingApi(apiBankingOverview, 60000);
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
  const bankingData = (banking.data as BankOverview) ?? null;

  const layerTotal = Math.max(1, total);
  const sbomPct = (counts.sbom ?? 0) / layerTotal;
  const cbomPct = (counts.cbom ?? 0) / layerTotal;
  const hbomPct = (counts.hbom ?? 0) / layerTotal;
  const vendorPct = (counts.vendor ?? 0) / layerTotal;
  const certPct = (counts.certificates ?? 0) / layerTotal;
  const estateRingPct = Math.min(1, total / 500);
  const ringTone = total ? total > 200 ? "green" : total > 50 ? "cyan" : "amber" : "slate";

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      <div role="tablist" aria-label="TechBOM sections" style={{ display: "flex", gap: 6, flexWrap: "wrap", margin: "2px 0 16px" }}>
        {TECHBOM_TABS.map((t) => (
          <button key={t.id} role="tab" aria-selected={wsActive === t.id} title={t.label}
            onClick={() => setWsParams({ tab: t.id })}
            style={{
              fontSize: 11, padding: "6px 11px", borderRadius: 999, cursor: "pointer",
              border: `1px solid ${wsActive === t.id ? "var(--accent)" : "var(--line-strong)"}`,
              background: wsActive === t.id ? "color-mix(in srgb, var(--accent) 14%, transparent)" : "var(--panel-2)",
              color: wsActive === t.id ? "var(--accent)" : "var(--dim)", fontFamily: "var(--mono)", letterSpacing: ".03em",
            }}>{t.label}</button>
        ))}
      </div>
      {wsActive === "overview" && (<>
      {/* Visual Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16, flexWrap: "wrap", gap: 16 }}>
        <div style={{ flex: "1 1 460px", minWidth: 280 }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px", borderRadius: 999, background: "color-mix(in srgb, var(--accent) 12%, transparent)", border: "1px solid var(--accent)", fontSize: 11, fontFamily: "var(--mono)", color: "var(--accent)", letterSpacing: "0.06em" }}>
            <span style={{ width: 6, height: 6, borderRadius: 99, background: rt.connected ? "var(--green)" : "var(--accent)" }} /> INTELLIGENCE · TECHNOLOGY BOM · ONE ASSET MODEL
          </div>
          <h1 style={{ fontSize: 26, fontWeight: 800, margin: "8px 0 6px", letterSpacing: "-0.02em", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ width: 34, height: 34, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--accent)", color: "var(--on-accent)" }}><IconComponent size={18} /></span>
            Live Asset Intelligence
          </h1>
          <p style={{ margin: 0, fontSize: 13.5, color: "var(--dim)", lineHeight: 1.5, maxWidth: 620 }}>
            Unified <b style={{ color: "var(--text)" }}>SBOM · CBOM · HBOM · Vendor</b> — one asset model, four materialized views. Snapshot <span style={{ color: "var(--accent)", fontFamily: "var(--mono)" }}>v{state?.state_version ?? 0} · {fmtSnapshotId(state?.snapshot_id)}</span>
          </p>
          <div style={{ display: "flex", gap: 8, marginTop: 12, flexWrap: "wrap" }}>
            <span className="kicker" style={{ fontSize: 10 }}>MATERIALIZED VIEWS</span>
            <span style={{ color: "var(--line-strong)" }}>·</span>
            <span className="kicker" style={{ fontSize: 10 }}>HMAC-SIGNED EXPORTS</span>
            <span style={{ color: "var(--line-strong)" }}>·</span>
            <span style={{ fontSize: 11, color: "var(--dim)" }}>dependency edges {state?.dependency_count ?? 0}</span>
          </div>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-start", flexWrap: "wrap" }}>
          <Panel style={{ padding: "10px 14px", minWidth: 160, display: "flex", alignItems: "center", gap: 12 }}>
            <Ring pct={estateRingPct} label={String(total)} sub="assets" tone={ringTone} />
            <div>
              <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)" }}>ESTATE COVERAGE</div>
              <div style={{ fontSize: 12, color: "var(--dim)", maxWidth: 130, lineHeight: 1.4 }}>{total ? `${Object.keys(counts).length} layers · ${state?.dependency_count ?? 0} edges` : "No BOM yet — run a scan"}</div>
              <div style={{ marginTop: 6 }}><Bar value={estateRingPct} tone={ringTone} /></div>
            </div>
          </Panel>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <button className="btn primary" onClick={captureSnapshot} style={{ fontSize: 12, padding: "8px 14px", borderRadius: "var(--r)" }}>Capture snapshot</button>
            <div style={{ display: "flex", gap: 6, justifyContent: "center" }}>
              <Badge tone={rt.connected ? "green" : "amber"}>{rt.connected ? "SSE LIVE" : rt.backend === false ? "OFFLINE" : "POLLING"}</Badge>
            </div>
            <span style={{ fontSize: 11, color: "var(--faint)", textAlign: "center" }}>v{state?.state_version ?? 0} · {fmtSnapshotId(state?.snapshot_id).slice(0, 16)}</span>
          </div>
        </div>
      </div>

      {/* Visual KPI cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 14, marginBottom: 14 }}>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--accent)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", display: "flex", alignItems: "center", gap: 6 }}><IconTarget size={12} /> TOTAL ASSETS</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{total}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>Across all layers</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--accent) 14%, transparent)", border: "1px solid var(--accent)", color: "var(--accent)" }}><IconComponent size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <div style={{ height: 6, display: "flex", borderRadius: 99, overflow: "hidden", border: "1px solid var(--line)" }}>
              <div style={{ width: `${sbomPct * 100}%`, background: "var(--violet)" }} /><div style={{ width: `${cbomPct * 100}%`, background: "var(--accent)" }} /><div style={{ width: `${hbomPct * 100}%`, background: "var(--slate)" }} /><div style={{ flex: 1, background: "var(--green)" }} />
            </div>
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6, display: "flex", gap: 8 }}><span>● SBOM</span><span>● CBOM</span><span>● HBOM</span><span>● Vendor</span></div>
          </div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--violet)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>SBOM — APPLICATION</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{counts.sbom ?? 0}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>Software components</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--violet) 14%, transparent)", border: "1px solid var(--violet)", color: "var(--violet)" }}>SB</span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <Bar value={sbomPct} tone="violet" />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>{Math.round(sbomPct * 100)}% of estate</div>
          </div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--accent)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>CBOM — CRYPTO</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{counts.cbom ?? 0}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>Crypto assets</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--accent) 14%, transparent)", border: "1px solid var(--accent)", color: "var(--accent)" }}><IconCrypto size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <Bar value={cbomPct} tone="cyan" />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>{Math.round(cbomPct * 100)}% of estate</div>
          </div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--slate)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>HBOM — HARDWARE</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{counts.hbom ?? 0}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>Hardware roots</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--panel-2)", border: "1px solid var(--line)", color: "var(--slate)" }}><IconHardware size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <Bar value={hbomPct} tone="slate" />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>{Math.round(hbomPct * 100)}% of estate</div>
          </div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--green)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>VENDOR · CERTS</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{(counts.vendor ?? 0) + (counts.certificates ?? 0)}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>{counts.vendor ?? 0} vendors · {counts.certificates ?? 0} certs</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--green) 14%, transparent)", border: "1px solid var(--green)", color: "var(--green)" }}><IconCertificate size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <div style={{ display: "flex", gap: 4 }}><span style={{ flex: 1 }}><Bar value={(counts.vendor ?? 0) / layerTotal} tone="green" /></span><span style={{ flex: 1 }}><Bar value={(counts.certificates ?? 0) / layerTotal} tone="green" /></span></div>
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>Supply chain + TLS trust</div>
          </div>
        </div>
      </div>
      {/* Layer composition strip */}
      <div className="panel" style={{ padding: "12px 16px", marginBottom: 14, borderLeft: "3px solid var(--accent)", background: "color-mix(in srgb, var(--accent) 4%, var(--panel))" }}>
        <div style={{ display: "flex", gap: 16, alignItems: "center", flexWrap: "wrap" }}>
          <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: ".06em", color: "var(--faint)" }}>LAYER COMPOSITION</div>
          <div style={{ flex: 1, minWidth: 200, height: 10, display: "flex", borderRadius: 99, overflow: "hidden", border: "1px solid var(--line)" }}>
            <div style={{ width: `${sbomPct * 100}%`, background: "var(--violet)" }} title={`SBOM ${counts.sbom ?? 0}`} />
            <div style={{ width: `${cbomPct * 100}%`, background: "var(--accent)" }} title={`CBOM ${counts.cbom ?? 0}`} />
            <div style={{ width: `${hbomPct * 100}%`, background: "var(--slate)" }} title={`HBOM ${counts.hbom ?? 0}`} />
            <div style={{ width: `${vendorPct * 100}%`, background: "var(--green)" }} title={`Vendor ${counts.vendor ?? 0}`} />
            <div style={{ flex: 1, background: "color-mix(in srgb, var(--green) 60%, transparent)" }} title={`Certs ${counts.certificates ?? 0}`} />
          </div>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            <Badge tone="violet">SBOM {counts.sbom ?? 0}</Badge>
            <Badge tone="cyan">CBOM {counts.cbom ?? 0}</Badge>
            <Badge tone="slate">HBOM {counts.hbom ?? 0}</Badge>
            <Badge tone="green">Vendor {counts.vendor ?? 0}</Badge>
          </div>
          <Badge tone={state?.dependency_count ? "green" : "slate"}>{state?.dependency_count ?? 0} edges</Badge>
        </div>
      </div>

      {state?.scan_in_progress && (
        <div className="notice" style={{ marginBottom: 12, borderColor: "var(--amber)", color: "var(--amber)" }}>
          <strong className="ico-row"><IconWarn className="ico" size={ICON_MD} />LIVE SCAN IN PROGRESS</strong> — the BOM is partially updated. Use <em>Capture snapshot</em> or wait for the scan to finish for a stable export.
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
            {state ? (
              <BomGraph state={state} />
            ) : (
              <div className="faint" style={{ padding: 12 }}>
                No Technology BOM yet — the graph appears after the first materialisation
                (backend offline or no scan has run).
              </div>
            )}
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
        <BankingTab overview={bankingData} />
      )}

      {view === 7 && (
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
      </>)}
      {wsActive === "inventory" && <TechbomInventory />}
      {wsActive === "applications" && <TechbomApplications />}
      {wsActive === "infrastructure" && <TechbomInfrastructure />}
      {wsActive === "layers" && <TechbomLayers />}
      {wsActive === "reconciliation" && <TechbomReconciliation />}
      {wsActive === "relationships" && <TechbomRelationships />}
      {wsActive === "lifecycle" && <TechbomLifecycle />}
      {wsActive === "evidence" && <TechbomEvidence />}
      {wsActive === "history" && <TechbomHistory />}
      {wsActive === "export" && <TechbomExport />}
    </div>
  );
}

/* ── workspace sections (docs/boms/01_PRODUCT_SPEC.md §6 navigation) ─── */

function TechbomInventory() {
  const [q, setQ] = useState("");
  const [cat, setCat] = useState("");
  const read = useApi(() => apiTechBomWorkspaceInventory(q || undefined, cat || undefined), [q, cat]);
  const rows = (read.data?.rows ?? []) as TechbomInventoryRow[];
  const [selected, setSelected] = useState<TechbomInventoryRow | null>(null);
  const detail = useApi(() => apiTechBomWorkspaceAssetDetail(selected?.asset_ref ?? ""), [selected?.asset_ref]);
  return (
    <>
      <Panel title="Technology Inventory" sub="one canonical asset model — Related BOMs cite primary records and verified links only; a shared name or layer is never a link">
        <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
          <input value={q} onChange={(e) => setQ(e.target.value)}
            placeholder="search by asset, component, vendor, version or ID"
            aria-label="search technology inventory"
            style={{ flex: 1, minWidth: 220, padding: "7px 10px", borderRadius: "var(--r)", border: "1px solid var(--line-strong)", background: "var(--panel-2)", color: "var(--text)", fontSize: 12 }} />
          {["SOFTWARE", "CRYPTO", "HARDWARE", "NETWORK", "SUPPLIER"].map((c) => (
            <button key={c} onClick={() => setCat(cat === c ? "" : c)}
              style={{
                fontSize: 10.5, padding: "5px 10px", borderRadius: 999, cursor: "pointer", fontFamily: "var(--mono)",
                border: `1px solid ${cat === c ? "var(--accent)" : "var(--line-strong)"}`,
                background: cat === c ? "color-mix(in srgb, var(--accent) 14%, transparent)" : "var(--panel-2)",
                color: cat === c ? "var(--accent)" : "var(--dim)",
              }}>{c}</button>
          ))}
          <Badge tone="slate">{read.data?.total ?? (read.source === "live" ? rows.length : "—")} rows</Badge>
        </div>
        <WsState read={read} noun="technology inventory">
          <WsTable
            head={["Asset ID", "Asset name", "Category", "Vendor", "Product/version", "Environment", "Related BOMs", "Dependencies", "Evidence", "Last observed"]}
            colSpan={10}
            rows={rows.slice(0, 200).map((r, i) => (
              <tr key={`${r.asset_ref}-${i}`} style={{ cursor: "pointer" }} onClick={() => setSelected(r)}>
                <td><code style={{ fontSize: 10.5 }}>{r.asset_ref}</code></td>
                <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.name}</span></td>
                <td><Badge tone="slate">{r.category}</Badge></td>
                <td><span style={{ fontSize: 11 }}>{r.vendor || "—"}</span></td>
                <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{r.product_version || "—"}</span></td>
                <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{r.environment || "—"}</span></td>
                <td>
                  <span style={{ display: "inline-flex", gap: 4, flexWrap: "wrap" }}>
                    {Object.entries(r.related).map(([bom, state]) =>
                      state === "NOT_ESTABLISHED" ? null : <RelatedBadge key={bom} state={state} />)}
                    {Object.values(r.related).every((st) => st === "NOT_ESTABLISHED")
                      ? <span style={{ fontSize: 10.5, color: "var(--faint)" }}>not established</span> : null}
                  </span>
                </td>
                <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{r.dependencies}</span></td>
                <td><EvidenceBadge evidence={r.evidence} /></td>
                <td><span style={{ fontSize: 10.5, fontFamily: "var(--mono)", color: "var(--dim)" }}>{String(r.last_observed ?? "—").slice(0, 10)}</span></td>
              </tr>
            ))}
          />
        </WsState>
      </Panel>
      {selected && (
        <Drawer title={selected.name} sub={`${selected.category} · ${selected.asset_ref}`} onClose={() => setSelected(null)}>
          {!detail.data ? <p className="faint" style={{ fontSize: 12 }}>{detail.running ? "Reading the asset…" : "The asset detail did not return."}</p> : (
            (() => {
              const d = detail.data as Record<string, any>;
              return (
                <div style={{ display: "grid", gap: 12 }}>
                  <div style={{ fontSize: 12, display: "grid", gap: 4 }}>
                    <div><b>Asset ID</b> <code>{String(d.asset_ref)}</code> · <b>Environment</b> {String(d.environment || "—")} · <b>Category</b> {String(d.category)}</div>
                    <div><b>Owner</b> {String(d.owner || "—")} · <b>Source</b> {String(d.source || "—")} · <b>Last observed</b> {String(d.last_observed ?? "—").slice(0, 10)}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>CROSS-BOM RELATIONSHIPS</div>
                    {(d.related ?? []).map((rel: Record<string, any>, i: number) => (
                      <div key={i} style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 11.5, color: "var(--dim)", marginBottom: 3 }}>
                        <span style={{ width: 62, fontWeight: 600, color: "var(--text)" }}>{String(rel.bom)}</span>
                        <RelatedBadge state={String(rel.state)} />
                        <span style={{ fontSize: 10.5, color: "var(--faint)" }}>{String(rel.basis)}</span>
                      </div>
                    ))}
                  </div>
                  <div>
                    <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>DEPENDENCIES — VERIFIED ONLY</div>
                    {(d.dependencies ?? []).length ? (d.dependencies ?? []).map((dep: Record<string, any>, i: number) => (
                      <div key={i} style={{ fontSize: 11, color: "var(--dim)" }}>{String(dep.to)} · {String(dep.type)} · {String(dep.evidence)}</div>
                    )) : <div style={{ fontSize: 11.5, color: "var(--dim)" }}>No verified dependency recorded — a shared name is not a relationship.</div>}
                  </div>
                  <div>
                    <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>EVIDENCE</div>
                    <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                      <EvidenceBadge evidence={d.evidence ?? { state: "UNKNOWN", freshness: "NOT_COLLECTED" }} />
                      <span style={{ fontSize: 10.5, color: "var(--faint)" }}>{String(d.evidence?.basis ?? "")}</span>
                    </div>
                  </div>
                </div>
              );
            })()
          )}
        </Drawer>
      )}
    </>
  );
}

function TechbomApplications() {
  const read = useApi(apiTechBomWorkspaceApplications);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="Application & Service Registry" sub="registered systems with their verified links — crypto assets, suppliers, dependency edges">
      <WsState read={read} noun="application registry">
        <WsTable head={["ID", "Name", "Version", "Owner", "Environment", "Criticality", "Crypto assets", "Vendors", "Dependencies"]} colSpan={9}
          rows={rows.slice(0, 200).map((r, i) => (
            <tr key={i}>
              <td><code style={{ fontSize: 10.5 }}>{r.id}</code></td>
              <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.name}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{r.version || "—"}</span></td>
              <td><span style={{ fontSize: 11 }}>{r.owner || "—"}</span></td>
              <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{r.environment || "—"}</span></td>
              <td><Badge tone={r.criticality === "HIGH" ? "amber" : "slate"}>{r.criticality || "—"}</Badge></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{r.crypto_assets}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{r.vendors}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{r.dependencies}</span></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function TechbomInfrastructure() {
  const read = useApi(apiTechBomWorkspaceInfrastructure);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="Infrastructure Inventory" sub="hardware and network as stored — an unrecorded lifecycle is UNKNOWN, never assumed supported">
      <WsState read={read} noun="infrastructure inventory">
        <WsTable head={["Kind", "ID", "Name", "Detail", "Vendor", "Last seen", "Lifecycle"]} colSpan={7}
          rows={rows.slice(0, 200).map((r, i) => (
            <tr key={i}>
              <td><Badge tone={r.kind === "HARDWARE" ? "slate" : "cyan"}>{r.kind}</Badge></td>
              <td><code style={{ fontSize: 10.5 }}>{r.id}</code></td>
              <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.name}</span></td>
              <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{r.detail || "—"}</span></td>
              <td><span style={{ fontSize: 11 }}>{r.vendor || "—"}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5 }}>{String(r.last_seen ?? "—").slice(0, 10)}</span></td>
              <td><Badge tone="slate">{r.lifecycle}</Badge></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function TechbomLayers() {
  const read = useApi(apiTechBomWorkspaceLayers);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="Technology Layers" sub="one asset model, materialized per layer — a row's layer is its primary record">
      <WsState read={read} noun="layer inventory">
        <WsTable head={["Layer", "Label", "Count", "Source"]} colSpan={4}
          rows={rows.map((r, i) => (
            <tr key={i}>
              <td><Badge tone="cyan">{r.layer}</Badge></td>
              <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.label}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{r.count}</span></td>
              <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{r.source}</span></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function TechbomReconciliation() {
  const read = useApi(apiTechBomWorkspaceReconciliation);
  const screens = (read.data?.screens ?? []) as Array<Record<string, any>>;
  const [open, setOpen] = useState<string | null>(null);
  return (
    <Panel title="Six-BOM Reconciliation" sub="records are connected only where stored evidence establishes the relationship">
      <WsState read={read} noun="reconciliation">
        <div style={{ display: "grid", gap: 8 }}>
          {screens.map((s) => (
            <div key={s.screen} className="panel" style={{ padding: "10px 12px" }}>
              <div style={{ display: "flex", gap: 10, alignItems: "center", cursor: "pointer" }}
                onClick={() => setOpen(open === s.screen ? null : s.screen)}>
                <Badge tone={s.count ? "amber" : "green"}>{s.count}</Badge>
                <span style={{ fontSize: 12, fontWeight: 600 }}>{s.question}</span>
                <span style={{ marginLeft: "auto", fontSize: 10, color: "var(--faint)", fontFamily: "var(--mono)" }}>{open === s.screen ? "hide" : "show"}</span>
              </div>
              {open === s.screen && (
                <div style={{ marginTop: 8, borderTop: "1px solid var(--line)", paddingTop: 8 }}>
                  {(s.rows ?? []).length ? (s.rows ?? []).slice(0, 50).map((row: Record<string, any>, i: number) => (
                    <div key={i} style={{ fontSize: 11, color: "var(--dim)", marginBottom: 2, fontFamily: "var(--mono)" }}>
                      {Object.entries(row).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join("|") : String(v)}`).join("  ·  ")}
                    </div>
                  )) : <div style={{ fontSize: 11.5, color: "var(--dim)" }}>Nothing stored to reconcile — not a healthy zero.</div>}
                </div>
              )}
            </div>
          ))}
          <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 4 }}>{String(read.data?.rule ?? "")}</div>
        </div>
      </WsState>
    </Panel>
  );
}

function TechbomRelationships() {
  const read = useApi(apiTechBomWorkspaceRelationships);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="Technology Relationships" sub="verified relationships only — a shared name or layer is not a relationship">
      <WsState read={read} noun="relationship inventory">
        <WsTable head={["Source", "Target", "Type", "Evidence"]} colSpan={4}
          rows={rows.slice(0, 200).map((r, i) => (
            <tr key={i}>
              <td><code style={{ fontSize: 10.5 }}>{r.source}</code></td>
              <td><code style={{ fontSize: 10.5 }}>{r.target}</code></td>
              <td><Badge tone="slate">{r.type}</Badge></td>
              <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{r.evidence}</span></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function TechbomLifecycle() {
  const read = useApi(apiTechBomWorkspaceLifecycle);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="Lifecycle Intelligence" sub="an unrecorded lifecycle is UNKNOWN, never assumed supported">
      <WsState read={read} noun="lifecycle inventory">
        <WsTable head={["Asset", "Name", "Kind", "Lifecycle", "Risk level", "Last verified"]} colSpan={6}
          rows={rows.slice(0, 200).map((r, i) => (
            <tr key={i}>
              <td><code style={{ fontSize: 10.5 }}>{r.asset_ref}</code></td>
              <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.name}</span></td>
              <td><Badge tone="slate">{r.kind}</Badge></td>
              <td><Badge tone={r.lifecycle === "END_OF_LIFE" ? "red" : r.lifecycle === "SUPPORTED" ? "pass" : "slate"}>{r.lifecycle}</Badge></td>
              <td><Badge tone={r.risk_level === "HIGH" ? "amber" : "slate"}>{r.risk_level}</Badge></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5 }}>{String(r.last_verified ?? "—").slice(0, 10)}</span></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function TechbomEvidence() {
  const read = useApi(apiTechBomWorkspaceEvidence);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="Evidence & Provenance" sub="Measured / Imported / Inferred / Unknown / Contradicted with freshness — never a generic green">
      <WsState read={read} noun="evidence inventory">
        <WsTable head={["Asset", "Name", "Category", "Evidence", "Freshness", "Basis", "Last observed"]} colSpan={7}
          rows={rows.slice(0, 200).map((r, i) => (
            <tr key={i}>
              <td><code style={{ fontSize: 10.5 }}>{r.asset_ref}</code></td>
              <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.name}</span></td>
              <td><Badge tone="slate">{r.category}</Badge></td>
              <td><Badge tone={r.evidence_state === "MEASURED" ? "pass" : r.evidence_state === "IMPORTED" ? "cyan" : r.evidence_state === "INFERRED" ? "amber" : r.evidence_state === "CONTRADICTED" ? "red" : "slate"}>{r.evidence_state}</Badge></td>
              <td><Badge tone={r.freshness === "CURRENT" ? "green" : r.freshness === "STALE" ? "amber" : "slate"}>{r.freshness}</Badge></td>
              <td><span style={{ fontSize: 10.5, color: "var(--faint)" }}>{r.basis}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5 }}>{String(r.last_observed ?? "—").slice(0, 10)}</span></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function TechbomHistory() {
  const read = useApi(apiTechBomWorkspaceHistory);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="TechBOM History" sub="captured snapshots as stored — content-addressed, no invented versions">
      <WsState read={read} noun="history">
        <WsTable head={["Version", "Snapshot", "State", "Captured", "Components", "SHA-256"]} colSpan={6}
          rows={rows.slice(0, 100).map((r, i) => (
            <tr key={i}>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>v{r.version}</span></td>
              <td><code style={{ fontSize: 10.5 }}>{String(r.snapshot_id ?? "").slice(0, 16)}</code></td>
              <td><Badge tone="slate">{r.state}</Badge></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5 }}>{String(r.captured_at ?? "—").slice(0, 10)}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{r.total_components}</span></td>
              <td><code style={{ fontSize: 10.5 }}>{String(r.content_sha256 ?? "").slice(0, 12)}…</code></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function TechbomExport() {
  const read = useApi(apiTechBomWorkspaceExport);
  const formats = (read.data?.formats ?? []) as Array<Record<string, unknown>>;
  return (
    <Panel title="Export & Validation" sub="exports carry the stored relationship states as recorded">
      <WsState read={read} noun="export inventory">
        <WsTable head={["Format", "Path", "State"]} colSpan={3}
          rows={formats.map((f, i) => (
            <tr key={i}>
              <td><span style={{ fontSize: 12, fontWeight: 600 }}>{String(f.format)}</span></td>
              <td><code style={{ fontSize: 11 }}>{String(f.path)}</code></td>
              <td><Badge tone="pass">{String(f.state)}</Badge></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}
