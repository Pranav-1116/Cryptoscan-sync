import React, { useEffect, useState, useMemo } from "react";
import BomCrossNav from "../components/BomCrossNav";
import { CanonicalDetailLink } from "../components/AssetDetail";
import { Link, useSearchParams } from "react-router-dom";
import { Panel, Badge, Bar, Ring, Drawer } from "../components/ui";
import { usePollingApi, LiveBadge, useApi } from "../lib/apiUi.jsx";
import {
  apiHbomWorkspaceOverview, apiHbomWorkspaceAssets, apiHbomWorkspaceAssetDetail,
  apiHbomWorkspaceCategory, apiHbomWorkspaceFirmware, apiHbomWorkspaceCrypto,
  apiHbomWorkspaceLifecycle, apiHbomWorkspaceEvidence, apiHbomWorkspaceHistory,
  apiHbomWorkspaceExport, type HbomAssetRow,
} from "../lib/api.js";
import { useChannelRefresh } from "../lib/realtime.js";
import { apiLiveBom, LiveBomResponse, apiHbomEstate, apiHbomPin, apiHbomSnapshot, apiHbomSnapshots, apiHbomSnapshotDiff, HbomEstateDocument, HbomEstateComponent, HbomSnapshotMeta, HbomSnapshotDiff } from "../lib/api.js";
import { IconCertificate, IconCrypto, IconHardware, IconTarget, IconClock, IconSecurity, IconInfo, IconWarn, IconSearch } from "../components/icons";

/* HBOM — two honest surfaces visualized:
   1. Live-scan BOM (hardware a scan-run happened to see)
   2. Unified estate HBOM — ONE document over every persisted hardware row, content-addressed and pinnable */

// Provenance of an HBOM row: devices imported by a stored estate observation are
// declared, not fingerprinted by an agent, and the table must not blur the two.
const observationSource = (doc: HbomEstateDocument | null): string | null => {
  const direct = (doc?.metadata?.sources ?? []).find((item) => item.startsWith("estate observation"));
  return direct ?? null;
};
const fromObservation = (component: HbomEstateComponent, source: string | null): boolean =>
  Boolean(source) && component.evidence?.source === source;

const HBOM_TABS: Array<{ id: string; label: string }> = [
  { id: "overview", label: "HBOM Overview" },
  { id: "inventory", label: "Hardware Inventory" },
  { id: "compute", label: "Servers & Compute" },
  { id: "hsm", label: "HSM Inventory" },
  { id: "tpm", label: "TPM & Secure Elements" },
  { id: "network", label: "Network Hardware" },
  { id: "storage", label: "Storage Hardware" },
  { id: "firmware", label: "Firmware Intelligence" },
  { id: "crypto", label: "Hardware Crypto Capabilities" },
  { id: "lifecycle", label: "Hardware Lifecycle" },
  { id: "evidence", label: "Evidence & Provenance" },
  { id: "history", label: "HBOM History" },
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

function LifeBadge({ lifecycle }: { lifecycle: string }) {
  const tone = lifecycle === "END_OF_LIFE" ? "red" : lifecycle === "SUPPORTED" ? "pass" : "slate";
  return <Badge tone={tone}>{lifecycle}</Badge>;
}

function CapList({ caps }: { caps: Record<string, unknown> }) {
  const algos = Array.isArray(caps.algorithms) ? (caps.algorithms as unknown[]).map(String) : [];
  if (!algos.length && !caps.acceleration) return <span style={{ fontSize: 11, color: "var(--faint)" }}>none recorded</span>;
  return (
    <span style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
      {algos.slice(0, 4).map((a) => <Badge key={a} tone="slate">{a}</Badge>)}
      {caps.acceleration ? <Badge tone="violet">ACCELERATION</Badge> : null}
    </span>
  );
}

export default function Hbom() {
  const [wsParams, setWsParams] = useSearchParams();
  const active = HBOM_TABS.some((t) => t.id === wsParams.get("tab")) ? wsParams.get("tab") as string : "overview";
  const res = usePollingApi(apiLiveBom, 8000, [], { channels: ["crypto", "estate"] });
  useChannelRefresh(["crypto", "estate"], [res.run]);
  const live = res.source === "live";
  const bom = (res.data ?? null) as LiveBomResponse | null;
  const devices = bom?.hbom.components ?? [];

  const estate = usePollingApi(apiHbomEstate, 8000, [], { channels: ["estate", "crypto"] });
  const estateDoc = (estate.data ?? null) as HbomEstateDocument | null;
  const estateLive = estate.source === "live";

  const [snapshots, setSnapshots] = useState<HbomSnapshotMeta[]>([]);
  const [snapshotsNote, setSnapshotsNote] = useState("");
  const [snapshotsLoaded, setSnapshotsLoaded] = useState(false);
  const [pinBusy, setPinBusy] = useState(false);
  const [pinResult, setPinResult] = useState<string | null>(null);
  const [openSnapshot, setOpenSnapshot] = useState<any>(null);
  const [diffFor, setDiffFor] = useState<string | null>(null);
  const [diffData, setDiffData] = useState<HbomSnapshotDiff | null>(null);
  const [diffKeyBy, setDiffKeyBy] = useState<"asset_id" | "bom_ref">("asset_id");
  const [diffBusy, setDiffBusy] = useState(false);

  useEffect(() => {
    let alive = true;
    async function loadSnapshots() {
      const r = await apiHbomSnapshots();
      if (!alive) return;
      if (r.source === "live" && r.data) {
        setSnapshots(Array.isArray(r.data.snapshots) ? r.data.snapshots : []);
        setSnapshotsNote(typeof r.data.note === "string" ? r.data.note : "");
        setSnapshotsLoaded(true);
      } else {
        setSnapshots([]);
        setSnapshotsNote("");
        setSnapshotsLoaded(false);
      }
      setOpenSnapshot(null);
    }
    void loadSnapshots();
    return () => { alive = false; };
  }, []);

  async function pinSnapshot() {
    setPinBusy(true);
    setPinResult(null);
    const r = await apiHbomPin();
    setPinBusy(false);
    if (r.source === "live" && r.data) {
      setPinResult(r.data.note || (r.data.created ? "Estate HBOM pinned." : "Returned the existing pin."));
      const relisted = await apiHbomSnapshots();
      if (relisted.source === "live" && relisted.data) {
        setSnapshots(Array.isArray(relisted.data.snapshots) ? relisted.data.snapshots : []);
        setSnapshotsLoaded(true);
      }
    } else {
      setPinResult("Pin failed — the snapshot was not created.");
    }
  }

  async function viewSnapshot(id: string) {
    if (openSnapshot?.snapshot_id === id) {
      setOpenSnapshot(null);
      return;
    }
    const r = await apiHbomSnapshot(id);
    if (r.source === "live" && r.data) {
      setOpenSnapshot(r.data);
    } else {
      setOpenSnapshot({ snapshot_id: id, integrity: "UNAVAILABLE", integrity_note: "Snapshot could not be loaded." });
    }
  }

  async function loadDiff(targetId: string, againstId: string, keyBy: "asset_id" | "bom_ref") {
    setDiffBusy(true);
    try {
      const r = await apiHbomSnapshotDiff(targetId, againstId, keyBy);
      setDiffFor(targetId);
      if (r.source === "live" && r.data) setDiffData(r.data.diff);
      else setDiffData(null);
    } finally {
      setDiffBusy(false);
    }
  }

  const meta = estateDoc?.metadata;
  const estateSource = observationSource(estateDoc);
  // "not read" is not "zero": every estate figure below is gated on the estate
  // document actually having been returned. The two invented normalisers that
  // used to sit in the bars (/100, /80, /50, /40, /12) are gone — a bar now only
  // draws a ratio of two counts the document itself reports.
  const estateRead = estateLive && estateDoc != null;
  const ec = meta?.component_count ?? 0;
  const anchoredShare = ec > 0 ? Math.min(1, ((meta?.hsm_count ?? 0) + (meta?.tpm_count ?? 0)) / ec) : 0;
  const hsmShare = ec > 0 ? Math.min(1, (meta?.hsm_count ?? 0) / ec) : 0;

  // Live breakdown by type
  const liveByType = useMemo(() => {
    const m: Record<string, number> = {};
    devices.forEach((d: any) => { const t = d.type || "unknown"; m[t] = (m[t] || 0) + 1; });
    return Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 5);
  }, [devices]);

  // Estate breakdown by device_type
  const estateByType = useMemo(() => {
    if (!estateDoc) return [];
    const m: Record<string, number> = {};
    estateDoc.components.forEach((c) => { const t = c.device_type || "unknown"; m[t] = (m[t] || 0) + 1; });
    return Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 5);
  }, [estateDoc]);

  const ringPct = estateRead ? anchoredShare : 0;
  const ringTone = estateRead ? "green" : "slate";

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      <BomCrossNav current="HBOM" />
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16, flexWrap: "wrap", gap: 16 }}>
        <div style={{ flex: "1 1 420px", minWidth: 280 }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px", borderRadius: 999, background: "color-mix(in srgb, var(--accent) 12%, transparent)", border: "1px solid color-mix(in srgb, var(--accent) 35%, var(--line))", fontSize: 11, fontFamily: "var(--mono)", color: "var(--accent)", letterSpacing: "0.06em" }}>
            <span style={{ width: 6, height: 6, borderRadius: 99, background: estateLive ? "var(--green)" : "var(--accent)" }} /> BOMS · HBOM · HARDWARE ROOTS
          </div>
          <h1 style={{ fontSize: 26, fontWeight: 800, margin: "8px 0 6px", letterSpacing: "-0.02em", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ width: 34, height: 34, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--accent)", color: "var(--on-accent)" }}><IconHardware size={18} /></span>
            Hardware Bill of Materials
          </h1>
          <p style={{ margin: 0, fontSize: 13.5, color: "var(--dim)", lineHeight: 1.5, maxWidth: 620 }}>
            Every crypto-capable hardware device from live scans.
          </p>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-start", flexWrap: "wrap" }}>
          <Panel style={{ padding: "10px 14px", minWidth: 160, display: "flex", alignItems: "center", gap: 12 }}>
            <Ring pct={ringPct} label={estateRead ? String(ec) : "—"} sub={estateRead ? "estate" : "not read"} tone={ringTone} />
            <div>
              <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)" }}>HARDWARE POSTURE</div>
              <div style={{ fontSize: 12, color: "var(--dim)", maxWidth: 130, lineHeight: 1.4 }}>{estateRead
                ? `${meta?.hsm_count ?? 0} HSM · ${meta?.tpm_count ?? 0} TPM anchored ${meta?.as_of ? new Date(meta.as_of).toLocaleDateString() : "—"}`
                : estateLive ? "estate HBOM not returned" : "estate HBOM not read"}</div>
              <div style={{ marginTop: 6 }}><Bar value={ringPct} tone={ringTone} /></div>
            </div>
          </Panel>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <button onClick={() => void pinSnapshot()} disabled={pinBusy} className="btn primary" style={{ fontSize: 12, padding: "8px 14px", borderRadius: "var(--r)" }}>{pinBusy ? "Pinning…" : "Pin estate HBOM"}</button>
            <Link to="/live-scanners" className="btn outline" style={{ textDecoration: "none", fontSize: 12, padding: "8px 14px", borderRadius: "var(--r)", textAlign: "center", border: "1px solid var(--line-strong)", background: "var(--panel-2)" }}>Realtime scanners →</Link>
            <span style={{ fontSize: 11, color: "var(--faint)", textAlign: "center" }}>{estateDoc?.content_hash ? `SHA-256 ${estateDoc.content_hash.slice(0, 8)}…` : "no hash yet"}</span>
          </div>
        </div>
      </div>

      <div role="tablist" aria-label="HBOM sections" style={{ display: "flex", gap: 6, flexWrap: "wrap", margin: "2px 0 16px" }}>
        {HBOM_TABS.map((t) => (
          <button key={t.id} role="tab" aria-selected={active === t.id} title={t.label}
            onClick={() => setWsParams({ tab: t.id })}
            style={{
              fontSize: 11, padding: "6px 11px", borderRadius: 999, cursor: "pointer",
              border: `1px solid ${active === t.id ? "var(--accent)" : "var(--line-strong)"}`,
              background: active === t.id ? "color-mix(in srgb, var(--accent) 14%, transparent)" : "var(--panel-2)",
              color: active === t.id ? "var(--accent)" : "var(--dim)", fontFamily: "var(--mono)", letterSpacing: ".03em",
            }}>{t.label}</button>
        ))}
      </div>

      {active === "overview" && (<>
      {/* KPI cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 14, marginBottom: 18 }}>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--accent)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", display: "flex", alignItems: "center", gap: 6 }}><IconHardware size={12} /> LIVE-SCAN COMPONENTS</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{devices.length}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>Current scan-run view</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--accent) 14%, transparent)", border: "1px solid color-mix(in srgb, var(--accent) 35%, var(--line))", color: "var(--accent)" }}><IconTarget size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--dim)", marginBottom: 6 }}><span>{liveByType.length ? liveByType[0][0] : "—"} top</span><span style={{ color: live ? "var(--green)" : "var(--faint)" }}>{live ? "● LIVE" : "offline"}</span></div>
            <Bar value={estateRead && estateDoc!.components.length ? Math.min(1, devices.length / estateDoc!.components.length) : 0} tone={live ? "cyan" : "slate"} />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>
              {estateRead && estateDoc!.components.length
                ? `${Math.round((devices.length / estateDoc!.components.length) * 100)}% of the persisted estate seen by this scan-run`
                : "What this scan happened to see"}
            </div>
          </div>
        </div>

        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${(meta?.component_count ?? 0) ? "var(--green)" : "var(--slate)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", display: "flex", alignItems: "center", gap: 6 }}><IconSecurity size={12} /> ESTATE COMPONENTS</div>
              <div style={{ fontSize: 32, fontWeight: 800, color: ec ? "var(--green)" : "var(--faint)", margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{estateRead ? ec : "—"}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>Unified persisted DB truth</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: (meta?.component_count ?? 0) ? "color-mix(in srgb, var(--green) 14%, transparent)" : "var(--panel-2)", border: `1px solid color-mix(in srgb, ${(meta?.component_count ?? 0) ? "var(--green)" : "var(--line)"} 35%, var(--line))`, color: (meta?.component_count ?? 0) ? "var(--green)" : "var(--faint)" }}><IconCertificate size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--dim)", marginBottom: 6 }}><span>ENV {meta?.environment || "—"}</span><span style={{ color: "var(--green)" }}>content-addressed</span></div>
            <Bar value={anchoredShare} tone={ec ? "green" : "slate"} />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>
              {ec ? `${Math.round(anchoredShare * 100)}% of components carry an HSM/TPM anchor` : "ONE document — not live engine memory"}
            </div>
          </div>
        </div>

        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${(meta?.hsm_count ?? 0) ? "var(--violet)" : "var(--line-strong)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", display: "flex", alignItems: "center", gap: 6 }}><IconCrypto size={12} /> HSM FLEET</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{estateRead ? meta?.hsm_count ?? 0 : "—"}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>Hardware security modules</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: (meta?.hsm_count ?? 0) ? "color-mix(in srgb, var(--violet) 14%, transparent)" : "var(--panel-2)", border: `1px solid color-mix(in srgb, ${(meta?.hsm_count ?? 0) ? "var(--violet)" : "var(--line)"} 35%, var(--line))`, color: (meta?.hsm_count ?? 0) ? "var(--violet)" : "var(--faint)" }}><IconCrypto size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 6 }}>
              <Badge tone={meta?.hsm_count ? "violet" : "slate"}>HSM {estateRead ? meta?.hsm_count ?? 0 : "—"}</Badge>
              <Badge tone={meta?.tpm_count ? "violet" : "slate"}>TPM {estateRead ? meta?.tpm_count ?? 0 : "—"}</Badge>
            </div>
            <Bar value={hsmShare} tone={ec ? "violet" : "slate"} />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>{ec ? "share of estate components" : "estate not read"}</div>
          </div>
        </div>

        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--green)", background: snapshots.length ? "color-mix(in srgb, var(--green) 4%, var(--panel))" : "var(--panel)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>PINNED SNAPSHOTS</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{snapshots.length}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>Verbatim + SHA-256 self-check</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: snapshots.length ? "color-mix(in srgb, var(--green) 14%, transparent)" : "var(--panel-2)", border: `1px solid color-mix(in srgb, ${snapshots.length ? "var(--green)" : "var(--line)"} 35%, var(--line))`, color: snapshots.length ? "var(--green)" : "var(--faint)" }}><IconClock size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--dim)", marginBottom: 6 }}><span>{snapshotsLoaded ? "content-addressed" : "not loaded"}</span><span style={{ color: snapshots.length ? "var(--green)" : "var(--faint)" }}>{snapshots.length ? "auditable" : "none pinned"}</span></div>
            <Bar value={snapshots.length ? Math.min(1, snapshots.length / 10) : 0} tone={snapshots.length ? "green" : "slate"} />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>Identical renderings collapse</div>
          </div>
        </div>
      </div>

      {/* Analytics strip */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 14, marginBottom: 18 }}>
        <Panel title="Live hardware by type" sub="this scan-run's view — what was seen on the wire" style={{ padding: "14px 16px" }}>
          {liveByType.length ? liveByType.map(([t, n]) => (
            <div key={t} style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
              <span style={{ width: 110, fontSize: 11, color: "var(--dim)", fontFamily: "var(--mono)" }}>{t}</span>
              <div style={{ flex: 1 }}><Bar value={devices.length ? n / devices.length : 0} tone="cyan" /></div>
              <span style={{ fontSize: 11, fontFamily: "var(--mono)", color: "var(--text)", minWidth: 28, textAlign: "right" }}>{n}</span>
            </div>
          )) : <div style={{ fontSize: 12, color: "var(--dim)", padding: "8px 0" }}>No live HBOM — run a hardware scan in Operations → Realtime scanners</div>}
          <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 4, borderTop: "1px solid var(--line)", paddingTop: 8 }}>Live scan opinion — empty until a scan runs</div>
        </Panel>
        <Panel title="Estate composition" sub="persisted DB truth — by device_type" style={{ padding: "14px 16px" }}>
          {estateByType.length ? estateByType.map(([t, n]) => (
            <div key={t} style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
              <span style={{ width: 110, fontSize: 11, color: "var(--dim)", fontFamily: "var(--mono)" }}>{t}</span>
              <div style={{ flex: 1 }}><Bar value={(meta?.component_count ?? 0) ? n / (meta!.component_count!) : 0} tone="green" /></div>
              <span style={{ fontSize: 11, fontFamily: "var(--mono)", color: "var(--text)", minWidth: 28, textAlign: "right" }}>{n}</span>
            </div>
          )) : <div style={{ fontSize: 12, color: "var(--dim)", padding: "8px 0" }}><span title={"No persisted hardware assets for this environment — HBOM is empty, not fabricated"}>{"No persisted hardware assets for this environment"}</span></div>}
          <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 4, borderTop: "1px solid var(--line)", paddingTop: 8 }}>Estate document — regenerated from rows · anchor {meta?.as_of ? new Date(meta.as_of).toLocaleDateString() : "—"}</div>
        </Panel>
        <Panel title="Integrity posture" sub="content hash + evidence anchoring" style={{ padding: "14px 16px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
            <div style={{ width: 54, height: 54, borderRadius: 999, background: estateDoc ? "color-mix(in srgb, var(--green) 14%, transparent)" : "var(--panel-2)", border: `2px solid ${estateDoc ? "var(--green)" : "var(--line)"}`, display: "grid", placeItems: "center", color: estateDoc ? "var(--green)" : "var(--faint)", fontSize: 16, fontWeight: 800 }}>{estateDoc ? "✓" : "—"}</div>
            <div>
              <div style={{ fontSize: 12, fontWeight: 700 }}>Document integrity</div>
              <div style={{ fontSize: 11, color: "var(--dim)", fontFamily: "var(--mono)" }}>{estateDoc ? `${estateDoc.content_hash.slice(0, 16)}…` : "no document"}</div>
              <div style={{ fontSize: 10, color: estateDoc ? "var(--green)" : "var(--faint)", marginTop: 2 }}>{estateDoc ? `anchor ${meta?.as_of ? new Date(meta.as_of).toLocaleDateString() : "—"}` : "awaiting persisted assets"}</div>
            </div>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8, textAlign: "center" }}>
            <div style={{ padding: "8px 6px", background: "var(--panel-2)", borderRadius: "var(--r)", border: "1px solid var(--line)" }}><div style={{ fontSize: 16, fontWeight: 800, fontFamily: "var(--mono)" }}>{estateRead ? estateDoc!.components.reduce((a, c) => a + (c.evidence?.evidence_ids?.length ?? 0), 0) : "—"}</div><div style={{ fontSize: 10, color: "var(--faint)" }}>EVIDENCE REFS</div></div>
            <div style={{ padding: "8px 6px", background: "color-mix(in srgb, var(--violet) 8%, var(--panel-2))", borderRadius: "var(--r)", border: "1px solid var(--line)" }}><div style={{ fontSize: 16, fontWeight: 800, color: "var(--violet)" }}>{snapshots.length}</div><div style={{ fontSize: 10, color: "var(--faint)" }}>SNAPSHOTS</div></div>
            <div style={{ padding: "8px 6px", background: "color-mix(in srgb, var(--green) 8%, var(--panel-2))", borderRadius: "var(--r)", border: "1px solid var(--line)" }}><div style={{ fontSize: 16, fontWeight: 800, color: "var(--green)" }}>{estateRead ? meta?.sources?.length ?? 0 : "—"}</div><div style={{ fontSize: 10, color: "var(--faint)" }}>SOURCES</div></div>
          </div>
        </Panel>
      </div>

      {/* Live-scan HBOM */}
      <div className="panel" style={{ padding: 0, overflow: "hidden", marginBottom: 18 }}>
        <div style={{ padding: "14px 18px", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10, borderBottom: "1px solid var(--line)", background: "var(--bg-2)" }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, display: "flex", alignItems: "center", gap: 8 }}><IconInfo size={14} style={{ color: "var(--accent)" }} /> Trusted Hardware Layer</h3>
            <p style={{ margin: "4px 0 0", fontSize: 11, color: "var(--dim)" }}>Every crypto-capable hardware device from the live scan · <span style={{ color: "var(--accent)" }}>ephemeral — not estate truth</span></p>
          </div>
          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            {live && <LiveBadge source="live" label="LIVE" />}
            <Badge tone={devices.length ? "green" : "slate"}>{devices.length} components</Badge>
          </div>
        </div>
        <div style={{ overflowX: "auto" }}>
          <table className="tbl" style={{ width: "100%" }}>
            <thead><tr><th>Type</th><th>Vendor / Component</th><th>Firmware</th><th>Capabilities</th><th>Host</th></tr></thead>
            <tbody>
              {devices.map((h: any) => (
                <tr key={h.ref + h.name}>
                  <td><Badge tone="violet">{h.type}</Badge></td>
                  <td><span className="mono" style={{ fontWeight: 700, fontSize: 12 }}>{h.name}</span></td>
                  <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{h.version || "—"}</span></td>
                  <td><span style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>{(h.caps ?? []).length ? h.caps.map((c: string) => <Badge key={c} tone="slate">{c}</Badge>) : <span style={{ color: "var(--faint)", fontSize: 11 }}>—</span>}</span></td>
                  <td><span className="mono" style={{ fontSize: 11, color: "var(--dim)" }}>{h.ref}</span></td>
                </tr>
              ))}
              {!devices.length && (
                <tr><td colSpan={5} style={{ padding: 28, textAlign: "center", color: "var(--dim)" }}><div style={{ fontWeight: 600, color: "var(--text)" }}>No HBOM yet</div><div style={{ fontSize: 12, marginTop: 4 }}><span title={"Run a live hardware scan in Operations → Realtime scanners — empty is not fabricated"}>{"Run a live hardware scan in Operations → Realtime scanners"}</span></div></td></tr>
              )}
            </tbody>
          </table>
        </div>
        <div style={{ padding: "10px 16px", background: "var(--bg-2)", borderTop: "1px solid var(--line)", display: "flex", gap: 12, flexWrap: "wrap", fontSize: 11, color: "var(--dim)" }}>
          <span><span style={{ width: 8, height: 8, borderRadius: 99, background: "var(--accent)", display: "inline-block" }} /> live scan</span>
          <span style={{ marginLeft: "auto", fontFamily: "var(--mono)" }}>Ephemeral — not persisted</span>
        </div>
      </div>

      {/* Estate HBOM */}
      <div className="panel" style={{ padding: 0, overflow: "hidden", marginBottom: 18 }}>
        <div style={{ padding: "14px 18px", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10, borderBottom: "1px solid var(--line)", background: "var(--bg-2)" }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, display: "flex", alignItems: "center", gap: 8 }}><span style={{ width: 8, height: 8, borderRadius: 99, background: "var(--green)" }} /> Unified Estate HBOM</h3>
            <p style={{ margin: "4px 0 0", fontSize: 11, color: "var(--dim)" }}>ONE document over the persisted hardware inventory and the newest stored estate observation · per-asset identity + evidence refs · <span style={{ color: "var(--green)" }}>SHA-256 {estateDoc ? estateDoc.content_hash.slice(0, 12) : "—"}…</span></p>
          </div>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
            {estateLive && <LiveBadge source="live" label="LIVE" />}
            <Badge tone={ec ? "violet" : "slate"}>{estateRead ? `${ec} ESTATE` : "estate not read"}</Badge>
            {meta?.hsm_count ? <Badge tone="violet">HSM {meta.hsm_count}</Badge> : null}
            {meta?.tpm_count ? <Badge tone="violet">TPM {meta.tpm_count}</Badge> : null}
            <Badge tone="slate">0 deps — declared</Badge>
          </div>
        </div>
        {!estateDoc ? (
          <div style={{ padding: 32, textAlign: "center", color: "var(--dim)" }}>
            <div style={{ width: 40, height: 40, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--panel-2)", border: "1px solid var(--line)", margin: "0 auto 10px" }}><IconHardware size={16} style={{ color: "var(--faint)" }} /></div>
            <div style={{ fontWeight: 600, color: "var(--text)" }}>Estate document unavailable</div>
            <div style={{ fontSize: 12, marginTop: 4 }}><span title={"Generated from persisted hardware_assets — not live engine memory, not TechBOM hardware layer"}>{"Generated from persisted hardware_assets"}</span></div>
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table className="tbl" style={{ width: "100%" }}>
              <thead><tr><th>Asset</th><th>Vendor / Model</th><th>Type</th><th>Firmware</th><th>Modules</th><th>Agent</th><th>Last seen</th><th>Evidence</th></tr></thead>
              <tbody>
                {estateDoc.components.map((c) => (
                  <tr key={c.asset_id}>
                    <td><span className="mono" style={{ fontWeight: 700, fontSize: 12 }}>{c.asset_id}</span></td>
                    <td><span className="mono" style={{ fontSize: 11 }}>{c.name}</span></td>
                    <td><Badge tone="violet">{c.device_type}</Badge></td>
                    <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{typeof c.firmware?.details === "string" ? c.firmware.details : ((c.firmware?.details as any)?.version || "—")}</span></td>
                    <td><span style={{ display: "flex", gap: 4 }}>{c.security_modules?.hsm ? <Badge tone="green">HSM</Badge> : null}{c.security_modules?.tpm ? <Badge tone="green">TPM</Badge> : null}{!c.security_modules?.hsm && !c.security_modules?.tpm ? <span style={{ color: "var(--faint)", fontSize: 11 }}>—</span> : null}</span></td>
                    <td><span className="mono" style={{ fontSize: 11, color: "var(--dim)" }}>{c.evidence?.agent_id || (fromObservation(c, estateSource) ? "no agent (imported)" : "—")}</span></td>
                    <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{c.evidence?.last_seen ? new Date(c.evidence.last_seen).toLocaleDateString() : "—"}</span></td>
                    <td><span style={{ display: "flex", gap: 4, flexWrap: "wrap" }}><Badge tone={fromObservation(c, estateSource) ? "amber" : "slate"}>{c.evidence?.evidence_ids?.length ?? 0} refs</Badge>{fromObservation(c, estateSource) ? <Badge tone="amber">imported</Badge> : null}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!estateDoc.components.length && <div style={{ padding: 20, textAlign: "center", color: "var(--dim)", fontSize: 12 }}><span title={"No hardware assets persisted for this environment — empty, not fabricated"}>{"No hardware assets persisted for this environment"}</span></div>}
          </div>
        )}
        {estateDoc && <div style={{ padding: "10px 16px", background: "var(--bg-2)", borderTop: "1px solid var(--line)", fontSize: 11, color: "var(--dim)", display: "flex", gap: 8, flexWrap: "wrap" }}><span>Sources: {meta?.sources?.join(", ") || "—"}</span>
          {(meta?.notes ?? []).map((note) => <span key={note} style={{ color: "var(--dim)" }}>{note}</span>)}
          <span style={{ marginLeft: "auto", fontFamily: "var(--mono)" }}>NOT TechBOM hardware layer · NOT live engine memory</span></div>}
      </div>

      {/* Pinned snapshots */}
      <div className="panel" style={{ padding: 0, overflow: "hidden" }}>
        <div style={{ padding: "14px 18px", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10, borderBottom: "1px solid var(--line)", background: "var(--bg-2)" }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, display: "flex", alignItems: "center", gap: 8 }}><IconClock size={14} style={{ color: "var(--accent)" }} /> Pinned Estate Snapshots</h3>
            <p style={{ margin: "4px 0 0", fontSize: 11, color: "var(--dim)" }}>Content-addressed (SHA-256) · identical collapse · verbatim + integrity self-check</p>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <button className="btn sm outline" disabled={pinBusy} onClick={() => void pinSnapshot()} style={{ fontSize: 11.5, padding: "4px 10px" }}>{pinBusy ? "Pinning…" : "Pin current →"}</button>
            <Badge tone={snapshots.length ? "green" : "slate"}>{snapshots.length} pins</Badge>
          </div>
        </div>
        {pinResult && <div style={{ padding: "8px 16px", fontSize: 12, color: "var(--dim)", background: "color-mix(in srgb, var(--accent) 6%, transparent)", borderBottom: "1px solid var(--line)" }}>{pinResult}</div>}
        {!snapshotsLoaded ? (
          <div style={{ padding: 28, textAlign: "center", color: "var(--dim)", fontSize: 12 }}>Snapshot list unavailable — backend not reachable</div>
        ) : snapshots.length === 0 ? (
          <div style={{ padding: 28, textAlign: "center", color: "var(--dim)" }}><div style={{ fontWeight: 600, color: "var(--text)" }}>No snapshots pinned yet</div><div style={{ fontSize: 12, marginTop: 4 }}><span title={"Pin freezes the current rendering for export and audit — identical pins collapse"}>{"Pin freezes the current rendering for export and audit"}</span></div></div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table className="tbl" style={{ width: "100%" }}>
              <thead><tr><th>Content hash</th><th>Env</th><th>Components</th><th>Anchor</th><th>Pinned at</th><th>By</th><th></th></tr></thead>
              <tbody>
                {snapshots.map((s, index) => (
                  <React.Fragment key={s.snapshot_id}>
                    <tr>
                      <td><span style={{ fontFamily: "var(--mono)", fontSize: 11, padding: "2px 6px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>{String(s.content_hash || "").slice(0, 12)}…</span></td>
                      <td><Badge tone="slate">{s.environment || "—"}</Badge></td>
                      <td><span style={{ fontFamily: "var(--mono)", fontWeight: 700, fontSize: 12 }}>{s.component_count ?? "—"}</span></td>
                      <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{s.as_of ? new Date(s.as_of).toLocaleDateString() : "—"}</span></td>
                      <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{s.snapshotted_at ? new Date(s.snapshotted_at).toLocaleDateString() : "—"}</span></td>
                      <td><span style={{ fontSize: 11 }}>{s.created_by || "—"}</span></td>
                      <td>
                        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                          <button className="btn sm" onClick={() => void viewSnapshot(s.snapshot_id)} style={{ fontSize: 11.5, padding: "4px 10px" }}>{openSnapshot?.snapshot_id === s.snapshot_id ? "Hide" : "Verify & View"}</button>
                          {snapshots.length > 1 && index < snapshots.length - 1 && (
                            <button className="btn sm outline" disabled={diffBusy} onClick={() => diffFor === s.snapshot_id ? (setDiffFor(null), setDiffData(null)) : void loadDiff(s.snapshot_id, snapshots[index + 1].snapshot_id, diffKeyBy)} style={{ fontSize: 11.5, padding: "4px 10px" }}>{diffFor === s.snapshot_id ? "Hide Diff" : "Diff vs Prev"}</button>
                          )}
                        </div>
                      </td>
                    </tr>
                    {openSnapshot?.snapshot_id === s.snapshot_id && (
                      <tr><td colSpan={7} style={{ background: "var(--bg-2)", borderTop: "1px dashed var(--line)" }}>
                        <div style={{ padding: "10px 4px", display: "grid", gap: 8 }}>
                          <div style={{ fontSize: 12.5, display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                            <strong style={{ fontSize: 12 }}>VERBATIM DOCUMENT</strong>
                            <Badge tone={openSnapshot.integrity === "OK" ? "green" : openSnapshot.integrity === "MISMATCH" ? "red" : "slate"}>{String(openSnapshot.integrity || "—")}</Badge>
                            <span style={{ color: openSnapshot.integrity === "OK" ? "var(--dim)" : "var(--red)", fontSize: 12 }}>{openSnapshot.integrity_note}</span>
                          </div>
                          {openSnapshot.payload && (
                            <div style={{ display: "grid", gap: 4 }}>
                              <div style={{ fontSize: 12 }}>{openSnapshot.payload.metadata?.component_count ?? 0} components · {openSnapshot.payload.metadata?.hsm_count ?? 0} HSM · {openSnapshot.payload.metadata?.tpm_count ?? 0} TPM · anchor {openSnapshot.payload.metadata?.as_of || "—"}</div>
                              <pre style={{ fontSize: 11, margin: 0, maxHeight: 220, overflow: "auto", background: "var(--bg)", padding: 8, border: "1px solid var(--line)" }}>{JSON.stringify(openSnapshot.payload, null, 2)}</pre>
                            </div>
                          )}
                        </div>
                      </td></tr>
                    )}
                    {diffFor === s.snapshot_id && (
                      <tr><td colSpan={7} style={{ background: "var(--bg-2)", borderTop: "1px dashed var(--line)" }}>
                        <div style={{ padding: "10px 4px", display: "grid", gap: 8 }}>
                          <div style={{ fontSize: 12.5, display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                            <strong style={{ fontSize: 12 }}>PIN COMPARISON</strong>
                            {diffData ? <><Badge tone={diffData.summary.added ? "green" : "slate"}>+{diffData.summary.added} added</Badge><Badge tone={diffData.summary.removed ? "red" : "slate"}>−{diffData.summary.removed} removed</Badge><Badge tone={diffData.summary.changed ? "amber" : "slate"}>{diffData.summary.changed} changed</Badge><Badge tone="slate">{diffData.summary.unchanged} unchanged</Badge>{diffData.identical && <Badge tone="green">IDENTICAL</Badge>}
                              <div style={{ display: "flex", gap: 4, marginLeft: "auto" }}>{(["asset_id", "bom_ref"] as const).map((mode) => <button key={mode} className={`btn sm ${diffKeyBy === mode ? "" : "outline"}`} disabled={diffBusy} onClick={() => { setDiffKeyBy(mode); void loadDiff(s.snapshot_id, snapshots[index + 1].snapshot_id, mode); }} style={{ fontSize: 11, padding: "3px 8px" }}>{mode === "asset_id" ? "estate drift" : "exact"}</button>)}</div>
                            </> : <span style={{ color: "var(--red)", fontSize: 12 }}>Diff unavailable</span>}
                          </div>
                          {diffData?.excluded_paths.length ? <div style={{ fontSize: 11, color: "var(--dim)" }}>Excluded as observation churn: {diffData.excluded_paths.join(", ")}</div> : null}
                          {diffData && diffKeyBy === "bom_ref" && <div style={{ fontSize: 11, color: "var(--dim)" }}>Exact mode: every field the documents carry is compared, including observation churn.</div>}
                          {diffData?.components.added.length ? <div style={{ fontSize: 12 }}><strong>ADDED</strong> {diffData.components.added.map((a) => <span key={a.key} className="mono" style={{ marginRight: 10 }}>{a.name || a.key}</span>)}</div> : null}
                          {diffData?.components.removed.length ? <div style={{ fontSize: 12 }}><strong>REMOVED</strong> {diffData.components.removed.map((r) => <span key={r.key} className="mono" style={{ marginRight: 10 }}>{r.name || r.key}</span>)}</div> : null}
                          {diffData?.components.changed.map((ch) => <div key={ch.key} style={{ fontSize: 12, display: "grid", gap: 2 }}><span className="mono" style={{ fontWeight: 600 }}>{ch.key}</span>{ch.changes.map((c) => <span key={c.path} style={{ color: "var(--dim)", fontSize: 12 }}>{c.path}: <span className="mono">{String(c.before ?? "—")}</span> → <span className="mono" style={{ color: "var(--amber)" }}>{String(c.after ?? "—")}</span></span>)}</div>)}
                        </div>
                      </td></tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
            {snapshotsNote && <div style={{ padding: "8px 16px", fontSize: 11, color: "var(--faint)", background: "var(--bg-2)", borderTop: "1px solid var(--line)" }}>{snapshotsNote}</div>}
          </div>
        )}
      </div>
      </>)}
      {active === "inventory" && <HbomInventory />}
      {active === "compute" && <HbomCategory kind="compute" label="Servers & Compute" noun="server or compute" />}
      {active === "hsm" && <HbomCategory kind="hsm" label="HSM Inventory" noun="HSM" />}
      {active === "tpm" && <HbomCategory kind="tpm" label="TPM & Secure Elements" noun="TPM record" />}
      {active === "network" && <HbomCategory kind="network" label="Network Hardware" noun="network device" />}
      {active === "storage" && <HbomCategory kind="storage" label="Storage Hardware" noun="storage device" />}
      {active === "firmware" && <HbomFirmware />}
      {active === "crypto" && <HbomCrypto />}
      {active === "lifecycle" && <HbomLifecycle />}
      {active === "evidence" && <HbomEvidence />}
      {active === "history" && <HbomHistory />}
      {active === "export" && <HbomExport />}
    </div>
  );
}

/* ── workspace sections (docs/boms/01_PRODUCT_SPEC.md §3 navigation) ─── */

function HbomInventory() {
  const [q, setQ] = useState("");
  const read = useApi(() => apiHbomWorkspaceAssets(q || undefined), [q]);
  const rows = (read.data?.rows ?? []) as HbomAssetRow[];
  const [selected, setSelected] = useState<HbomAssetRow | null>(null);
  const detail = useApi(
    () => apiHbomWorkspaceAssetDetail(selected?.asset_id ?? ""),
    [selected?.asset_id],
  );
  return (
    <>
      <Panel title="Hardware Inventory" sub="serial references are masked at the API boundary — click a device for firmware, TPM/HSM metadata and evidence">
        <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
          <input value={q} onChange={(e) => setQ(e.target.value)}
            placeholder="search by asset id, manufacturer or model"
            aria-label="search hardware assets"
            style={{ flex: 1, minWidth: 220, padding: "7px 10px", borderRadius: "var(--r)", border: "1px solid var(--line-strong)", background: "var(--panel-2)", color: "var(--text)", fontSize: 12 }} />
          <Badge tone="slate">{read.data?.total ?? (read.source === "live" ? rows.length : "—")} assets</Badge>
        </div>
        <WsState read={read} noun="hardware inventory">
          <WsTable
            head={["Asset ID", "Manufacturer", "Model", "Serial reference", "Firmware", "Category", "Location", "Crypto capabilities", "Lifecycle", "Evidence"]}
            colSpan={10}
            rows={rows.map((r) => (
              <tr key={r.asset_id} style={{ cursor: "pointer" }} onClick={() => setSelected(r)}>
                <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.asset_id}</span></td>
                <td><span style={{ fontSize: 11.5 }}>{r.manufacturer || "—"}</span></td>
                <td><span style={{ fontSize: 11.5 }}>{r.model || "—"}</span></td>
                <td><span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--dim)" }}>{r.serial_reference || "NOT_COLLECTED"}</span></td>
                <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{r.firmware || "NOT_COLLECTED"}</span></td>
                <td><Badge tone="slate">{r.category}</Badge></td>
                <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{r.location || "NOT_COLLECTED"}</span></td>
                <td><CapList caps={r.crypto_capabilities} /></td>
                <td><LifeBadge lifecycle={r.lifecycle} /></td>
                <td>
                  <span style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                    <Badge tone={r.evidence.freshness === "CURRENT" ? "pass" : r.evidence.freshness === "STALE" ? "amber" : "slate"}>{r.evidence.freshness}</Badge>
                    {r.evidence.fingerprinted ? <Badge tone="violet">fingerprinted</Badge> : <Badge tone="slate">not fingerprinted</Badge>}
                  </span>
                </td>
              </tr>
            ))}
          />
        </WsState>
      </Panel>
      {selected && (
        <Drawer title={selected.model || selected.asset_id} sub={selected.asset_id} onClose={() => setSelected(null)}>
          <CanonicalDetailLink assetRef={`hw:${selected.asset_id}`} />
          {!detail.data ? <p className="faint" style={{ fontSize: 12 }}>{detail.running ? "Reading the device…" : "The device detail did not return."}</p> : (
            (() => {
              const d = detail.data as Record<string, any>;
              const a: HbomAssetRow = d.asset ?? selected;
              return (
                <div style={{ display: "grid", gap: 12 }}>
                  <div style={{ display: "grid", gap: 6, fontSize: 12 }}>
                    <div><b>Device</b> {a.manufacturer || "—"} {a.model || ""} · {a.category}</div>
                    <div><b>Firmware</b> {a.firmware || "NOT_COLLECTED"} · <b>Serial</b> <span style={{ fontFamily: "var(--mono)" }}>{a.serial_reference || "NOT_COLLECTED"}</span></div>
                    <div><b>Location</b> {a.location || "NOT_COLLECTED"}</div>
                    <div><b>Lifecycle</b> <LifeBadge lifecycle={a.lifecycle} /> <span style={{ fontSize: 10.5, color: "var(--faint)" }}>{a.lifecycle_basis}</span></div>
                  </div>
                  {Object.keys(d.tpm ?? {}).length > 0 && (
                    <div>
                      <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>TPM & SECURE BOOT</div>
                      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                        {Object.entries(d.tpm).map(([k, v]) => <Badge key={k} tone="slate">{k}: {String(v)}</Badge>)}
                      </div>
                    </div>
                  )}
                  {Object.keys(d.hsm ?? {}).length > 0 && (
                    <div>
                      <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>HSM CAPABILITIES — APPROVED METADATA ONLY</div>
                      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                        {Object.entries(d.hsm).map(([k, v]) => <Badge key={k} tone="slate">{k}: {String(v)}</Badge>)}
                      </div>
                    </div>
                  )}
                  <div>
                    <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>CPU CRYPTOGRAPHIC ACCELERATION</div>
                    <CapList caps={d.cpu_acceleration ?? {}} />
                  </div>
                  <div>
                    <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>HARDWARE CAPABILITIES — CAPABILITY IS NEVER USE</div>
                    <CapList caps={a.crypto_capabilities} />
                  </div>
                  <div>
                    <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>RELATED ASSETS</div>
                    <div style={{ fontSize: 11.5, color: "var(--dim)" }}>{String(d.related?._note ?? "no stored cross-BOM link rows name this hardware asset")}</div>
                  </div>
                  {(d.firmware_history ?? []).length > 0 && (
                    <div>
                      <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>FIRMWARE CHANGE HISTORY</div>
                      {(d.firmware_history ?? []).slice(0, 8).map((h: Record<string, unknown>, i: number) => (
                        <div key={i} style={{ fontSize: 11, color: "var(--dim)", fontFamily: "var(--mono)" }}>
                          {String(h.observed_at ?? "—").slice(0, 19)} · {String(h.event_type)}{h.change_class ? ` · ${String(h.change_class)}` : ""}
                        </div>
                      ))}
                    </div>
                  )}
                  <div>
                    <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>EVIDENCE</div>
                    <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 4 }}>
                      <Badge tone={a.evidence.freshness === "CURRENT" ? "pass" : "slate"}>{a.evidence.freshness}</Badge>
                      <Badge tone="slate">{a.evidence.evidence_records} evidence record(s)</Badge>
                      {a.evidence.agent_id ? <Badge tone="violet">agent {a.evidence.agent_id}</Badge> : <Badge tone="slate">no agent</Badge>}
                    </div>
                    {(d.evidence_history ?? []).slice(0, 6).map((e: Record<string, unknown>, i: number) => (
                      <div key={i} style={{ fontSize: 11, color: "var(--dim)" }}>{String(e.event_type)} · {String(e.source)} · {String(e.observed_at ?? "—").slice(0, 19)}</div>
                    ))}
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

function HbomCategory({ kind, label, noun }: { kind: "compute" | "hsm" | "tpm" | "network" | "storage"; label: string; noun: string }) {
  const read = useApi(() => apiHbomWorkspaceCategory(kind), [kind]);
  const rows = (read.data?.rows ?? []) as HbomAssetRow[];
  return (
    <Panel title={label} sub={`stored ${noun} records — metadata only, key material never`}>
      <WsState read={read} noun={noun}>
        <WsTable head={["Asset ID", "Manufacturer", "Model", "Firmware", "Crypto capabilities", "Lifecycle", "Evidence"]} colSpan={7}
          rows={rows.map((r) => (
            <tr key={r.asset_id}>
              <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.asset_id}</span></td>
              <td><span style={{ fontSize: 11.5 }}>{r.manufacturer || "—"}</span></td>
              <td><span style={{ fontSize: 11.5 }}>{r.model || "—"}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{r.firmware || "NOT_COLLECTED"}</span></td>
              <td><CapList caps={r.crypto_capabilities} /></td>
              <td><LifeBadge lifecycle={r.lifecycle} /></td>
              <td><Badge tone={r.evidence.freshness === "CURRENT" ? "pass" : "slate"}>{r.evidence.freshness}</Badge></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function HbomFirmware() {
  const read = useApi(apiHbomWorkspaceFirmware);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="Firmware Intelligence" sub="firmware versions and change events as recorded — an unrecorded version is NOT_COLLECTED, never current">
      <WsState read={read} noun="firmware inventory">
        <WsTable head={["Asset", "Model", "Firmware", "Last check", "Freshness", "Change events"]} colSpan={6}
          rows={rows.slice(0, 200).map((r) => (
            <tr key={r.asset_id}>
              <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.asset_id}</span></td>
              <td><span style={{ fontSize: 11.5 }}>{r.model || "—"}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{r.firmware || "NOT_COLLECTED"}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5, color: "var(--dim)" }}>{String(r.last_firmware_check ?? "—").slice(0, 10)}</span></td>
              <td><Badge tone={r.freshness === "CURRENT" ? "pass" : r.freshness === "STALE" ? "amber" : "slate"}>{r.freshness}</Badge></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{r.change_events}</span></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function HbomCrypto() {
  const read = useApi(apiHbomWorkspaceCrypto);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="Hardware Crypto Capabilities" sub="supported features as reported — a hardware capability is never drawn as use">
      <WsState read={read} noun="crypto-capability inventory">
        <WsTable head={["Asset", "Model", "Capabilities", "Usage state", "Basis"]} colSpan={5}
          rows={rows.slice(0, 200).map((r) => (
            <tr key={r.asset_id}>
              <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.asset_id}</span></td>
              <td><span style={{ fontSize: 11.5 }}>{r.model || "—"}</span></td>
              <td><CapList caps={r.capabilities} /></td>
              <td><Badge tone="slate">{r.usage_state}</Badge></td>
              <td><span style={{ fontSize: 10.5, color: "var(--faint)" }}>{r.basis}</span></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function HbomLifecycle() {
  const read = useApi(apiHbomWorkspaceLifecycle);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="Hardware Lifecycle" sub="supported, end-of-life or unknown — an unrecorded lifecycle is UNKNOWN, never assumed supported">
      <WsState read={read} noun="lifecycle inventory">
        <WsTable head={["Asset", "Model", "Lifecycle", "Basis", "Last seen", "Freshness"]} colSpan={6}
          rows={rows.slice(0, 200).map((r) => (
            <tr key={r.asset_id}>
              <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.asset_id}</span></td>
              <td><span style={{ fontSize: 11.5 }}>{r.model || "—"}</span></td>
              <td><LifeBadge lifecycle={r.lifecycle} /></td>
              <td><span style={{ fontSize: 10.5, color: "var(--faint)" }}>{r.lifecycle_basis}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5 }}>{String(r.last_seen ?? "—").slice(0, 10)}</span></td>
              <td><Badge tone={r.freshness === "CURRENT" ? "pass" : r.freshness === "STALE" ? "amber" : "slate"}>{r.freshness}</Badge></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function HbomEvidence() {
  const read = useApi(apiHbomWorkspaceEvidence);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  const cov = (read.data?.collection_coverage ?? {}) as Record<string, number>;
  return (
    <Panel title="Evidence & Provenance" sub="what backs each record and how complete the collection is — a gap is a collection gap, not a healthy device">
      <WsState read={read} noun="evidence inventory">
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
          {Object.entries(cov).map(([k, v]) => <Badge key={k} tone="slate">{k.replace(/_/g, " ")}: {v}</Badge>)}
        </div>
        <WsTable head={["Asset", "Event", "Change class", "Source", "Observed", "Evidence ID", "Freshness"]} colSpan={7}
          rows={rows.slice(0, 200).map((r, i) => (
            <tr key={i}>
              <td><span style={{ fontSize: 11.5, fontWeight: 600 }}>{r.asset_id}</span></td>
              <td><Badge tone="slate">{r.event_type}</Badge></td>
              <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{r.change_class || "—"}</span></td>
              <td><span style={{ fontSize: 11 }}>{r.source || "—"}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5 }}>{String(r.observed_at ?? "—").slice(0, 19)}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5, color: "var(--dim)" }}>{r.evidence_id ? `${String(r.evidence_id).slice(0, 10)}…` : "—"}</span></td>
              <td><Badge tone={r.freshness === "CURRENT" ? "pass" : r.freshness === "STALE" ? "amber" : "slate"}>{r.freshness}</Badge></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function HbomHistory() {
  const read = useApi(apiHbomWorkspaceHistory);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="HBOM History" sub="hardware events as stored — an immutable record of what changed and when">
      <WsState read={read} noun="history">
        <WsTable head={["Asset", "Event", "Change class", "Source", "Observed"]} colSpan={5}
          rows={rows.slice(0, 200).map((r, i) => (
            <tr key={i}>
              <td><span style={{ fontSize: 11.5, fontWeight: 600 }}>{r.asset_id}</span></td>
              <td><Badge tone="slate">{r.event_type}</Badge></td>
              <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{r.change_class || "—"}</span></td>
              <td><span style={{ fontSize: 11 }}>{r.source || "—"}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5 }}>{String(r.observed_at ?? "—").slice(0, 19)}</span></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function HbomExport() {
  const read = useApi(apiHbomWorkspaceExport);
  const snapshots = (read.data?.snapshots ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="Export & Validation" sub="pinned snapshots are content-addressed — a hash proves the bytes are unchanged, not that the estate is healthy">
      <WsState read={read} noun="snapshot inventory">
        <WsTable head={["Snapshot", "Content hash", "Components", "Generator", "Environment", "Pinned"]} colSpan={6}
          rows={snapshots.map((s) => (
            <tr key={s.snapshot_id}>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5 }}>{String(s.snapshot_id).slice(0, 12)}…</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5, color: "var(--dim)" }}>{String(s.content_hash).slice(0, 16)}…</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{s.component_count}</span></td>
              <td><Badge tone="slate">{s.generator}</Badge></td>
              <td><span style={{ fontSize: 11 }}>{s.environment || "—"}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5 }}>{String(s.snapshotted_at ?? "—").slice(0, 19)}</span></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}
