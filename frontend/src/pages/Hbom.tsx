import React, { useEffect, useState, useMemo } from "react";
import { Link } from "react-router-dom";
import { Panel, Badge, Bar, Ring } from "../components/ui";
import { usePollingApi, LiveBadge } from "../lib/apiUi.jsx";
import { useChannelRefresh } from "../lib/realtime.js";
import { apiLiveBom, LiveBomResponse, apiHbomEstate, apiHbomPin, apiHbomSnapshot, apiHbomSnapshots, apiHbomSnapshotDiff, HbomEstateDocument, HbomSnapshotMeta, HbomSnapshotDiff } from "../lib/api.js";
import { IconCertificate, IconCrypto, IconHardware, IconTarget, IconClock, IconSecurity, IconInfo, IconWarn, IconSearch } from "../components/icons";

/* HBOM — two honest surfaces visualized:
   1. Live-scan BOM (hardware a scan-run happened to see)
   2. Unified estate HBOM — ONE document over every persisted hardware row, content-addressed and pinnable */

export default function Hbom() {
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

  const ringPct = estateDoc ? Math.min(1, (meta?.component_count ?? 0) / 100) : devices.length ? Math.min(1, devices.length / 50) : 0;
  const ringTone = estateDoc ? "green" : devices.length ? "cyan" : "slate";

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16, flexWrap: "wrap", gap: 16 }}>
        <div style={{ flex: "1 1 420px", minWidth: 280 }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px", borderRadius: 999, background: "color-mix(in srgb, var(--accent) 12%, transparent)", border: "1px solid var(--accent)", fontSize: 11, fontFamily: "var(--mono)", color: "var(--accent)", letterSpacing: "0.06em" }}>
            <span style={{ width: 6, height: 6, borderRadius: 99, background: estateLive ? "var(--green)" : "var(--accent)" }} /> BOMS · HBOM · HARDWARE ROOTS
          </div>
          <h1 style={{ fontSize: 26, fontWeight: 800, margin: "8px 0 6px", letterSpacing: "-0.02em", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ width: 34, height: 34, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--accent)", color: "var(--on-accent)" }}><IconHardware size={18} /></span>
            Hardware Bill of Materials
          </h1>
          <p style={{ margin: 0, fontSize: 13.5, color: "var(--dim)", lineHeight: 1.5, maxWidth: 620 }}>
            Every <b style={{ color: "var(--text)" }}>crypto-capable hardware device</b> — TPM · HSM · CPU crypto · secure elements · firmware — from live scans and the <span style={{ color: "var(--accent)" }}>unified estate document</span> over persisted rows.
          </p>
          <div style={{ display: "flex", gap: 8, marginTop: 12, flexWrap: "wrap" }}>
            <span className="kicker" style={{ fontSize: 10 }}>CONTENT-ADDRESSED · SHA-256</span>
            <span style={{ color: "var(--line-strong)" }}>·</span>
            <span className="kicker" style={{ fontSize: 10 }}>EVIDENCE-REFERENCED</span>
            <span style={{ color: "var(--line-strong)" }}>·</span>
            <span style={{ fontSize: 11, color: "var(--dim)" }}>NOT the TechBOM hardware layer</span>
          </div>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-start", flexWrap: "wrap" }}>
          <Panel style={{ padding: "10px 14px", minWidth: 160, display: "flex", alignItems: "center", gap: 12 }}>
            <Ring pct={ringPct} label={estateDoc ? String(meta?.component_count ?? 0) : String(devices.length)} sub={estateDoc ? "estate" : "live"} tone={ringTone} />
            <div>
              <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)" }}>HARDWARE POSTURE</div>
              <div style={{ fontSize: 12, color: "var(--dim)", maxWidth: 130, lineHeight: 1.4 }}>{estateDoc ? `${meta?.hsm_count ?? 0} HSM · ${meta?.tpm_count ?? 0} TPM anchored ${meta?.as_of ? new Date(meta.as_of).toLocaleDateString() : "—"}` : devices.length ? `${devices.length} live components` : "No hardware yet"}</div>
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

      {/* KPI cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 14, marginBottom: 18 }}>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--accent)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", display: "flex", alignItems: "center", gap: 6 }}><IconHardware size={12} /> LIVE-SCAN COMPONENTS</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{devices.length}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>Current scan-run view</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--accent) 14%, transparent)", border: "1px solid var(--accent)", color: "var(--accent)" }}><IconTarget size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--dim)", marginBottom: 6 }}><span>{liveByType.length ? liveByType[0][0] : "—"} top</span><span style={{ color: live ? "var(--green)" : "var(--faint)" }}>{live ? "● LIVE" : "offline"}</span></div>
            <Bar value={devices.length ? Math.min(1, devices.length / 40) : 0} tone="cyan" />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>What this scan happened to see</div>
          </div>
        </div>

        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${(meta?.component_count ?? 0) ? "var(--green)" : "var(--slate)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", display: "flex", alignItems: "center", gap: 6 }}><IconSecurity size={12} /> ESTATE COMPONENTS</div>
              <div style={{ fontSize: 32, fontWeight: 800, color: (meta?.component_count ?? 0) ? "var(--green)" : "var(--faint)", margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{meta?.component_count ?? 0}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>Unified persisted DB truth</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: (meta?.component_count ?? 0) ? "color-mix(in srgb, var(--green) 14%, transparent)" : "var(--panel-2)", border: `1px solid ${(meta?.component_count ?? 0) ? "var(--green)" : "var(--line)"}`, color: (meta?.component_count ?? 0) ? "var(--green)" : "var(--faint)" }}><IconCertificate size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--dim)", marginBottom: 6 }}><span>ENV {meta?.environment || "—"}</span><span style={{ color: "var(--green)" }}>content-addressed</span></div>
            <Bar value={meta?.component_count ? Math.min(1, meta.component_count / 80) : 0} tone={(meta?.component_count ?? 0) ? "green" : "slate"} />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>ONE document — not live engine memory</div>
          </div>
        </div>

        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${(meta?.hsm_count ?? 0) ? "var(--violet)" : "var(--line-strong)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", display: "flex", alignItems: "center", gap: 6 }}><IconCrypto size={12} /> HSM FLEET</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{meta?.hsm_count ?? 0}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>Hardware security modules</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: (meta?.hsm_count ?? 0) ? "color-mix(in srgb, var(--violet) 14%, transparent)" : "var(--panel-2)", border: `1px solid ${(meta?.hsm_count ?? 0) ? "var(--violet)" : "var(--line)"}`, color: (meta?.hsm_count ?? 0) ? "var(--violet)" : "var(--faint)" }}><IconCrypto size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 6 }}>
              <Badge tone={meta?.hsm_count ? "violet" : "slate"}>HSM {meta?.hsm_count ?? 0}</Badge>
              <Badge tone={meta?.tpm_count ? "violet" : "slate"}>TPM {meta?.tpm_count ?? 0}</Badge>
            </div>
            <Bar value={meta?.hsm_count ? Math.min(1, meta.hsm_count / 12) : 0} tone="violet" />
          </div>
        </div>

        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--green)", background: snapshots.length ? "color-mix(in srgb, var(--green) 4%, var(--panel))" : "var(--panel)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>PINNED SNAPSHOTS</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{snapshots.length}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>Verbatim + SHA-256 self-check</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: snapshots.length ? "color-mix(in srgb, var(--green) 14%, transparent)" : "var(--panel-2)", border: `1px solid ${snapshots.length ? "var(--green)" : "var(--line)"}`, color: snapshots.length ? "var(--green)" : "var(--faint)" }}><IconClock size={16} /></span>
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
          )) : <div style={{ fontSize: 12, color: "var(--dim)", padding: "8px 0" }}>No persisted hardware assets for this environment — HBOM is empty, not fabricated</div>}
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
            <div style={{ padding: "8px 6px", background: "var(--panel-2)", borderRadius: "var(--r)", border: "1px solid var(--line)" }}><div style={{ fontSize: 16, fontWeight: 800, fontFamily: "var(--mono)" }}>{estateDoc ? (estateDoc.components.reduce((a, c) => a + (c.evidence?.evidence_ids?.length ?? 0), 0)) : 0}</div><div style={{ fontSize: 10, color: "var(--faint)" }}>EVIDENCE REFS</div></div>
            <div style={{ padding: "8px 6px", background: "color-mix(in srgb, var(--violet) 8%, var(--panel-2))", borderRadius: "var(--r)", border: "1px solid var(--line)" }}><div style={{ fontSize: 16, fontWeight: 800, color: "var(--violet)" }}>{snapshots.length}</div><div style={{ fontSize: 10, color: "var(--faint)" }}>SNAPSHOTS</div></div>
            <div style={{ padding: "8px 6px", background: "color-mix(in srgb, var(--green) 8%, var(--panel-2))", borderRadius: "var(--r)", border: "1px solid var(--line)" }}><div style={{ fontSize: 16, fontWeight: 800, color: "var(--green)" }}>{estateDoc ? (meta?.sources?.length ?? 0) : 0}</div><div style={{ fontSize: 10, color: "var(--faint)" }}>SOURCES</div></div>
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
                <tr><td colSpan={5} style={{ padding: 28, textAlign: "center", color: "var(--dim)" }}><div style={{ fontWeight: 600, color: "var(--text)" }}>No HBOM yet</div><div style={{ fontSize: 12, marginTop: 4 }}>Run a live hardware scan in Operations → Realtime scanners — empty is not fabricated</div></td></tr>
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
            <p style={{ margin: "4px 0 0", fontSize: 11, color: "var(--dim)" }}>ONE document over every persisted hardware_assets row · per-asset identity + evidence refs · <span style={{ color: "var(--green)" }}>SHA-256 {estateDoc ? estateDoc.content_hash.slice(0, 12) : "—"}…</span></p>
          </div>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
            {estateLive && <LiveBadge source="live" label="LIVE" />}
            <Badge tone={meta?.component_count ? "violet" : "slate"}>{meta?.component_count ?? 0} ESTATE</Badge>
            {meta?.hsm_count ? <Badge tone="violet">HSM {meta.hsm_count}</Badge> : null}
            {meta?.tpm_count ? <Badge tone="violet">TPM {meta.tpm_count}</Badge> : null}
            <Badge tone="slate">0 deps — declared</Badge>
          </div>
        </div>
        {!estateDoc ? (
          <div style={{ padding: 32, textAlign: "center", color: "var(--dim)" }}>
            <div style={{ width: 40, height: 40, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--panel-2)", border: "1px solid var(--line)", margin: "0 auto 10px" }}><IconHardware size={16} style={{ color: "var(--faint)" }} /></div>
            <div style={{ fontWeight: 600, color: "var(--text)" }}>Estate document unavailable</div>
            <div style={{ fontSize: 12, marginTop: 4 }}>Generated from persisted hardware_assets — not live engine memory, not TechBOM hardware layer</div>
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
                    <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{(c.firmware?.details as any)?.version || "—"}</span></td>
                    <td><span style={{ display: "flex", gap: 4 }}>{c.security_modules?.hsm ? <Badge tone="green">HSM</Badge> : null}{c.security_modules?.tpm ? <Badge tone="green">TPM</Badge> : null}{!c.security_modules?.hsm && !c.security_modules?.tpm ? <span style={{ color: "var(--faint)", fontSize: 11 }}>—</span> : null}</span></td>
                    <td><span className="mono" style={{ fontSize: 11, color: "var(--dim)" }}>{c.evidence?.agent_id || "—"}</span></td>
                    <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{c.evidence?.last_seen ? new Date(c.evidence.last_seen).toLocaleDateString() : "—"}</span></td>
                    <td><Badge tone="slate">{c.evidence?.evidence_ids?.length ?? 0} refs</Badge></td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!estateDoc.components.length && <div style={{ padding: 20, textAlign: "center", color: "var(--dim)", fontSize: 12 }}>No hardware assets persisted for this environment — empty, not fabricated</div>}
          </div>
        )}
        {estateDoc && <div style={{ padding: "10px 16px", background: "var(--bg-2)", borderTop: "1px solid var(--line)", fontSize: 11, color: "var(--dim)", display: "flex", gap: 8, flexWrap: "wrap" }}><span>Sources: {meta?.sources?.join(", ") || "—"}</span><span style={{ marginLeft: "auto", fontFamily: "var(--mono)" }}>NOT TechBOM hardware layer · NOT live engine memory</span></div>}
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
          <div style={{ padding: 28, textAlign: "center", color: "var(--dim)" }}><div style={{ fontWeight: 600, color: "var(--text)" }}>No snapshots pinned yet</div><div style={{ fontSize: 12, marginTop: 4 }}>Pin freezes the current rendering for export and audit — identical pins collapse</div></div>
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
    </div>
  );
}
