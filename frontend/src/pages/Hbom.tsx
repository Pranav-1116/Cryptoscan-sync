import React, { useEffect, useState } from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import { usePollingApi, LiveBadge } from "../lib/apiUi.jsx";
import { useRealtimeRefresh } from "../lib/realtime.js";
import {
  apiLiveBom, LiveBomResponse,
  apiHbomEstate, apiHbomPin, apiHbomSnapshot, apiHbomSnapshots, apiHbomSnapshotDiff,
  HbomEstateDocument, HbomSnapshotMeta, HbomSnapshotDiff,
} from "../lib/api.js";

/* HBOM — two honest surfaces (§4.4):
   1. The live-scan BOM (GET /api/v1/live-scan/bom) — hardware a
      scan-run happened to see. Empty until a live scan runs.
   2. The INDEPENDENT, unified estate HBOM (round 71) — ONE document
      over every persisted hardware_assets row, per-asset identity +
      evidence references, content-addressed and pinnable. */

export default function Hbom() {
  const res = usePollingApi(apiLiveBom, 8000);
  useRealtimeRefresh(res.run);
  const live = res.source === "live";
  const bom = (res.data ?? null) as LiveBomResponse | null;
  const devices = bom?.hbom.components ?? [];

  // the unified estate document (round 71) — regenerated from rows
  const estate = usePollingApi(apiHbomEstate, 8000);
  const estateDoc = (estate.data ?? null) as HbomEstateDocument | null;
  const estateLive = estate.source === "live";

  // pinned estate snapshots — content-addressed, served verbatim
  const [snapshots, setSnapshots] = useState<HbomSnapshotMeta[]>([]);
  const [snapshotsNote, setSnapshotsNote] = useState("");
  const [snapshotsLoaded, setSnapshotsLoaded] = useState(false);
  const [pinBusy, setPinBusy] = useState(false);
  const [pinResult, setPinResult] = useState<string | null>(null);
  const [openSnapshot, setOpenSnapshot] = useState<any>(null);
  // §4.4 (round 72): two-pin estate comparison — "asset_id" joins by
  // device and ignores observation churn (named exclusions); "bom_ref"
  // compares everything the documents carry.
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
      if (r.source === "live" && r.data) {
        setDiffData(r.data.diff);
      } else {
        setDiffData(null);
      }
    } finally {
      setDiffBusy(false);
    }
  }

  const meta = estateDoc?.metadata;

  return (
    <>
      <PageHead
        crumb="boms / hbom"
        title="HBOM"
        sub="Hardware Bill of Materials — TPM · HSM · CPU crypto · secure elements · firmware · capability"
        right={
          <>
            {live && <LiveBadge source="live" label="LIVE" />}
            <Badge tone={devices.length ? "green" : ""}><span className="dot" /> {devices.length} COMPONENTS</Badge>
          </>
        }
      />
      <Panel title="Trusted hardware layer" sub="every crypto-capable hardware device from the live scan">
        <Table
          head={["type", "vendor / component", "firmware", "capabilities", "host"]}
          rows={devices.map((h) => [
            <Badge tone="violet">{h.type}</Badge>,
            <span className="mono" style={{ fontWeight: 600 }}>{h.name}</span>,
            <span className="num">{h.version || "—"}</span>,
            <span className="row">{(h.caps ?? []).map((c) => <Badge key={c}>{c}</Badge>)}</span>,
            <span className="mono">{h.ref}</span>,
          ])}
        />
        {!devices.length && (
          <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>
            No HBOM yet — run a live hardware scan in Operations → Realtime scanners.
          </div>
        )}
      </Panel>

      <Panel
        title="Unified estate HBOM"
        sub="the independent generator — ONE document over every persisted hardware asset (DB truth), with identity and evidence references"
      >
        {!estateDoc && (
          <div className="dim" style={{ fontSize: 13 }}>
            Estate document unavailable — the unified HBOM is generated from persisted hardware assets.
          </div>
        )}
        {estateDoc && (
          <>
            <div className="row" style={{ gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
              {estateLive && <LiveBadge source="live" label="LIVE" />}
              <Badge tone={meta?.component_count ? "violet" : ""}>{meta?.component_count ?? 0} ESTATE COMPONENTS</Badge>
              <Badge tone="green">SHA-256 {estateDoc.content_hash.slice(0, 16)}…</Badge>
              <Badge>ANCHOR {meta?.as_of ? new Date(meta.as_of).toLocaleString() : "—"}</Badge>
              <Badge>ENV {meta?.environment || "—"}</Badge>
              {meta?.hsm_count ? <Badge tone="violet">HSM {meta.hsm_count}</Badge> : null}
              {meta?.tpm_count ? <Badge tone="violet">TPM {meta.tpm_count}</Badge> : null}
              <Badge tone="">DEPENDENCIES 0 (declared, not invented)</Badge>
            </div>
            <Table
              head={["asset", "vendor / model", "type", "firmware", "security modules", "agent", "last seen", "evidence"]}
              rows={estateDoc.components.map((c) => [
                <span className="mono" style={{ fontWeight: 600 }}>{c.asset_id}</span>,
                <span className="mono">{c.name}</span>,
                <Badge tone="violet">{c.device_type}</Badge>,
                <span className="num">{(c.firmware?.details as any)?.version || "—"}</span>,
                <span className="row">
                  {c.security_modules?.hsm ? <Badge key="hsm" tone="green">HSM</Badge> : null}
                  {c.security_modules?.tpm ? <Badge key="tpm" tone="green">TPM</Badge> : null}
                  {!c.security_modules?.hsm && !c.security_modules?.tpm ? <span className="dim">—</span> : null}
                </span>,
                <span className="mono">{c.evidence?.agent_id || "—"}</span>,
                <span className="num">{c.evidence?.last_seen ? new Date(c.evidence.last_seen).toLocaleString() : "—"}</span>,
                <Badge>{c.evidence?.evidence_ids?.length ?? 0} refs</Badge>,
              ])}
            />
            {!estateDoc.components.length && (
              <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>
                No hardware assets are persisted for this environment yet — the HBOM is empty, not fabricated.
              </div>
            )}
            <div className="dim" style={{ fontSize: 12, marginTop: 10 }}>
              Sources: {meta?.sources?.join(", ") || "—"} · this document is NOT the TechBOM hardware layer nor the live engine's in-memory BOM.
              {meta?.notes?.length ? ` ${meta.notes.join(" ")}` : ""}
            </div>
          </>
        )}
      </Panel>

      <Panel
        title="Pinned estate snapshots"
        sub="content-addressed (SHA-256) · identical renderings collapse · served verbatim with an integrity self-check"
      >
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", marginBottom: 10 }}>
          <button className="btn sm" disabled={pinBusy} onClick={() => void pinSnapshot()} style={{ fontSize: 11.5, padding: "4px 10px" }}>
            {pinBusy ? "Pinning…" : "Pin current estate HBOM"}
          </button>
          {pinResult && <span style={{ fontSize: 12.5, color: "var(--dim)" }}>{pinResult}</span>}
        </div>
        {!snapshotsLoaded && (
          <div className="dim" style={{ fontSize: 13 }}>
            Snapshot list unavailable.
          </div>
        )}
        {snapshotsLoaded && snapshots.length === 0 && (
          <div className="dim" style={{ fontSize: 13 }}>
            No estate snapshots pinned yet — pinning freezes the current rendering for export and audit.
          </div>
        )}
        {snapshots.length > 0 && (
          <div style={{ overflowX: "auto", marginTop: 4 }}>
            <table className="tbl" style={{ width: "100%" }}>
              <thead>
                <tr>
                  <th>Content Hash</th>
                  <th>Environment</th>
                  <th>Components</th>
                  <th>Anchor (as-of)</th>
                  <th>Pinned At</th>
                  <th>Pinned By</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {snapshots.map((s, index) => (
                  <React.Fragment key={s.snapshot_id}>
                    <tr>
                      <td>
                        <span style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{String(s.content_hash || "").slice(0, 16)}…</span>
                      </td>
                      <td><span style={{ fontSize: 12 }}>{s.environment || "—"}</span></td>
                      <td><span style={{ fontSize: 12 }}>{s.component_count ?? "—"}</span></td>
                      <td><span style={{ fontSize: 12, color: "var(--dim)" }}>{s.as_of ? new Date(s.as_of).toLocaleString() : "—"}</span></td>
                      <td><span style={{ fontSize: 12, color: "var(--dim)" }}>{s.snapshotted_at ? new Date(s.snapshotted_at).toLocaleString() : "—"}</span></td>
                      <td><span style={{ fontSize: 12 }}>{s.created_by || "—"}</span></td>
                      <td>
                        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                          <button
                            className="btn sm"
                            onClick={() => void viewSnapshot(s.snapshot_id)}
                            style={{ fontSize: 11.5, padding: "4px 10px" }}
                          >
                            {openSnapshot?.snapshot_id === s.snapshot_id ? "Hide" : "Verify & View"}
                          </button>
                          {snapshots.length > 1 && index < snapshots.length - 1 && (
                            <button
                              className="btn sm outline"
                              disabled={diffBusy}
                              onClick={() => {
                                if (diffFor === s.snapshot_id) {
                                  setDiffFor(null);
                                  setDiffData(null);
                                } else {
                                  void loadDiff(s.snapshot_id, snapshots[index + 1].snapshot_id, diffKeyBy);
                                }
                              }}
                              style={{ fontSize: 11.5, padding: "4px 10px" }}
                              title={"Compare this pin against the previous (older) pin — computed from the two pinned payloads, never stored."}
                            >
                              {diffFor === s.snapshot_id ? "Hide Diff" : "Diff vs Prev Pin"}
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                    {openSnapshot?.snapshot_id === s.snapshot_id && (
                      <tr>
                        <td colSpan={7} style={{ background: "var(--bg-2)", borderTop: "1px dashed var(--line)" }}>
                          <div style={{ padding: "10px 4px", display: "grid", gap: 8 }}>
                            <div style={{ fontSize: 12.5, display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                              <strong style={{ fontSize: 12 }}>VERBATIM DOCUMENT</strong>
                              <Badge variant={openSnapshot.integrity === "OK" ? "success" : openSnapshot.integrity === "MISMATCH" ? "danger" : "neutral"}>
                                {String(openSnapshot.integrity || "—")}
                              </Badge>
                              <span style={{ color: openSnapshot.integrity === "OK" ? "var(--dim)" : "var(--red)", fontSize: 12 }}>
                                {openSnapshot.integrity_note}
                              </span>
                            </div>
                            {openSnapshot.payload && (
                              <div style={{ display: "grid", gap: 4 }}>
                                <div style={{ fontSize: 12 }}>
                                  {openSnapshot.payload.metadata?.component_count ?? 0} components ·
                                  {" "}{openSnapshot.payload.metadata?.hsm_count ?? 0} HSM ·
                                  {" "}{openSnapshot.payload.metadata?.tpm_count ?? 0} TPM ·
                                  {" "}anchor {openSnapshot.payload.metadata?.as_of || "—"}
                                </div>
                                <div style={{ fontSize: 12 }}>
                                  Evidence per component: agent, first/last seen, last verified, fingerprint, evidence IDs —
                                  {" "}{(openSnapshot.payload.components || []).map((c: any) => c.evidence?.evidence_ids?.length ?? 0).reduce((a: number, b: number) => a + b, 0)} references total.
                                </div>
                                <pre style={{ fontSize: 11, margin: 0, maxHeight: 220, overflow: "auto", background: "var(--bg-1)", padding: 8, border: "1px solid var(--line)" }}>
                                  {JSON.stringify(openSnapshot.payload, null, 2)}
                                </pre>
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                    {diffFor === s.snapshot_id && (
                      <tr>
                        <td colSpan={7} style={{ background: "var(--bg-2)", borderTop: "1px dashed var(--line)" }}>
                          <div style={{ padding: "10px 4px", display: "grid", gap: 8 }}>
                            <div style={{ fontSize: 12.5, display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                              <strong style={{ fontSize: 12 }}>PIN COMPARISON</strong>
                              {diffData ? (
                                <>
                                  <Badge variant={diffData.summary.added > 0 ? "success" : "neutral"}>
                                    +{diffData.summary.added} devices added
                                  </Badge>
                                  <Badge variant={diffData.summary.removed > 0 ? "danger" : "neutral"}>
                                    −{diffData.summary.removed} removed
                                  </Badge>
                                  <Badge variant={diffData.summary.changed > 0 ? "warn" : "neutral"}>
                                    {diffData.summary.changed} changed
                                  </Badge>
                                  <Badge variant="neutral">{diffData.summary.unchanged} unchanged</Badge>
                                  {diffData.identical && <Badge variant="success">IDENTICAL ESTATE</Badge>}
                                  <div style={{ display: "flex", gap: 4, marginLeft: "auto" }}>
                                    {(["asset_id", "bom_ref"] as const).map((mode) => (
                                      <button
                                        key={mode}
                                        className={`btn sm ${diffKeyBy === mode ? "" : "outline"}`}
                                        disabled={diffBusy}
                                        onClick={() => {
                                          setDiffKeyBy(mode);
                                          void loadDiff(s.snapshot_id, snapshots[index + 1].snapshot_id, mode);
                                        }}
                                        style={{ fontSize: 11, padding: "3px 8px" }}
                                        title={mode === "asset_id"
                                          ? "Device-keyed estate drift — observation churn (re-observations) excluded by name"
                                          : "Exact comparison — observation churn visible too"}
                                      >
                                        {mode === "asset_id" ? "estate drift" : "exact"}
                                      </button>
                                    ))}
                                  </div>
                                </>
                              ) : (
                                <span style={{ color: "var(--red)", fontSize: 12 }}>
                                  Diff unavailable — the comparison could not be computed.
                                </span>
                              )}
                            </div>
                            {diffData && diffData.components.added.length > 0 && (
                              <div style={{ fontSize: 12.5 }}>
                                <strong style={{ fontSize: 12 }}>ADDED</strong>{" "}
                                {diffData.components.added.map((a) => (
                                  <span key={a.key} className="mono" style={{ marginRight: 10 }}>
                                    {a.name || a.key}
                                  </span>
                                ))}
                              </div>
                            )}
                            {diffData && diffData.components.removed.length > 0 && (
                              <div style={{ fontSize: 12.5 }}>
                                <strong style={{ fontSize: 12 }}>REMOVED</strong>{" "}
                                {diffData.components.removed.map((r) => (
                                  <span key={r.key} className="mono" style={{ marginRight: 10 }}>
                                    {r.name || r.key}
                                  </span>
                                ))}
                              </div>
                            )}
                            {diffData && diffData.components.changed.map((ch) => (
                              <div key={ch.key} style={{ fontSize: 12.5, display: "grid", gap: 2 }}>
                                <span className="mono" style={{ fontWeight: 600 }}>{ch.key}</span>
                                {ch.changes.map((c) => (
                                  <span key={c.path} style={{ color: "var(--dim)", fontSize: 12 }}>
                                    {c.path}: <span className="mono">{String(c.before ?? "—")}</span> →{" "}
                                    <span className="mono" style={{ color: "var(--amber)" }}>{String(c.after ?? "—")}</span>
                                  </span>
                                ))}
                              </div>
                            ))}
                            {diffData && (
                              <div className="dim" style={{ fontSize: 11.5 }}>
                                Computed from the two pinned payloads (never stored).
                                {diffData.key_by === "asset_id"
                                  ? ` Excluded as observation churn: ${diffData.excluded_paths.join(", ")}.`
                                  : " Exact mode: every field the documents carry is compared."}
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
            {snapshotsNote && <div className="dim" style={{ fontSize: 12, marginTop: 8 }}>{snapshotsNote}</div>}
          </div>
        )}
      </Panel>
    </>
  );
}
