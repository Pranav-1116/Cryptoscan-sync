import React, { useEffect, useRef, useState } from "react";
import { apiCbomLegacyImports, apiCbomLegacyReview, apiCbomReconcileLegacy, LegacyImportPage, LegacyImportReview } from "../lib/api";
import { MixedHistoryDecision, UnassignedHistory } from "./CbomControlledHistory";
import CbomRescanInspection from "./CbomRescanInspection";
import { usePrivateScopeCurrent } from "./PrivateScope";
import { Badge, Bar } from "./ui";
import { RequireRole } from "../lib/auth";
import { CBOM_WRITE_ROLES } from "../lib/rbac";
import { IconClock, IconWarn, IconComponent, IconSecurity } from "./icons";

/** Existing CBOM workflow, not a separate dashboard. No automatic write/retry. */
export default function CbomLegacyReview({ refresh, onCommitted }: { refresh: number; onCommitted: () => void }) {
  const current = usePrivateScopeCurrent();
  const generation = useRef(0);
  const mounted = useRef(true);
  const [open, setOpen] = useState(false);
  const [inspectionEpoch, setInspectionEpoch] = useState(0);
  const [page, setPage] = useState<LegacyImportPage | null>(null);
  const [review, setReview] = useState<LegacyImportReview | null>(null);
  const [reason, setReason] = useState("");
  const [accepted, setAccepted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [receipt, setReceipt] = useState("");
  const valid = (token: number) => mounted.current && current() && token === generation.current;
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; generation.current++; }; }, []);

  async function load(pageNumber = 1, preserveReceipt = false) {
    const token = ++generation.current;
    setInspectionEpoch(value => value + 1);
    setReview(null); setReason(""); setAccepted(false); setPage(null); setBusy(true); setMessage(""); if (!preserveReceipt) setReceipt("");
    const response = await apiCbomLegacyImports(pageNumber);
    if (!valid(token)) return;
    setBusy(false);
    if (response.source === "live" && response.data) setPage(response.data);
    else setMessage("Historical review unavailable. No clearance assumed. Refresh to reconcile current inventory.");
  }
  // An import or successful reconciliation invalidates any prior review, even
  // when the system ID stayed the same. Never silently reuse a stale snapshot.
  useEffect(() => { if (open) void load(1, true); }, [refresh, open]);

  async function inspect(id: string) {
    const token = ++generation.current;
    setReview(null); setReason(""); setAccepted(false); setReceipt(""); setMessage(""); setBusy(true);
    const response = await apiCbomLegacyReview(id);
    if (!valid(token)) return;
    setBusy(false);
    if (response.source === "live" && response.data) setReview(response.data);
    else setMessage("Review could not be loaded (missing, inaccessible, oversized or unavailable). No changes made by this read.");
  }
  async function submit() {
    if (!review || !accepted || busy || !current() || reason.trim().length < 20 || !review.replacement_document_sha256) return;
    const token = ++generation.current;
    setBusy(true); setMessage("");
    const response = await apiCbomReconcileLegacy(review.system_id, {
      expected_snapshot_sha256: review.snapshot_sha256,
      replacement_document_sha256: review.replacement_document_sha256,
      reason: reason.trim(),
    });
    if (!valid(token)) return;
    setBusy(false); setReview(null); setAccepted(false); setReason("");
    if (response.source === "live" && response.data) {
      setReceipt(`Reconciliation committed. Audit receipt: ${response.data.audit_id}. Detached ${response.data.detached_assets} historical associations; archived ${response.data.archived_declarations} unshared declarations. Original records retained. Not a scan or approval.`);
      // Refresh parent coverage without discarding this durable receipt.
      onCommitted();
    } else {
      setMessage(`${response.error || "Request failed"}. Reconciliation is not confirmed. It may have committed if the response was lost. Reload inventory and audit before any new submission; no automatic retry. Linked scanner evidence, incomplete replacements and stale reviews are refused.`);
    }
  }
  function controlledCommitted(value: string) { setReceipt(value); setReview(null); onCommitted(); }
  return <section className="panel" style={{ padding: 16, marginBottom: 16, borderTop: "2px solid var(--amber)" }} aria-label="Historical import review">
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10, flexWrap: "wrap", marginBottom: 8 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <span style={{ width: 32, height: 32, borderRadius: 8, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--amber) 14%, transparent)", border: "1px solid var(--amber)" }}><IconClock size={14} style={{ color: "var(--amber)" }} /></span>
        <div>
          <h2 style={{ margin: 0, fontSize: 14, fontWeight: 700 }}>Historical Import Review</h2>
          <div style={{ fontSize: 11, color: "var(--dim)" }}>Legacy HIGH/CURRENT claims · retained records · blocks clean export</div>
        </div>
        <Badge tone="amber">HISTORICAL</Badge><Badge tone="red">BLOCKS EXPORT</Badge>
      </div>
      <span style={{ fontSize: 11, color: "var(--dim)" }}>Reimport first, then reconcile with rationale</span>
    </div>
    <div style={{ display: "grid", gridTemplateColumns: "repeat(3, minmax(0,1fr))", gap: 8, marginBottom: 12 }}>
      {[
        ["1 · Surface", "Old claims without proof", "var(--amber)"],
        ["2 · Reimport", "Upload replacement document", "var(--accent)"],
        ["3 · Reconcile", "Rationale + audit receipt", "var(--green)"],
      ].map(([t, d, c]) => (
        <div key={t} style={{ padding: "8px 10px", background: "var(--bg-2)", border: "1px solid var(--line)", borderTop: `2px solid ${c}`, borderRadius: "var(--r)" }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: c }}>{t}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>{d}</div>
        </div>
      ))}
    </div>
    <button type="button" className="btn primary sm" disabled={busy} onClick={() => {
      if (open) void load(page?.page || 1); else setOpen(true);
    }}>{open ? "Refresh historical review" : "Review historical imports"}</button>
    {busy && <div role="status" style={{ marginTop: 8, padding: "8px 10px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", fontSize: 12, display: "flex", gap: 8, alignItems: "center" }}><span style={{ width: 8, height: 8, borderRadius: 99, background: "var(--accent)" }} />Loading historical review…</div>}
    {message && <div role="status" style={{ marginTop: 8, padding: "8px 10px", background: "color-mix(in srgb, var(--amber) 10%, transparent)", border: "1px solid var(--amber)", borderRadius: "var(--r)", fontSize: 12, color: "var(--dim)" }}>{message}</div>}
    {receipt && <div role="status" style={{ marginTop: 8, padding: "8px 10px", background: "color-mix(in srgb, var(--green) 10%, transparent)", border: "1px solid var(--green)", borderRadius: "var(--r)", fontSize: 12, color: "var(--text)", overflowWrap: "anywhere" }}><Badge tone="green">AUDIT</Badge> {receipt}</div>}
    {page && <>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 10, padding: "8px 10px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", alignItems: "center" }}>
        <Badge tone="amber">{page.total} systems need review</Badge><Badge tone={page.unassigned_review_required ? "red" : "green"}>{page.unassigned_review_required} unassigned</Badge><span style={{ fontSize: 11, color: "var(--dim)" }}>Controlled operator review required</span>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 8, marginTop: 10 }}>
        {page.systems.map(system => (
          <div key={system.id} style={{ padding: "10px 12px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: 12, fontWeight: 600 }}>{system.name}</span>
            <button type="button" className="btn sm primary" disabled={busy} onClick={() => void inspect(system.id)}>Review</button>
          </div>
        ))}
      </div>
      <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
        {page.page > 1 && <button className="btn sm" disabled={busy} onClick={() => void load(page.page - 1)}>Previous</button>}
        {page.page * page.page_size < page.total && <button className="btn sm" disabled={busy} onClick={() => void load(page.page + 1)}>Next</button>}
      </div>
    </>}
    {open && <UnassignedHistory key={refresh} onCommitted={controlledCommitted} />}
    {open && <CbomRescanInspection key={`rescan-${refresh}-${inspectionEpoch}`} />}
    {review && <div style={{ marginTop: 12, padding: 12, background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 8 }}>
        <span style={{ fontSize: 13, fontWeight: 700 }}>{review.system_name}</span><Badge tone="amber">{review.pending_assets} pending</Badge>{review.mixed_evidence_assets > 0 ? <Badge tone="red">{review.mixed_evidence_assets} linked evidence</Badge> : <Badge tone="green">No mixed evidence</Badge>}
      </div>
      <div style={{ fontSize: 12, color: "var(--dim)", marginTop: 4 }}>{review.message}</div>
      <div style={{ marginTop: 8, padding: "8px 10px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", fontFamily: "var(--mono)", fontSize: 11, overflowWrap: "anywhere" }}>Replacement SHA-256: {review.replacement_document_sha256 || "— none — reimport first via import form, then refresh"}</div>
      {review.mixed_evidence_assets > 0 && <div role="status" style={{ marginTop: 8, padding: "8px 10px", background: "color-mix(in srgb, var(--red) 10%, transparent)", border: "1px solid var(--red)", borderRadius: "var(--r)", fontSize: 12, color: "var(--red)" }}><IconWarn size={12} style={{ marginRight: 6 }} />{review.mixed_evidence_assets} records have linked scanner evidence — auto-reconcile blocked → use controlled two-human review below.</div>}
      {review.mixed_evidence_assets > 0 && <MixedHistoryDecision key={review.snapshot_sha256} review={review} onCommitted={controlledCommitted} />}
      <div style={{ display: "flex", flexDirection: "column", gap: 6, marginTop: 8, maxHeight: 180, overflow: "auto" }}>{review.assets.map(asset => (<div key={asset.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "6px 8px", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: "var(--r)", fontSize: 11 }}><span><strong>{asset.algorithm}</strong> · {asset.reported_confidence} · {asset.linked_evidence_count} evidence</span><Badge tone="slate">REVIEW</Badge></div>))}</div>
      <label style={{ display: "flex", flexDirection: "column", gap: 4, marginTop: 10, fontSize: 11, color: "var(--dim)" }}>Review rationale (no secrets)<textarea style={{ padding: "8px 10px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg-2)", color: "var(--text)", fontSize: 12.5, minHeight: 60 }} value={reason} maxLength={500} disabled={busy} onChange={event => setReason(event.target.value)} /></label>
      <label style={{ display: "flex", gap: 8, alignItems: "flex-start", marginTop: 8, padding: "8px 10px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", fontSize: 11, color: "var(--dim)" }}><input type="checkbox" checked={accepted} disabled={busy} onChange={event => setAccepted(event.target.checked)} /><span>I reviewed original declaration and replacement fingerprint — retires historical associations only, not scanner evidence, does not establish coverage.</span></label>
      <RequireRole anyOf={[...CBOM_WRITE_ROLES]}>
      <button type="button" className="btn primary sm" disabled={busy || !accepted || reason.trim().length < 20 || !review.replacement_document_sha256 || review.mixed_evidence_assets > 0 || review.pending_assets === 0} onClick={() => void submit()} style={{ marginTop: 8 }}>Reconcile historical declarations</button>
      </RequireRole>
    </div>}
  </section>;
}
