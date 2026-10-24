import React, { useEffect, useRef, useState } from "react";
import { apiCbomLegacyImports, apiCbomLegacyReview, apiCbomReconcileLegacy, LegacyImportPage, LegacyImportReview } from "../lib/api";
import { MixedHistoryDecision, UnassignedHistory } from "./CbomControlledHistory";
import CbomRescanInspection from "./CbomRescanInspection";
import { usePrivateScopeCurrent } from "./PrivateScope";

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
  return <section className="panel" style={{ padding: 20, marginBottom: 20 }} aria-label="Historical import review">
    <h2 style={{ fontSize: 18 }}>Historical import review</h2>
    <p>Old imports can carry HIGH confidence or CURRENT coverage without measured proof. Original records are retained; unresolved historical imports block clean CBOM exports and assessments.</p>
    <button type="button" className="btn outline" disabled={busy} onClick={() => {
      if (open) void load(page?.page || 1); else setOpen(true);
    }}>{open ? "Refresh historical review" : "Review historical imports"}</button>
    {busy && <p role="status">Loading or submitting historical review…</p>}
    {message && <p role="status">{message}</p>}
    {receipt && <p role="status" style={{ overflowWrap: "anywhere" }}>{receipt}</p>}
    {page && <>
      <p>{page.total} systems require review. {page.unassigned_review_required} unassigned historical records require controlled operator review.</p>
      {page.systems.map(system => <p key={system.id}><button type="button" className="btn outline" disabled={busy} onClick={() => void inspect(system.id)}>Review {system.name}</button></p>)}
      {page.page > 1 && <button disabled={busy} onClick={() => void load(page.page - 1)}>Previous review page</button>}
      {page.page * page.page_size < page.total && <button disabled={busy} onClick={() => void load(page.page + 1)}>Next review page</button>}
    </>}
    {open && <UnassignedHistory key={refresh} onCommitted={controlledCommitted} />}
    {open && <CbomRescanInspection key={`rescan-${refresh}-${inspectionEpoch}`} />}
    {review && <div>
      <h3>{review.system_name}: {review.pending_assets} historical records</h3>
      <p>{review.message}</p>
      <p style={{ overflowWrap: "anywhere" }}>Replacement document SHA-256: {review.replacement_document_sha256 || "None — first reimport the original CBOM using the import form above, then refresh this review."}</p>
      {review.mixed_evidence_assets > 0 && <p role="status">{review.mixed_evidence_assets} records have linked scanner evidence. Automatic reconciliation is blocked. Preserve evidence and use the controlled two-human review below.</p>}
      {review.mixed_evidence_assets > 0 && <MixedHistoryDecision key={review.snapshot_sha256} review={review} onCommitted={controlledCommitted} />}
      <ul>{review.assets.map(asset => <li key={asset.id}>{asset.algorithm}: historically reported {asset.reported_confidence}; {asset.linked_evidence_count} linked evidence records. Review required, not measured confidence.</li>)}</ul>
      <label>Review rationale (no secrets)<textarea value={reason} maxLength={500} disabled={busy} onChange={event => setReason(event.target.value)} /></label>
      <label style={{ display: "block" }}><input type="checkbox" checked={accepted} disabled={busy} onChange={event => setAccepted(event.target.checked)} />I reviewed the original declaration and replacement fingerprint. This retires historical associations, not scanner evidence, and does not establish scan coverage.</label>
      <button type="button" className="btn outline" disabled={busy || !accepted || reason.trim().length < 20 || !review.replacement_document_sha256 || review.mixed_evidence_assets > 0 || review.pending_assets === 0} onClick={() => void submit()}>Reconcile historical declarations</button>
    </div>}
  </section>;
}
