import React, { useEffect, useRef, useState } from "react";
import { apiLegacyOrphans, apiLegacyOrphanReview, apiLegacyAssign, apiLegacyMixedCase, apiLegacyMixedPropose, apiLegacyMixedApprove, LegacyImportReview, LegacyOrphanPage, LegacyOrphanReview, LegacyMixedCase } from "../lib/api";
import { usePrivateScopeCurrent } from "./PrivateScope";

function useDecisionFence() {
  const current = usePrivateScopeCurrent();
  const epoch = useRef(0), mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; epoch.current++; }; }, []);
  return { next: () => ++epoch.current, valid: (token: number) => mounted.current && current() && epoch.current === token };
}
const uncertain = "Decision not confirmed. Reload inventory and audit before a new intentional submission; no automatic retry. Context clearing is not server rollback.";

export function UnassignedHistory({ onCommitted }: { onCommitted: (receipt: string) => void }) {
  const fence = useDecisionFence();
  const [listing, setListing] = useState<LegacyOrphanPage | null>(null), [selected, setSelected] = useState<LegacyOrphanReview | null>(null);
  const [system, setSystem] = useState(""), [reason, setReason] = useState(""), [reference, setReference] = useState("");
  const [busy, setBusy] = useState(false), [message, setMessage] = useState("");
  async function load(page = 1) {
    const token = fence.next(); if (!fence.valid(token)) return; setBusy(true); setSelected(null); setListing(null); setMessage("");
    const result = await apiLegacyOrphans(page); if (!fence.valid(token)) return;
    setBusy(false); if (result.data && result.source === "live") setListing(result.data);
    else setMessage("Unassigned history unavailable; no clearance assumed.");
  }
  async function inspect(id: string) {
    const token = fence.next(); if (!fence.valid(token)) return; setBusy(true); setSelected(null); setSystem(""); setReason(""); setReference(""); setMessage("");
    const result = await apiLegacyOrphanReview(id); if (!fence.valid(token)) return;
    setBusy(false); if (result.data && result.source === "live") setSelected(result.data);
    else setMessage("Unassigned source review unavailable or changed. Refresh before any decision.");
  }
  async function assign() {
    if (!selected || busy || !system.trim() || reason.trim().length < 20 || reference.trim().length < 3) return;
    const token = fence.next(); if (!fence.valid(token)) return; setBusy(true);
    const result = await apiLegacyAssign(selected.asset_id, { expected_snapshot_sha256: selected.snapshot_sha256, system_id: system.trim(), reason: reason.trim(), evidence_ref: reference.trim() });
    if (!fence.valid(token)) return;
    setBusy(false); setSelected(null); setListing(null); setReason(""); setSystem(""); setReference("");
    if (result.data && result.source === "live") onCommitted(`Ownership assignment committed. Audit receipt: ${result.data.audit_id}. Operator-declared ownership only; historical review/export blocks remain. Not a scan or approval.`);
    else setMessage(`${result.error || "Request failed"}. ${uncertain}`);
  }
  return <section aria-label="Unassigned history decisions" style={{ marginTop: 18 }}>
    <h3>Unassigned histories</h3><p>Assign declared responsibility before source review. This does not certify ownership authority, remove evidence or clear export blocks.</p>
    <button type="button" disabled={busy} onClick={() => void load()}>Review unassigned records</button>
    {listing && <><p>{listing.total} unassigned records; page {listing.page}.</p>
      {listing.assets.map((asset) => <p key={asset.id}><button disabled={busy} onClick={() => void inspect(asset.id)}>Inspect {asset.algorithm} ({asset.id})</button></p>)}
      {listing.page > 1 && <button disabled={busy} onClick={() => void load(listing.page - 1)}>Previous unassigned page</button>}
      {listing.page * listing.page_size < listing.total && <button disabled={busy} onClick={() => void load(listing.page + 1)}>Next unassigned page</button>}</>}
    {selected && <><p>{selected.algorithm}: {selected.linked_evidence_count} retained evidence links. {selected.unassigned ? "Unassigned" : "Already associated — refresh required"}.</p>
      <label>Destination system ID (same estate)<input value={system} maxLength={36} disabled={busy} onChange={e => setSystem(e.target.value)} /></label>
      <label>Ownership rationale (no secrets)<textarea value={reason} maxLength={500} disabled={busy} onChange={e => setReason(e.target.value)} /></label>
      <label>Ownership evidence reference<input value={reference} maxLength={500} disabled={busy} onChange={e => setReference(e.target.value)} /></label>
      <button disabled={busy || !selected.unassigned || !system.trim() || reason.trim().length < 20 || reference.trim().length < 3} onClick={() => void assign()}>Assign declared responsibility</button></>}
    {busy && <p role="status">Reading or submitting ownership decision…</p>}{message && <p role="status">{message}</p>}
  </section>;
}

export function MixedHistoryDecision({ review, onCommitted }: { review: LegacyImportReview; onCommitted: (receipt: string) => void }) {
  const fence = useDecisionFence();
  const [record, setRecord] = useState<LegacyMixedCase | null>(null), [loaded, setLoaded] = useState(false);
  const [reason, setReason] = useState(""), [reference, setReference] = useState("");
  const [accepted, setAccepted] = useState(false), [busy, setBusy] = useState(false), [message, setMessage] = useState("");
  async function load() {
    const token = fence.next(); if (!fence.valid(token)) return; setBusy(true); setRecord(null); setLoaded(false); setAccepted(false); setReason(""); setReference(""); setMessage("");
    const result = await apiLegacyMixedCase(review.system_id); if (!fence.valid(token)) return;
    setBusy(false); if (result.data && result.source === "live") { setRecord(result.data.case); setLoaded(true); }
    else setMessage("Controlled case unavailable; no clearance assumed.");
  }
  async function submit(approve: boolean) {
    if (busy || !accepted || reason.trim().length < 20 || reference.trim().length < 3 || !review.replacement_document_sha256) return;
    if (approve && (!record || record.payload.expected_snapshot_sha256 !== review.snapshot_sha256)) return;
    const token = fence.next(); if (!fence.valid(token)) return; setBusy(true); setMessage("");
    const result = approve ? await apiLegacyMixedApprove(review.system_id, { expected_case_sha256: record!.payload_sha256, reason: reason.trim(), evidence_ref: reference.trim() })
      : await apiLegacyMixedPropose(review.system_id, { expected_snapshot_sha256: review.snapshot_sha256, replacement_document_sha256: review.replacement_document_sha256, reason: reason.trim(), evidence_ref: reference.trim() });
    if (!fence.valid(token)) return;
    setBusy(false); setAccepted(false); setReason(""); setReference("");
    if (result.data && result.source === "live") {
      if (approve && "audit_id" in result.data) onCommitted(`Mixed-history decision committed. Audit receipt: ${result.data.audit_id}. Original assets and evidence retained; current exports explicitly partial. No clean posture grade or bank approval.`);
      else { setRecord(result.data as LegacyMixedCase); setLoaded(true); setMessage("Proposal committed; a DIFFERENT current CISO or administrator must review it. This is not independent bank acceptance."); }
    } else { setLoaded(false); setRecord(null); setMessage(`${result.error || "Request failed"}. ${uncertain}`); }
  }
  const pending = record?.payload?.state === "PENDING_SECOND_HUMAN";
  const snapshotMatches = record?.payload?.expected_snapshot_sha256 === review.snapshot_sha256;
  return <section aria-label="Controlled mixed history decision" style={{ marginTop: 18 }}>
    <h3>Controlled mixed-source retention</h3>
    <p>Retain every original asset/evidence link. Replace current declarations only after two human reviews. Exports remain explicitly partial and posture grades blocked; this does not certify the evidence chain or a bank deployment.</p>
    <button disabled={busy} onClick={() => void load()}>Load controlled mixed review</button>
    {loaded && <><p>Case: {record?.payload?.state || "No proposal"}. A different current CISO/administrator is required for approval.</p>
      {record && <dl style={{ overflowWrap: "anywhere" }}><dt>Immutable case SHA-256</dt><dd>{record.payload_sha256}</dd><dt>Proposing human ID</dt><dd>{record.payload.submitted_by}</dd><dt>Proposal rationale</dt><dd>{record.payload.reason}</dd><dt>Proposal evidence reference</dt><dd>{record.payload.evidence_ref}</dd><dt>Proposal snapshot</dt><dd>{snapshotMatches ? "Matches this source review" : "Changed — refresh source and submit a new proposal"}</dd></dl>}
      <label>Mixed-source rationale (no secrets)<textarea value={reason} maxLength={500} disabled={busy} onChange={e => setReason(e.target.value)} /></label>
      <label>Mixed-source evidence reference<input value={reference} maxLength={500} disabled={busy} onChange={e => setReference(e.target.value)} /></label>
      <label><input type="checkbox" checked={accepted} disabled={busy} onChange={e => setAccepted(e.target.checked)} />I reviewed the replacement fingerprint, retained evidence and partial-export implications. This is not a scan or bank approval.</label>
      <button disabled={busy || !accepted || !review.replacement_document_sha256 || reason.trim().length < 20 || reference.trim().length < 3} onClick={() => void submit(false)}>Submit mixed-source proposal</button>
      {pending && <button disabled={busy || !snapshotMatches || !accepted || !review.replacement_document_sha256 || reason.trim().length < 20 || reference.trim().length < 3} onClick={() => void submit(true)}>Approve as second human</button>}</>}
    {busy && <p role="status">Reading or submitting controlled case…</p>}{message && <p role="status">{message}</p>}
  </section>;
}
