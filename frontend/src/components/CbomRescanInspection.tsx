import React, { useEffect, useRef, useState } from "react";
import { apiRetainedHistories, apiRescanInspection, RescanInspection } from "../lib/api";
import { usePrivateScopeCurrent } from "./PrivateScope";

/** A live-shaped/malformed 200 must not manufacture a verified badge. */
function verified(proof: RescanInspection, systemId: string, jobId: string): boolean {
  const empty = proof.result === "VERIFIED_EMPTY_SCOPED_RESCAN";
  return (empty || proof.result === "VERIFIED_SCOPED_RESCAN")
    && proof.system_id === systemId && proof.job_id === jobId
    && proof.clears_partial_history === false && proof.bank_approved === false
    && proof.whole_system_coverage_verified === false && proof.absence_proven === false
    && /^[0-9a-f]{64}$/.test(proof.source_snapshot_sha256 || "")
    && Number.isInteger(proof.parsed_files) && proof.parsed_files > 0
    && Number.isInteger(proof.unparsed_files) && proof.unparsed_files >= 0
    && proof.parsed_files + proof.unparsed_files <= 1000
    && proof.integrity?.result === (empty ? "EMPTY" : "PASS")
    && proof.integrity.content_intact === true && proof.integrity.chain_intact === true
    && proof.integrity.manifest_intact === true && proof.integrity.hash_format_valid === true
    && Number.isInteger(proof.integrity.records) && proof.integrity.records <= 10000
    && (empty ? proof.integrity.records === 0 : proof.integrity.records > 0);
}

/** Existing historical-review subpanel. Reads proof, never clears a grade fence. */
export default function CbomRescanInspection() {
  const current = usePrivateScopeCurrent(), generation = useRef(0), mounted = useRef(true);
  const [listing, setListing] = useState<Awaited<ReturnType<typeof apiRetainedHistories>>["data"]>(null);
  const [system, setSystem] = useState<{ id: string; name: string } | null>(null), [job, setJob] = useState("");
  const [proof, setProof] = useState<RescanInspection | null>(null), [busy, setBusy] = useState(false), [message, setMessage] = useState("");
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; generation.current++; }; }, []);
  const valid = (token: number) => mounted.current && current() && generation.current === token;
  async function load(page = 1) {
    const token = ++generation.current; if (!valid(token)) return;
    setBusy(true); setListing(null); setSystem(null); setJob(""); setProof(null); setMessage("");
    const result = await apiRetainedHistories(page); if (!valid(token)) return;
    setBusy(false); if (result.source === "live" && result.data) setListing(result.data);
    else setMessage("Retained histories unavailable. No clearance assumed.");
  }
  async function inspect() {
    if (!system || !job.trim() || busy) return;
    const token = ++generation.current; if (!valid(token)) return;
    setBusy(true); setProof(null); setMessage("");
    const result = await apiRescanInspection(system.id, job.trim()); if (!valid(token)) return;
    setBusy(false);
    if (result.source === "live" && result.data && verified(result.data, system.id, job.trim())) setProof(result.data);
    else setMessage(`${result.error || "Rescan evidence unavailable"}. No verified rescan or clearance assumed; inspect current job/evidence and refresh intentionally.`);
  }
  return <section aria-label="Retained history rescan inspection" style={{ marginTop: 18 }}>
    <h3>Inspect post-review rescan evidence</h3>
    <p>Verify a completed local-source job against this system, parsed-file receipts and committed evidence. This checks the new scan, not the retained historical content. It is NOT complete system coverage, proof of absence, runtime use, or bank approval. Partial exports and clean-grade blocks remain.</p>
    <button disabled={busy} onClick={() => void load()}>Review retained histories</button>
    {listing && <><p>{listing.total} systems retain mixed history; page {listing.page}.</p>
      {listing.systems.map(row => <p key={row.id}><button disabled={busy} onClick={() => { generation.current++; setSystem(row); setJob(""); setProof(null); setMessage(""); }}>Inspect rescan for {row.name}</button></p>)}
      {listing.page > 1 && <button disabled={busy} onClick={() => void load(listing.page - 1)}>Previous retained page</button>}
      {listing.page * listing.page_size < listing.total && <button disabled={busy} onClick={() => void load(listing.page + 1)}>Next retained page</button>}</>}
    {system && <><h4>{system.name}</h4><label>Completed source job ID<input value={job} maxLength={36} disabled={busy} onChange={e => { setJob(e.target.value); setProof(null); }} /></label>
      <button disabled={busy || !job.trim()} onClick={() => void inspect()}>Verify scoped rescan evidence</button></>}
    {proof && <div role="status" style={{ overflowWrap: "anywhere" }}>
      <p>{proof.result === "VERIFIED_EMPTY_SCOPED_RESCAN" ? "Verified empty committed scope — absence is NOT proven." : "Committed source evidence verified for this scoped rescan."}</p>
      <p>{proof.parsed_files} parsed files; {proof.unparsed_files} unparsed files; {proof.integrity.records} committed records (including tombstones). Integrity: {proof.integrity.result}.</p>
      <p>Completed: {proof.completed_at}. Inspected: {proof.inspected_at}. Inspection snapshot SHA-256: {proof.source_snapshot_sha256}.</p>
      <p><span title={"Partial history remains. No clean posture grade or bank approval. A completed parser receipt is not an independently verified coverage denominator."}>{"Partial history remains."}</span></p>
    </div>}
    {busy && <p role="status">Reading committed rescan proof…</p>}{message && <p role="status">{message}</p>}
  </section>;
}
