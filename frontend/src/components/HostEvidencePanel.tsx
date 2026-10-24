import React, { useEffect, useRef, useState } from "react";
import { apiApproveHostScope, apiImportHostSnapshot, apiInspectHostSnapshot, apiHostCbom, HostImportReceipt, HostSnapshotInspection } from "../lib/api";
import HostAssociationsPanel from "./HostAssociationsPanel";
import { usePrivateScopeCurrent } from "./PrivateScope";

function validReceipt(value: HostImportReceipt, approval: string) {
  return value?.approval_id === approval && value.source_basis === "IMPORTED"
    && value.host_identity_attested === false && value.whole_host_coverage_verified === false
    && value.runtime_use === "UNKNOWN" && value.pqc_assessment === "UNKNOWN" && value.policy_result === "NOT_EVALUATED"
    && /^[0-9a-f]{64}$/.test(value.snapshot_sha256 || "")
    && Number.isInteger(value.evidence_count) && value.evidence_count > 0 && value.evidence_count <= 1100;
}

/** Existing CBOM console workflow. No auto-collection/upload/replay or sample data. */
export default function HostEvidencePanel() {
  const current = usePrivateScopeCurrent(), generation = useRef(0), alive = useRef(true);
  const [system, setSystem] = useState(""), [approval, setApproval] = useState("");
  const [manifest, setManifest] = useState<unknown>(null), [snapshot, setSnapshot] = useState<unknown>(null);
  const [receipt, setReceipt] = useState<HostImportReceipt | null>(null), [detail, setDetail] = useState<HostSnapshotInspection | null>(null);
  const [busy, setBusy] = useState(false), [message, setMessage] = useState("");
  useEffect(() => { alive.current = true; return () => { alive.current = false; generation.current++; }; }, []);
  const valid = (token: number) => alive.current && current() && generation.current === token;
  function resetProof() { generation.current++; setReceipt(null); setDetail(null); setMessage(""); }
  function validDetail(value: HostSnapshotInspection): boolean {
    const snap = value.snapshot;
    if (!snap || typeof snap.manifest?.host_id !== "string" || typeof snap.manifest.environment !== "string" || typeof snap.finished_at !== "string"
      || !Array.isArray(snap.receipts) || snap.receipts.length < 1 || snap.receipts.length > 100) return false;
    let facts = 0;
    return snap.receipts.every(r => {
      if (!r || typeof r.input_id !== "string" || typeof r.reason !== "string" || !["PARSED", "DENIED", "UNSUPPORTED", "INVALID", "BUDGET_EXCEEDED", "UNAVAILABLE"].includes(r.status) || !Array.isArray(r.facts)) return false;
      facts += r.facts.length;
      return facts <= 1000 && (r.status === "PARSED" ? r.facts.length > 0 : r.facts.length === 0)
        && r.facts.every(f => f && ["CERTIFICATE", "TLS_CONFIGURATION", "SOFTWARE", "BINARY", "OS_RELEASE", "PROCESS", "LOADED_LIBRARY", "LISTENER", "SERVICE", "HARDWARE"].includes(f.kind) && typeof f.algorithm === "string"
          && ["OBSERVED", "DECLARED"].includes(f.local_basis) && f.runtime_use === "UNKNOWN"
          && (f.kind !== "OS_RELEASE" || (f.local_basis === "DECLARED" && f.algorithm === "UNKNOWN" && f.key_size === null))
          && (!["PROCESS", "LOADED_LIBRARY", "LISTENER", "SERVICE", "HARDWARE"].includes(f.kind)
            || (f.local_basis === "OBSERVED" && f.algorithm === "UNKNOWN" && f.key_size === null
              && f.purpose === "HOST_RUNTIME_METADATA" && f.operation_use === "UNKNOWN" && f.capabilities_observed === false
              && typeof f.identity_key === "string" && /^[0-9a-f]{64}$/.test(f.interface_sha256 || "")))
          && (f.key_size === null || Number.isInteger(f.key_size)));
    });
  }
  async function read(file: File | undefined, kind: "manifest" | "snapshot") {
    if (!file || busy) return;
    const token = ++generation.current; if (!valid(token)) return;
    setBusy(true); setReceipt(null); setDetail(null); setMessage("");
    if (kind === "manifest") { setManifest(null); setApproval(""); setSnapshot(null); } else setSnapshot(null);
    try {
      if (file.size > (kind === "manifest" ? 131072 : 1500000)) throw new Error("Local JSON exceeds metadata size limit");
      const data: unknown = JSON.parse(await file.text()); if (!valid(token)) return;
      if (kind === "manifest") setManifest(data); else setSnapshot(data);
      setMessage(`${kind === "manifest" ? "Approval manifest" : "Offline snapshot"} loaded locally. Nothing uploaded yet.`);
    } catch { if (valid(token)) setMessage("Invalid or oversized JSON. No approval, import or collection performed."); }
    finally { if (valid(token)) setBusy(false); }
  }
  async function approve() {
    if (busy || !manifest || !system.trim()) return;
    const token = ++generation.current; if (!valid(token)) return;
    setBusy(true); setReceipt(null); setDetail(null); setMessage(""); setApproval("");
    const result = await apiApproveHostScope(system.trim(), manifest); if (!valid(token)) return;
    setBusy(false);
    if (result.source === "live" && result.ok && /^[0-9a-f-]{36}$/.test(result.data?.subject_id || "")) {
      setApproval(result.data!.subject_id); setMessage("Scope approved for one offline snapshot. This does not execute collection or attest host identity.");
    } else setMessage(`${result.error || "Approval unavailable"}. No collection authorized by this console. Production host adapter remains unqualified.`);
  }
  async function ingest() {
    if (busy || !snapshot || !approval.trim()) return;
    const id = approval.trim(), token = ++generation.current; if (!valid(token)) return;
    setBusy(true); setReceipt(null); setDetail(null); setMessage("");
    const result = await apiImportHostSnapshot(id, snapshot); if (!valid(token)) return;
    setBusy(false);
    if (result.source === "live" && result.ok && result.data && validReceipt(result.data, id)) {
      setReceipt(result.data); setSnapshot(null); setMessage("Metadata committed as IMPORTED. Collection failures remain unknown; no observed coverage grade was updated.");
    } else setMessage(`${result.error || "Import unavailable or receipt unverified"}. No success assumed. Inspect this approval before intentionally retrying.`);
  }
  async function inspect() {
    if (busy || !approval.trim()) return;
    const id = approval.trim(), token = ++generation.current; if (!valid(token)) return;
    setBusy(true); setReceipt(null); setDetail(null); setMessage("");
    const result = await apiInspectHostSnapshot(id); if (!valid(token)) return;
    setBusy(false);
    const value = result.data, proof = value?.integrity;
    if (result.source === "live" && result.ok && value && validReceipt(value, id)
      && proof?.result === "PASS" && proof.content_intact === true && proof.chain_intact === true
      && proof.manifest_intact === true && proof.hash_format_valid === true
      && validDetail(value)) {
      setReceipt(value); setDetail(value);
    } else setMessage(`${result.error || "Host evidence unavailable or integrity unverified"}. No verified receipt or security verdict assumed.`);
  }
  async function download() {
    if (busy || !detail) return;
    const id = approval.trim(), token = ++generation.current; if (!valid(token)) return;
    setBusy(true); setMessage("");
    const result = await apiHostCbom(id); if (!valid(token)) return;
    setBusy(false);
    if (result.source !== "live" || !result.ok || result.data?.specVersion !== "1.6" || result.data?.bomFormat !== "CycloneDX") {
      setMessage(`${result.error || "Export unavailable"}. No validated document downloaded.`); return;
    }
    const url = URL.createObjectURL(new Blob([JSON.stringify(result.data, null, 2)], { type: "application/json" }));
    const link = document.createElement("a"); link.href = url; link.download = `host-${id}-cyclonedx-1.6.json`; link.click(); URL.revokeObjectURL(url);
    setMessage("CycloneDX 1.6 metadata downloaded. Schema validity is not runtime evidence, complete discovery, migration compatibility or bank approval.");
  }
  return <section aria-label="Approved offline host evidence" style={{ marginTop: 24 }}>
    <h3>Approved host collection · no Git required</h3>
    <p>Explicit files and supported package metadata only. No remote execution, privileged scan, automatic upload or unrestricted filesystem discovery. Run the offline collector as an unprivileged user after scope approval.</p>
    <p><strong>IMPORTED evidence — host identity and runtime use unverified.</strong> Windows execution and production host admission are not qualified. Library presence does not establish algorithm use; configured TLS does not establish effective TLS.</p>
    <p>Admin/CISO approve the scope; analysts import; auditors/viewers inspect without changing scans.</p>
    <label>Host system ID<input maxLength={120} value={system} disabled={busy} onChange={e => { resetProof(); setSystem(e.target.value); setManifest(null); setSnapshot(null); setApproval(""); }} /></label>
    <label>Approved host manifest JSON<input type="file" accept="application/json,.json" disabled={busy} onChange={e => { void read(e.target.files?.[0], "manifest"); e.target.value = ""; }} /></label>
    <button disabled={busy || !manifest || !system.trim()} onClick={() => void approve()}>Approve host scope</button>
    <label>Host approval ID<input maxLength={36} value={approval} disabled={busy} onChange={e => { resetProof(); setApproval(e.target.value); setSnapshot(null); }} /></label>
    <label>Offline host snapshot JSON<input type="file" accept="application/json,.json" disabled={busy} onChange={e => { void read(e.target.files?.[0], "snapshot"); e.target.value = ""; }} /></label>
    <button disabled={busy || !snapshot || !approval.trim()} onClick={() => void ingest()}>Import approved metadata</button>
    <button disabled={busy || !approval.trim()} onClick={() => void inspect()}>Inspect host evidence</button>
    {busy && <p role="status">Processing scoped host metadata…</p>}{message && <p role="status">{message}</p>}
    {receipt && <div style={{ overflowWrap: "anywhere" }}><p>Evidence status: IMPORTED · Scan {receipt.scan_id} · {receipt.evidence_count} chained records.</p>
      <p>Snapshot SHA-256: {receipt.snapshot_sha256}</p><p>Runtime use: UNKNOWN · PQC assessment: UNKNOWN · Policy: NOT_EVALUATED. Complete-host coverage is not proven.</p></div>}
    {detail && <><h4>{detail.snapshot.manifest.host_id} · {detail.snapshot.manifest.environment}</h4><p>Stored content, chain and manifest integrity checked. Claimed collection time: {detail.snapshot.finished_at}. This does not authenticate the originating host.</p>
      <table><thead><tr><th>Approved input</th><th>Receipt</th><th>Metadata / limitations</th></tr></thead><tbody>{detail.snapshot.receipts.map(r => <tr key={r.input_id}><td>{r.input_id}</td><td>{r.status} · {r.reason}</td><td>{r.facts.map((f, i) => <p key={i}>{f.kind} · {f.process_name || f.library_path || f.service_name || (f.address ? `${f.address}:${f.port}` : null) || f.model || f.hardware_type || f.software_name || f.algorithm} · {f.software_version || f.key_size || "size/version UNKNOWN"}{f.service_state ? ` · ${f.service_state}` : ""} · local claim {f.local_basis} · runtime UNKNOWN</p>)}</td></tr>)}</tbody></table>
      <p>System-to-host scope is operator DECLARED, not host attestation. Endpoint/HSM/KMS use and six-BOM dependencies are not established by co-existence.</p>
      <button disabled={busy} onClick={() => void download()}>Download CycloneDX 1.6 host CBOM</button><HostAssociationsPanel key={detail.approval_id + detail.snapshot_sha256} detail={detail} /></>}
  </section>;
}
