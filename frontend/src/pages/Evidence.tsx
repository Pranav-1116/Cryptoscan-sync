import React, { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { Badge, Button } from "../components/ui";
import AuthenticatedDownload from "../components/AuthenticatedDownload";
import {
  activeTenantId, apiAuditList, apiAuditVerify, apiFindings, apiScansPage,
  apiVerifyStoredScan, type AuditChainStatus, type AuditEvent, type Finding,
  type ScanSummaryRow, type ScanVerification, type ApiResult,
} from "../lib/api";

const PAGE_SIZE = 50;
const SCAN_PAGE_SIZE = 20;
const present = (value: unknown): value is string => typeof value === "string" && value.trim().length > 0;
const field = (value: unknown) => present(value) ? value : "Not supplied";
const failure = (result: ApiResult<unknown>, subject: string) => {
  const status = result.error?.match(/HTTP (\d{3})/)?.[1];
  if (status === "401") return `Authentication required to ${subject}. Sign in and try again.`;
  if (status === "403") return `Access denied to ${subject} for this account or tenant.`;
  return status ? `Unable to ${subject} (HTTP ${status}).` : `Unable to ${subject}; the service is offline or unreachable.`;
};
const validCount = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 0;

export default function Evidence() {
  const [tab, setTab] = useState<"scan" | "audit">("scan");
  const [auditVisited, setAuditVisited] = useState(false);
  const [session, setSession] = useState(0);
  const [tenant, setTenant] = useState(activeTenantId());
  useEffect(() => {
    const reset = () => { setTenant(activeTenantId()); setSession(n => n + 1); setAuditVisited(false); setTab("scan"); };
    window.addEventListener("zelinx:tenant", reset);
    window.addEventListener("zelinx:auth", reset);
    return () => { window.removeEventListener("zelinx:tenant", reset); window.removeEventListener("zelinx:auth", reset); };
  }, []);
  return (
    <div className="page" style={{ maxWidth: 1280, margin: "0 auto", padding: "10px 0 60px" }}>
      <h1 style={{ fontSize: 26, margin: "4px 0 6px" }}>Evidence</h1>
      <p style={{ color: "var(--dim)", margin: "0 0 20px" }}>Inspect stored scan observations separately from the platform action audit ledger. Verification applies only to the scope reported by the server.</p>
      <div role="tablist" aria-label="Evidence views" onKeyDown={event => {
        if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
        event.preventDefault();
        const next = event.key === "Home" ? "scan" : event.key === "End" ? "audit" : tab === "scan" ? "audit" : "scan";
        if (next === "audit") setAuditVisited(true);
        setTab(next);
        document.getElementById(`${next}-tab`)?.focus();
      }} style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 20 }}>
        <button id="scan-tab" type="button" role="tab" tabIndex={tab === "scan" ? 0 : -1} aria-controls="scan-panel" aria-selected={tab === "scan"} className={`btn ${tab === "scan" ? "primary" : "outline"}`} onClick={() => setTab("scan")}>Scan Evidence</button>
        <button id="audit-tab" type="button" role="tab" tabIndex={tab === "audit" ? 0 : -1} aria-controls="audit-panel" aria-selected={tab === "audit"} className={`btn ${tab === "audit" ? "primary" : "outline"}`} onClick={() => { setAuditVisited(true); setTab("audit"); }}>Audit Ledger</button>
      </div>
      <div id="scan-panel" role="tabpanel" aria-labelledby="scan-tab" hidden={tab !== "scan"}>
        <ScanEvidence key={`scan-${session}`} tenant={tenant} />
      </div>
      <div id="audit-panel" role="tabpanel" aria-labelledby="audit-tab" hidden={tab !== "audit"}>
        {auditVisited && <AuditLedger key={`audit-${session}`} />}
      </div>
    </div>
  );
}

function ScanEvidence({ tenant }: { tenant: string | null }) {
  const [scans, setScans] = useState<ScanSummaryRow[]>([]);
  const [scanTotal, setScanTotal] = useState<number | null>(null);
  const [scanPage, setScanPage] = useState(1);
  const [scanLoading, setScanLoading] = useState(true);
  const [scanPaging, setScanPaging] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [findingTotal, setFindingTotal] = useState<number | null>(null);
  const [findingPage, setFindingPage] = useState(1);
  const [findingLoading, setFindingLoading] = useState(false);
  const [findingPaging, setFindingPaging] = useState(false);
  const [findingError, setFindingError] = useState<string | null>(null);
  const [verification, setVerification] = useState<ScanVerification | null>(null);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  const verifyEpoch = useRef(0);
  const requestEpoch = useRef(0);
  const mounted = useRef(true);
  const scanPagingGuard = useRef(false);
  const findingPagingGuard = useRef(false);

  useEffect(() => {
    mounted.current = true;
    let active = true;
    void apiScansPage(1, SCAN_PAGE_SIZE).then(res => {
      if (!active) return;
      if (res.source !== "live" || !res.data) { setScanError(failure(res, "list scans")); return; }
      const data = res.data;
      if (!Array.isArray(data.scans) || !validCount(data.total_count) || !data.scans.every(s => present(s?.scan_id)) || (data.total_count > 0 && !data.scans.length)) {
        setScanError("Scan list response is incomplete; scan state is unknown."); return;
      }
      setScans(data.scans);
      setScanTotal(data.total_count);
      setSelected(data.scans[0]?.scan_id ?? null);
    }).finally(() => { if (active) setScanLoading(false); });
    return () => { active = false; mounted.current = false; requestEpoch.current++; verifyEpoch.current++; };
  }, []);

  useEffect(() => {
    const epoch = ++requestEpoch.current;
    verifyEpoch.current++;
    setVerification(null); setVerifyError(null); setVerifying(false);
    setFindings([]); setFindingTotal(null); setFindingPage(1); setFindingError(null);
    if (!selected) { setFindingLoading(false); return; }
    setFindingLoading(true);
    void apiFindings({ scan_id: selected, page: 1, page_size: PAGE_SIZE }).then(res => {
      if (!mounted.current || epoch !== requestEpoch.current) return;
      if (res.source !== "live" || !res.data) { setFindingError(failure(res, "list scan evidence")); return; }
      const data = res.data;
      if (!Array.isArray(data.findings) || !validCount(data.total_count) || !data.findings.every(f => present(f?.evidence_id) && f.scan_id === selected) || (data.total_count > 0 && !data.findings.length)) {
        setFindingError("Scan evidence response is incomplete; observations are unknown."); return;
      }
      setFindings(data.findings); setFindingTotal(data.total_count);
    }).finally(() => { if (mounted.current && epoch === requestEpoch.current) setFindingLoading(false); });
    return () => { requestEpoch.current++; verifyEpoch.current++; };
  }, [selected]);

  async function moreScans() {
    if (scanPagingGuard.current || scanTotal === null) return;
    scanPagingGuard.current = true; setScanPaging(true); setScanError(null);
    const next = scanPage + 1;
    try {
      const res = await apiScansPage(next, SCAN_PAGE_SIZE);
      if (!mounted.current) return;
      if (res.source !== "live" || !res.data) { setScanError(failure(res, "load more scans")); return; }
      if (!Array.isArray(res.data.scans) || !validCount(res.data.total_count) || !res.data.scans.every(s => present(s?.scan_id)) || !res.data.scans.length || res.data.scans.every(s => scans.some(r => r.scan_id === s.scan_id))) { setScanError("Scan page response is incomplete or repeated."); return; }
      setScans(rows => [...rows, ...res.data!.scans.filter(s => !rows.some(r => r.scan_id === s.scan_id))]);
      setScanTotal(res.data.total_count); setScanPage(next);
    } finally { scanPagingGuard.current = false; if (mounted.current) setScanPaging(false); }
  }

  async function moreFindings() {
    if (findingPagingGuard.current || !selected || findingTotal === null) return;
    findingPagingGuard.current = true; setFindingPaging(true); setFindingError(null);
    const epoch = requestEpoch.current;
    const next = findingPage + 1;
    try {
      const res = await apiFindings({ scan_id: selected, page: next, page_size: PAGE_SIZE });
      if (!mounted.current || epoch !== requestEpoch.current) return;
      if (res.source !== "live" || !res.data) { setFindingError(failure(res, "load more scan evidence")); return; }
      if (!Array.isArray(res.data.findings) || !res.data.findings.length || !res.data.findings.every(f => present(f?.evidence_id) && f.scan_id === selected) || !validCount(res.data.total_count) || res.data.findings.every(f => findings.some(r => r.evidence_id === f.evidence_id))) { setFindingError("Scan evidence page response is incomplete or repeated."); return; }
      setFindings(rows => [...rows, ...res.data!.findings.filter(f => !rows.some(r => r.evidence_id === f.evidence_id))]);
      setFindingTotal(res.data.total_count); setFindingPage(next);
    } finally { findingPagingGuard.current = false; if (mounted.current && epoch === requestEpoch.current) setFindingPaging(false); }
  }

  async function verifyScan() {
    if (!selected || verifying) return;
    const epoch = ++verifyEpoch.current;
    setVerification(null); setVerifyError(null); setVerifying(true);
    const res = await apiVerifyStoredScan(selected);
    if (!mounted.current || epoch !== verifyEpoch.current) return;
    if (res.source !== "live" || !res.data) setVerifyError(failure(res, "verify this scan"));
    else {
      const v = res.data;
      if (v.scan_id !== selected || !["PASS", "FAIL", "EMPTY", "UNVERIFIABLE"].includes(v.result) || !validCount(v.records)
        || typeof v.chain_intact !== "boolean" || typeof v.content_intact !== "boolean" || typeof v.manifest_intact !== "boolean" || typeof v.hash_format_valid !== "boolean"
        || !Array.isArray(v.errors) || (v.result === "PASS" && (!v.records || !v.chain_intact || !v.content_intact || !v.manifest_intact || !v.hash_format_valid || v.errors.length))) {
        setVerifyError("Scan verification response is incomplete or inconsistent; verdict unavailable.");
      } else setVerification(v);
    }
    setVerifying(false);
  }

  return (
    <div>
      <p style={{ color: "var(--dim)", fontSize: 13 }}>Source: persisted tenant-scoped scans and findings. Stored hashes are identifiers, not proof of integrity. A verification response covers the entire selected scan, not each evidence record.</p>
      {tenant && <p style={{ color: "var(--dim)", fontSize: 12 }}>Active tenant: {tenant}</p>}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 330px), 1fr))", gap: 20 }}>
        <section className="panel" aria-label="Scan selection" style={{ padding: 20 }}>
          <h2 style={{ fontSize: 17, marginTop: 0 }}>Scans</h2>
          {scanLoading && <p role="status">Loading scans…</p>}
          {scanError && <p role="alert">{scanError}</p>}
          {!scanLoading && scanTotal === 0 && <p>No scans returned for this tenant.</p>}
          {scans.map(scan => <button key={scan.scan_id} type="button" aria-pressed={selected === scan.scan_id} onClick={() => {
            if (selected === scan.scan_id) return;
            verifyEpoch.current++; requestEpoch.current++;
            setVerification(null); setVerifyError(null); setVerifying(false);
            setFindings([]); setFindingTotal(null); setFindingError(null);
            setSelected(scan.scan_id);
          }} style={{ display: "block", width: "100%", textAlign: "left", background: selected === scan.scan_id ? "var(--bg-2)" : "transparent", border: "1px solid var(--line)", color: "var(--text)", borderRadius: "var(--r)", padding: 12, marginBottom: 8, cursor: "pointer", overflowWrap: "anywhere" }}>
            <strong>{scan.scan_id}</strong><br /><span style={{ color: "var(--dim)", fontSize: 12 }}>{field(scan.status)} · {field(scan.target_location)}</span>
          </button>)}
          {scanTotal !== null && <p style={{ color: "var(--dim)", fontSize: 12 }}>Loaded {scans.length} of {scanTotal} scans</p>}
          {scanTotal !== null && scans.length < scanTotal && <Button onClick={() => void moreScans()} disabled={scanPaging}>{scanPaging ? "Loading…" : "Load more scans"}</Button>}
        </section>
        <section className="panel" aria-label="Scan observations" style={{ padding: 20, minWidth: 0 }}>
          <h2 style={{ fontSize: 17, marginTop: 0 }}>Scan Evidence</h2>
          {!selected && !scanLoading && <p>Select a scan to inspect its observations.</p>}
          {selected && <>
            <p style={{ overflowWrap: "anywhere" }}>Scan ID: <strong>{selected}</strong></p>
            <Button onClick={() => void verifyScan()} disabled={verifying}>{verifying ? "Verifying…" : "Verify selected scan"}</Button>
            {verifyError && <p role="alert">{verifyError}</p>}
            {verification ? <div role="status" style={{ marginTop: 12 }}>
              <Badge variant={verification.result === "PASS" ? "success" : verification.result === "FAIL" ? "danger" : "warning"}>{verification.result}</Badge>{" "}
              <span>Server scan verification: {verification.result} · {verification.records} records checked.</span>
              {verification.result === "EMPTY" && <p>Empty scan; no observation integrity was established.</p>}
              {verification.result === "UNVERIFIABLE" && <p>Stored scan cannot be verified (incomplete or missing manifest).</p>}
              {verification.result === "FAIL" && <p>Scan integrity failed. Investigate the stored chain and manifest.</p>}
            </div> : !verifying && !verifyError && <p role="status" style={{ color: "var(--dim)" }}>Scan verification not requested; per-record integrity verdict unavailable from this API.</p>}
            {findingLoading && <p role="status">Loading scan evidence…</p>}
            {findingError && <p role="alert">{findingError}</p>}
            {!findingLoading && findingTotal === 0 && <p>No evidence observations returned for this scan.</p>}
            {findings.map(f => <article key={f.evidence_id} style={{ borderTop: "1px solid var(--line)", marginTop: 14, paddingTop: 14, overflowWrap: "anywhere" }}>
              <h3 style={{ fontSize: 14, margin: "0 0 8px" }}>Evidence ID: {f.evidence_id}</h3>
              <dl style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "6px 12px", margin: 0, fontSize: 12 }}>
                <dt>Algorithm</dt><dd style={{ margin: 0 }}>{field(f.algorithm)}</dd>
                <dt>Location</dt><dd style={{ margin: 0 }}>{field(f.file_path)}{validCount(f.line_number) && f.line_number > 0 ? ` · line ${f.line_number}` : ""}</dd>
                <dt>Observed</dt><dd style={{ margin: 0 }}>{field(f.created_at)}</dd>
                <dt>Scanner</dt><dd style={{ margin: 0 }}>{field(f.finding_data?.scanner_id)}</dd>
                <dt>Code origin</dt><dd style={{ margin: 0 }}>{field(f.finding_data?.code_origin)}</dd>
                <dt>Content hash</dt><dd style={{ margin: 0 }}>{field(f.content_hash)}</dd>
                <dt>Chain hash</dt><dd style={{ margin: 0 }}>{field(f.chain_hash)}</dd>
              </dl>
              <p style={{ color: "var(--dim)", fontSize: 11, marginBottom: 0 }}>Provenance fields shown only when provided by the redacted server projection. Per-record verification is not supplied by this endpoint; raw finding data is not displayed.</p>
            </article>)}
            {findingTotal !== null && <p style={{ color: "var(--dim)", fontSize: 12 }}>Loaded {findings.length} of {findingTotal} observations</p>}
            {findingTotal !== null && findings.length < findingTotal && <Button onClick={() => void moreFindings()} disabled={findingPaging}>{findingPaging ? "Loading…" : "Load more evidence"}</Button>}
            <p style={{ marginTop: 16 }}><Link to="/findings">Open findings console</Link></p>
          </>}
        </section>
      </div>
    </div>
  );
}

function AuditLedger() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(true);
  const [paging, setPaging] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [verify, setVerify] = useState<AuditChainStatus | null>(null);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  const mounted = useRef(true);
  const pagingGuard = useRef(false);
  const verifyEpoch = useRef(0);
  const selected = events.find(e => e.id === selectedId) ?? null;

  useEffect(() => {
    mounted.current = true;
    void apiAuditList({ page: 1, page_size: PAGE_SIZE }).then(res => {
      if (!mounted.current) return;
      if (res.source !== "live" || !res.data) { setError(failure(res, "view audit ledger")); return; }
      if (!Array.isArray(res.data.events) || !res.data.events.every(e => present(e?.id))) { setError("Audit response is incomplete; ledger entries are unknown."); return; }
      setEvents(res.data.events); setSelectedId(res.data.events[0]?.id ?? null); setHasMore(res.data.events.length === PAGE_SIZE);
    }).finally(() => { if (mounted.current) setLoading(false); });
    const epoch = ++verifyEpoch.current;
    void apiAuditVerify().then(res => {
      if (!mounted.current || epoch !== verifyEpoch.current) return;
      if (res.source !== "live" || !res.data) { setVerifyError(failure(res, "verify audit chain")); return; }
      if (!["OK", "TAMPERED"].includes(res.data.status) || !validCount(res.data.checked)) { setVerifyError("Audit verification response is incomplete; verdict unavailable."); return; }
      setVerify(res.data);
    });
    return () => { mounted.current = false; verifyEpoch.current++; };
  }, []);

  async function more() {
    if (pagingGuard.current || !hasMore) return;
    pagingGuard.current = true; setPaging(true); setError(null);
    const next = page + 1;
    try {
      const res = await apiAuditList({ page: next, page_size: PAGE_SIZE });
      if (!mounted.current) return;
      if (res.source !== "live" || !res.data) { setError(failure(res, "load more audit events")); return; }
      if (!Array.isArray(res.data.events) || !res.data.events.every(e => present(e?.id))) { setError("Audit page response is incomplete."); return; }
      setEvents(rows => [...rows, ...res.data!.events.filter(e => !rows.some(r => r.id === e.id))]);
      setPage(next); setHasMore(res.data.events.length === PAGE_SIZE);
    } finally { pagingGuard.current = false; if (mounted.current) setPaging(false); }
  }

  async function runVerification() {
    if (verifying) return;
    const epoch = ++verifyEpoch.current;
    setVerifying(true); setVerify(null); setVerifyError(null);
    const res = await apiAuditVerify();
    if (!mounted.current || epoch !== verifyEpoch.current) return;
    if (res.source !== "live" || !res.data) setVerifyError(failure(res, "verify audit chain"));
    else if (!["OK", "TAMPERED"].includes(res.data.status) || !validCount(res.data.checked)) setVerifyError("Audit verification response is incomplete; verdict unavailable.");
    else setVerify(res.data);
    setVerifying(false);
  }

  return <div>
    <p style={{ color: "var(--dim)", fontSize: 13 }}>Platform action audit events, distinct from scan findings. The chain verdict applies to the audit ledger as a whole, not to an individual event.</p>
    <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 16 }}>
      <AuthenticatedDownload path="/api/v1/auth/audit/export?format=jsonl" filename="audit-export.jsonl" className="btn outline">Export JSONL audit log</AuthenticatedDownload>
      <Button onClick={() => void runVerification()} disabled={verifying}>{verifying ? "Verifying…" : "Verify audit chain"}</Button>
    </div>
    {verifyError && <p role="alert">{verifyError}</p>}
    {verify && <p role="status"><Badge variant={verify.status === "OK" ? "success" : "danger"}>{verify.status}</Badge> Audit chain verification · {verify.checked} {verify.mode === "incremental" ? "suffix entries checked" : "entries checked"}. {verify.mode && `Mode: ${verify.mode}. `}{verify.status === "TAMPERED" && "A discrepancy was reported by the server."}</p>}
    {!verify && !verifyError && <p role="status">Audit verification pending or unavailable.</p>}
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 330px), 1fr))", gap: 20 }}>
      <section className="panel" aria-label="Audit events" style={{ padding: 20 }}>
        <h2 style={{ fontSize: 17, marginTop: 0 }}>Audit Ledger</h2>
        {loading && <p role="status">Loading audit events…</p>}
        {error && <p role="alert">{error}</p>}
        {!loading && !error && events.length === 0 && <p>No audit events returned.</p>}
        {events.map(e => <button key={e.id} type="button" aria-pressed={selectedId === e.id} onClick={() => setSelectedId(e.id)} style={{ display: "block", width: "100%", textAlign: "left", background: selectedId === e.id ? "var(--bg-2)" : "transparent", border: "1px solid var(--line)", color: "var(--text)", borderRadius: "var(--r)", padding: 12, marginBottom: 8, cursor: "pointer", overflowWrap: "anywhere" }}>
          <strong>{e.id}</strong><br /><span>{field(e.action)} · {field(e.outcome)}</span><br /><span style={{ color: "var(--dim)", fontSize: 12 }}>{field(e.actor)} · {field(e.created_at)}</span>
        </button>)}
        {hasMore && <Button onClick={() => void more()} disabled={paging}>{paging ? "Loading…" : "Load more audit events"}</Button>}
      </section>
      <section className="panel" aria-label="Audit event detail" style={{ padding: 20, minWidth: 0, overflowWrap: "anywhere" }}>
        <h2 style={{ fontSize: 17, marginTop: 0 }}>Audit event detail</h2>
        {!selected ? <p>Select an audit event to inspect its metadata. Individual event integrity is not independently verified by this endpoint.</p> : <dl style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "8px 12px", fontSize: 13 }}>
          <dt>Event ID</dt><dd style={{ margin: 0 }}>{selected.id}</dd>
          <dt>Actor</dt><dd style={{ margin: 0 }}>{field(selected.actor)}</dd>
          <dt>Action</dt><dd style={{ margin: 0 }}>{field(selected.action)}</dd>
          <dt>Outcome</dt><dd style={{ margin: 0 }}>{field(selected.outcome)}</dd>
          <dt>Timestamp</dt><dd style={{ margin: 0 }}>{field(selected.created_at)}</dd>
          <dt>Target</dt><dd style={{ margin: 0 }}>{field(selected.target_type)} · {field(selected.target_id)}</dd>
          <dt>Source IP</dt><dd style={{ margin: 0 }}>{field(selected.ip_address)}</dd>
        </dl>}
        {selected && <p style={{ fontSize: 12, color: "var(--dim)" }}>Unstructured event detail is withheld to avoid displaying raw secrets; no per-event integrity claim is available.</p>}
      </section>
    </div>
  </div>;
}
