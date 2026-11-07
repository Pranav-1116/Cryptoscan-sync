import PrivateScope, { usePrivateScopeCurrent } from "../components/PrivateScope";
import React, { useEffect, useRef, useState, useMemo } from "react";
import { Link } from "react-router-dom";
import { Panel, Badge, Bar, Ring, Button } from "../components/ui";
import { IconComponent, IconClock, IconSecurity, IconTarget, IconCloud, IconInfo } from "../components/icons";
import AuthenticatedDownload from "../components/AuthenticatedDownload";
import { activeTenantId, apiAuditList, apiAuditVerify, apiFindings, apiFindingVerify, apiScansPage, apiVerifyStoredScan, type AuditChainStatus, type AuditEvent, type Finding, type FindingVerifyVerdict, type ScanSummaryRow, type ScanVerification, type ApiResult } from "../lib/api";

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

function provenanceText(value: unknown): string {
  if (value == null) return "Not supplied";
  if (typeof value === "string") return value;
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v != null && v !== "")
      .map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : String(v)}`);
    return entries.length ? entries.join(" · ") : "Not supplied";
  }
  return String(value);
}

export default function Evidence() { return <PrivateScope><EvidencePage /></PrivateScope>; }

function EvidencePage() {
  const [tab, setTab] = useState<"scan" | "audit">("scan");
  const [auditVisited, setAuditVisited] = useState(false);
  const [session, setSession] = useState(0);
  const [tenant, setTenant] = useState(activeTenantId());
  useEffect(() => {
    const reset = () => { setTenant(activeTenantId()); setSession(n => n + 1); setAuditVisited(false); setTab("scan"); };
    window.addEventListener("zelinx:tenant", reset); window.addEventListener("zelinx:auth", reset);
    return () => { window.removeEventListener("zelinx:tenant", reset); window.removeEventListener("zelinx:auth", reset); };
  }, []);
  const hdrTone = tab === "audit" ? "violet" as const : "amber" as const;
  return (
    <div className="page" style={{ maxWidth: 1280, margin: "0 auto", padding: "10px 0 60px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 12, flexWrap: "wrap", gap: 16 }}>
        <div style={{ flex: "1 1 480px", minWidth: 280 }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px", borderRadius: 999, background: `color-mix(in srgb, var(--${hdrTone}) 12%, transparent)`, border: `1px solid var(--${hdrTone})`, fontSize: 11, fontFamily: "var(--mono)", color: `var(--${hdrTone})`, letterSpacing: ".06em" }}>
            <span style={{ width: 6, height: 6, borderRadius: 99, background: `var(--${hdrTone})` }} /> GOVERNANCE · EVIDENCE · WORM LEDGER
          </div>
          <h1 style={{ fontSize: 26, fontWeight: 800, margin: "8px 0 6px", letterSpacing: "-0.02em", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ width: 34, height: 34, borderRadius: 10, display: "grid", placeItems: "center", background: `var(--${hdrTone})`, color: "#fff" }}><IconComponent size={18} /></span>
            Evidence
          </h1>
          <p style={{ margin: 0, fontSize: 13.5, color: "var(--dim)", lineHeight: 1.5, maxWidth: 620 }}>
            Stored scan observations <b style={{ color: "var(--text)" }}>separately</b> from the platform action audit ledger. Verification covers only the scope the server reports — <span style={{ color: `var(--${hdrTone})` }}>no claim beyond verified records</span>.
          </p>
        </div>
        <Panel style={{ padding: "8px 12px", display: "flex", gap: 8, alignItems: "center" }}>
          <Badge tone={tab === "scan" ? "amber" : "violet"}>{tab === "scan" ? "SCAN EVIDENCE" : "AUDIT LEDGER"}</Badge>
          <span style={{ fontSize: 11, color: "var(--faint)" }}>{tenant ? `tenant ${tenant.slice(0, 8)}…` : "no tenant"}</span>
        </Panel>
      </div>

      <div role="tablist" aria-label="Evidence views" onKeyDown={event => {
        if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
        event.preventDefault();
        const next = event.key === "Home" ? "scan" : event.key === "End" ? "audit" : tab === "scan" ? "audit" : "scan";
        if (next === "audit") setAuditVisited(true);
        setTab(next);
        document.getElementById(`${next}-tab`)?.focus();
      }} style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        <button id="scan-tab" type="button" role="tab" tabIndex={tab === "scan" ? 0 : -1} aria-controls="scan-panel" aria-selected={tab === "scan"} onClick={() => setTab("scan")} style={{ padding: "8px 16px", borderRadius: "var(--r)", fontSize: 13, fontWeight: tab === "scan" ? 700 : 500, cursor: "pointer", background: tab === "scan" ? "var(--amber)" : "var(--bg-2)", color: tab === "scan" ? "#fff" : "var(--text)", border: `1px solid ${tab === "scan" ? "var(--amber)" : "var(--line)"}` }}>Scan Evidence</button>
        <button id="audit-tab" type="button" role="tab" tabIndex={tab === "audit" ? 0 : -1} aria-controls="audit-panel" aria-selected={tab === "audit"} onClick={() => { setAuditVisited(true); setTab("audit"); }} style={{ padding: "8px 16px", borderRadius: "var(--r)", fontSize: 13, fontWeight: tab === "audit" ? 700 : 500, cursor: "pointer", background: tab === "audit" ? "var(--violet)" : "var(--bg-2)", color: tab === "audit" ? "#fff" : "var(--text)", border: `1px solid ${tab === "audit" ? "var(--violet)" : "var(--line)"}` }}>Audit Ledger</button>
        <span style={{ marginLeft: "auto", fontSize: 11, color: "var(--faint)", alignSelf: "center" }}>Scan integrity ≠ per-record truth · Ledger is platform actions, not scan findings</span>
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
  const scopeCurrent = usePrivateScopeCurrent();
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
  const [recordVerdicts, setRecordVerdicts] = useState<Record<string, { busy?: boolean; verdict?: FindingVerifyVerdict; error?: string }>>({});
  const recordRequests = useRef(new Map<string, symbol>());
  function verifyRecord(evidenceId: string) {
    if (!scopeCurrent() || recordRequests.current.has(evidenceId)) return;
    const request = Symbol(); const epoch = requestEpoch.current;
    recordRequests.current.set(evidenceId, request);
    setRecordVerdicts(prev => ({ ...prev, [evidenceId]: { busy: true } }));
    void apiFindingVerify(evidenceId).then(res => {
      if (!scopeCurrent() || !mounted.current || epoch !== requestEpoch.current) return;
      setRecordVerdicts(prev => {
        const next = { ...prev };
        if (res.source !== "live" || !res.data || res.data.evidence_id !== evidenceId || !["PASS", "FAIL"].includes(res.data.result) || ![res.data.content_intact, res.data.chain_intact, res.data.hash_format_valid].every(x => typeof x === "boolean") || !Array.isArray(res.data.errors) || !res.data.errors.every(x => typeof x === "string") || (res.data.result === "PASS" && (!res.data.content_intact || !res.data.chain_intact || !res.data.hash_format_valid || res.data.errors.length))) {
          next[evidenceId] = { error: failure(res, "verify this record") };
        } else next[evidenceId] = { verdict: res.data };
        return next;
      });
    }).finally(() => { if (recordRequests.current.get(evidenceId) === request) recordRequests.current.delete(evidenceId); });
  }
  useEffect(() => {
    mounted.current = true; let active = true;
    void apiScansPage(1, SCAN_PAGE_SIZE).then(res => {
      if (!active) return;
      if (res.source !== "live" || !res.data) { setScanError(failure(res, "list scans")); return; }
      const data = res.data;
      if (!Array.isArray(data.scans) || !validCount(data.total_count) || !data.scans.every(s => present(s?.scan_id)) || (data.total_count > 0 && !data.scans.length)) { setScanError("Scan list response is incomplete; scan state is unknown."); return; }
      setScans(data.scans); setScanTotal(data.total_count); setSelected(data.scans[0]?.scan_id ?? null);
    }).finally(() => { if (active) setScanLoading(false); });
    return () => { active = false; mounted.current = false; requestEpoch.current++; verifyEpoch.current++; };
  }, []);
  useEffect(() => {
    const epoch = ++requestEpoch.current;
    recordRequests.current.clear(); setRecordVerdicts({});
    verifyEpoch.current++; setVerification(null); setVerifyError(null); setVerifying(false);
    setFindings([]); setFindingTotal(null); setFindingPage(1); setFindingError(null);
    if (!selected) { setFindingLoading(false); return; }
    setFindingLoading(true);
    void apiFindings({ scan_id: selected, page: 1, page_size: PAGE_SIZE }).then(res => {
      if (!scopeCurrent() || !mounted.current || epoch !== requestEpoch.current) return;
      if (res.source !== "live" || !res.data) { setFindingError(failure(res, "list scan evidence")); return; }
      const data = res.data;
      if (!Array.isArray(data.findings) || !validCount(data.total_count) || !data.findings.every(f => present(f?.evidence_id) && f.scan_id === selected) || (data.total_count > 0 && !data.findings.length)) { setFindingError("Scan evidence response is incomplete; observations are unknown."); return; }
      setFindings(data.findings); setFindingTotal(data.total_count);
    }).finally(() => { if (mounted.current && epoch === requestEpoch.current) setFindingLoading(false); });
    return () => { requestEpoch.current++; verifyEpoch.current++; };
  }, [selected]);
  async function moreScans() {
    if (scanPagingGuard.current || scanTotal === null) return;
    scanPagingGuard.current = true; setScanPaging(true); setScanError(null); const next = scanPage + 1;
    try {
      const res = await apiScansPage(next, SCAN_PAGE_SIZE);
      if (!scopeCurrent() || !mounted.current) return;
      if (res.source !== "live" || !res.data) { setScanError(failure(res, "load more scans")); return; }
      if (!Array.isArray(res.data.scans) || !validCount(res.data.total_count) || !res.data.scans.every(s => present(s?.scan_id)) || !res.data.scans.length || res.data.scans.every(s => scans.some(r => r.scan_id === s.scan_id))) { setScanError("Scan page response is incomplete or repeated."); return; }
      setScans(rows => [...rows, ...res.data!.scans.filter(s => !rows.some(r => r.scan_id === s.scan_id))]); setScanTotal(res.data.total_count); setScanPage(next);
    } finally { scanPagingGuard.current = false; if (mounted.current) setScanPaging(false); }
  }
  async function moreFindings() {
    if (findingPagingGuard.current || !selected || findingTotal === null) return;
    findingPagingGuard.current = true; setFindingPaging(true); setFindingError(null); const epoch = requestEpoch.current; const next = findingPage + 1;
    try {
      const res = await apiFindings({ scan_id: selected, page: next, page_size: PAGE_SIZE });
      if (!scopeCurrent() || !mounted.current || epoch !== requestEpoch.current) return;
      if (res.source !== "live" || !res.data) { setFindingError(failure(res, "load more scan evidence")); return; }
      if (!Array.isArray(res.data.findings) || !res.data.findings.length || !res.data.findings.every(f => present(f?.evidence_id) && f.scan_id === selected) || !validCount(res.data.total_count) || res.data.findings.every(f => findings.some(r => r.evidence_id === f.evidence_id))) { setFindingError("Scan evidence page response is incomplete or repeated."); return; }
      setFindings(rows => [...rows, ...res.data!.findings.filter(f => !rows.some(r => r.evidence_id === f.evidence_id))]); setFindingTotal(res.data.total_count); setFindingPage(next);
    } finally { findingPagingGuard.current = false; if (mounted.current && epoch === requestEpoch.current) setFindingPaging(false); }
  }
  async function verifyScan() {
    if (!selected || verifying) return;
    const epoch = ++verifyEpoch.current; setVerification(null); setVerifyError(null); setVerifying(true);
    const res = await apiVerifyStoredScan(selected);
    if (!scopeCurrent() || !mounted.current || epoch !== verifyEpoch.current) return;
    if (res.source !== "live" || !res.data) setVerifyError(failure(res, "verify this scan"));
    else {
      const v = res.data;
      if (v.scan_id !== selected || !["PASS", "FAIL", "EMPTY", "UNVERIFIABLE"].includes(v.result) || !validCount(v.records) || typeof v.chain_intact !== "boolean" || typeof v.content_intact !== "boolean" || typeof v.manifest_intact !== "boolean" || typeof v.hash_format_valid !== "boolean" || !Array.isArray(v.errors) || (v.result === "PASS" && (!v.records || !v.chain_intact || !v.content_intact || !v.manifest_intact || !v.hash_format_valid || v.errors.length))) setVerifyError("Scan verification response is incomplete or inconsistent; verdict unavailable.");
      else setVerification(v);
    }
    setVerifying(false);
  }

  const checked = findings.filter(f => recordVerdicts[f.evidence_id]?.verdict);
  const passed = checked.filter(f => recordVerdicts[f.evidence_id]?.verdict?.result === "PASS").length;
  const kpiTotal = scanTotal ?? scans.length;
  const kpiFindings = findingTotal ?? findings.length;

  return (
    <div>
      {/* Scan KPIs */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 14, marginBottom: 16 }}>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--amber)" }}>
          <div style={{ padding: "14px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>STORED SCANS</div><div style={{ fontSize: 28, fontWeight: 800, margin: "4px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{scanLoading ? "…" : kpiTotal}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>tenant-scoped · hashes are identifiers</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--amber) 14%, transparent)", border: "1px solid var(--amber)", color: "var(--amber)" }}><IconCloud size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={scanTotal ? Math.min(1, scans.length / scanTotal) : 0} tone="amber" /><div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>Loaded {scans.length} of {scanTotal ?? "—"} scans</div></div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${verification?.result === "PASS" ? "var(--green)" : verification?.result === "FAIL" ? "var(--red)" : "var(--slate)"}` }}>
          <div style={{ padding: "14px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>SCAN VERDICT</div><div style={{ fontSize: 16, fontWeight: 800, margin: "6px 0 2px", lineHeight: 1 }}>{verification ? verification.result : verifying ? "VERIFYING…" : "NOT REQUESTED"}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>{verification ? `${verification.records} records checked` : "Covers selected scan, not each record"}</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: verification?.result === "PASS" ? "color-mix(in srgb, var(--green) 14%, transparent)" : "var(--panel-2)", border: `1px solid ${verification?.result === "PASS" ? "var(--green)" : "var(--line)"}`, color: verification?.result === "PASS" ? "var(--green)" : "var(--faint)" }}><IconSecurity size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={verification ? (verification.result === "PASS" ? 1 : 0.5) : 0} tone={verification?.result === "PASS" ? "green" : verification?.result === "FAIL" ? "red" : "slate"} /><div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>EMPTY / UNVERIFIABLE are honest states</div></div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--cyan)" }}>
          <div style={{ padding: "14px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>OBSERVATIONS IN SCAN</div><div style={{ fontSize: 28, fontWeight: 800, margin: "4px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{selected ? (findingLoading ? "…" : kpiFindings) : "—"}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>{selected ? `scan ${selected.slice(0,8)}…` : "Select a scan"}</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--cyan) 14%, transparent)", border: "1px solid var(--cyan)", color: "var(--cyan)" }}><IconTarget size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={findingTotal ? Math.min(1, findings.length / findingTotal) : 0} tone="cyan" /><div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>Loaded {findings.length} of {findingTotal ?? "—"} · paged 50</div></div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${checked.length ? "var(--green)" : "var(--slate)"}` }}>
          <div style={{ padding: "14px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>PER-RECORD SEALS</div><div style={{ fontSize: 18, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{checked.length}/{findings.length} verified</div><div style={{ fontSize: 11, color: checked.length ? "var(--green)" : "var(--dim)" }}>{checked.length ? `${passed} PASS · ${checked.length - passed} FAIL` : "Verify each record individually"}</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: checked.length ? "color-mix(in srgb, var(--green) 14%, transparent)" : "var(--panel-2)", border: `1px solid ${checked.length ? "var(--green)" : "var(--line)"}`, color: checked.length ? "var(--green)" : "var(--faint)" }}><IconInfo size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={findings.length ? checked.length / findings.length : 0} tone={checked.length ? "green" : "slate"} /><div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>Unverified ≠ sealed — on-demand only</div></div>
        </div>
      </div>

      <p style={{ color: "var(--dim)", fontSize: 12, background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "8px 12px" }}>Source: persisted tenant-scoped scans and findings. Stored hashes are identifiers, not proof of integrity. A verification response covers the entire selected scan, not each evidence record. {tenant && <span style={{ color: "var(--faint)" }}>· Active tenant: {tenant}</span>}</p>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 330px), 1fr))", gap: 16, marginTop: 12 }}>
        <section className="panel" aria-label="Scan selection" style={{ padding: 16 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}><h2 style={{ fontSize: 14, fontWeight: 800, margin: 0, display: "flex", alignItems: "center", gap: 8 }}><IconCloud size={14} style={{ color: "var(--amber)" }} /> Scans</h2><Badge tone="amber">{scans.length}/{scanTotal ?? "?"} </Badge></div>
          {scanLoading && <p role="status" style={{ fontSize: 13 }}>Loading scans…</p>}
          {scanError && <p role="alert" style={{ fontSize: 12, color: "var(--amber)", background: "color-mix(in srgb, var(--amber) 8%, transparent)", border: "1px solid var(--amber)", borderRadius: "var(--r)", padding: "8px 10px" }}>{scanError}</p>}
          {!scanLoading && scanTotal === 0 && <p style={{ fontSize: 13, color: "var(--dim)" }}>No scans returned for this tenant.</p>}
          {scans.map(scan => <button key={scan.scan_id} type="button" aria-pressed={selected === scan.scan_id} onClick={() => { if (selected === scan.scan_id) return; verifyEpoch.current++; requestEpoch.current++; setVerification(null); setVerifyError(null); setVerifying(false); setFindings([]); setFindingTotal(null); setFindingError(null); setSelected(scan.scan_id); }} style={{ display: "block", width: "100%", textAlign: "left", background: selected === scan.scan_id ? "color-mix(in srgb, var(--amber) 10%, transparent)" : "var(--panel-2)", border: `1px solid ${selected === scan.scan_id ? "var(--amber)" : "var(--line)"}`, color: "var(--text)", borderRadius: "var(--r)", padding: 12, marginBottom: 8, cursor: "pointer", overflowWrap: "anywhere" }}>
            <strong style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{scan.scan_id}</strong><br /><span style={{ color: "var(--dim)", fontSize: 11 }}>{field(scan.status)} · {field(scan.target_location)}</span>
            {Array.isArray(scan.statistics?.optional_stage_failures) && scan.statistics.optional_stage_failures.length > 0 && <span style={{ display: "block", marginTop: 4, fontSize: 11, color: "var(--amber)" }}>{scan.statistics.optional_stage_failures.length} optional stage{(scan.statistics.optional_stage_failures.length === 1 ? "" : "s")} failed — observation incomplete</span>}
          </button>)}
          {scanTotal !== null && <p style={{ color: "var(--faint)", fontSize: 11 }}>Loaded {scans.length} of {scanTotal} scans</p>}
          {scanTotal !== null && scans.length < scanTotal && <Button onClick={() => void moreScans()} disabled={scanPaging}>{scanPaging ? "Loading…" : "Load more scans"}</Button>}
        </section>

        <section className="panel" aria-label="Scan observations" style={{ padding: 16, minWidth: 0 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12, flexWrap: "wrap", gap: 8 }}>
            <h2 style={{ fontSize: 14, fontWeight: 800, margin: 0, display: "flex", alignItems: "center", gap: 8 }}><IconTarget size={14} style={{ color: "var(--amber)" }} /> Scan Evidence</h2>
            {selected && <Button variant="primary" onClick={() => void verifyScan()} disabled={verifying}>{verifying ? "Verifying…" : "Verify selected scan"}</Button>}
          </div>
          {!selected && !scanLoading && <div style={{ padding: 20, textAlign: "center", color: "var(--faint)", fontSize: 13, background: "var(--panel-2)", border: "1px dashed var(--line)", borderRadius: "var(--r)" }}>Select a scan to inspect its observations.</div>}
          {selected && <>
            <p style={{ overflowWrap: "anywhere", fontSize: 12, background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "8px 10px" }}>Scan ID: <strong style={{ fontFamily: "var(--mono)" }}>{selected}</strong></p>
            {verifyError && <p role="alert" style={{ fontSize: 12, color: "var(--red)", background: "color-mix(in srgb, var(--red) 8%, transparent)", border: "1px solid var(--red)", borderRadius: "var(--r)", padding: "8px 10px" }}>{verifyError}</p>}
            {verification ? <div role="status" style={{ marginTop: 10, padding: 10, background: `color-mix(in srgb, var(--${verification.result === "PASS" ? "green" : verification.result === "FAIL" ? "red" : "amber"}) 8%, transparent)`, border: `1px solid var(--${verification.result === "PASS" ? "green" : verification.result === "FAIL" ? "red" : "amber"})`, borderRadius: "var(--r)", fontSize: 12 }}><Badge variant={verification.result === "PASS" ? "success" : verification.result === "FAIL" ? "danger" : "warning"}>{verification.result}</Badge> <span>Server scan verification: {verification.result} · {verification.records} records checked.</span>{verification.result === "EMPTY" && <p style={{ margin: "6px 0 0" }}>Empty scan; no observation integrity was established.</p>}{verification.result === "UNVERIFIABLE" && <p style={{ margin: "6px 0 0" }}>Stored scan cannot be verified (incomplete or missing manifest).</p>}{verification.result === "FAIL" && <p style={{ margin: "6px 0 0" }}>Scan integrity failed. Investigate stored chain and manifest.</p>}</div> : !verifying && !verifyError && <p role="status" style={{ color: "var(--dim)", fontSize: 11, background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "8px 10px" }}>Scan verification not requested; the scan-level verdict appears here once requested — per-record seals are issued per record below.</p>}
            {findingLoading && <p role="status" style={{ fontSize: 12 }}>Loading scan evidence…</p>}
            {findingError && <p role="alert" style={{ fontSize: 12, color: "var(--red)", background: "color-mix(in srgb, var(--red) 8%, transparent)", border: "1px solid var(--red)", borderRadius: "var(--r)", padding: "8px 10px" }}>{findingError}</p>}
            {!findingLoading && findingTotal === 0 && <p style={{ fontSize: 12, color: "var(--dim)" }}>No evidence observations returned for this scan.</p>}
            {findings.map(f => <article key={f.evidence_id} style={{ border: "1px solid var(--line)", borderRadius: "var(--r)", marginTop: 12, padding: 12, background: "var(--panel-2)", overflowWrap: "anywhere" }}>
              <h3 style={{ fontSize: 12, margin: "0 0 8px", fontFamily: "var(--mono)" }}>Evidence ID: {f.evidence_id}</h3>
              <dl style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "6px 12px", margin: 0, fontSize: 11.5 }}>
                <dt style={{ color: "var(--faint)" }}>Algorithm</dt><dd style={{ margin: 0 }}>{field(f.algorithm)}</dd>
                <dt style={{ color: "var(--faint)" }}>Location</dt><dd style={{ margin: 0 }}>{field(f.file_path)}{validCount(f.line_number) && f.line_number > 0 ? ` · line ${f.line_number}` : ""}</dd>
                <dt style={{ color: "var(--faint)" }}>Observed</dt><dd style={{ margin: 0 }}>{field(f.created_at)}</dd>
                <dt style={{ color: "var(--faint)" }}>Scanner</dt><dd style={{ margin: 0 }}>{field(f.finding_data?.scanner_id)}</dd>
                <dt style={{ color: "var(--faint)" }}>Content hash</dt><dd style={{ margin: 0, fontFamily: "var(--mono)", fontSize: 11 }}>{f.content_hash ? `${String(f.content_hash).slice(0, 32)}…` : "Not supplied"}</dd>
                <dt style={{ color: "var(--faint)" }}>Chain hash</dt><dd style={{ margin: 0, fontFamily: "var(--mono)", fontSize: 11 }}>{String(field(f.chain_hash)).slice(0, 32)}…</dd>
                <dt style={{ color: "var(--faint)" }}>Provenance</dt><dd style={{ margin: 0 }}>{provenanceText(f.provenance)}</dd>
              </dl>
              <div style={{ marginTop: 10, display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                <button onClick={() => verifyRecord(f.evidence_id)} disabled={!!recordVerdicts[f.evidence_id]?.busy} style={{ fontSize: 11.5, padding: "5px 10px", borderRadius: "var(--r)", background: recordVerdicts[f.evidence_id]?.verdict?.result === "PASS" ? "var(--green)" : "var(--amber)", color: "#fff", border: "none", fontWeight: 700, cursor: recordVerdicts[f.evidence_id]?.busy ? "not-allowed" : "pointer", opacity: recordVerdicts[f.evidence_id]?.busy ? 0.6 : 1 }}>{recordVerdicts[f.evidence_id]?.busy ? "Verifying…" : "Verify this record"}</button>
                {recordVerdicts[f.evidence_id]?.error && <span role="alert" style={{ color: "var(--amber)", fontSize: 11 }}>{recordVerdicts[f.evidence_id]?.error}</span>}
                {recordVerdicts[f.evidence_id]?.verdict && (() => { const v = recordVerdicts[f.evidence_id]!.verdict!; return <span style={{ fontSize: 11 }}><Badge variant={v.result === "PASS" ? "success" : "danger"}>{v.result}</Badge> content {v.content_intact ? "intact" : "broken"} · chain {v.chain_intact ? "intact" : "broken"} · hash format {v.hash_format_valid ? "valid" : "invalid"} · verified by {field(v.verified_by)}</span>; })()}
              </div>
              <p style={{ color: "var(--faint)", fontSize: 10, margin: "8px 0 0" }}>Provenance fields shown only when provided by the redacted server projection; raw finding data is not displayed.</p>
            </article>)}
            {findingTotal !== null && <p style={{ color: "var(--dim)", fontSize: 11, marginTop: 10 }}>Loaded {findings.length} of {findingTotal} observations</p>}
            {findingTotal !== null && findings.length < findingTotal && <Button onClick={() => void moreFindings()} disabled={findingPaging}>{findingPaging ? "Loading…" : "Load more evidence"}</Button>}
            <p style={{ marginTop: 12 }}><Link to="/findings" style={{ fontSize: 12, color: "var(--amber)" }}>Open findings console →</Link></p>
          </>}
        </section>
      </div>
    </div>
  );
}

function AuditLedger() {
  const scopeCurrent = usePrivateScopeCurrent();
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(true);
  const [paging, setPaging] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [applied, setApplied] = useState<{ actor: string; action: string }>({ actor: "", action: "" });
  const [draft, setDraft] = useState<{ actor: string; action: string }>({ actor: "", action: "" });
  const [verify, setVerify] = useState<AuditChainStatus | null>(null);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  const mounted = useRef(true);
  const pagingGuard = useRef(false);
  const verifyEpoch = useRef(0);
  const selected = events.find(e => e.id === selectedId) ?? null;
  useEffect(() => {
    mounted.current = true; const epoch = ++verifyEpoch.current; setLoading(true);
    void apiAuditList({ page: 1, page_size: PAGE_SIZE, ...(applied.actor ? { actor: applied.actor } : {}), ...(applied.action ? { action: applied.action } : {}) }).then(res => {
      if (!scopeCurrent() || !mounted.current || epoch !== verifyEpoch.current) return;
      if (res.source !== "live" || !res.data) { setError(failure(res, "view audit ledger")); return; }
      if (!Array.isArray(res.data.events) || !res.data.events.every(e => present(e?.id))) { setError("Audit response is incomplete; ledger entries are unknown."); return; }
      setEvents(res.data.events); setSelectedId(res.data.events[0]?.id ?? null); setHasMore(res.data.events.length === PAGE_SIZE); setPage(1);
    }).finally(() => { if (mounted.current && epoch === verifyEpoch.current) setLoading(false); });
    const verifyChainEpoch = epoch;
    void apiAuditVerify().then(res => { if (!scopeCurrent() || !mounted.current || verifyChainEpoch !== verifyEpoch.current) return; if (res.source !== "live" || !res.data) { setVerifyError(failure(res, "verify audit chain")); return; } if (!["OK", "TAMPERED"].includes(res.data.status) || !validCount(res.data.checked)) { setVerifyError("Audit verification response is incomplete; verdict unavailable."); return; } setVerify(res.data); });
    return () => { mounted.current = false; verifyEpoch.current++; };
  }, [applied]);
  async function more() {
    if (pagingGuard.current || !hasMore) return;
    pagingGuard.current = true; setPaging(true); setError(null); const next = page + 1;
    try {
      const res = await apiAuditList({ page: next, page_size: PAGE_SIZE, ...(applied.actor ? { actor: applied.actor } : {}), ...(applied.action ? { action: applied.action } : {}) });
      if (!scopeCurrent() || !mounted.current) return;
      if (res.source !== "live" || !res.data) { setError(failure(res, "load more audit events")); return; }
      if (!Array.isArray(res.data.events) || !res.data.events.every(e => present(e?.id))) { setError("Audit page response is incomplete."); return; }
      setEvents(rows => [...rows, ...res.data!.events.filter(e => !rows.some(r => r.id === e.id))]); setPage(next); setHasMore(res.data.events.length === PAGE_SIZE);
    } finally { pagingGuard.current = false; if (mounted.current) setPaging(false); }
  }
  async function runVerification() {
    if (verifying) return; const epoch = ++verifyEpoch.current; setVerifying(true); setVerify(null); setVerifyError(null);
    const res = await apiAuditVerify();
    if (!scopeCurrent() || !mounted.current || epoch !== verifyEpoch.current) return;
    if (res.source !== "live" || !res.data) setVerifyError(failure(res, "verify audit chain"));
    else if (!["OK", "TAMPERED"].includes(res.data.status) || !validCount(res.data.checked)) setVerifyError("Audit verification response is incomplete; verdict unavailable.");
    else setVerify(res.data);
    setVerifying(false);
  }
  return <div>
    <p style={{ color: "var(--dim)", fontSize: 12, background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "8px 12px" }}>Platform action audit events, distinct from scan findings. The chain verdict applies to the audit ledger as a whole, not to an individual event.</p>
    {/* KPI for audit */}
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 14, marginBottom: 16 }}>
      <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${verify?.status === "OK" ? "var(--green)" : verify?.status === "TAMPERED" ? "var(--red)" : "var(--slate)"}` }}>
        <div style={{ padding: "14px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
          <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>AUDIT CHAIN</div><div style={{ fontSize: 16, fontWeight: 800, margin: "6px 0 2px", lineHeight: 1 }}>{verify ? verify.status : verifying ? "VERIFYING…" : "—"}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>{verify ? `${verify.checked} ${verify.mode === "incremental" ? "suffix" : "entries"} checked` : "Ledger-wide verdict"}</div></div>
          <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: verify?.status === "OK" ? "color-mix(in srgb, var(--green) 14%, transparent)" : "var(--panel-2)", border: `1px solid ${verify?.status === "OK" ? "var(--green)" : "var(--line)"}`, color: verify?.status === "OK" ? "var(--green)" : "var(--faint)" }}><IconSecurity size={16} /></span>
        </div>
        <div style={{ padding: "0 16px 12px" }}><Bar value={verify?.status === "OK" ? 1 : verify?.status === "TAMPERED" ? 1 : 0} tone={verify?.status === "OK" ? "green" : verify?.status === "TAMPERED" ? "red" : "slate"} /></div>
      </div>
      <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--violet)" }}>
        <div style={{ padding: "14px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
          <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>EVENTS LOADED</div><div style={{ fontSize: 28, fontWeight: 800, margin: "4px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{events.length}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>{hasMore ? "more available" : "all loaded"}</div></div>
          <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--violet) 14%, transparent)", border: "1px solid var(--violet)", color: "var(--violet)" }}><IconClock size={16} /></span>
        </div>
        <div style={{ padding: "0 16px 12px" }}><div style={{ fontSize: 10, color: "var(--faint)" }}>page of the ledger — the export carries all rows</div></div>
      </div>
      <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--cyan)" }}>
        <div style={{ padding: "14px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
          <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>EXPORT</div><div style={{ fontSize: 12, fontWeight: 800, margin: "6px 0 2px", lineHeight: 1 }}>WORM LEDGER JSONL</div><div style={{ fontSize: 11, color: "var(--dim)" }}>Full unfiltered export</div></div>
          <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--cyan) 14%, transparent)", border: "1px solid var(--cyan)", color: "var(--cyan)" }}><IconCloud size={16} /></span>
        </div>
        <div style={{ padding: "0 16px 12px", display: "flex", gap: 8 }}><AuthenticatedDownload path="/api/v1/auth/audit/export?format=jsonl" filename="audit-export.jsonl" className="btn outline" style={{ fontSize: 11, padding: "5px 10px" } as any}>Export JSONL</AuthenticatedDownload></div>
      </div>
    </div>

    <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 14, background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "10px 12px", alignItems: "center" }}>
      <label style={{ fontSize: 12, display: "flex", alignItems: "center", gap: 6 }}>Actor <input aria-label="Filter by actor" value={draft.actor} onChange={e => setDraft(d => ({ ...d, actor: e.target.value }))} style={{ padding: "5px 8px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)", color: "var(--text)" }} placeholder="e.g. alice" /></label>
      <label style={{ fontSize: 12, display: "flex", alignItems: "center", gap: 6 }}>Action <input aria-label="Filter by action" value={draft.action} onChange={e => setDraft(d => ({ ...d, action: e.target.value }))} style={{ padding: "5px 8px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)", color: "var(--text)" }} placeholder="e.g. auth.login" /></label>
      <button onClick={() => setApplied({ actor: draft.actor.trim(), action: draft.action.trim() })} style={{ fontSize: 12, padding: "6px 12px", borderRadius: "var(--r)", background: "var(--violet)", color: "#fff", border: "1px solid var(--violet)", fontWeight: 700, cursor: "pointer" }}>Apply filters</button>
      {(applied.actor || applied.action) && <button onClick={() => { setDraft({ actor: "", action: "" }); setApplied({ actor: "", action: "" }); }} style={{ fontSize: 12, padding: "6px 12px", borderRadius: "var(--r)", background: "var(--panel)", border: "1px solid var(--line)", cursor: "pointer" }}>Clear filters</button>}
      <button onClick={() => void runVerification()} disabled={verifying} style={{ marginLeft: "auto", fontSize: 12, padding: "6px 12px", borderRadius: "var(--r)", background: verify?.status === "OK" ? "var(--green)" : "var(--amber)", color: "#fff", border: "none", fontWeight: 700, cursor: verifying ? "not-allowed" : "pointer", opacity: verifying ? 0.6 : 1 }}>{verifying ? "Verifying…" : "Verify audit chain"}</button>
    </div>
    {(applied.actor || applied.action) && <p role="status" style={{ margin: "0 0 12px", fontSize: 11, background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "8px 12px", color: "var(--dim)" }}>Filtered view{applied.actor ? ` · actor=${applied.actor}` : ""}{applied.action ? ` · action=${applied.action}` : ""} — server-side filter, showing matching entries only. The export above remains the <strong>full unfiltered WORM ledger</strong>.</p>}
    {verifyError && <p role="alert" style={{ fontSize: 12, color: "var(--red)", background: "color-mix(in srgb, var(--red) 8%, transparent)", border: "1px solid var(--red)", borderRadius: "var(--r)", padding: "8px 12px" }}>{verifyError}</p>}
    {verify && <p role="status" style={{ fontSize: 12, background: verify.status === "OK" ? "color-mix(in srgb, var(--green) 8%, transparent)" : "color-mix(in srgb, var(--red) 8%, transparent)", border: `1px solid var(--${verify.status === "OK" ? "green" : "red"})`, borderRadius: "var(--r)", padding: "8px 12px" }}><Badge variant={verify.status === "OK" ? "success" : "danger"}>{verify.status}</Badge> Audit chain verification · {verify.checked} {verify.mode === "incremental" ? "suffix entries checked" : "entries checked"}. {verify.mode && `Mode: ${verify.mode}. `}{verify.status === "TAMPERED" && "A discrepancy was reported by the server."}</p>}
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 330px), 1fr))", gap: 16 }}>
      <section className="panel" aria-label="Audit events" style={{ padding: 16 }}>
        <h2 style={{ fontSize: 14, fontWeight: 800, margin: "0 0 12px", display: "flex", alignItems: "center", gap: 8 }}><IconInfo size={14} style={{ color: "var(--violet)" }} /> Audit Ledger</h2>
        {loading && <p role="status" style={{ fontSize: 12 }}>Loading audit events…</p>}
        {error && <p role="alert" style={{ fontSize: 12, color: "var(--amber)" }}>{error}</p>}
        {!loading && !error && events.length === 0 && <p style={{ fontSize: 12, color: "var(--dim)" }}>No audit events returned.</p>}
        {events.map(e => <button key={e.id} type="button" aria-pressed={selectedId === e.id} onClick={() => setSelectedId(e.id)} style={{ display: "block", width: "100%", textAlign: "left", background: selectedId === e.id ? "color-mix(in srgb, var(--violet) 10%, transparent)" : "var(--panel-2)", border: `1px solid ${selectedId === e.id ? "var(--violet)" : "var(--line)"}`, color: "var(--text)", borderRadius: "var(--r)", padding: 12, marginBottom: 8, cursor: "pointer", overflowWrap: "anywhere" }}>
          <strong style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{e.id}</strong><br /><span style={{ fontSize: 12 }}>{field(e.action)} · {field(e.outcome)}</span><br /><span style={{ color: "var(--dim)", fontSize: 11 }}>{field(e.actor)} · {field(e.created_at)}</span>
        </button>)}
        {hasMore && <Button onClick={() => void more()} disabled={paging}>{paging ? "Loading…" : "Load more audit events"}</Button>}
      </section>
      <section className="panel" aria-label="Audit event detail" style={{ padding: 16, minWidth: 0, overflowWrap: "anywhere" }}>
        <h2 style={{ fontSize: 14, fontWeight: 800, margin: "0 0 12px", display: "flex", alignItems: "center", gap: 8 }}><IconTarget size={14} style={{ color: "var(--violet)" }} /> Audit event detail</h2>
        {!selected ? <p style={{ fontSize: 12, color: "var(--dim)" }}>Select an audit event to inspect its metadata. Individual event integrity is not independently verified by this endpoint.</p> : <dl style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "8px 12px", fontSize: 12 }}>
          <dt style={{ color: "var(--faint)" }}>Event ID</dt><dd style={{ margin: 0, fontFamily: "var(--mono)" }}>{selected.id}</dd>
          <dt style={{ color: "var(--faint)" }}>Actor</dt><dd style={{ margin: 0 }}>{field(selected.actor)}</dd>
          <dt style={{ color: "var(--faint)" }}>Action</dt><dd style={{ margin: 0 }}>{field(selected.action)}</dd>
          <dt style={{ color: "var(--faint)" }}>Outcome</dt><dd style={{ margin: 0 }}>{field(selected.outcome)}</dd>
          <dt style={{ color: "var(--faint)" }}>Timestamp</dt><dd style={{ margin: 0 }}>{field(selected.created_at)}</dd>
          <dt style={{ color: "var(--faint)" }}>Target</dt><dd style={{ margin: 0 }}>{field(selected.target_type)} · {field(selected.target_id)}</dd>
          <dt style={{ color: "var(--faint)" }}>Source IP</dt><dd style={{ margin: 0 }}>{field(selected.ip_address)}</dd>
        </dl>}
        {selected && <p style={{ fontSize: 11, color: "var(--faint)", marginTop: 12, background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "8px 10px" }}>Unstructured event detail is withheld to avoid displaying raw secrets; no per-event integrity claim is available.</p>}
      </section>
    </div>
  </div>;
}
