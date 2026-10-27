import PrivateScope, { usePrivateScopeCurrent } from "../components/PrivateScope";
import React, { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { PageHead, Panel } from "../components/ui.jsx";
import { useLive } from "../lib/useLive";
import { readFailure, writeFailure } from "../lib/requestFeedback";
import { useI18n } from "../i18n/I18n";
import { activeTenantId, tenantFetch } from "../lib/api.js";

const actions: Record<string, [string, string]> = {
  "Propose assessor scope": ["POST", "engagements"],
  "Approve scope and independence assertion": ["POST", "engagements/:id/approve"],
  "Withdraw engagement/key authority": ["POST", "engagements/:id/withdraw"],
  "Import externally signed report / retest": ["POST", "engagements/:id/reports"],
  "Plan finding remediation": ["POST", "findings/:id/plan"],
  "Approve finding change": ["POST", "findings/:id/approve"],
  "Owner reports completion (not resolution)": ["POST", "findings/:id/report-complete"],
  "Assign or replace operating duty": ["POST", "assignments"],
  "Acknowledge assigned duty": ["POST", "assignments/:id/acknowledge"],
  "Record operating exercise": ["POST", "assignments/:id/exercises"],
  "Review operating exercise": ["POST", "assignments/:id/review-exercise"],
  "Propose bounded payments pilot": ["POST", "pilots"],
  "Replace pilot scope (resets reviews)": ["PUT", "pilots/:id"],
  "Technical owner reviews evidence loop": ["POST", "pilots/:id/technical-review"],
  "Customer accepts bounded pilot": ["POST", "pilots/:id/accept"],
};
const style = { boxSizing: "border-box" as const, minWidth: 0, width: "100%", padding: 8, color: "inherit", background: "var(--surface-2, #171f2c)", border: "1px solid #526074", borderRadius: 4 };
const prefix = "/api/v1/assurance/launch/";

export default function LaunchReadiness() {
  return <PrivateScope><LaunchReadinessPage /></PrivateScope>;
}

function LaunchReadinessPage() {
  const scopeCurrent = usePrivateScopeCurrent();
  const { t } = useI18n();
  const { data: operations, loading: operationsLoading, error: operationsError, reload: reloadOperations } = useLive<unknown>(prefix + "operations", null);
  const errorFocus = useRef<HTMLParagraphElement>(null);
  const [resultKind, setResultKind] = useState("launch.receipt");
  const [result, setResult] = useState<unknown>(null);
  const [error, setError] = useState("");
  const [action, setAction] = useState(Object.keys(actions)[0]);
  const [identifier, setIdentifier] = useState("");
  const [json, setJson] = useState("");
  const [busy, setBusy] = useState(false);
  const [recordKind, setRecordKind] = useState("security_engagement");
  const [recordOffset, setRecordOffset] = useState(0);
  const generation = useRef(0);
  const controller = useRef<AbortController | null>(null);
  const requestLock = useRef(false);

  useEffect(() => {
    const reset = () => {
      generation.current++; controller.current?.abort();
      setResult(null); setError(""); setIdentifier(""); setJson(""); setRecordOffset(0); setBusy(false); reloadOperations();
    };
    window.addEventListener("zelinx:tenant", reset);
    window.addEventListener("zelinx:auth", reset);
    return () => { generation.current++; controller.current?.abort(); window.removeEventListener("zelinx:tenant", reset); window.removeEventListener("zelinx:auth", reset); };
  }, []);

  useEffect(() => { if (error) errorFocus.current?.focus(); }, [error]);
  function reportError(message: string) {
    setError(message);
    // React can skip an identical state update. Repeated invalid submission
    // must still return focus to the existing feedback without clearing input.
    errorFocus.current?.focus();
  }

  async function request(path: string, method = "GET", payload?: unknown, base = prefix) {
    if (!scopeCurrent() || requestLock.current) return;
    requestLock.current = true;
    controller.current?.abort();
    const abort = new AbortController(); controller.current = abort;
    const current = generation.current; const estate = activeTenantId();
    let status: number | undefined;
    const deadline = window.setTimeout(() => {
      if (!scopeCurrent() || current !== generation.current || controller.current !== abort) return;
      abort.abort();
      setResult(null); reportError(method === "GET" ? "Read timed out; no cached success substituted." : writeFailure());
      requestLock.current = false; setBusy(false);
    }, 20000);
    setBusy(true); setError(""); setResult(null);
    try {
      const response = await tenantFetch(base + path, { method, signal: abort.signal,
        ...(payload === undefined ? {} : { headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) }) });
      status = response.status;
      if (!response.ok) {
        if (scopeCurrent() && current === generation.current && !abort.signal.aborted) reportError(method === "GET" ? readFailure(status) : writeFailure(status));
        return;
      }
      const body: unknown = await response.json();
      if (!scopeCurrent() || current !== generation.current || estate !== activeTenantId() || abort.signal.aborted) return;
      setResult(body);
      setResultKind(method !== "GET" ? "launch.receipt" : base === prefix ? "launch.current" : "launch.history");
      if (method !== "GET") reloadOperations();
    } catch { if (scopeCurrent() && current === generation.current && controller.current === abort && !abort.signal.aborted) reportError(method === "GET" ? "Read unavailable; no cached success substituted." : writeFailure(status)); }
    finally { window.clearTimeout(deadline); if (scopeCurrent() && current === generation.current && controller.current === abort) { requestLock.current = false; setBusy(false); } }
  }
  function submit(event: React.FormEvent) {
    event.preventDefault();
    try {
      if (json.length > 1200000) { reportError("Request exceeds console size limit. Draft retained."); return; }
      const body: unknown = JSON.parse(json);
      if (!body || Array.isArray(body) || typeof body !== "object") throw new Error("Provide a JSON object matching the documented schema");
      const [method, path] = actions[action];
      if (path.includes(":id") && !identifier.trim()) throw new Error("An exact record ID is required");
      void request(path.replace(":id", encodeURIComponent(identifier)), method, body);
    } catch { reportError("Enter a valid JSON object matching the documented schema and an exact record ID when required. Draft retained."); }
  }
  const show = (value: unknown) => <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", maxHeight: 560, overflow: "auto" }}>{JSON.stringify(value, null, 2)}</pre>;
  const needsId = actions[action][1].includes(":id");
  const missingId = !identifier.trim();
  const duties = operations && typeof operations === "object" && "duties" in operations && Array.isArray(operations.duties) ? operations.duties : null;
  const partial = duties && duties.length > 0 && (!("all_owner_reviewed_records_current" in (operations as object)) || (operations as { all_owner_reviewed_records_current?: boolean }).all_owner_reviewed_records_current !== true);
  return <div className="launch-readiness" style={{ minWidth: 0 }}>
    <style>{`.launch-readiness label { display: block; margin-block: .75rem; } .launch-readiness select, .launch-readiness button { max-inline-size: 100%; white-space: normal; } .launch-readiness :focus-visible { outline: 3px solid var(--blue, #70b7ff); outline-offset: 3px; }`}</style>
    <p aria-label="Selected estate"><strong>{t("launch.estate")}: <bdi dir="auto">{activeTenantId() || t("launch.platform")}</bdi></strong></p>
    <PageHead crumb="Overview / Launch readiness" title="Launch readiness" sub="GA · independent security evidence, accountable operations and one bounded customer workflow" />
    <Panel title="External acceptance stays explicit">
      <p>No assessor has been hired or test performed by this console. A signature proves origin and integrity, not independence, accreditation or certification. Certified infrastructure does not certify this product.</p>
      <p>Owner-reviewed exercises are retained assertions, not an SLA. A feature demonstration is not whole-bank coverage or commercial acceptance. Source/build/deployment associations require explicit evidence; they are not reproducible-build or runtime proof.</p>
      <p><Link to="/operator-decisions">Condition-level remediation</Link> · <Link to="/crypto-assurance">Registered coverage</Link> · <a href="/api/docs" target="_blank" rel="noreferrer">API schemas</a></p>
    </Panel>
    {error && <p ref={errorFocus} tabIndex={-1} role="alert">{error}</p>}
    <Panel title="Nine operating duties — selected estate">
      <button disabled={busy} onClick={() => { setError(""); setResult(null); reloadOperations(); }}>Refresh operating records</button>
      {operationsLoading ? <p role="status">{t("launch.loading")}</p> : operationsError ? <><p role="alert">{operationsError}</p><p>{t("launch.unavailable")}</p></> : <>
        {duties?.length === 0 && <p role="status">{t("launch.empty")}</p>}
        {partial && <p role="status">{t("launch.partial")}</p>}
        {operations === null ? <p>{t("launch.unavailable")}</p> : show(operations)}
      </>}
    </Panel>
    <Panel title="Read current scoped gates">
      <label>Exact engagement / pilot / finding / assignment ID<input aria-label="Exact record ID" dir="ltr" aria-describedby="launch-id-help" maxLength={36} style={style} value={identifier} onChange={e => setIdentifier(e.target.value)} /></label>
      <button disabled={busy || missingId} aria-describedby="launch-id-help" onClick={() => void request(`engagements/${encodeURIComponent(identifier)}/status`)}>Read independent security status</button>
      <button disabled={busy || missingId} aria-describedby="launch-id-help" onClick={() => void request(`pilots/${encodeURIComponent(identifier)}/status`)}>Read bounded pilot status</button>
      <p>Browse retained records for exact IDs and expected revisions. Reads recompute blockers; previous acceptance does not suppress stale evidence.</p>
      <label>Record kind<select aria-label="Record kind" value={recordKind} onChange={e => { setRecordKind(e.target.value); setRecordOffset(0); setResult(null); }}>{["security_engagement", "security_report", "security_finding", "operating_assignment", "operating_exercise", "customer_pilot"].map(kind => <option key={kind}>{kind}</option>)}</select></label>
      <label>Record offset<input aria-label="Record offset" type="number" min={0} max={1000000} value={recordOffset} onChange={e => setRecordOffset(Math.max(0, Math.min(1000000, Number(e.target.value) || 0)))} /></label>
      <button disabled={busy} onClick={() => void request(`records?kind=${recordKind}&limit=50&offset=${recordOffset}`, "GET", undefined, "/api/v1/assurance/")}>Read 50 retained revisions</button>
      <button disabled={busy || missingId} aria-describedby="launch-id-help" onClick={() => void request(`records/${recordKind}/${encodeURIComponent(identifier)}`, "GET", undefined, "/api/v1/assurance/")}>Read record history</button>
      <p>Lists contain all revisions, not only latest records. Use the returned has_more / next_offset to continue, and current status before acting. Record history returns at most 200 revisions.</p>
    </Panel>
    <Panel title="Structured, revision-checked actions">
      <p>{t("launch.meanings")}</p>
      <p id="launch-id-help">{missingId ? t("launch.idRequired") : t("launch.idScope")}</p>
      {busy && <p role="status">{t("launch.busy")}</p>}
      <p>Use the launch runbook templates and API schemas. No private keys belong in this form. Obtain assessor signatures externally; import only the public signed envelope. All writes require current durable human authority and exact-estate references.</p>
      <form onSubmit={submit}>
        <label>Action<select aria-label="Launch action" value={action} onChange={e => { setAction(e.target.value); setJson(""); setResult(null); }}>{Object.keys(actions).map(name => <option key={name}>{name}</option>)}</select></label>
        <label>Typed JSON body<textarea required aria-label="Typed JSON body" dir="ltr" rows={12} style={style} value={json} onChange={e => setJson(e.target.value)} placeholder="Paste a reviewed schema-valid object, including expected_revision where required" /></label>
        <button type="submit" aria-describedby="launch-id-help" disabled={busy || (needsId && missingId)}>{busy ? "Submitting…" : "Submit bounded action"}</button>
      </form>
      {result !== null && <details open><summary>{t(resultKind)}</summary>{show(result)}</details>}
    </Panel>
  </div>;
}
