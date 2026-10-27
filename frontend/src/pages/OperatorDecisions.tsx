import PrivateScope, { usePrivateScopeCurrent } from "../components/PrivateScope";
import React, { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { PageHead, Panel } from "../components/ui.jsx";
import { activeTenantId, tenantFetch } from "../lib/api.js";
import { useRealtime } from "../lib/realtime";

interface Section { items: Record<string, unknown>[]; has_more: boolean; next_offset: number | null }
interface Inbox { estate_id: string | null; as_of: string; sections: Record<string, Section>; uncertainty: string }
const names: Record<string, string> = { tasks: "Findings & accountable owners", jobs: "Failed, unsettled & waiting jobs", coverage: "Coverage & freshness — independent registered denominators", approvals: "Approvals & stale authority", executions: "Execution outcomes & recovery", changes: "Approved conditions & reported work", proofs: "Independent before / after proofs" };
const inputStyle = { width: "100%", padding: 8, background: "var(--surface-2, #171f2c)", color: "inherit", border: "1px solid #526074", borderRadius: 4 };

export default function OperatorDecisions() {
  return <PrivateScope><OperatorDecisionsPage /></PrivateScope>;
}

function OperatorDecisionsPage() {
  const scopeCurrent = usePrivateScopeCurrent();
  const stream = useRealtime();
  const [data, setData] = useState<Inbox | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [tab, setTab] = useState("tasks");
  const [offset, setOffset] = useState(0);
  const [epoch, setEpoch] = useState(0);
  const generation = useRef(0);
  const [action, setAction] = useState("propose");
  const [identifier, setIdentifier] = useState("");
  const [revision, setRevision] = useState("1");
  const [kind, setKind] = useState("SOURCE_SITE");
  const [fields, setFields] = useState<Record<string, string>>({});
  const [mutation, setMutation] = useState("");
  const [mutating, setMutating] = useState(false);
  const [proof, setProof] = useState<unknown>(null);
  const lastReplay = useRef(stream.replayIssue);
  const [replayAcknowledged, setReplayAcknowledged] = useState(false);
  const [loadingProof, setLoadingProof] = useState(false);
  const detailAbort = useRef<AbortController | null>(null);
  const mutationAbort = useRef<AbortController | null>(null);
  const mutationLock = useRef(false);
  const field = (name: string, label: string, type = "text") => <label key={name} style={{ display: "block", margin: "8px 0" }}>{label}<input required type={type} aria-label={label} style={inputStyle} value={fields[name] || (name === "freshness" ? "3600" : "")} onChange={e => setFields(f => ({ ...f, [name]: e.target.value }))} /></label>;

  // One in-flight poll. No localStorage cache, no polling while hidden. Every
  // interval reconciles the full SQL read model, independent of SSE delivery.
  useEffect(() => {
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let controller: AbortController | null = null;
    const mine = ++generation.current;
    setData(null); setError("");
    const poll = async () => {
      if (stopped || document.hidden || controller) return;
      const next = new AbortController(); controller = next;
      const timeout = setTimeout(() => next.abort(), 15000);
      setBusy(true);
      try {
        const response = await tenantFetch(`/api/v1/assurance/operator-decisions?offset=${offset}&limit=25`, { signal: next.signal });
        if (!response.ok) throw new Error(`Decision read failed (${response.status}); no cached success substituted.`);
        const body = await response.json() as Inbox;
        if (!stopped && scopeCurrent() && mine === generation.current) { setData(body); setError(""); }
      } catch (e) {
        if (!stopped && scopeCurrent() && mine === generation.current) { setError(e instanceof Error ? e.message : "Decision read unavailable"); setData(null); }
      } finally {
        clearTimeout(timeout); controller = null;
        if (!stopped) { setBusy(false); timer = setTimeout(poll, 30000); }
      }
    };
    const visible = () => { if (!document.hidden) { clearTimeout(timer); void poll(); } };
    const reset = () => {
      ++generation.current; controller?.abort(); detailAbort.current?.abort(); mutationAbort.current?.abort();
      setData(null); setProof(null); setMutation(""); setFields({}); setIdentifier(""); setOffset(0); setEpoch(e => e + 1);
    };
    window.addEventListener("zelinx:tenant", reset); window.addEventListener("zelinx:auth", reset);
    document.addEventListener("visibilitychange", visible);
    void poll();
    return () => { stopped = true; clearTimeout(timer); controller?.abort(); window.removeEventListener("zelinx:tenant", reset); window.removeEventListener("zelinx:auth", reset); document.removeEventListener("visibilitychange", visible); };
  }, [offset, epoch]);
  useEffect(() => {
    if (lastReplay.current === stream.replayIssue) return;
    lastReplay.current = stream.replayIssue;
    setReplayAcknowledged(false); setData(null); setEpoch(e => e + 1);
  }, [stream.replayIssue]);
  useEffect(() => () => { generation.current++; detailAbort.current?.abort(); mutationAbort.current?.abort(); }, []);

  async function showEvidence(section: string, id: string) {
    if (!scopeCurrent()) return;
    detailAbort.current?.abort(); const controller = new AbortController(); detailAbort.current = controller;
    const mine = generation.current; setLoadingProof(true); setProof(null);
    try {
      const path = section === "coverage" ? `/api/v1/assurance/registers/${encodeURIComponent(id)}/coverage` : `/api/v1/assurance/records/${section === "proofs" ? "condition_proof" : "remediation_change"}/${encodeURIComponent(id)}`;
      const response = await tenantFetch(path, { signal: controller.signal });
      if (!response.ok) throw new Error(`Evidence read failed (${response.status})`);
      const body = await response.json();
      if (scopeCurrent() && mine === generation.current && !controller.signal.aborted) setProof(body);
    } catch (e) { if (!controller.signal.aborted && mine === generation.current) setMutation(String(e)); }
    finally { if (detailAbort.current === controller) setLoadingProof(false); }
  }
  async function submit(e: React.FormEvent) {
    e.preventDefault(); if (!scopeCurrent() || mutationLock.current) return;
    mutationLock.current = true;
    setMutating(true); setMutation("");
    const controller = new AbortController(); mutationAbort.current = controller;
    const timeout = setTimeout(() => controller.abort(), 20000);
    try {
      let body: Record<string, unknown>; let suffix = "";
      if (action === "create-task") {
        body = { evidence_id: fields.evidenceId, owner_ref: fields.owner, notes: fields.notes || null };
      } else if (action === "propose") {
        body = { kind, freshness_seconds: Number(fields.freshness || "3600"), owner_ref: fields.owner, change_ref: fields.change, verification_criteria: fields.criteria, expires_at: new Date(fields.expires).toISOString(),
          ...(kind === "SOURCE_SITE" ? { task_id: fields.task, expected_algorithm: fields.algorithm } : { before_run_id: fields.before, endpoint: fields.endpoint, expected_fingerprint_sha256: fields.fingerprint }) };
      } else {
        suffix = `/${encodeURIComponent(identifier)}/${action}`;
        body = { expected_revision: Number(revision), ...((action === "approve" || action === "revoke") ? { evidence_ref: fields.evidence, reason: fields.reason } : action === "report-complete" ? { evidence_ref: fields.evidence, completed_at: new Date(fields.completed).toISOString() } : { rescan_id: fields.rescan, expected_proof_revision: Number(fields.proofRevision || "0") }) };
      }
      const response = await tenantFetch(action === "create-task" ? "/api/v1/assurance/remediation-tasks" : `/api/v1/assurance/remediation-changes${suffix}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body), signal: controller.signal });
      const result = await response.json();
      if (!scopeCurrent() || mutationAbort.current !== controller || controller.signal.aborted) return;
      if (!response.ok) throw new Error(JSON.stringify(result.detail || result));
      setMutation(`Retained ${result.kind || "task"} ${result.subject_id || result.id}, revision ${result.revision || "initial"}. ${result.payload?.result || result.payload?.state || ""}`);
      setProof(result); setEpoch(n => n + 1);
    } catch (e) { if (scopeCurrent() && mutationAbort.current === controller) setMutation(`Action outcome not assumed successful: ${String(e)}. Refresh history before retrying an interrupted request.`); }
    finally { clearTimeout(timeout); if (scopeCurrent() && mutationAbort.current === controller) { mutationLock.current = false; setMutating(false); } }
  }
  const page = data?.sections[tab];
  return <div>
    <PageHead crumb="Operations / decisions" title="Operator decisions" sub="Attention → evidence → coverage → accountable owner → independently observed fix. No substitute risk score." />
    <p><Link to="/remediation">Task lifecycle</Link> · Selected estate: {activeTenantId() || "platform / explicitly scoped NULL"}</p>
    {stream.replayIssue && !replayAcknowledged && <div role="alert" style={{ border: "1px solid #d39934", padding: 16 }}>Replay reset / gap: {stream.replayIssue}. Events are not a complete history. {data ? <button onClick={() => setReplayAcknowledged(true)}>Acknowledge fresh SQL reconciliation</button> : "Waiting for a fresh SQL read."}</div>}
    {error && <p role="alert">{error}</p>}
    <p role="status">{busy ? "Reconciling…" : data ? `SQL observation: ${data.as_of}. Reconciled every 30s while visible; freshness is not collection completeness.` : "No current decision data available."} <button onClick={() => { setProof(null); setEpoch(n => n + 1); }}>Reconcile now</button></p>
    <p>{data?.uncertainty || "Coverage is UNKNOWN until an independently registered estate and collection receipts are available."} Every section is paginated; a page is never the whole estate.</p>
    <aside aria-label="Coverage and uncertainty" style={{ padding: 16, border: "1px solid #526074", margin: "16px 0" }}>
      <strong>Coverage is part of the decision, not a score.</strong>
      {data?.sections.coverage?.items.length ? data.sections.coverage.items.map((r, i) => <p key={i}>Register {String(r.register_id)}: {String(r.registered_targets)} expected targets · owner completeness {String(r.register_completeness)} · observed / stale / blocked / unattempted: {JSON.stringify(r.counts)}. Registered scope only, not whole-bank coverage.</p>) : <p>Coverage UNKNOWN: no current register in this page. Do not interpret an empty task list as low risk.</p>}
      <p>Coverage overview is paginated too. Select Coverage to inspect omissions, freshness and the next register page.</p>
    </aside>
    <nav aria-label="Decision sections" style={{ display: "flex", gap: 8, flexWrap: "wrap", margin: "16px 0" }}>{Object.entries(names).map(([key, label]) => <button key={key} aria-pressed={key === tab} onClick={() => { setTab(key); setOffset(0); }}>{label}</button>)}</nav>
    <Panel title={names[tab]}>
      {!page?.items.length ? <p>No rows in this page. This does not prove no risk, complete coverage, or successful jobs.</p> : page.items.map((item, i) => <article key={String(item.id || item.register_id || i)} style={{ padding: 16, borderBottom: "1px solid #526074" }}>
        <h3>{String(item.id || item.register_id)} · {String(item.status || item.state || item.result || item.register_completeness || "Review")}</h3>
        {item.needs_attention === true && <p><strong>Needs attention — stored status is not current independent resolution.</strong></p>}
        {item.current_condition_verified != null && <p>Current approved condition: {item.current_condition_verified ? "VERIFIED within observation window" : "NOT VERIFIED / stale or unavailable"}</p>}
        {item.priority != null && <p>Finding priority: {String(item.priority)}</p>}
        {(item.evidence_freshness != null || item.freshness_state != null || item.condition_expires_at != null) && <p>Freshness: {String(item.freshness_state || item.evidence_freshness || "Observation window recorded")} · condition expiry: {String(item.condition_expires_at || "not established")}</p>}
        {item.approval_current != null && <p>Approval: <strong>{item.approval_current ? "Within recorded authority window" : "STALE / superseded / changed authority"}</strong></p>}
        {item.owner != null && <p>Accountable owner: <strong>{String(item.owner)}</strong></p>}
        {item.next_action != null && <p>Next decision: {String(item.next_action)}</p>}
        {item.criteria != null && <p>Verification criteria: {String(item.criteria)}</p>}
        {item.reason != null && <p>{String(item.reason)}</p>}
        <details><summary>Supporting evidence, freshness and scope</summary><pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", maxHeight: 360, overflow: "auto" }}>{JSON.stringify(item, null, 2)}</pre></details>
        {(tab === "proofs" || tab === "changes") && <button onClick={() => void showEvidence(tab, String(item.id))}>Read retained {tab === "proofs" ? "before / after proof" : "approval & change history"}</button>}
        {tab === "coverage" && <p>Registered: {String(item.registered_targets)} · Owner completeness: {String(item.register_completeness)} · <button onClick={() => void showEvidence("coverage", String(item.register_id))}>Read full registered coverage in selected estate</button></p>}
      </article>)}
      <p>Offset {offset}. <button disabled={offset === 0} onClick={() => setOffset(0)}>First page</button> <button disabled={!page?.has_more} onClick={() => setOffset(page?.next_offset || 0)}>Next page</button></p>
    </Panel>
    <Panel title="Condition-level remediation workflow">
      <p>Propose an explicit condition; a different authorized reviewer approves it. Reported completion is only a declaration. A subsequent independent collector must observe the exact condition. Missing evidence stays INCONCLUSIVE. Expired / changed authority requires a new proposal.</p>
      <form onSubmit={submit} style={{ maxWidth: 760 }}>
        <label>Step <select aria-label="Workflow step" value={action} onChange={e => { setAction(e.target.value); setFields({}); }}>{["create-task", "propose", "approve", "report-complete", "verify", "revoke"].map(x => <option key={x}>{x}</option>)}</select></label>
        {action === "create-task" ? <>{field("evidenceId", "Original finding evidence ID")}{field("owner", "Accountable owner reference")}{field("notes", "Task context")}</> : action === "propose" ? <>
          <label>Condition <select aria-label="Condition kind" value={kind} onChange={e => setKind(e.target.value)}><option>SOURCE_SITE</option><option>TLS_CERTIFICATE</option></select></label>
          {field("owner", "Accountable owner reference")}{field("change", "Approved change / ticket reference")}{field("criteria", "Human verification criteria (machine predicate remains explicit)")}{field("expires", "Approval expiry", "datetime-local")}{field("freshness", "Maximum observation age in seconds (60–604800)", "number")}
          {kind === "SOURCE_SITE" ? <>{field("task", "Assigned task ID")}{field("algorithm", "Expected replacement algorithm at original file / line / purpose")}</> : <>{field("before", "Before TLS run ID")}{field("endpoint", "Exact observed endpoint, including port")}{field("fingerprint", "Expected replacement certificate SHA256 (64 lowercase hex)")}</>}
        </> : <>
          <label>Change ID<input required aria-label="Change ID" style={inputStyle} value={identifier} onChange={e => setIdentifier(e.target.value)} /></label>
          <label>Expected revision<input required type="number" min="1" aria-label="Expected revision" style={inputStyle} value={revision} onChange={e => setRevision(e.target.value)} /></label>
          {(action === "approve" || action === "revoke") && <>{field("evidence", "Approval evidence reference")}{field("reason", "Reviewer rationale")}</>}
          {action === "report-complete" && <>{field("evidence", "Reported action evidence reference")}{field("completed", "Actual change completion time", "datetime-local")}</>}
          {action === "verify" && <>{field("rescan", "Independent source scan ID or TLS run ID (started after change)")}{field("proofRevision", "Expected prior proof revision (0 for first verification)", "number")}</>}
        </>}
        <button disabled={mutating} type="submit">{mutating ? "Submitting…" : "Submit bounded workflow action"}</button>
      </form>
      {mutation && <p role="status">{mutation}</p>}
      {loadingProof && <p>Loading retained evidence…</p>}
      {proof != null && <details open><summary>Immutable evidence / action receipt</summary><pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", maxHeight: 600, overflow: "auto" }}>{JSON.stringify(proof, null, 2)}</pre></details>}
    </Panel>
  </div>;
}
