import PrivateScope, { usePrivateScopeCurrent } from "../components/PrivateScope";
import React, { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { PageHead, Panel } from "../components/ui.jsx";
import { GapBar, StackedBar, StateCell, VizEmpty, toneColor } from "../components/viz.jsx";
import { activeTenantId, tenantFetch } from "../lib/api.js";
import { useRealtime } from "../lib/realtime";

/* Operator decisions — the inbox drawn as what it is: a page of a register,
 * with per-section counts, per-item state rails and the retention gaps named.
 *
 * Nothing here scores risk. A duration bar is scaled against the largest value
 * in the same page; a field the read did not return is not drawn as zero; the
 * raw record stays available under each item because a decision may need it,
 * but it is never the interface.
 */

interface Section { items: Record<string, unknown>[]; has_more: boolean; next_offset: number | null }
interface Inbox { estate_id: string | null; as_of: string; sections: Record<string, Section>; uncertainty: string }
const names: Record<string, string> = { tasks: "Findings & accountable owners", jobs: "Failed, unsettled & waiting jobs", coverage: "Coverage & freshness — independent registered denominators", approvals: "Approvals & stale authority", executions: "Execution outcomes & recovery", changes: "Approved conditions & reported work", proofs: "Independent before / after proofs" };
const inputStyle = { width: "100%", padding: 8, background: "var(--surface-2, #171f2c)", color: "inherit", border: "1px solid #526074", borderRadius: 4 };
const COVERAGE_ORDER = ["OBSERVED", "STALE", "BLOCKED", "UNSUPPORTED", "NOT_ATTEMPTED"];
const COVERAGE_TONE: Record<string, string> = { OBSERVED: "green", STALE: "amber", BLOCKED: "red", UNSUPPORTED: "slate", NOT_ATTEMPTED: "violet" };

/** One labelled fact. `ratio` draws a bar scaled to its own group's maximum. */
function Fact({ label, children, tone = "", ratio, note }: { label: string; children: React.ReactNode; tone?: string; ratio?: number | null; note?: string }) {
  return (
    <div style={{ minWidth: 0 }}>
      <div className="mono" style={{ fontSize: 9.5, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--faint)" }}>{label}</div>
      <div style={{ fontSize: 12, color: tone ? toneColor(tone) : "var(--text)", fontWeight: tone ? 600 : 400, lineHeight: 1.4, overflowWrap: "anywhere" }}>{children}</div>
      {typeof ratio === "number" && Number.isFinite(ratio) && (
        <span style={{ display: "block", height: 4, marginTop: 3, background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: 1 }}>
          <span style={{ display: "block", width: `${Math.max(0, Math.min(1, ratio)) * 100}%`, height: "100%", background: toneColor(tone) }} />
        </span>
      )}
      {note && <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 2 }}>{note}</div>}
    </div>
  );
}

function sectionsOf(data: Inbox | null): Array<[string, Section | undefined]> {
  return Object.keys(names).map((key) => [key, data?.sections?.[key]]);
}

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
  const rail = sectionsOf(data);
  const returned = rail.filter(([, s]) => s) as Array<[string, Section]>;
  const maxCount = Math.max(0, ...returned.map(([, s]) => s.items?.length ?? 0));
  const coverage = data?.sections?.coverage?.items ?? [];
  // Duration bars are scaled against the largest duration in this page only.
  const maxSeconds = Math.max(
    0,
    ...(page?.items ?? []).flatMap((item) => [Number(item.queue_wait_seconds), Number(item.execution_seconds)]).filter((n) => Number.isFinite(n)),
  );
  const dur = (value: unknown) => {
    const n = Number(value);
    return Number.isFinite(n) ? { text: `${n.toFixed(n >= 10 ? 0 : 1)}s`, ratio: maxSeconds > 0 ? n / maxSeconds : null } : null;
  };
  return <div>
    <PageHead crumb="Operations / decisions" title="Operator decisions" sub="Attention → evidence → coverage → accountable owner → independently observed fix. No substitute risk score." />
    <p><Link to="/remediation">Task lifecycle</Link> · Selected estate: {activeTenantId() || "platform / explicitly scoped NULL"}</p>
    {stream.replayIssue && !replayAcknowledged && <div role="alert" style={{ border: "1px solid #d39934", padding: 16 }}>Replay reset / gap: {stream.replayIssue}. Events are not a complete history. {data ? <button onClick={() => setReplayAcknowledged(true)}>Acknowledge fresh SQL reconciliation</button> : "Waiting for a fresh SQL read."}</div>}
    {error && <p role="alert">{error}</p>}
    <p role="status" style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>{busy ? "Reconciling…" : data ? `SQL observation: ${data.as_of}. Reconciled every 30s while visible; freshness is not collection completeness.` : "No current decision data available."} <button onClick={() => { setProof(null); setEpoch(n => n + 1); }}>Reconcile now</button></p>

    {/* State board — what this read actually covers. */}
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 8, margin: "10px 0" }}>
      <StateCell label="read model" value={data ? "SQL" : "—"} note={data ? "full reconciliation per interval" : "no current read"} tone={data ? "green" : ""} />
      <StateCell label="estate" value={data?.estate_id ?? "NULL"} note="explicitly scoped, never inherited" />
      <StateCell label="observed at" value={data ? new Date(data.as_of).toLocaleTimeString() : "—"} note={data ? data.as_of : "not observed"} />
      <StateCell label="sections with rows" value={`${returned.filter(([, s]) => (s.items?.length ?? 0) > 0).length} / ${Object.keys(names).length}`} note="this page only" />
      <StateCell label="page scope" value="ONE PAGE" tone="amber" note="never the whole estate" />
    </div>
    <div style={{ marginBottom: 12 }}>
      <GapBar label="whole-estate completeness" reason="This read returns one page of each section; a page is not a denominator, and an empty section is not coverage." />
    </div>

    {/* Section rail — count per section, bar relative to the fullest section here. */}
    <Panel title="Register sections in this read">
      {!returned.length ? <VizEmpty title="No sections returned" note="A failed or empty read draws nothing; it is not a zero." />
        : <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 8 }}>
          {rail.map(([key, section]) => {
            const count = section?.items?.length ?? 0;
            return <div key={key} style={{ border: "1px solid var(--line)", borderTop: `2px solid ${count ? toneColor("") : "var(--line-strong)"}`, borderRadius: "var(--r)", background: "var(--panel-2)", padding: "7px 9px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <span className="mono" style={{ fontSize: 10.5, letterSpacing: "0.05em", textTransform: "uppercase", color: "var(--dim)" }}>{key}</span>
                <span className="mono" style={{ marginLeft: "auto", fontSize: 12, fontVariantNumeric: "tabular-nums", color: count ? "var(--text)" : "var(--faint)" }}>{section ? count : "—"}</span>
              </div>
              <span style={{ display: "block", height: 5, marginTop: 5, background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: 1 }}>
                <span style={{ display: "block", width: `${maxCount > 0 ? (count / maxCount) * 100 : 0}%`, height: "100%", background: count ? toneColor("") : "transparent" }} />
              </span>
              <span className="mono" style={{ fontSize: 9.5, color: "var(--faint)" }}>{!section ? "not in payload" : section.has_more ? `next page at ${section.next_offset ?? "?"}` : "page complete"}</span>
            </div>;
          })}
        </div>}
    </Panel>

    {/* Coverage is a composition of a registered denominator, not a score. */}
    <aside aria-label="Coverage and uncertainty" style={{ margin: "12px 0" }}>
      <Panel title="Registered coverage — denominators, not a score">
        <p style={{ margin: "0 0 8px", fontSize: 11.5, color: "var(--dim)" }}>{data?.uncertainty || "Coverage is UNKNOWN until an independently registered estate and collection receipts are available."} Every section is paginated; a page is never the whole estate.</p>
        {coverage.length ? coverage.map((r, i) => {
          const counts = (r.counts ?? {}) as Record<string, number>;
          const registered = Number(r.registered_targets ?? 0);
          const keys = [...COVERAGE_ORDER.filter((k) => k in counts), ...Object.keys(counts).filter((k) => !COVERAGE_ORDER.includes(k))];
          return <div key={String(r.register_id ?? i)} style={{ borderTop: i ? "1px solid var(--line)" : undefined, padding: "8px 0" }}>
            <div style={{ display: "flex", alignItems: "baseline", gap: 8, flexWrap: "wrap" }}>
              <span className="mono" style={{ fontSize: 11.5 }}>{String(r.register_id ?? "unidentified register")}</span>
              <span className="mono" style={{ fontSize: 10.5, color: "var(--faint)", fontVariantNumeric: "tabular-nums" }}>registered {registered} target(s) · owner completeness {String(r.register_completeness ?? "not reported")}</span>
            </div>
            <div style={{ marginTop: 5 }}>
              <StackedBar segments={keys.map((k) => ({ key: k, label: k.replace(/_/g, " ").toLowerCase(), value: Number(counts[k] ?? 0), tone: COVERAGE_TONE[k] ?? "" }))}
                note="Composition of targets this register attempted — registered scope only, not whole-bank coverage." />
            </div>
          </div>;
        }) : <p style={{ margin: 0, fontSize: 11.5, color: "var(--dim)" }}>Coverage UNKNOWN: no current register in this page. Do not interpret an empty task list as low risk.</p>}
        <p className="mono" style={{ margin: "8px 0 0", fontSize: 10.5, color: "var(--faint)" }}>Coverage overview is paginated too. Select Coverage to inspect omissions, freshness and the next register page.</p>
      </Panel>
    </aside>

    <nav aria-label="Decision sections" style={{ display: "flex", gap: 8, flexWrap: "wrap", margin: "16px 0" }}>{Object.entries(names).map(([key, label]) => <button key={key} aria-pressed={key === tab} onClick={() => { setTab(key); setOffset(0); }}>{label}</button>)}</nav>
    <Panel title={names[tab]}>
      {!page?.items.length ? <p>No rows in this page. This does not prove no risk, complete coverage, or successful jobs.</p> : page.items.map((item, i) => {
        const attention = item.needs_attention === true;
        const state = String(item.status || item.state || item.result || item.register_completeness || "Review");
        const stateTone = attention ? "red" : /FAIL|ERROR|STALE|EXPIRED|BLOCKED|EXCEEDED/.test(state.toUpperCase()) ? "red" : /COMPLET/.test(state.toUpperCase()) ? "amber" : "";
        const queue = dur(item.queue_wait_seconds);
        const exec = dur(item.execution_seconds);
        const proofFresh = item.freshness_state != null || item.evidence_freshness != null;
        return <article key={String(item.id || item.register_id || i)} style={{ padding: "12px 14px", borderBottom: "1px solid var(--line)", borderLeft: `2px solid ${attention ? toneColor("red") : "transparent"}` }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginBottom: 8 }}>
            <span aria-hidden style={{ width: 7, height: 7, borderRadius: 999, background: toneColor(stateTone) }} />
            <span className="mono" style={{ fontSize: 12, fontWeight: 600, overflowWrap: "anywhere" }}>{String(item.id || item.register_id)}</span>
            <span className="mono" style={{ fontSize: 10.5, letterSpacing: "0.05em", textTransform: "uppercase", color: toneColor(stateTone), border: `1px solid ${toneColor(stateTone)}`, borderRadius: 2, padding: "0 4px" }}>{state}</span>
            {item.reported_complete === true && <span className="mono" style={{ fontSize: 9.5, textTransform: "uppercase", letterSpacing: "0.05em", color: "var(--amber)" }}>declared complete — not observed</span>}
            {item.deadline_exceeded === true && <span className="mono" style={{ fontSize: 9.5, textTransform: "uppercase", letterSpacing: "0.05em", color: "var(--red)" }}>deadline exceeded</span>}
            {item.current_condition_verified === false && <span className="mono" style={{ fontSize: 9.5, textTransform: "uppercase", letterSpacing: "0.05em", color: "var(--amber)" }}>condition not verified</span>}
          </div>
          {attention && <p style={{ margin: "0 0 8px", fontSize: 11.5, color: "var(--red)" }}>Needs attention — stored status is not current independent resolution.</p>}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))", gap: "10px 14px" }}>
            {item.owner != null && <Fact label="Accountable owner">{String(item.owner)}</Fact>}
            {item.priority != null && <Fact label="Finding priority">{String(item.priority)}</Fact>}
            {item.current_condition_verified != null && <Fact label="Current approved condition" tone={item.current_condition_verified ? "green" : "amber"}>{item.current_condition_verified ? "VERIFIED within observation window" : "NOT VERIFIED / stale or unavailable"}</Fact>}
            {proofFresh && <Fact label="Freshness" tone={/STALE|UNAVAILABLE/.test(String(item.freshness_state || item.evidence_freshness).toUpperCase()) ? "amber" : ""}>{String(item.freshness_state || item.evidence_freshness)}</Fact>}
            {item.condition_expires_at != null && <Fact label="Condition expiry">{String(item.condition_expires_at)}</Fact>}
            {item.approval_current != null && <Fact label="Approval" tone={item.approval_current ? "green" : "red"}>{item.approval_current ? "Within recorded authority window" : "STALE / superseded / changed authority"}</Fact>}
            {Array.isArray(item.stale_reasons) && (item.stale_reasons as unknown[]).length > 0 && <Fact label="Stale reasons" tone="amber">{(item.stale_reasons as unknown[]).map(String).join(" · ")}</Fact>}
            {item.expires_at != null && <Fact label="Authority expires">{String(item.expires_at)}</Fact>}
            {queue && <Fact label="Queue wait" ratio={queue.ratio} note="scaled to the longest wait in this page">{queue.text}</Fact>}
            {exec && <Fact label="Execution" ratio={exec.ratio} note="scaled to the longest execution in this page">{exec.text}</Fact>}
            {item.stage != null && <Fact label="Stage">{String(item.stage)}</Fact>}
            {item.heartbeat_at != null && <Fact label="Last heartbeat">{String(item.heartbeat_at)}</Fact>}
            {item.deadline_at != null && <Fact label="Deadline" tone={item.deadline_exceeded === true ? "red" : ""}>{String(item.deadline_at)}</Fact>}
            {item.criteria != null && <Fact label="Verification criteria">{String(item.criteria)}</Fact>}
            {item.reason != null && <Fact label="Recorded reason">{String(item.reason)}</Fact>}
            {item.next_action != null && <Fact label="Decision required" tone="amber">{`Next decision: ${String(item.next_action)}`}</Fact>}
          </div>
          <details style={{ marginTop: 8 }}><summary className="mono" style={{ fontSize: 10.5, color: "var(--dim)", cursor: "pointer" }}>Supporting evidence, freshness and scope</summary><pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", maxHeight: 360, overflow: "auto", fontSize: 11.5 }}>{JSON.stringify(item, null, 2)}</pre></details>
          {(tab === "proofs" || tab === "changes") && <button onClick={() => void showEvidence(tab, String(item.id))}>Read retained {tab === "proofs" ? "before / after proof" : "approval & change history"}</button>}
          {tab === "coverage" && <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", marginTop: 6 }}><span className="mono" style={{ fontSize: 10.5, color: "var(--faint)" }}>Registered: {String(item.registered_targets)} · Owner completeness: {String(item.register_completeness)}</span><button onClick={() => void showEvidence("coverage", String(item.register_id))}>Read full registered coverage in selected estate</button></div>}
        </article>;
      })}
      <p style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>Offset {offset}. <button disabled={offset === 0} onClick={() => setOffset(0)}>First page</button> <button disabled={!page?.has_more} onClick={() => setOffset(page?.next_offset || 0)}>Next page</button></p>
    </Panel>

    <Panel title="Condition-level remediation workflow">
      <p style={{ margin: "0 0 8px", fontSize: 11.5, color: "var(--dim)" }}>Propose an explicit condition; a different authorized reviewer approves it. Reported completion is only a declaration. A subsequent independent collector must observe the exact condition. Missing evidence stays INCONCLUSIVE. Expired / changed authority requires a new proposal.</p>
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
      {proof != null && <details open><summary className="mono" style={{ fontSize: 10.5, color: "var(--dim)", cursor: "pointer" }}>Immutable evidence / action receipt</summary><pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", maxHeight: 600, overflow: "auto", fontSize: 11.5 }}>{JSON.stringify(proof, null, 2)}</pre></details>}
    </Panel>
  </div>;
}
