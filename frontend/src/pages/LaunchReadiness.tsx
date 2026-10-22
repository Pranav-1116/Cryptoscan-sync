import React, { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { PageHead, Panel } from "../components/ui.jsx";
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
const style = { width: "100%", padding: 8, color: "inherit", background: "var(--surface-2, #171f2c)", border: "1px solid #526074", borderRadius: 4 };
const prefix = "/api/v1/assurance/launch/";

export default function LaunchReadiness() {
  const [operations, setOperations] = useState<unknown>(null);
  const [result, setResult] = useState<unknown>(null);
  const [error, setError] = useState("");
  const [action, setAction] = useState(Object.keys(actions)[0]);
  const [identifier, setIdentifier] = useState("");
  const [json, setJson] = useState("");
  const [busy, setBusy] = useState(false);
  const [epoch, setEpoch] = useState(0);
  const [recordKind, setRecordKind] = useState("security_engagement");
  const [recordOffset, setRecordOffset] = useState(0);
  const generation = useRef(0);
  const controller = useRef<AbortController | null>(null);

  useEffect(() => {
    const reset = () => {
      generation.current++; controller.current?.abort();
      setResult(null); setOperations(null); setError(""); setIdentifier(""); setJson(""); setRecordOffset(0); setBusy(false); setEpoch(x => x + 1);
    };
    window.addEventListener("zelinx:tenant", reset);
    window.addEventListener("zelinx:auth", reset);
    return () => { generation.current++; controller.current?.abort(); window.removeEventListener("zelinx:tenant", reset); window.removeEventListener("zelinx:auth", reset); };
  }, []);

  useEffect(() => {
    const abort = new AbortController();
    const current = generation.current;
    const estate = activeTenantId();
    let live = true;
    setOperations(null);
    tenantFetch(prefix + "operations", { signal: abort.signal }).then(async response => {
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const body: unknown = await response.json();
      if (live && current === generation.current && estate === activeTenantId()) setOperations(body);
    }).catch(err => { if (live && !abort.signal.aborted && current === generation.current) setError(String(err)); });
    return () => { live = false; abort.abort(); };
  }, [epoch]);

  async function request(path: string, method = "GET", payload?: unknown, base = prefix) {
    if (busy) return;
    controller.current?.abort();
    const abort = new AbortController(); controller.current = abort;
    const current = ++generation.current; const estate = activeTenantId();
    setBusy(true); setError(""); setResult(null);
    try {
      const response = await tenantFetch(base + path, { method, signal: abort.signal,
        ...(payload === undefined ? {} : { headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) }) });
      const body: unknown = await response.json();
      if (current !== generation.current || estate !== activeTenantId()) return;
      if (!response.ok) throw new Error(`HTTP ${response.status}: ${JSON.stringify(body)}`);
      setResult(body); setEpoch(x => x + 1);
    } catch (err) { if (!abort.signal.aborted && current === generation.current) setError(String(err)); }
    finally { if (current === generation.current) setBusy(false); }
  }
  function submit(event: React.FormEvent) {
    event.preventDefault();
    try {
      if (json.length > 1200000) throw new Error("Request exceeds console size limit");
      const body: unknown = JSON.parse(json);
      if (!body || Array.isArray(body) || typeof body !== "object") throw new Error("Provide a JSON object matching the documented schema");
      const [method, path] = actions[action];
      if (path.includes(":id") && !identifier) throw new Error("An exact record ID is required");
      void request(path.replace(":id", encodeURIComponent(identifier)), method, body);
    } catch (err) { setError(String(err)); }
  }
  const show = (value: unknown) => <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", maxHeight: 560, overflow: "auto" }}>{JSON.stringify(value, null, 2)}</pre>;
  return <div>
    <PageHead crumb="Overview / Launch readiness" title="Launch readiness" sub="Preview · independent security evidence, accountable operations and one bounded customer workflow" />
    <Panel title="External acceptance stays explicit">
      <p>No assessor has been hired or test performed by this console. A signature proves origin and integrity, not independence, accreditation or certification. Certified infrastructure does not certify this product.</p>
      <p>Owner-reviewed exercises are retained assertions, not an SLA. A feature demonstration is not whole-bank coverage or commercial acceptance. Source/build/deployment associations require explicit evidence; they are not reproducible-build or runtime proof.</p>
      <p><Link to="/operator-decisions">Condition-level remediation</Link> · <Link to="/crypto-assurance">Registered coverage</Link> · <a href="/api/docs" target="_blank" rel="noreferrer">API schemas</a></p>
    </Panel>
    {error && <p role="alert">{error}</p>}
    <Panel title="Nine operating duties — selected estate">
      <button disabled={busy} onClick={() => { setError(""); setEpoch(x => x + 1); }}>Refresh operating records</button>
      {operations === null ? <p>No current operating read available.</p> : show(operations)}
    </Panel>
    <Panel title="Read current scoped gates">
      <label>Exact engagement / pilot / finding / assignment ID<input aria-label="Exact record ID" maxLength={36} style={style} value={identifier} onChange={e => setIdentifier(e.target.value)} /></label>
      <button disabled={busy || !identifier} onClick={() => void request(`engagements/${encodeURIComponent(identifier)}/status`)}>Read independent security status</button>
      <button disabled={busy || !identifier} onClick={() => void request(`pilots/${encodeURIComponent(identifier)}/status`)}>Read bounded pilot status</button>
      <p>Browse retained records for exact IDs and expected revisions. Reads recompute blockers; previous acceptance does not suppress stale evidence.</p>
      <label>Record kind<select aria-label="Record kind" value={recordKind} onChange={e => { setRecordKind(e.target.value); setRecordOffset(0); setResult(null); }}>{["security_engagement", "security_report", "security_finding", "operating_assignment", "operating_exercise", "customer_pilot"].map(kind => <option key={kind}>{kind}</option>)}</select></label>
      <label>Record offset<input aria-label="Record offset" type="number" min={0} max={1000000} value={recordOffset} onChange={e => setRecordOffset(Math.max(0, Math.min(1000000, Number(e.target.value) || 0)))} /></label>
      <button disabled={busy} onClick={() => void request(`records?kind=${recordKind}&limit=50&offset=${recordOffset}`, "GET", undefined, "/api/v1/assurance/")}>Read 50 retained revisions</button>
      <button disabled={busy || !identifier} onClick={() => void request(`records/${recordKind}/${encodeURIComponent(identifier)}`, "GET", undefined, "/api/v1/assurance/")}>Read record history</button>
      <p>Lists contain all revisions, not only latest records. Use the returned has_more / next_offset to continue, and current status before acting. Record history returns at most 200 revisions.</p>
    </Panel>
    <Panel title="Structured, revision-checked actions">
      <p>Use the launch runbook templates and API schemas. No private keys belong in this form. Obtain assessor signatures externally; import only the public signed envelope. All writes require current durable human authority and exact-estate references.</p>
      <form onSubmit={submit}>
        <label>Action<select aria-label="Launch action" value={action} onChange={e => { setAction(e.target.value); setJson(""); setResult(null); }}>{Object.keys(actions).map(name => <option key={name}>{name}</option>)}</select></label>
        <label>Typed JSON body<textarea required aria-label="Typed JSON body" rows={12} style={style} value={json} onChange={e => setJson(e.target.value)} placeholder="Paste a reviewed schema-valid object, including expected_revision where required" /></label>
        <button type="submit" disabled={busy}>{busy ? "Submitting…" : "Submit bounded action"}</button>
      </form>
      {result !== null && <details open><summary>Immutable action receipt / current gate result</summary>{show(result)}</details>}
    </Panel>
  </div>;
}
