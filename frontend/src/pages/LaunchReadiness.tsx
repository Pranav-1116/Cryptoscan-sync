import PrivateScope, { usePrivateScopeCurrent } from "../components/PrivateScope";
import React, { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { PageHead, Panel } from "../components/ui.jsx";
import { GapBar, KpiMeter, StackedBar, StateCell, VizEmpty, toneColor } from "../components/viz.jsx";
import { useLive } from "../lib/useLive";
import { readFailure, writeFailure } from "../lib/requestFeedback";
import { useI18n } from "../i18n/I18n";
import { activeTenantId, tenantFetch } from "../lib/api.js";

/* Launch readiness — drawn, not narrated.
 *
 * Every figure on this screen is a field of the operations payload or of a
 * record read: duty state comes from `duties[].issues`, the SLA rail comes from
 * `sla_authorized` (which the server always returns false, with its reason), and
 * anything the payload does not carry is drawn hatched as "not measured" rather
 * than as a zero. The external-acceptance limits are stated as tiles because
 * they are limits, not decoration; the raw payload stays available as a record
 * underneath, not as the page.
 */

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

const ISSUE_LABEL: Record<string, string> = {
  UNASSIGNED: "no assignment",
  PROCEDURE_EVIDENCE_DIGEST_CHANGED: "procedure digest changed",
  EXERCISE_EVIDENCE_DIGEST_CHANGED: "exercise digest changed",
  PROCEDURE_OR_EXERCISE_EVIDENCE_UNAVAILABLE_OR_CORRUPT: "evidence unreadable",
  OWNER_OR_BACKUP_NO_LONGER_ACTIVE: "owner inactive",
  OWNER_ACKNOWLEDGEMENT_MISSING: "unacknowledged",
  PROCEDURE_REVIEW_OVERDUE: "review overdue",
  CURRENT_ASSIGNMENT_EXERCISE_MISSING: "exercise missing",
  EXERCISE_FAILED_UNREVIEWED_OR_STALE: "exercise stale / unreviewed",
};

type Duty = { duty: string; issues: string[]; assignment: unknown; exercise: unknown };

/** The scalars of a returned record, drawn; the document itself stays below. */
function ScalarBoard({ value }: { value: unknown }) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const rows = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v === null || ["string", "number", "boolean"].includes(typeof v))
    .slice(0, 8);
  if (!rows.length) return null;
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 8, margin: "8px 0" }}>
      {rows.map(([k, v]) => {
        const text = v === null ? "null" : typeof v === "boolean" ? (v ? "true" : "false") : String(v);
        const tone = typeof v === "boolean" ? (v ? "green" : "red") : v === null ? "amber" : "";
        return <StateCell key={k} label={k.replace(/_/g, " ")} value={text} tone={tone} note={v === null ? "returned as null — not a measured value" : undefined} />;
      })}
    </div>
  );
}

export default function LaunchReadiness() {
  return <PrivateScope><LaunchReadinessPage /></PrivateScope>;
}

/** One duty: a cell whose dot is its state and whose ticks are its coded gaps. */
function DutyCell({ record }: { record: Duty }) {
  const issues = Array.isArray(record.issues) ? record.issues : [];
  const clean = issues.length === 0;
  const tone = clean ? "var(--green)" : "var(--red)";
  return (
    <div style={{ border: "1px solid var(--line)", borderTop: `2px solid ${tone}`, borderRadius: "var(--r)", background: "var(--panel-2)", padding: "8px 10px", minWidth: 0 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <span aria-hidden style={{ width: 7, height: 7, borderRadius: 999, background: tone, flex: "0 0 auto" }} />
        <span className="mono" style={{ fontSize: 10.5, letterSpacing: "0.05em", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={record.duty}>
          {String(record.duty).replace(/_/g, " ")}
        </span>
        <span className="mono" style={{ marginLeft: "auto", fontSize: 10.5, color: clean ? "var(--green)" : "var(--red)", fontVariantNumeric: "tabular-nums" }}>
          {clean ? "CLEAN" : `${issues.length} gap${issues.length === 1 ? "" : "s"}`}
        </span>
      </div>
      {/* Two measured facts behind the state, drawn as ticks so "missing" is visible. */}
      <div style={{ display: "flex", gap: 4, marginTop: 6 }}>
        {[["assignment", record.assignment], ["exercise", record.exercise]].map(([label, value]) => {
          const present = Boolean(value);
          return (
            <span key={String(label)} className="mono" title={`${label}: ${present ? "recorded" : "not recorded"}`}
              style={{ flex: 1, fontSize: 9.5, letterSpacing: "0.04em", textTransform: "uppercase", textAlign: "center", padding: "2px 0", borderRadius: 2, border: `1px ${present ? "solid var(--line-strong)" : "dashed var(--line-strong)"}`, color: present ? "var(--dim)" : "var(--faint)", background: present ? "var(--bg-2)" : "transparent" }}>
              {String(label)} {present ? "·" : "–"}
            </span>
          );
        })}
      </div>
      {issues.length > 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: 2, marginTop: 6 }}>
          {issues.map((code, i) => (
            <span key={`${code}-${i}`} className="mono" title={code} style={{ fontSize: 9.5, color: "var(--red)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              ▸ {ISSUE_LABEL[code] ?? code}
            </span>
          ))}
        </div>
      )}
    </div>
  );
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
  const show = (value: unknown) => <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", maxHeight: 560, overflow: "auto", fontSize: 11.5 }}>{JSON.stringify(value, null, 2)}</pre>;
  const needsId = actions[action][1].includes(":id");
  const missingId = !identifier.trim();
  const duties = operations && typeof operations === "object" && "duties" in operations && Array.isArray((operations as { duties?: unknown }).duties)
    ? ((operations as { duties: Duty[] }).duties)
    : null;
  const payload = (operations ?? {}) as { all_owner_reviewed_records_current?: boolean; sla_authorized?: boolean; reason?: string };
  const partial = duties && duties.length > 0 && payload.all_owner_reviewed_records_current !== true;
  const cleanCount = (duties ?? []).filter((d) => !(d.issues ?? []).length).length;
  const gapCount = (duties ?? []).length - cleanCount;
  const openCodes = (duties ?? []).reduce((n, d) => n + (d.issues ?? []).length, 0);

  const limits = [
    {
      kicker: "Independence",
      text: "No assessor has been hired or test performed by this console. A signature proves origin and integrity, not independence, accreditation or certification. Certified infrastructure does not certify this product.",
    },
    {
      kicker: "Operating evidence",
      text: "Owner-reviewed exercises are retained assertions, not an SLA. A feature demonstration is not whole-bank coverage or commercial acceptance. Source/build/deployment associations require explicit evidence; they are not reproducible-build or runtime proof.",
    },
  ];

  return <div className="launch-readiness" style={{ minWidth: 0 }}>
    <style>{`.launch-readiness label { display: block; margin-block: .75rem; } .launch-readiness select, .launch-readiness button { max-inline-size: 100%; white-space: normal; } .launch-readiness :focus-visible { outline: 3px solid var(--blue, #70b7ff); outline-offset: 3px; }`}</style>
    <p aria-label="Selected estate"><strong>{t("launch.estate")}: <bdi dir="auto">{activeTenantId() || t("launch.platform")}</bdi></strong></p>
    <PageHead crumb="Overview / Launch readiness" title="Launch readiness" sub="GA · independent security evidence, accountable operations and one bounded customer workflow" />

    <Panel title="External acceptance stays explicit">
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 10 }}>
        {limits.map((l) => (
          <div key={l.kicker} style={{ border: "1px solid var(--line)", borderLeft: "2px dashed var(--line-strong)", borderRadius: "var(--r)", background: "var(--panel-2)", padding: "10px 12px" }}>
            <span className="mono" style={{ fontSize: 10, letterSpacing: "0.09em", textTransform: "uppercase", color: "var(--faint)" }}>{l.kicker} — outside this console</span>
            <p style={{ margin: "6px 0 0", fontSize: 11.5, lineHeight: 1.5, color: "var(--dim)" }}>{l.text}</p>
          </div>
        ))}
      </div>
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginTop: 10, fontSize: 11 }}>
        <Link to="/operator-decisions">Condition-level remediation</Link>
        <span style={{ color: "var(--faint)" }}>·</span>
        <Link to="/crypto-assurance">Registered coverage</Link>
        <span style={{ color: "var(--faint)" }}>·</span>
        <a href="/api/docs" target="_blank" rel="noreferrer">API schemas</a>
      </div>
    </Panel>

    {error && <p ref={errorFocus} tabIndex={-1} role="alert">{error}</p>}

    <Panel title="Nine operating duties — selected estate">
      <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap", marginBottom: 10 }}>
        <button disabled={busy} onClick={() => { setError(""); setResult(null); reloadOperations(); }}>Refresh operating records</button>
        <span className="mono" style={{ fontSize: 10, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--faint)" }}>
          duty state = server issue codes · no score
        </span>
      </div>

      {operationsLoading ? <p role="status">{t("launch.loading")}</p> : operationsError ? <><p role="alert">{operationsError}</p><p>{t("launch.unavailable")}</p></> : <>
        {/* State board — the three fields the server actually returns. */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 8, marginBottom: 10 }}>
          <StateCell label="duties returned" value={duties ? duties.length : "—"}
            note={duties ? `${cleanCount} clean · ${gapCount} with gaps` : "payload carries no duty register"} />
          <StateCell label="open issue codes" value={duties ? openCodes : "—"} tone={openCodes ? "red" : duties ? "green" : ""}
            note={duties ? (openCodes ? "each code listed on its duty" : "no coded gap on any duty") : "not measured"} />
          <StateCell label="owner-reviewed current"
            value={payload.all_owner_reviewed_records_current === true ? "CURRENT" : payload.all_owner_reviewed_records_current === false ? "NOT CURRENT" : "NOT OBSERVED"}
            tone={payload.all_owner_reviewed_records_current === true ? "green" : payload.all_owner_reviewed_records_current === false ? "red" : ""}
            note="server-computed over the duty register" />
          <StateCell label="SLA" value={payload.sla_authorized === true ? "AUTHORIZED" : payload.sla_authorized === false ? "NOT AUTHORIZED" : "NOT OBSERVED"}
            tone={payload.sla_authorized === true ? "green" : payload.sla_authorized === false ? "red" : ""}
            note={payload.reason ? "reason recorded on payload" : "no authorization field returned"} />
        </div>

        {duties && duties.length > 0 && (
          <div style={{ marginBottom: 10 }}>
            <StackedBar
              note="Composition of the returned duty register. A share of this register is not a share of the bank."
              segments={[
                { key: "clean", label: "clean duty", value: cleanCount, tone: "green" },
                { key: "gaps", label: "duty with gaps", value: gapCount, tone: "red" },
              ]}
            />
          </div>
        )}

        {payload.reason && payload.sla_authorized !== true && (
          <div style={{ marginBottom: 10 }}>
            <GapBar label="SLA authorised" reason={String(payload.reason)} />
          </div>
        )}

        {duties?.length === 0 && <p role="status">{t("launch.empty")}</p>}
        {partial && <p role="status">{t("launch.partial")}</p>}

        {duties && duties.length > 0 && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))", gap: 8 }}>
            {duties.map((d) => <DutyCell key={String(d.duty)} record={d} />)}
          </div>
        )}

        {!duties && !operationsLoading && !operationsError && (
          <div style={{ marginTop: 10 }}>
            <VizEmpty title="No duty register in this read" note="The payload returned no `duties` array, so no duty state is drawn. Absence is not coverage." />
          </div>
        )}

        {operations === null ? <p>{t("launch.unavailable")}</p> : (
          <details style={{ marginTop: 10 }}>
            <summary className="mono" style={{ fontSize: 10.5, color: "var(--dim)", cursor: "pointer" }}>Raw operating payload</summary>
            {show(operations)}
          </details>
        )}
      </>}
    </Panel>

    <Panel title="Read current scoped gates">
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: 14 }}>
        <div>
          <span className="mono" style={{ fontSize: 10, letterSpacing: "0.09em", textTransform: "uppercase", color: "var(--faint)" }}>Current gate · one exact record</span>
          <label>Exact engagement / pilot / finding / assignment ID<input aria-label="Exact record ID" dir="ltr" aria-describedby="launch-id-help" maxLength={36} style={style} value={identifier} onChange={e => setIdentifier(e.target.value)} /></label>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button disabled={busy || missingId} aria-describedby="launch-id-help" onClick={() => void request(`engagements/${encodeURIComponent(identifier)}/status`)}>Read independent security status</button>
            <button disabled={busy || missingId} aria-describedby="launch-id-help" onClick={() => void request(`pilots/${encodeURIComponent(identifier)}/status`)}>Read bounded pilot status</button>
          </div>
        </div>
        <div>
          <span className="mono" style={{ fontSize: 10, letterSpacing: "0.09em", textTransform: "uppercase", color: "var(--faint)" }}>Retained revisions · paginated</span>
          <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 8 }}>
            <label>Record kind<select aria-label="Record kind" value={recordKind} onChange={e => { setRecordKind(e.target.value); setRecordOffset(0); setResult(null); }}>{["security_engagement", "security_report", "security_finding", "operating_assignment", "operating_exercise", "customer_pilot"].map(kind => <option key={kind}>{kind}</option>)}</select></label>
            <label>Record offset<input aria-label="Record offset" type="number" min={0} max={1000000} value={recordOffset} onChange={e => setRecordOffset(Math.max(0, Math.min(1000000, Number(e.target.value) || 0)))} /></label>
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button disabled={busy} onClick={() => void request(`records?kind=${recordKind}&limit=50&offset=${recordOffset}`, "GET", undefined, "/api/v1/assurance/")}>Read 50 retained revisions</button>
            <button disabled={busy || missingId} aria-describedby="launch-id-help" onClick={() => void request(`records/${recordKind}/${encodeURIComponent(identifier)}`, "GET", undefined, "/api/v1/assurance/")}>Read record history</button>
          </div>
        </div>
      </div>
      <div className="mono" style={{ marginTop: 10, fontSize: 10.5, color: "var(--faint)", lineHeight: 1.6 }}>
        Browse retained records for exact IDs and expected revisions. Reads recompute blockers; previous acceptance does not suppress stale evidence.<br />
        Lists contain all revisions, not only latest records. Use the returned has_more / next_offset to continue, and current status before acting. Record history returns at most 200 revisions.
      </div>
    </Panel>

    <Panel title="Structured, revision-checked actions">
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 8, marginBottom: 10 }}>
        <div style={{ border: "1px solid var(--line)", borderLeft: `2px solid ${toneColor("amber")}`, borderRadius: "var(--r)", background: "var(--panel-2)", padding: "8px 10px", fontSize: 11.5, lineHeight: 1.5, color: "var(--dim)" }}>
          {t("launch.meanings")}
        </div>
        <div style={{ border: "1px solid var(--line)", borderLeft: "2px dashed var(--line-strong)", borderRadius: "var(--r)", background: "var(--panel-2)", padding: "8px 10px", fontSize: 11.5, lineHeight: 1.5, color: "var(--dim)" }}>
          <span title={"No private keys belong in this form. Import only the public signed envelope. All writes require current durable human authority and exact-estate references."}>{"No private keys belong in this form."}</span>
        </div>
      </div>
      <p id="launch-id-help" style={{ fontSize: 11.5, color: missingId ? "var(--amber)" : "var(--dim)" }}>{missingId ? t("launch.idRequired") : t("launch.idScope")}</p>
      {busy && <p role="status">{t("launch.busy")}</p>}
      <form onSubmit={submit}>
        <label>Action<select aria-label="Launch action" value={action} onChange={e => { setAction(e.target.value); setJson(""); setResult(null); }}>{Object.keys(actions).map(name => <option key={name}>{name}</option>)}</select></label>
        <label>Typed JSON body<textarea required aria-label="Typed JSON body" dir="ltr" rows={12} style={style} value={json} onChange={e => setJson(e.target.value)} placeholder="Paste a reviewed schema-valid object, including expected_revision where required" /></label>
        <button type="submit" aria-describedby="launch-id-help" disabled={busy || (needsId && missingId)}>{busy ? "Submitting…" : "Submit bounded action"}</button>
      </form>
      {result !== null && <div style={{ marginTop: 12 }}>
        <div className="mono" style={{ fontSize: 10, letterSpacing: "0.09em", textTransform: "uppercase", color: "var(--faint)" }}>{t(resultKind)}</div>
        <ScalarBoard value={result} />
        <details open><summary className="mono" style={{ fontSize: 10.5, color: "var(--dim)", cursor: "pointer" }}>Retained record</summary>{show(result)}</details>
      </div>}
    </Panel>
  </div>;
}
