import PrivateScope from "../components/PrivateScope";
import React, { useState } from "react";
import { Link } from "react-router-dom";
import { Badge, PageHead, Panel } from "../components/ui.jsx";
import { Json, idInputStyle, useAssuranceRead } from "../lib/assuranceRead";
import { usePrivateScopeCurrent } from "../components/PrivateScope";
import { apiAssuranceCoverage, apiAssuranceCreateRegister, getRoles,
  type AssuranceCoverage, type AssuranceRecord, type CoverageCounts } from "../lib/api.js";

/** Workflow 2 of 7: registered coverage.
 *
 * The denominator is the owner's own register — not discovered assets. This screen
 * exists to make that visible: it prints the basis strings the server returned, and
 * it never renders a whole-bank percentage, because the server does not compute one.
 */
const STATES: (keyof CoverageCounts)[] = ["OBSERVED", "STALE", "BLOCKED", "UNSUPPORTED", "NOT_ATTEMPTED"];

export default function AssuranceCoverage() {
  return <PrivateScope><AssuranceCoveragePage /></PrivateScope>;
}

function AssuranceCoveragePage() {
  const [register, setRegister] = useState("");
  const [scope, setScope] = useState("");
  const [owner, setOwner] = useState("");
  const [evidenceRef, setEvidenceRef] = useState("");
  const [targetId, setTargetId] = useState("");
  const [sourcePath, setSourcePath] = useState("");
  const [permissionRef, setPermissionRef] = useState("");
  const [freshness, setFreshness] = useState(86400);
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState("");
  const [created, setCreated] = useState<AssuranceRecord | null>(null);
  const scopeCurrent = usePrivateScopeCurrent();
  const canManage = getRoles().some(role => ["superadmin", "ciso", "security_analyst"].includes(role));
  const read = useAssuranceRead<AssuranceCoverage>();
  const data = read.data;

  const createRegister = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (creating || !scopeCurrent()) return;
    setCreating(true);
    setCreateError("");
    setCreated(null);
    read.clear();
    try {
      const result = await apiAssuranceCreateRegister({
        expected_revision: 0,
        scope_description: scope.trim(), register_owner: owner.trim(),
        completeness: "UNKNOWN", completeness_evidence_ref: evidenceRef.trim(),
        targets: [{ target_id: targetId.trim(), owner_ref: owner.trim(), kind: "SOURCE",
          source_class: "source", target_ref: sourcePath.trim(), method: "LOCAL_SOURCE",
          permission_ref: permissionRef.trim(), freshness_seconds: freshness }],
      });
      if (!scopeCurrent()) return;
      if (result.source !== "live" || !result.data) {
        setCreateError(`Register creation unconfirmed (${result.error || "no receipt"}); inspect current history before retrying.`);
        return;
      }
      const receipt = result.data;
      if (receipt.kind !== "estate_register" || receipt.revision !== 1
        || !/^[0-9a-f-]{36}$/.test(receipt.subject_id || "")
        || !/^[0-9a-f]{64}$/.test(receipt.payload_sha256 || "")) {
        setCreateError("Register response has no verifiable revision identity; inspect current history before retrying.");
        return;
      }
      setCreated(receipt);
      setRegister(receipt.subject_id);
      await read.run(() => apiAssuranceCoverage(receipt.subject_id), "Coverage report");
    } catch (error) {
      if (scopeCurrent()) setCreateError(`Register creation unconfirmed: ${error instanceof Error ? error.message : String(error)}; inspect history before retrying.`);
    } finally {
      if (scopeCurrent()) setCreating(false);
    }
  };

  return <div className="assurance-coverage" style={{ minWidth: 0 }}>
    <PageHead crumb="Assurance / Registered coverage" title="Registered coverage"
      sub="Owner-registered denominator · freshness from SQL receipts · no whole-bank percentage"
      right={<><Badge tone="cyan">{canManage ? "DECLARE + READ" : "READ ONLY"}</Badge><Badge tone="amber">DENOMINATOR IS THE REGISTER</Badge></>} />

    <Panel title="Read this before reading the counts">
      <p>The register is what the owner <em>declared</em> exists. Coverage is measured against that declaration,
        so a small estate and a complete estate look identical on this screen. The server returns
        <code> whole_bank_verified: false</code> for exactly this reason, and this screen does not soften it.</p>
      <p>An <code>OBSERVED</code> row whose freshness window has passed is shown as <code>STALE</code>: the last
        receipt is quoted with its timestamp, not extrapolated forward.</p>
      <p><Link to="/assurance-records">Assertion records</Link> · <Link to="/assurance-sampling">Accuracy sampling</Link></p>
    </Panel>

    {canManage && <Panel title="Declare one local source target">
      <p>This creates an owner-supplied register revision, <strong>not a scan or approval</strong>.
        Its target begins NOT_ATTEMPTED; only a later exact durable job receipt can establish OBSERVED.
        Enter an existing permission reference rather than treating this form as permission to collect.</p>
      <form onSubmit={event => void createRegister(event)}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 250px), 1fr))", gap: 12 }}>
          <label>Scope description<input required maxLength={500} style={idInputStyle} value={scope}
            onChange={event => setScope(event.target.value)} /></label>
          <label>Register owner (declared)<input required maxLength={500} style={idInputStyle} value={owner}
            onChange={event => setOwner(event.target.value)} /></label>
          <label>Scope evidence reference<input required maxLength={500} style={idInputStyle} value={evidenceRef}
            onChange={event => setEvidenceRef(event.target.value)} /></label>
          <label>Target ID<input required maxLength={80} pattern="[a-zA-Z0-9._-]+" style={idInputStyle}
            value={targetId} onChange={event => setTargetId(event.target.value)} /></label>
          <label>Exact absolute source path<input required maxLength={500} style={idInputStyle} value={sourcePath}
            onChange={event => setSourcePath(event.target.value)} /></label>
          <label>Existing collection permission reference<input required maxLength={500} style={idInputStyle}
            value={permissionRef} onChange={event => setPermissionRef(event.target.value)} /></label>
          <label>Freshness window (seconds)<input required type="number" min={60} max={31536000} step={1}
            style={idInputStyle} value={freshness} onChange={event => setFreshness(Number(event.target.value))} /></label>
        </div>
        <button className="btn primary sm" style={{ marginTop: 12 }} disabled={creating || !sourcePath.trim().startsWith("/")}
          type="submit">{creating ? "Creating…" : "Create register (no scan)"}</button>
      </form>
      {createError && <p role="alert">{createError}</p>}
      {created && <p role="status">Register <code>{created.subject_id}</code> · revision {created.revision} ·
        receipt SHA-256 <code>{created.payload_sha256}</code>. Read the current report below.</p>}
    </Panel>}

    <Panel title="Register to inspect">
      <label style={{ display: "block", margin: "8px 0" }}>Exact register ID
        <input aria-label="Register ID" dir="ltr" maxLength={36} style={idInputStyle} value={register}
          onChange={e => { read.clear(); setRegister(e.target.value); }} />
      </label>
      <button className="btn primary sm" disabled={read.busy || !register.trim()}
        onClick={() => void read.run(() => apiAssuranceCoverage(register.trim()), "Coverage report")}>
        {read.busy ? "Reading…" : "Read coverage"}
      </button>
      {read.error && <p role="alert">{read.error}</p>}
      {!data && !read.busy && !read.error && <p>Register IDs are listed under
        {" "}<code>kind=estate_register</code> on the records screen. A register revision is required before any
        coverage claim exists.</p>}
    </Panel>

    {data && <>
      <Panel title={`Register ${data.register_id} · revision ${data.revision}`}>
        <p role="status">{data.registered_targets} registered target(s) · as of {data.as_of}</p>
        <p><strong>Scope as declared:</strong> {data.scope_description || "—"}</p>
        <p><strong>Register completeness:</strong> <code>{data.register_completeness}</code> ·
          evidence <code>{data.completeness_evidence_ref || "—"}</code></p>
        <table>
          <thead><tr><th>state</th><th>targets</th><th>meaning</th></tr></thead>
          <tbody>
            {STATES.map(state => <tr key={state}>
              <td><code>{state}</code></td>
              <td>{data.counts[state]}</td>
              <td>{MEANING[state]}</td>
            </tr>)}
          </tbody>
        </table>
        <p><strong>Denominator basis:</strong> <code>{data.denominator_basis}</code></p>
        <p><strong>Completeness basis:</strong> <code>{data.completeness_basis}</code></p>
        <p><strong>whole_bank_verified:</strong> {String(data.whole_bank_verified)} — the platform does not verify
          that the register lists everything, so it will not show you a percentage that assumes it does.</p>
      </Panel>

      <Panel title="By registered kind">
        <table>
          <thead><tr><th>kind</th>{STATES.map(s => <th key={s}>{s}</th>)}</tr></thead>
          <tbody>
            {Object.entries(data.by_kind).map(([kind, counts]) => <tr key={kind}>
              <td><code>{kind}</code></td>
              {STATES.map(state => <td key={state}>{counts[state] ?? 0}</td>)}
            </tr>)}
          </tbody>
        </table>
      </Panel>

      <Panel title="Registered targets">
        <table>
          <thead><tr><th>target</th><th>kind</th><th>method</th><th>state</th><th>last success</th><th>expires</th></tr></thead>
          <tbody>
            {data.targets.map(target => <tr key={target.target_id}>
              <td><code>{target.target_ref || target.target_id}</code></td>
              <td>{target.kind}</td>
              <td>{target.method}</td>
              <td><strong>{target.state}</strong></td>
              <td>{target.last_successful_at || "—"}</td>
              <td>{target.expires_at || "—"}</td>
            </tr>)}
          </tbody>
        </table>
        <details><summary>Server payload, verbatim (includes each retained receipt)</summary><Json value={data} /></details>
      </Panel>
    </>}
  </div>;
}

const MEANING: Record<keyof CoverageCounts, string> = {
  OBSERVED: "a current receipt exists inside its freshness window",
  STALE: "a receipt exists, but its freshness window has passed",
  BLOCKED: "the target was reached and collection was refused or failed — the reason is in its receipt",
  UNSUPPORTED: "no collector for this method is qualified in this build",
  NOT_ATTEMPTED: "registered, never collected — this is not evidence of absence",
};
