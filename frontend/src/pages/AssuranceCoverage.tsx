import PrivateScope from "../components/PrivateScope";
import React, { useState } from "react";
import { Link } from "react-router-dom";
import { Badge, PageHead, Panel } from "../components/ui.jsx";
import { Json, idInputStyle, useAssuranceRead } from "../lib/assuranceRead";
import { apiAssuranceCoverage, type AssuranceCoverage, type CoverageCounts } from "../lib/api.js";

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
  const read = useAssuranceRead<AssuranceCoverage>();
  const data = read.data;

  return <div className="assurance-coverage" style={{ minWidth: 0 }}>
    <PageHead crumb="Assurance / Registered coverage" title="Registered coverage"
      sub="Owner-registered denominator · freshness from SQL receipts · no whole-bank percentage"
      right={<><Badge tone="cyan">READ ONLY</Badge><Badge tone="amber">DENOMINATOR IS THE REGISTER</Badge></>} />

    <Panel title="Read this before reading the counts">
      <p>The register is what the owner <em>declared</em> exists. Coverage is measured against that declaration,
        so a small estate and a complete estate look identical on this screen. The server returns
        <code> whole_bank_verified: false</code> for exactly this reason, and this screen does not soften it.</p>
      <p>An <code>OBSERVED</code> row whose freshness window has passed is shown as <code>STALE</code>: the last
        receipt is quoted with its timestamp, not extrapolated forward.</p>
      <p><Link to="/assurance-records">Assertion records</Link> · <Link to="/assurance-sampling">Accuracy sampling</Link></p>
    </Panel>

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
