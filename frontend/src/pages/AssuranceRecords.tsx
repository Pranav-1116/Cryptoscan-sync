import PrivateScope from "../components/PrivateScope";
import React, { useState } from "react";
import { Link } from "react-router-dom";
import { Badge, PageHead, Panel } from "../components/ui.jsx";
import { Json, idInputStyle, shortSha, useAssuranceRead } from "../lib/assuranceRead";
import {
  apiAssuranceHistory, apiAssuranceKinds, apiAssuranceRecords,
  type AssuranceRecord, type AssuranceRecords,
} from "../lib/api.js";

/** Workflow 1 of 7: the retained assertion history itself.
 *
 * Every assurance workflow writes append-only revisions into one table; this screen
 * is the only place an operator can read that table with its hash chain intact.
 * It does not resolve an assertion into an asset, a finding or a BOM fact — the
 * payload is quoted, not interpreted.
 */
export default function AssuranceRecords() {
  return <PrivateScope><AssuranceRecordsPage /></PrivateScope>;
}

function AssuranceRecordsPage() {
  const [kind, setKind] = useState("estate_register");
  const [offset, setOffset] = useState(0);
  const [subject, setSubject] = useState("");
  const list = useAssuranceRead<AssuranceRecords>();
  const history = useAssuranceRead<{ revisions: AssuranceRecord[]; has_more: boolean }>();

  return <div className="assurance-records" style={{ minWidth: 0 }}>
    <PageHead crumb="Assurance / Records" title="Assertion records"
      sub="Append-only revisions shared by all seven assurance workflows · hash-chained · not an asset inventory"
      right={<><Badge tone="cyan">READ ONLY</Badge><Badge tone="slate">ASSERTIONS, NOT INVENTORY</Badge></>} />

    <Panel title="What this table is, and is not">
      <p>A record here is an <strong>assertion</strong> — a register revision, a reviewed coverage observation,
        a relationship approval, a sample review. It is not an asset, a deployment or a fact about a live host.
        The chain proves that a stored revision is the one that was written; it does not prove the assertion is true.</p>
      <p>Deleting or rewriting a revision is a database-administrator action that the API refuses and a hash chain
        cannot prevent. Storage immutability is an operational control, not a property of this screen.</p>
      <p><Link to="/operator-decisions">Operator decisions</Link> · <Link to="/assurance-coverage">Registered coverage</Link> ·
        <Link to="/assurance-trace">Application trace</Link></p>
    </Panel>

    <Panel title="Read revisions of one kind">
      <label style={{ display: "block", margin: "8px 0" }}>Record kind
        <select aria-label="Record kind" style={idInputStyle} value={kind}
          onChange={e => { list.clear(); setKind(e.target.value); setOffset(0); }}>
          {apiAssuranceKinds.map(k => <option key={k}>{k}</option>)}
        </select>
      </label>
      <label style={{ display: "block", margin: "8px 0" }}>Offset
        <input aria-label="Record offset" type="number" min={0} max={1000000} style={idInputStyle} value={offset}
          onChange={e => { list.clear(); setOffset(Math.max(0, Math.min(1000000, Number(e.target.value) || 0))); }} />
      </label>
      <button className="btn primary sm" disabled={list.busy}
        onClick={() => void list.run(() => apiAssuranceRecords(kind, offset), "Revision list")}>
        {list.busy ? "Reading…" : "Read up to 100 revisions"}
      </button>
      {list.error && <p role="alert">{list.error}</p>}
      {list.data && <>
        <p role="status">{list.data.records.length} revision(s) · includes every revision, not only latest ·
          {list.data.has_more
            ? ` more available at offset ${list.data.next_offset}`
            : " the server reports this is the last page"}</p>
        <table>
          <thead><tr><th>revision</th><th>subject</th><th>payload sha256</th><th>previous</th><th>by</th><th>created</th><th /></tr></thead>
          <tbody>
            {list.data.records.map(record => <tr key={record.id}>
              <td>{record.revision}</td>
              <td><code>{record.subject_id}</code></td>
              <td><code title={record.payload_sha256}>{shortSha(record.payload_sha256)}</code></td>
              <td><code title={record.previous_sha256 || ""}>{shortSha(record.previous_sha256)}</code></td>
              <td><code>{shortSha(record.created_by)}</code></td>
              <td>{record.created_at || "—"}</td>
              <td><button className="btn ghost sm" disabled={history.busy}
                onClick={() => { setSubject(record.subject_id); void history.run(
                  () => apiAssuranceHistory(record.kind, record.subject_id), "Revision history"); }}>
                history
              </button></td>
            </tr>)}
          </tbody>
        </table>
        {list.data.records.length === 0 && <p role="status">
          No revision of kind <code>{kind}</code> exists in this estate. That is an empty table, not a clean estate:
          a workflow nobody has run leaves no record.
        </p>}
      </>}
      {list.data && <details><summary>Server payload, verbatim</summary><Json value={list.data} /></details>}
    </Panel>

    <Panel title={subject ? `History of ${subject}` : "History of one subject"}>
      {!subject && <p>Pick a row above; the history read is keyed by the exact (kind, subject) pair, because the
        same identifier can exist in two kinds.</p>}
      {history.error && <p role="alert">{history.error}</p>}
      {history.data && <>
        <p role="status">{history.data.revisions.length} revision(s) returned; the server caps a history read at 200
          {history.data.has_more ? " and reports more remain" : " and reports no more remain"}.</p>
        {history.data.revisions.map(record => <details key={record.id}>
          <summary>revision {record.revision} · <code>{shortSha(record.payload_sha256)}</code></summary>
          <Json value={record.payload} />
        </details>)}
      </>}
    </Panel>
  </div>;
}
