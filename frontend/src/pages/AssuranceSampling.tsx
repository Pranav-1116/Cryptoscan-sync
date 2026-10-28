import PrivateScope from "../components/PrivateScope";
import React, { useState } from "react";
import { Link } from "react-router-dom";
import { Badge, PageHead, Panel } from "../components/ui.jsx";
import { Json, idInputStyle, shortSha, useAssuranceRead } from "../lib/assuranceRead";
import { apiAssuranceWorkbook, type AssuranceWorkbook } from "../lib/api.js";

/** Workflow 4 of 7: accuracy sampling workbooks.
 *
 * The workbook is the frozen prediction set handed to a domain owner. This screen
 * renders it as-is, including UNREVIEWED truth labels: it never computes precision or
 * recall, because those numbers belong to the review that publishes them, not to a
 * screen that can be read before the review exists.
 */
export default function AssuranceSampling() {
  return <PrivateScope><AssuranceSamplingPage /></PrivateScope>;
}

function AssuranceSamplingPage() {
  const [sample, setSample] = useState("");
  const [phase, setPhase] = useState<"FIRST_PASS" | "HOLDOUT">("FIRST_PASS");
  const read = useAssuranceRead<AssuranceWorkbook>();
  const data = read.data;

  return <div className="assurance-sampling" style={{ minWidth: 0 }}>
    <PageHead crumb="Assurance / Accuracy sampling" title="Accuracy sampling"
      sub="Frozen predictions · blind truth labels · reviewed by the domain owner, not by the console"
      right={<><Badge tone="cyan">READ ONLY</Badge><Badge tone="amber">NO METRIC COMPUTED HERE</Badge></>} />

    <Panel title="Why this screen shows labels, not scores">
      <p>The workbook is the question: here are the frozen predictions, label them. Precision, recall and miss
        counts are calculated from those labels when a review is published through
        <code> POST /assurance/samples/&#123;id&#125;/reviews</code>, and an unreviewed sample has none.</p>
      <p>A <code>HOLDOUT</code> phase reads the repeat sample, so the same units are not labelled twice from
        memory. Showing <code>UNREVIEWED</code> as anything other than unreviewed would be the exact error this
        workflow exists to prevent.</p>
      <p><Link to="/assurance-records">Assertion records</Link> · <Link to="/assurance-trace">Application trace</Link></p>
    </Panel>

    <Panel title="Sample to open">
      <label style={{ display: "block", margin: "8px 0" }}>Exact sample ID
        <input aria-label="Sample ID" dir="ltr" maxLength={36} style={idInputStyle} value={sample}
          onChange={e => { read.clear(); setSample(e.target.value); }} />
      </label>
      <label style={{ display: "block", margin: "8px 0" }}>Phase
        <select aria-label="Phase" style={idInputStyle} value={phase}
          onChange={e => { read.clear(); setPhase(e.target.value as "FIRST_PASS" | "HOLDOUT"); }}>
          <option value="FIRST_PASS">FIRST_PASS</option>
          <option value="HOLDOUT">HOLDOUT</option>
        </select>
      </label>
      <button className="btn primary sm" disabled={read.busy || !sample.trim()}
        onClick={() => void read.run(() => apiAssuranceWorkbook(sample.trim(), phase), "Workbook")}>
        {read.busy ? "Reading…" : "Read workbook"}
      </button>
      {read.error && <p role="alert">{read.error}</p>}
      <p>Only an approved sample has a workbook; the server answers 404 for a sample that is still a proposal.
        A HOLDOUT read has no repeat sample until one is seeded, and the error says so.</p>
    </Panel>

    {data && <Panel title={`Sample ${data.sample_id} · ${data.phase}`}>
      <p role="status">{data.units.length} unit(s) in this phase · domain owner {data.domain_owner || "—"}</p>
      <p><strong>Scope:</strong> {data.scope || "—"}</p>
      <p><strong>Frozen sample sha256:</strong> <code title={data.sample_sha256}>{shortSha(data.sample_sha256)}</code></p>
      <p><em>{data.note}</em></p>
      <table>
        <thead><tr><th>unit</th><th>prediction</th><th>truth label</th><th>explanation</th></tr></thead>
        <tbody>
          {data.units.map(unit => <tr key={unit.unit_id}>
            <td><code>{unit.unit_id}</code>{unit.package_identity && <><br /><small>{unit.package_identity}</small></>}</td>
            <td><code>{unit.prediction === undefined ? "—" : JSON.stringify(unit.prediction)}</code></td>
            <td><strong>{unit.truth_label || "UNREVIEWED"}</strong></td>
            <td>{unit.explanation || "—"}</td>
          </tr>)}
        </tbody>
      </table>
      {data.units.length === 0 && <p role="status">No units in this phase. A holdout workbook before a repeat
        sample exists is empty, not perfect.</p>}
      <details><summary>Server payload, verbatim</summary><Json value={data} /></details>
    </Panel>}
  </div>;
}
