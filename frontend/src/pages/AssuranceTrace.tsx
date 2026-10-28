import PrivateScope from "../components/PrivateScope";
import React, { useState } from "react";
import { Link } from "react-router-dom";
import { Badge, PageHead, Panel } from "../components/ui.jsx";
import { Json, idInputStyle, shortSha, useAssuranceRead } from "../lib/assuranceRead";
import { apiAssuranceTrace, type AssuranceTrace } from "../lib/api.js";

/** Workflow 3 of 7: the application crypto trace.
 *
 * A path here means: this deployment, this artifact digest, this SBOM binding, this
 * package identity, this reviewed relationship, this crypto evidence record. It does
 * NOT mean the code calls the algorithm, that the firmware is trusted, or that the
 * component was present at runtime — the server marks those unverified and the screen
 * shows them instead of a green tick.
 */
export default function AssuranceTrace() {
  return <PrivateScope><AssuranceTracePage /></PrivateScope>;
}

function AssuranceTracePage() {
  const [application, setApplication] = useState("");
  const read = useAssuranceRead<AssuranceTrace>();
  const data = read.data;

  return <div className="assurance-trace" style={{ minWidth: 0 }}>
    <PageHead crumb="Assurance / Application trace" title="Application trace"
      sub="Deployment → artifact → SBOM → package → reviewed relationship → crypto evidence"
      right={<><Badge tone="cyan">READ ONLY</Badge><Badge tone="amber">CALL PATH NOT PROVEN</Badge></>} />

    <Panel title="What a resolved path proves">
      <p>A resolved path is an <strong>evidence chain</strong>: every hop names a stored record and a digest.
        It is not a call graph and not a runtime observation. The server returns
        <code> runtime_verified: false</code> and <code>complete: false</code> for every trace, and each path
        carries <code>deployed_verified</code> and <code>invocation_verified</code> — both false.</p>
      <p>An unresolved component is listed with a reason rather than dropped: a component with no reviewed
        crypto edge is a gap in the evidence, not a component without cryptography.</p>
      <p><Link to="/assurance-coverage">Registered coverage</Link> · <Link to="/assurance-qualification">Qualification</Link></p>
    </Panel>

    <Panel title="Application to trace">
      <label style={{ display: "block", margin: "8px 0" }}>Exact application / system ID
        <input aria-label="Application ID" dir="ltr" maxLength={36} style={idInputStyle} value={application}
          onChange={e => { read.clear(); setApplication(e.target.value); }} />
      </label>
      <button className="btn primary sm" disabled={read.busy || !application.trim()}
        onClick={() => void read.run(() => apiAssuranceTrace(application.trim()), "Application trace")}>
        {read.busy ? "Tracing…" : "Read trace"}
      </button>
      {read.error && <p role="alert">{read.error}</p>}
      <p>The server caps a trace at 200 deployments, 5000 paths and 5000 unresolved components and returns
        HTTP 409 when a scope exceeds that, asking you to narrow it. It does not truncate silently, and neither
        does this screen.</p>
    </Panel>

    {data && <>
      <Panel title={`Application ${data.application_id}`}>
        <p role="status">{data.paths.length} resolved path(s) · {data.unresolved.length} unresolved · complete: {String(data.complete)} ·
          runtime verified: {String(data.runtime_verified)}</p>
        <p><em>{data.note}</em></p>
        {data.paths.length === 0 && <p role="status">No resolved path. This means no reviewed relationship currently
          links a component of this application to a crypto evidence record — not that the application uses no crypto.</p>}
        {data.paths.length > 0 && <table>
          <thead><tr><th>package</th><th>algorithm</th><th>purpose</th><th>location</th><th>evidence</th><th>trust</th></tr></thead>
          <tbody>
            {data.paths.map((path, index) => <tr key={`${path.relationship_id}-${index}`}>
              <td><code>{path.package_identity || "—"}</code><br />
                <small>artifact {shortSha(path.artifact_digest)} · {path.artifact_identity_source}</small></td>
              <td>{path.algorithm || "—"}</td>
              <td>{path.purpose || "—"}</td>
              <td><code>{path.location?.file || "—"}{path.location?.line ? `:${path.location.line}` : ""}</code></td>
              <td><code>{path.crypto_evidence_id || "—"}</code><br />
                <small>relationship {shortSha(path.relationship_sha256)}</small></td>
              <td><code>{JSON.stringify(path.trust)}</code></td>
            </tr>)}
          </tbody>
        </table>}
      </Panel>

      <Panel title="Unresolved">
        {data.unresolved.length === 0
          ? <p role="status">Nothing unresolved. That is still not completeness: the server's
            <code> complete</code> flag is the authority, and it is false.</p>
          : <table>
            <thead><tr><th>reason</th><th>artifact</th><th>binding</th><th>package</th></tr></thead>
            <tbody>
              {data.unresolved.map((row, index) => <tr key={index}>
                <td><code>{row.reason}</code></td>
                <td><code>{shortSha(row.artifact_id)}</code></td>
                <td><code>{shortSha(row.sbom_binding_id)}</code></td>
                <td><code>{row.package_identity || row.bom_ref || "—"}</code></td>
              </tr>)}
            </tbody>
          </table>}
        <details><summary>Server payload, verbatim</summary><Json value={data} /></details>
      </Panel>
    </>}
  </div>;
}
