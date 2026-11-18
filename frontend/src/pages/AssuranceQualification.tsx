import PrivateScope from "../components/PrivateScope";
import React, { useState } from "react";
import { Link } from "react-router-dom";
import { Badge, PageHead, Panel } from "../components/ui.jsx";
import { Json, idInputStyle, useAssuranceRead } from "../lib/assuranceRead";
import {
  apiAssuranceAdapter, apiAssuranceRedisQualification, apiAssuranceSupplierObservations,
  type AdapterStatus, type RedisQualification, type SupplierObservations,
} from "../lib/api.js";

/** Workflows 5–7 of 7: adapter qualification, supplier evidence, and the Redis
 * infrastructure qualification. Three questions that all sound like "is it
 * supported?" and are answered differently:
 *
 *  - an adapter is qualified for *one exact offline profile*, never for a vendor;
 *  - supplier observations are read from an approved quarantine blob, and are
 *    explicitly not joined to identity automatically;
 *  - infrastructure qualification is per role × scenario, by measurement and a
 *    separate human review — not by a sentinel that happens to be promoted.
 */
export default function AssuranceQualification() {
  return <PrivateScope><AssuranceQualificationPage /></PrivateScope>;
}

function AssuranceQualificationPage() {
  return <div className="assurance-qualification" style={{ minWidth: 0 }}>
    <PageHead crumb="Assurance / Qualification" title="Qualification"
      sub="Exact profiles, quarantined supplier evidence, and per-role infrastructure measurement"
      right={<><Badge tone="cyan">READ ONLY</Badge><Badge tone="amber">NO LIVE VENDOR SUPPORT</Badge></>} />

    <Panel title="Three questions, three different answers">
      <p><strong>Adapter:</strong> <code>OFFLINE_PROFILE_EXERCISED</code> means one offline JSON profile passed
        its cases against this build's engine fingerprint and every cited supplier record is still approved and
        untampered. It never means the vendor's API works, and <code>live_vendor_supported</code> is always false.</p>
      <p><strong>Supplier evidence:</strong> observations are parsed out of the approved quarantine blob. There is
        no automatic identity join and no independent truth verification — the bytes came from the supplier.</p>
      <p><strong>Infrastructure:</strong> a role × scenario cell is accepted only when a reviewed measurement is
        current for the exact approved objective revision. A local sentinel promotion is not qualification.</p>
      <p><Link to="/assurance-records">Assertion records</Link> · <Link to="/assurance-trace">Application trace</Link></p>
    </Panel>

    <Adapters />
    <Redis />
  </div>;
}

function Adapters() {
  const [adapter, setAdapter] = useState("");
  const [evidence, setEvidence] = useState("");
  const status = useAssuranceRead<AdapterStatus>();
  const observations = useAssuranceRead<SupplierObservations>();

  return <>
    <Panel title="Adapter profile">
      <label style={{ display: "block", margin: "8px 0" }}>Exact adapter manifest ID
        <input aria-label="Adapter ID" dir="ltr" maxLength={36} style={idInputStyle} value={adapter}
          onChange={e => { status.clear(); observations.clear(); setAdapter(e.target.value); }} />
      </label>
      <button className="btn primary sm" disabled={status.busy || !adapter.trim()}
        onClick={() => void status.run(() => apiAssuranceAdapter(adapter.trim()), "Adapter status")}>
        {status.busy ? "Reading…" : "Read adapter status"}
      </button>
      {status.error && <p role="alert">{status.error}</p>}
      {status.data && <>
        <p role="status">support status <strong>{status.data.support_status}</strong> ·
          offline profile exercised: {String(status.data.offline_profile_exercised)} ·
          live vendor supported: {String(status.data.live_vendor_supported)}</p>
        {!status.data.qualification && <p role="alert">
          <span title={"No qualification exists for this manifest. It is a declared profile, not a supported adapter: the server will refuse supplier observations for it with HTTP 409."}>{"No qualification exists for this manifest."}</span>
        </p>}
        {status.data.qualification && <details open>
          <summary>Qualification payload (engine and manifest fingerprints)</summary>
          <Json value={status.data.qualification.payload} />
        </details>}
        <details><summary>Manifest payload</summary><Json value={status.data.manifest.payload} /></details>
      </>}

      <label style={{ display: "block", margin: "8px 0" }}>Approved supplier evidence ID
        <input aria-label="Supplier evidence ID" dir="ltr" maxLength={36} style={idInputStyle} value={evidence}
          onChange={e => { observations.clear(); setEvidence(e.target.value); }} />
      </label>
      <button className="btn primary sm" disabled={observations.busy || !adapter.trim() || !evidence.trim()}
        onClick={() => void observations.run(
          () => apiAssuranceSupplierObservations(adapter.trim(), evidence.trim()), "Supplier observations")}>
        {observations.busy ? "Reading…" : "Read observations from the quarantine blob"}
      </button>
      {observations.error && <p role="alert">{observations.error}</p>}
      {observations.data && <>
        <p role="status">source sha256 <code>{observations.data.source_sha256.slice(0, 12)}…</code> ·
          build digest <code>{observations.data.build_digest}</code> ·
          automatic identity joins: {String(observations.data.automatic_identity_joins)}</p>
        <p>Facts are the supplier's own statement about its product. They are not observations of your estate,
          and <code>independent_truth_verified</code> is {String(observations.data.independent_truth_verified)}.</p>
        <details><summary>Parsed facts, verbatim</summary><Json value={observations.data.facts ?? observations.data} /></details>
      </>}
    </Panel>
  </>;
}

function Redis() {
  const [objectives, setObjectives] = useState("");
  const read = useAssuranceRead<RedisQualification>();
  const data = read.data;

  return <Panel title="Redis deployment qualification">
    <label style={{ display: "block", margin: "8px 0" }}>Exact approved objectives ID
      <input aria-label="Objectives ID" dir="ltr" maxLength={36} style={idInputStyle} value={objectives}
        onChange={e => { read.clear(); setObjectives(e.target.value); }} />
    </label>
    <button className="btn primary sm" disabled={read.busy || !objectives.trim()}
      onClick={() => void read.run(() => apiAssuranceRedisQualification(objectives.trim()), "Redis qualification")}>
      {read.busy ? "Reading…" : "Read qualification matrix"}
    </button>
    {read.error && <p role="alert">{read.error}</p>}
    {data && <>
      <p role="status">deployment meets objectives: <strong>{String(data.deployment_evidence_meets_objectives)}</strong> ·
        whole infrastructure qualified: <strong>{String(data.whole_infrastructure_qualified)}</strong></p>
      <p><strong>Basis:</strong> <code>{data.qualification_basis}</code></p>
      <p><strong>Unqualified roles:</strong> {data.unqualified_roles.length
        ? data.unqualified_roles.join(", ")
        : "none — every role has an approved objective revision"}</p>
      <table>
        <thead><tr><th>role</th><th>scenario</th><th>state</th><th>accepted</th><th>measurement</th></tr></thead>
        <tbody>
          {data.matrix.map(cell => <tr key={`${cell.role}-${cell.scenario}`}>
            <td>{cell.role}</td>
            <td><code>{cell.scenario}</code></td>
            <td><code>{cell.state}</code></td>
            <td>{cell.accepted ? "yes" : "no"}</td>
            <td><code>{cell.measurement_id || "—"}</code></td>
          </tr>)}
        </tbody>
      </table>
      <p><code>AMBIGUOUS_LATEST_MEASUREMENT_ORDER</code> means two measurements claim the same instant and the
        server will not pick a winner; it is shown as unaccepted rather than resolved by ordering.</p>
      <p><code>local_sentinel_promotion_is_deployment_qualification:{" "}
        {String(data.local_sentinel_promotion_is_deployment_qualification)}</code> — a promoted local
        sentinel is not a deployment qualification.</p>
      <details><summary>Server payload, verbatim</summary><Json value={data} /></details>
    </>}
  </Panel>;
}
