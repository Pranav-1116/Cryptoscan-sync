import React from "react";
import { CascadeTraversalEvidence, CascadeSeedEvidence, TraversalEvidenceEnvelope, TraversalPathEvidence } from "../lib/api";

const show = (value: unknown) => typeof value === "string" ? value : JSON.stringify(value);

function Path({ path }: { path: TraversalPathEvidence }) {
  return <details>
    <summary>{path.nodes.join(" → ")} · {path.scope} · {path.available ? "witness available" : "witness unavailable"}
      {path.mixed_provenance && " · mixed provenance"} · {path.evidence_gap_count} missing-reference edges</summary>
    <div>Walk direction: {path.direction}. Edge arrows below retain their actual recorded orientation.</div>
    {path.edges.map((edge, i) => <div key={i} style={{ padding: 8, borderLeft: "2px solid var(--dim)", margin: 4 }}>
      <strong>{edge.from} → {edge.to} · {edge.relation} · {edge.provenance}</strong>
      <div>Source: {edge.source || "unattributed"} · record: {edge.record_id || "unavailable"}</div>
      {edge.operational_condition && <div>Operational mode: {edge.operational_condition.mode} · {edge.operational_condition.conditional_outcome}</div>}
      <div>Confidence: {edge.confidence ?? "unspecified"} · {edge.confidence_meaning}</div>
      <div>Eligibility: {edge.freshness.eligibility} · {edge.freshness.validity === "UNBOUNDED" ? "No expiry deadline — not verified freshness" : `deadline: ${edge.valid_until}`}</div>
      <div>Observation: {edge.freshness.observation.status} {edge.freshness.observation.value}</div>
      <div>Confirmation: {edge.freshness.confirmation.status} {edge.freshness.confirmation.value}</div>
      <div>Verification timestamp: {edge.freshness.verification_timestamp.status} {edge.freshness.verification_timestamp.value} (timestamp only, not independently reverified)</div>
      <div>{edge.freshness.note}</div>
      <div>{edge.evidence_missing ? "Evidence reference missing" : "Evidence pointers (not reverified):"}</div>
      <ul>{edge.evidence_references.map((ref, j) => <li key={j} style={{ overflowWrap: "anywhere" }}>{show(ref)}</li>)}</ul>
      {edge.references_truncated && <div>Reference list truncated.</div>}
      {edge.identity && Object.keys(edge.identity).length > 0 && <pre style={{ whiteSpace: "pre-wrap" }}>{show(edge.identity)}</pre>}
    </div>)}
    {!path.edges.length && <div><span title={"Zero-hop target selection; no relationship or runtime observation asserted."}>{"Zero-hop target selection"}</span></div>}
  </details>;
}

function Seeds({ rows, count, truncated, label }: { rows: CascadeSeedEvidence[]; count: number; truncated: boolean; label: string }) {
  return <details><summary>{label}: {rows.length} listed of {count}</summary>
    {rows.slice(0, 10).map((seed, i) => <div key={`${seed.system_id}-${i}`}>
      <strong>{seed.system_id}</strong> · {seed.basis}
      {seed.path ? <Path path={seed.path} /> : <>
        <div><span title={"Seed chain not verified; supporting records/context only. No missing edge is invented."}>{"Seed chain not verified"}</span></div>
        <details><summary>Recorded context: {seed.records?.length || 0} listed of {seed.record_count || 0}</summary>
          <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{JSON.stringify(seed.records || [], null, 2)}</pre>
        </details>
      </>}
      {seed.record_listing_truncated && <div>Seed record list truncated.</div>}
    </div>)}
    {(truncated || rows.length > 10) && <div><span title={"Seed explanations truncated; showing at most 10 entries here. Exposure counts unchanged."}>{"Seed explanations truncated"}</span></div>}
  </details>;
}

function Witnesses({ value, label }: { value: TraversalEvidenceEnvelope; label: string }) {
  return <details><summary>{label}: {value.returned_count} witnesses / {value.requested_count} requested systems</summary>
    <div>Evidence as of {value.as_of}. One minimum-hop witness, not every alternative path.</div>
    {(!value.complete_for_requested_systems || value.truncated) && <div role="status">Incomplete witness coverage: {value.missing_witness_count} missing within the selected subset; limit {value.limit}. Exposure counts unchanged.</div>}
    {value.missing_system_ids.length > 0 && <div>Missing witnesses: {value.missing_system_ids.join(", ")}{value.missing_system_ids_truncated && " (list truncated)"}</div>}
    {value.paths.slice(0, 20).map((path, i) => <Path key={`${path.system_id}-${i}`} path={path} />)}
    {value.paths.length > 20 && <div><span title={"Showing first 20 paths here; the response contains additional witnesses."}>{"Showing first 20 paths here"}</span></div>}
  </details>;
}

export default function TraversalEvidencePanel({ evidence }: { evidence?: CascadeTraversalEvidence | null }) {
  return <section aria-label="Traversal evidence" style={{ fontSize: 12 }}>
    <strong>Why each system is included</strong>
    <div><span title={"Per-edge provenance and freshness only. No aggregate confidence or failure probability. Evidence pointers are not reverified. Declarations are not observed runtime use."}>{"Per-edge provenance and freshness only."}</span></div>
    {!evidence ? <div><span title={"Traversal evidence unavailable for this stored answer. Do not reconstruct it from current relationships."}>{"Traversal evidence unavailable for this stored answer."}</span></div> : <>
      <Seeds rows={evidence.direct} count={evidence.direct_count} truncated={evidence.direct_truncated} label="Direct seed context" />
      <Seeds rows={evidence.potential_direct} count={evidence.potential_direct_count} truncated={evidence.potential_direct_truncated} label="Potential seed context" />
      <Witnesses value={evidence.dependent_consumers} label="Dependent-consumer paths" />
      <Witnesses value={evidence.supporting_context} label="Supporting-context paths" />
      <Witnesses value={evidence.potential} label="Potential, not active exposure" />
      {evidence.vendor_subtiers && <Witnesses value={evidence.vendor_subtiers} label="Declared supplier paths" />}
    </>}
  </section>;
}
