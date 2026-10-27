import React from "react";
import { OperationalImpact } from "../lib/api";

export default function OperationalImpactPanel({ impact }: { impact?: OperationalImpact | null }) {
  return <section aria-label="Operational dependency conditions" style={{ fontSize: 12 }}>
    <strong>Conditional operational review</strong>
    <div>Dependency mode is not a failure verdict. Optional, failover and buffered edges remain in exposure review.</div>
    {!impact ? <div>Operational modes unavailable for this stored answer. Missing metadata is unknown, not hard dependency or safe operation.</div> : <>
      <div>{Object.entries(impact.mode_counts).map(([mode, count]) => `${mode}: ${count}`).join(" · ")}</div>
      <div>{impact.scope}</div>
      <div>{impact.note}</div>
      <div>Non-current operational records excluded: {impact.non_current_edge_count}. This is not evidence of remediation.</div>
      {impact.source_coverage == null && <div>Source completeness unknown; mode counts describe the loaded review subgraph only.</div>}
      {impact.edges.slice(0, 20).map((edge, i) => <details key={`${edge.from}-${edge.to}-${edge.record_id}-${i}`}>
        <summary>{edge.from} → {edge.to} · {edge.condition.mode} · {edge.consumer_scope} → {edge.provider_scope}</summary>
        <div>Assertion: {edge.condition.assertion_status} · not independently verified.</div>
        <div>{edge.condition.conditional_outcome}</div>
        <div>Operational evidence pointer: {edge.condition.assertion.evidence_ref || "missing"} (not reverified)</div>
        <div>Relationship evidence pointers: {JSON.stringify(edge.relationship_evidence.evidence_references)}</div>
        <ul>{(edge.condition.assertion.assumptions || []).map((assumption, j) => <li key={j}>Declared assumption: {assumption}</li>)}</ul>
        {edge.condition.mode === "FAILOVER" && <>
          <div>Declared alternatives: {(edge.condition.assertion.failover_system_ids || []).join(", ") || "missing"}</div>
          <div>Loaded registry identities: {edge.condition.failover_references.loaded_system_ids.join(", ") || "none resolved"}; identity is not health or successful switchover.</div>
          {!!edge.condition.failover_references.not_in_loaded_registry.length && <div>Alternative references not in loaded registry: {edge.condition.failover_references.not_in_loaded_registry.join(", ")}</div>}
        </>}
        {edge.condition.mode === "ASYNC_BUFFERED" && <>
          <div>Declared capacity: {edge.condition.assertion.buffer_capacity_messages ?? "unknown"} messages · retention: {edge.condition.assertion.buffer_retention_seconds ?? "unknown"} seconds</div>
          <div>No safe buffering duration or time-to-impact has been calculated.</div>
        </>}
        <ul>{edge.condition.gaps.map((gap, j) => <li key={j}>{gap}</li>)}</ul>
      </details>)}
      {(impact.edges_truncated || impact.edges.length > 20) && <div role="status">Operational explanation list truncated: showing {Math.min(20, impact.edges.length)} of {impact.edge_count} loaded records. Counts are not calculated from this preview.</div>}
    </>}
  </section>;
}
