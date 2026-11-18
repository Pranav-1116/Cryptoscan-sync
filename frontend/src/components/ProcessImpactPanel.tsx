import React from "react";
import { ProcessImpact } from "../lib/api";

export default function ProcessImpactPanel({ impact, legacy }: { impact?: ProcessImpact | null; legacy?: { id?: string; name?: string }[] }) {
  return <section aria-label="Business process impact" style={{ fontSize: 12 }}>
    <strong>Business process review</strong>
    {!impact || impact.schema !== "cryptoscan.business-process-impact/1" ? <>
      <div><span title={"Process projection unavailable for this stored answer. Legacy linked processes are not a complete scoped business-impact assessment."}>{"Process projection unavailable for this stored answer."}</span></div>
      {legacy?.map((p, i) => <div key={p.id || i}>{p.name || p.id}</div>)}
    </> : <>
      <div>Modeled process exposure: {impact.counts.exposure} · Review processes: {impact.counts.review}</div>
      <div>Context-only processes: {impact.counts.context_only} · Potential-only processes: {impact.counts.potential_only}</div>
      <div>{impact.note}</div>
      <div>{impact.coverage.systems_without_recorded_links_count} implicated systems have no usable recorded process link. This is unknown coverage, not zero impact.</div>
      {impact.coverage.unresolved_or_invalid_link_count > 0 && <div>{impact.coverage.unresolved_or_invalid_link_count} unresolved/invalid support records excluded.</div>}
      {(!impact.coverage.source_coverage || impact.coverage.source_coverage.processes_truncated || impact.coverage.source_coverage.support_links_truncated) && <div><span title={"Process source coverage is unknown or truncated; counts describe loaded records only."}>{"Process source coverage is unknown or truncated"}</span></div>}
      {(impact.coverage.processes_truncated || impact.processes.length > 20) && <div>Process explanations bounded: {impact.coverage.returned_process_count} returned of {impact.coverage.total_process_count}; showing first 20 here. Counts and economic context are not calculated from this preview.</div>}
      {impact.processes.slice(0, 20).map(process => <details key={process.id}>
        <summary>{process.name || process.id} ({process.id}) · {process.exposed ? "modeled exposure" : process.context_only ? "supporting context only" : "potential only"}</summary>
        {process.name_conflict && <div>Conflicting names recorded for this process ID.</div>}
        <div>{process.reason_count} recorded inclusion reasons. Support roles are declarations, not failure-mode guarantees.</div>
        {process.reasons.slice(0, 10).map((reason, i) => <div key={i} style={{ padding: 6 }}>
          <strong>{reason.system_id} → process:{process.id}</strong> · {reason.system_scope} · {reason.certainty}
          <div>Declared role: {reason.role || "unspecified"} · {reason.support_link.provenance} · source: {reason.support_link.source || "unknown"}</div>
          <div>Mapping record: {reason.support_link.record_id || "unavailable"} · eligibility: {reason.support_link.freshness.eligibility}</div>
          <div>Support observation: {reason.support_link.freshness.observation.status} {reason.support_link.freshness.observation.value} · confirmation: {reason.support_link.freshness.confirmation.status} {reason.support_link.freshness.confirmation.value}</div>
          <div>{reason.support_link.freshness.validity === "UNBOUNDED" ? "No support expiry deadline — not verified freshness" : `Support deadline: ${reason.support_link.valid_until}`}</div>
          <div>System explanation: {reason.system_explanation.group} / {reason.system_explanation.system_id} · {reason.system_explanation.available ? "present, not independently verified" : "missing or outside the bounded explanation set"}</div>
          <div>{reason.support_link.evidence_missing ? "Support evidence reference missing" : "Support pointers (not reverified):"}</div>
          {reason.support_link.references_truncated && <div>Support reference list truncated.</div>}
          {reason.support_link.evidence_references.map((ref, j) => <pre key={j} style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{typeof ref === "string" ? ref : JSON.stringify(ref)}</pre>)}
        </div>)}
        {(process.reasons_truncated || process.reasons.length > 10) && <div><span title={"Inclusion reasons truncated; showing at most 10 here. The process remains counted once by ID."}>{"Inclusion reasons truncated"}</span></div>}
      </details>)}
      <details><summary>Declared business context — not predicted loss</summary>
        <div>Recorded revenue/day known sum: {impact.economic_context.revenue_daily.known_sum ?? "unknown (arithmetic overflow)"}; {impact.economic_context.revenue_daily.complete_sum == null ? "incomplete" : "complete for loaded exposed process metrics and recorded system mappings only"}. No currency conversion or currency consistency was verified.</div>
        <div>Recorded customer-count sum: {impact.economic_context.customer_count.known_sum ?? "unknown (arithmetic overflow)"}; {impact.economic_context.customer_count.complete_sum == null ? "incomplete" : "complete for loaded exposed process metrics and recorded system mappings only"}. Not a count of unique people.</div>
        <div>{impact.economic_context.unmapped_exposed_system_count} exposed systems have no current support mapping.</div>
        <div>{impact.economic_context.scope}. {impact.economic_context.note}</div>
      </details>
    </>}
  </section>;
}
