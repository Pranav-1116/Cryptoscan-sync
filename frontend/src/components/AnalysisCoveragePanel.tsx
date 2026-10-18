import React from "react";
import type { AnalysisCoverage } from "../lib/api";

const label = (value: string) => value.replace(/_/g, " ");

/** Limits qualify the answer; they never drive modeled membership or totals. */
export default function AnalysisCoveragePanel({ coverage }: { coverage?: AnalysisCoverage | null }) {
  if (!coverage || coverage.schema !== "cryptoscan.analysis-coverage/1") return (
    <section aria-label="Coverage and limitations" style={{ padding: 12, border: "1px solid var(--amber)", borderRadius: "var(--r)" }}>
      <strong>Coverage unavailable for this stored answer</strong>
      <div role="status">Do not reconstruct historical coverage from today's graph. Missing metadata is not zero exposure or proof of safety.</div>
    </section>
  );
  const inputs = Object.entries(coverage.collections).filter(([, read]) => read.truncated);
  const gaps = coverage.missing_links.filter(gap => gap.count !== null && gap.count > 0);
  const details = coverage.explanations.filter(row => row.truncated || (row.missing_within_selected_count ?? 0) > 0);
  return (
    <section aria-label="Coverage and limitations" style={{ padding: 12, border: "1px solid var(--amber)", borderRadius: "var(--r)", fontSize: 12 }}>
      <strong>Coverage and limitations · {label(coverage.status)}</strong>
      <div role="status">
        Estate completeness: unknown. {coverage.note}
        {!coverage.source_metadata_available && <div>Source read metadata unavailable; collection completeness cannot be assessed.</div>}
        {!coverage.analysis_performed && <div>No traversal performed for this unresolved selection.</div>}
        {coverage.known_input_truncation && <div><b>Source input truncated. Modeled membership and counts may omit exposure.</b></div>}
        {coverage.known_horizon_omission && <div><b>Loaded relationships continue beyond a traversal horizon. Omitted neighbours are not included in impact totals.</b></div>}
        {coverage.horizon_extension_unknown && <div><b>Traversal extension not evaluated. Unknown is not zero additional systems.</b></div>}
        {coverage.explanation_truncation && <div>Explanation listings truncated; compact membership counts are independent of these detail limits.</div>}
      </div>
      {inputs.length > 0 && <ul>{inputs.map(([name, read]) => <li key={name}>
        {label(name)}: returned {read.returned ?? "unknown"} {read.unit}, limit {read.limit ?? "unknown"}; omitted input reported.
        {read.known_total != null ? ` Known total in query: ${read.known_total}.` : read.observed_lower_bound != null ? ` Observed lower bound: ${read.observed_lower_bound}; exact total unknown.` : " Exact total unknown."}
      </li>)}</ul>}
      {gaps.length > 0 && <div><b>Missing-link / assertion gaps in loaded evidence (not additive):</b><ul>{gaps.map(gap => <li key={gap.name}>
        {label(gap.name)}: {gap.count}{gap.denominator != null && ` of ${gap.denominator}`} · {gap.scope}
      </li>)}</ul></div>}
      {details.length > 0 && <ul>{details.map(row => <li key={row.name}>
        {label(row.name)}: {row.truncated ? "listing truncated" : "missing selected witnesses"}; limit {row.limit ?? "not specified"}.
        {(row.missing_within_selected_count ?? 0) > 0 && ` Missing selected witnesses: ${row.missing_within_selected_count}.`}
      </li>)}</ul>}
      <details>
        <summary>Read limits, traversal horizons and individual coverage checks</summary>
        <ul>{Object.entries(coverage.collections).map(([name, read]) => <li key={name}>
          {label(name)}: {read.returned ?? "unknown"} / limit {read.limit ?? "unknown"} {read.unit} · {read.truncated ? "truncated" : "within reported read limit; not discovery certification"}
          {read.scope && ` · ${read.scope}`}
        </li>)}</ul>
        <ul>{coverage.traversals.map((walk, index) => <li key={index}>
          {label(walk.scope)} {walk.direction}, depth {walk.max_depth}, {walk.unit}: {walk.extension_check === "NOT_EVALUATED" ? "extension not evaluated" : `unvisited next-hop neighbours: ${walk.unvisited_neighbour_count ?? "unknown"}`} · {walk.note}
        </li>)}</ul>
        <ul>{coverage.missing_links.map(gap => <li key={gap.name}>
          {label(gap.name)}: {gap.count ?? "not assessed / not applicable to selection"} · {gap.scope}
        </li>)}</ul>
        <ul>{coverage.explanations.map(row => <li key={row.name}>
          {label(row.name)}: returned {row.returned ?? "not counted"} / requested {row.requested ?? "not counted"}; limit {row.limit ?? "not specified"} · {row.scope}
        </li>)}</ul>
      </details>
      <div>No overall coverage percentage is inferred. “Within read limit” does not certify complete discovery or operational availability.</div>
    </section>
  );
}
