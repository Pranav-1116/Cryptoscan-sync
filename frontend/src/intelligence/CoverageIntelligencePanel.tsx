import React from "react";
import type { CoverageIntelligence } from "./types";

/** Estate coverage intelligence. The banner is the point: a missing asset must
 *  never silently become a clean security result, and a refused percentage is
 *  shown as refused, not estimated. */
export default function CoverageIntelligencePanel({
  coverage,
}: {
  coverage: CoverageIntelligence;
}) {
  return (
    <section aria-label="Estate coverage intelligence">
      <h2>Collection coverage — what the estate can and cannot see</h2>
      {coverage.verdict !== "COVERAGE_COMPLETE" && (
        <div className="banner">
          A missing asset must never silently become a clean security result.
        </div>
      )}
      <table aria-label="Coverage summary">
        <tbody>
          <tr>
            <th>verdict</th>
            <td>
              <span
                className={
                  coverage.verdict === "COVERAGE_COMPLETE"
                    ? "chip chip-ok"
                    : "chip chip-bad"
                }
              >
                {coverage.verdict}
              </span>{" "}
              {coverage.reason}
            </td>
          </tr>
          <tr>
            <th>targets</th>
            <td>
              authorized {coverage.authorized_targets} · discovered{" "}
              {coverage.discovered_assets} · unknown {coverage.unknown_assets}
            </td>
          </tr>
          <tr>
            <th>coverage %</th>
            <td>
              {coverage.coverage_percent !== null ? (
                `${coverage.coverage_percent}%`
              ) : (
                <span className="chip chip-unknown">
                  REFUSED — {coverage.percent_note ?? "denominator unknown"}
                </span>
              )}
            </td>
          </tr>
          <tr>
            <th>needs eyes</th>
            <td>
              stale evidence {coverage.stale_evidence} · access denied{" "}
              {coverage.access_denied_targets} · unverified relationships{" "}
              {coverage.unverified_relationships}
            </td>
          </tr>
        </tbody>
      </table>
      {coverage.gaps.length > 0 && (
        <table aria-label="Coverage gaps">
          <thead>
            <tr>
              <th>gap</th>
              <th>count</th>
              <th>detail</th>
              <th>clean result?</th>
            </tr>
          </thead>
          <tbody>
            {coverage.gaps.map((g, i) => (
              <tr key={`${g.kind}-${i}`}>
                <td>
                  <span className="chip chip-bad">{g.kind}</span>
                </td>
                <td>{g.count}</td>
                <td>{g.detail}</td>
                <td>
                  {g.is_clean_result ? "yes" : (
                    <span className="chip chip-unknown">never</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
