import React from "react";
import type { SimulationResult, SimulatedDependency } from "./types";

function DependencyTable({
  title,
  rows,
  assumed,
}: {
  title: string;
  rows: SimulatedDependency[];
  assumed: boolean;
}) {
  return (
    <table aria-label={title}>
      <thead>
        <tr>
          <th>{title}</th>
          <th>dependency chain</th>
          {assumed && <th>why assumed</th>}
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <tr key={row.asset}>
            <td>{row.asset}</td>
            <td>
              {row.chain.map((hop, i) => (
                <span key={i}>
                  {i > 0 && " → "}
                  <span
                    className={
                      hop.provenance === "PROVEN" ? "chip chip-ok" : "chip chip-unknown"
                    }
                  >
                    {hop.from} [{hop.provenance}] {hop.predicate} {hop.to}
                  </span>
                </span>
              ))}
            </td>
            {assumed && <td className="muted">{row.why_assumed}</td>}
          </tr>
        ))}
        {rows.length === 0 && (
          <tr>
            <td colSpan={assumed ? 3 : 2} className="muted">
              none recorded
            </td>
          </tr>
        )}
      </tbody>
    </table>
  );
}

/** Simulation output. The hypothetical banner is permanent: a simulated result
 *  is never shown as a real production change, and proven dependencies are
 *  never mixed with assumed ones. */
export default function SimulationPanel({ result }: { result: SimulationResult }) {
  return (
    <section aria-label="Scenario simulation">
      <h2>
        Simulation — {result.scenario}: {result.description}
      </h2>
      <div className="banner">
        HYPOTHETICAL — simulated against snapshot {result.snapshot.snapshot_id} v
        {result.snapshot.version} ({result.snapshot.captured_at}). Never shown as
        a real production change.
      </div>
      <DependencyTable
        title="proven dependencies"
        rows={result.proven_dependencies}
        assumed={false}
      />
      <DependencyTable
        title="assumed dependencies (not proven)"
        rows={result.assumed_dependencies}
        assumed
      />
      <table aria-label="What would be required">
        <thead>
          <tr>
            <th>approvals that WOULD be required</th>
            <th>rollback that WOULD be planned</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>
              <ul>
                {result.approvals_required.map((a, i) => (
                  <li key={i}>{a}</li>
                ))}
              </ul>
            </td>
            <td>
              <ul>
                {result.rollback_plan.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
            </td>
          </tr>
        </tbody>
      </table>
    </section>
  );
}
