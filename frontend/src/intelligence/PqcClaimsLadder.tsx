import React from "react";
import type { PqcStageName, PqcSubject } from "./types";
import { FlowStrip, type FlowState } from "../components/viz";

const STAGES: PqcStageName[] = [
  "SUPPORT_AVAILABLE",
  "CONFIGURED",
  "RUNTIME_OBSERVED",
  "NETWORK_NEGOTIATED",
  "MIGRATION_VALIDATED",
];

function stageChip(state: string) {
  if (state === "CLAIMED") return <span className="chip chip-ok">CLAIMED</span>;
  if (state === "CLAIMED_STALE")
    return <span className="chip chip-unknown">CLAIMED — STALE</span>;
  return <span className="chip chip-unknown">NOT CLAIMED</span>;
}

/** The five PQC migration stages per subject. Support is never drawn as
 *  readiness: the ladder stays visible and the readiness chip only turns
 *  positive on validated evidence. */
export default function PqcClaimsLadder({
  subjects,
}: {
  subjects: PqcSubject[];
}) {
  return (
    <section aria-label="PQC migration stages">
      <h2>PQC migration — five stages, five separate claims</h2>
      <div className="banner">
        A library supporting ML-KEM is not PQC readiness. Support is not
        configured, configured is not observed, observed is not validated.
      </div>
      <div style={{ margin: "10px 0 12px" }}>
        <FlowStrip
          label="the five PQC stages in order"
          stages={STAGES.map((stage) => {
            const claimed = subjects.filter(
              (s) => (s.stages[stage]?.state ?? "NOT_CLAIMED") !== "NOT_CLAIMED",
            ).length;
            const state: FlowState =
              claimed === 0 ? "pending" : claimed === subjects.length ? "done" : "active";
            return {
              label: stage,
              state,
              note: `${claimed}/${subjects.length} subject(s) claim this stage`,
            };
          })}
        />
      </div>
      <table aria-label="PQC claims by subject">
        <thead>
          <tr>
            <th>subject</th>
            {STAGES.map((s) => (
              <th key={s}>{s.replace(/_/g, " ")}</th>
            ))}
            <th>readiness</th>
            <th>why</th>
          </tr>
        </thead>
        <tbody>
          {subjects.map((s) => (
            <tr key={s.subject}>
              <td>{s.subject}</td>
              {STAGES.map((stage) => (
                <td key={stage}>{stageChip(s.stages[stage]?.state ?? "NOT_CLAIMED")}</td>
              ))}
              <td>
                <span
                  className={
                    s.readiness === "PQC_READY_VALIDATED"
                      ? "chip chip-ok"
                      : "chip chip-unknown"
                  }
                >
                  {s.readiness}
                </span>
              </td>
              <td className="muted">{s.readiness_reason}</td>
            </tr>
          ))}
          {subjects.length === 0 && (
            <tr>
              <td colSpan={8} className="muted">
                no migration-stage claims recorded — unknown, which is neither
                ready nor fine
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </section>
  );
}
