import React, { useState } from "react";
import type { RiskDimension } from "./types";
import { Bar } from "../components/ui.jsx";

function bandTone(d: RiskDimension): string {
  if (!d.known) return "slate";
  if (d.band === "CRITICAL" || d.band === "HIGH") return "red";
  if (d.band === "MEDIUM") return "amber";
  return "green";
}

/** The five risk dimensions, kept separate. Blending is never the default —
 *  the panel says so, and an unknown dimension is drawn as UNKNOWN, never 0. */
export default function RiskDimensionsPanel({
  dimensions,
}: {
  dimensions: RiskDimension[];
}) {
  const [open, setOpen] = useState<string | null>(null);

  return (
    <section aria-label="Risk dimensions">
      <h2>Risk — five separate dimensions, every score explainable</h2>
      <p className="muted">
        <span title={"Scores are never blended into one opaque number here. Each dimension shows the exact rules and evidence that produced it; an unknown dimension is unknown, not zero."}>{"Scores are never blended into one opaque number here."}</span>
      </p>
      <table aria-label="Risk dimensions">
        <thead>
          <tr>
            <th>dimension</th>
            <th>score</th>
            <th>band</th>
            <th>sense</th>
            <th>rules &amp; evidence</th>
            <th>reason</th>
          </tr>
        </thead>
        <tbody>
          {dimensions.map((d) => (
            <tr key={d.dimension}>
              <td>{d.dimension}</td>
              <td>
                {d.known && d.score !== null ? (
                  <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 120 }}>
                    <span style={{ fontFamily: "var(--mono)", fontWeight: 600, fontSize: 13, fontVariantNumeric: "tabular-nums" }}>
                      {d.score}
                    </span>
                    <div style={{ flex: 1, minWidth: 60, marginTop: 2 }}>
                      <Bar
                        value={Math.max(0, Math.min(100, d.score)) / 100}
                        tone={bandTone(d)}
                      />
                    </div>
                  </div>
                ) : (
                  <span className="chip chip-unknown">UNKNOWN — not zero</span>
                )}
              </td>
              <td>
                <span
                  className={
                    d.known
                      ? d.band === "CRITICAL" || d.band === "HIGH"
                        ? "chip chip-bad"
                        : "chip"
                      : "chip chip-unknown"
                  }
                >
                  {d.band}
                </span>
              </td>
              <td className="muted">
                {d.sense === "confidence" ? "higher is better" : "higher is risk"}
              </td>
              <td>
                <span
                  className="evidence"
                  role="button"
                  tabIndex={0}
                  onClick={() => setOpen(open === d.dimension ? null : d.dimension)}
                >
                  {d.factors.length} factor(s)
                </span>
                {open === d.dimension && (
                  <table aria-label={`${d.dimension} factors`}>
                    <tbody>
                      {d.factors.map((f, i) => (
                        <tr key={`${f.rule}-${i}`}>
                          <td>{f.rule}</td>
                          <td>{f.input}</td>
                          <td>+{f.contribution}</td>
                          <td>{f.evidence_ids.join(", ") || "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </td>
              <td className="muted">{d.reason ?? ""}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
