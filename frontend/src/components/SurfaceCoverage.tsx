/* Discovery surface coverage — the honest coverage sentence, rendered verbatim.
 *
 * The matrix comes from GET /estate/evidence/discovery/surfaces, which resolves
 * each surface against the detectors that actually exist in this build. Nothing
 * here is computed on the client: the claim sentence, the maturity ceiling, the
 * gaps and the observed state are all echoed from the response.
 *
 * Three axes are shown side by side because collapsing them is how a partial
 * collector becomes a marketing claim:
 *   kind        — how the surface is read (live API, probe, artifact, code, import)
 *   maturity    — the ceiling of what the collector can establish, with its gaps
 *   observed    — what the last discovery run actually collected (or "not observed")
 */
import React, { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Panel, Badge } from "./ui.jsx";
import { apiDiscoverySurfaces, type DiscoverySurfaces, type DiscoverySurface } from "../lib/api.js";

const MATURITY_TONE: Record<string, string> = {
  MEASURED: "green",
  PARTIAL: "amber",
  METADATA_ONLY: "cyan",
  IMPORT_ONLY: "slate",
  DECLARED_ONLY: "slate",
  NOT_IMPLEMENTED: "red",
};

const KIND_LABEL: Record<string, string> = {
  LIVE_CONTROL_PLANE: "live control plane",
  LIVE_PROBE: "live probe",
  ARTIFACT_PARSER: "artifact parser",
  STATIC_ANALYSIS: "static analysis",
  IMPORT: "import",
  DECLARATION: "declaration",
};

const OBSERVED_TONE: Record<string, string> = {
  COMPLETE: "green",
  PARTIAL: "amber",
  FAILED: "red",
  NOT_ATTEMPTED: "slate",
  NOT_OBSERVED: "slate",
};

function observedText(surface: DiscoverySurface): string {
  const observed = surface.observed;
  if (observed.state === "NOT_OBSERVED") return "not observed";
  if (observed.state === "NOT_ATTEMPTED") return "plane not attempted";
  const count = typeof observed.collected === "number" ? ` · ${observed.collected} collected` : "";
  return `${observed.state.toLowerCase()}${count}`;
}

export default function SurfaceCoverage() {
  const [doc, setDoc] = useState<DiscoverySurfaces | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);

  const load = useCallback(async () => {
    const result = await apiDiscoverySurfaces();
    if (result.source === "live" && result.data) {
      setDoc(result.data);
      setError(null);
    } else {
      setDoc(null);
      setError(result.detail || result.error || "coverage matrix unavailable");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  if (error) {
    return (
      <Panel title="Discovery coverage" sub="what this build can read, per crypto surface">
        {/* role="status", not "alert": an unread matrix is a standing condition of
            this panel, and it must not make the page's genuine run alerts ambiguous. */}
        <p role="status" style={{ margin: 0, fontSize: 12.5, color: "var(--amber)" }}>
          Coverage matrix not read — {error}. No coverage claim is printed that was not read from
          the registry.
        </p>
      </Panel>
    );
  }

  if (!doc) {
    return (
      <Panel title="Discovery coverage" sub="what this build can read, per crypto surface">
        <p style={{ margin: 0, fontSize: 12.5, color: "var(--dim)" }}>Reading the surface registry…</p>
      </Panel>
    );
  }

  const rollup = doc.rollup;

  return (
    <Panel
      title="Discovery coverage"
      sub="each surface resolves against the detectors present in this build — no surface is claimed complete"
      style={{ marginTop: 24 }}
    >
      <p style={{ margin: "0 0 12px", fontSize: 12.5, color: "var(--text)", lineHeight: 1.5 }}>
        {doc.claim}
      </p>

      <div className="row" style={{ gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
        <Badge tone="cyan">{rollup.surfaces} surfaces</Badge>
        {Object.entries(rollup.by_maturity)
          .filter(([, count]) => count > 0)
          .map(([state, count]) => (
            <Badge key={state} tone={MATURITY_TONE[state] ?? "slate"}>
              {count} {state.replace(/_/g, " ").toLowerCase()}
            </Badge>
          ))}
        <Badge tone={rollup.observed_in_last_run ? "green" : "slate"}>
          {rollup.observed_in_last_run} observed in last run
        </Badge>
        <Badge tone="slate">{rollup.credentials_resolved} credential-resolved</Badge>
        <Badge tone="slate">{rollup.no_credentials_needed} need no credentials</Badge>
      </div>

      <div style={{ display: "grid", gap: 8 }}>
        {doc.surfaces.map((surface) => {
          const expanded = open === surface.id;
          const missing = surface.detectors.filter((detector) => !detector.present);
          return (
            <div
              key={surface.id}
              style={{ border: "1px solid var(--line)", borderRadius: "var(--r)", background: "var(--panel-2)" }}
            >
              <button
                type="button"
                aria-expanded={expanded}
                onClick={() => setOpen(expanded ? null : surface.id)}
                style={{
                  width: "100%", display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap",
                  padding: "9px 12px", background: "transparent", border: "none", cursor: "pointer",
                  color: "var(--text)", textAlign: "left",
                }}
              >
                <span style={{ fontSize: 13, fontWeight: 600, minWidth: 190 }}>{surface.label}</span>
                <Badge tone="violet">{KIND_LABEL[surface.kind] ?? surface.kind}</Badge>
                <Badge tone={MATURITY_TONE[surface.maturity] ?? "slate"}>
                  {surface.maturity.replace(/_/g, " ")}
                </Badge>
                <Badge tone={OBSERVED_TONE[surface.observed.state] ?? "slate"}>
                  {observedText(surface)}
                </Badge>
                {surface.configuration.state !== "CONFIGURED" && (
                  <Badge tone={surface.configuration.state === "NOT_CONFIGURED" ? "amber" : "slate"}>
                    {surface.configuration.state === "NOT_CONFIGURED" ? "not configured here" : "configuration unknown"}
                  </Badge>
                )}
                {missing.length > 0 && <Badge tone="red">{missing.length} detector(s) absent</Badge>}
                <span style={{ marginLeft: "auto", fontFamily: "var(--mono)", fontSize: 10.5, color: "var(--faint)" }}>
                  {expanded ? "hide detail" : "detail"}
                </span>
              </button>

              {expanded && (
                <div style={{ padding: "0 12px 12px", display: "grid", gap: 8 }}>
                  <div style={{ fontSize: 12, color: "var(--text)" }}>
                    <strong style={{ color: "var(--dim)" }}>Reads:</strong> {surface.reads}
                  </div>
                  <div
                    style={{
                      fontSize: 12, color: "var(--amber)", background: "color-mix(in srgb, var(--amber) 8%, transparent)",
                      border: "1px solid var(--amber)", borderRadius: "var(--r)", padding: "6px 9px",
                    }}
                  >
                    <strong>Cannot claim:</strong> {surface.cannot_claim}
                  </div>
                  {surface.gaps.length > 0 && (
                    <div style={{ fontSize: 11.5, color: "var(--dim)" }}>
                      <strong>Known gaps:</strong>{" "}
                      {surface.gaps.map((gap, index) => (
                        <span key={gap}>
                          {index > 0 ? " · " : ""}
                          {gap}
                        </span>
                      ))}
                    </div>
                  )}
                  <div style={{ fontSize: 11.5, color: "var(--dim)" }}>
                    <strong>Plane(s):</strong> {surface.planes.join(", ")} ·{" "}
                    <strong>Configuration:</strong> {surface.configuration.state.toLowerCase()}
                    {surface.configuration.reason ? ` (${surface.configuration.reason})` : ""}
                  </div>
                  <div style={{ fontSize: 11.5, color: "var(--dim)" }}>
                    <strong>Observed:</strong> {observedText(surface)}
                    {surface.observed.reason ? ` — ${surface.observed.reason}` : ""}
                  </div>
                  <div style={{ fontSize: 10.5, fontFamily: "var(--mono)", color: "var(--faint)", overflowWrap: "anywhere" }}>
                    {surface.detectors.map((detector) => (
                      <div key={detector.ref} style={{ color: detector.present ? "var(--faint)" : "var(--red)" }}>
                        {detector.present ? "present" : "absent"} · {detector.ref}
                        {detector.reason ? ` — ${detector.reason}` : ""}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      <p style={{ margin: "12px 0 0", fontSize: 10.5, color: "var(--faint)" }}>
        {doc.note}{" "}
        <Link to="/collector-depth" style={{ color: "var(--accent)" }}>
          How far each collector actually reaches →
        </Link>
      </p>
    </Panel>
  );
}
