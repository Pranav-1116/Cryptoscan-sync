/* The simulation workspace.
 *
 * Everything on this page is a question asked of a *copy* of the twin. That shapes the
 * whole screen:
 *
 * - the scenario is built from this estate's own values (algorithms, protocols, components,
 *   targets), so a scenario is a choice rather than a guess at a string;
 * - the preview comes first, on its own request. "Would this match anything?" is cheap and
 *   the six BOM projections are not, and an operator needs to know a scenario matches
 *   nothing *before* reading a page of empty diffs;
 * - a run reports the engine's own `live_state_modified` and `live_projection_unchanged`
 *   fields rather than claiming read-only in prose;
 * - a stored run is labelled quarantined and carries the projection id it was measured
 *   against, because a simulation read a year later is a record of what was *asked*.
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Panel, Badge, Stat } from "../components/ui";
import { IconTarget, IconSecurity } from "../components/icons";
import {
  apiSimulationCatalog, apiSimulationPlan, apiSimulationRun, apiSimulationRuns,
  LiveBadge, ApiResult,
} from "../lib/api.js";
import type {
  SimulationCatalog, SimulationPreview, SimulationRun, SimulationRuns, SimulationScenario,
} from "../lib/api.js";

const FIELD_LABEL: Record<string, string> = {
  from: "From (the value the evidence holds today)",
  to: "To (the value the scenario would use instead)",
  key_size: "Key size (bits)",
};

const inputStyle: React.CSSProperties = {
  width: "100%", padding: "7px 10px", borderRadius: "var(--r)", background: "var(--panel-2)",
  border: "1px solid var(--line)", color: "var(--text)", fontSize: 12.5, fontFamily: "var(--mono)",
};

const labelStyle: React.CSSProperties = {
  display: "block", fontSize: 10.5, letterSpacing: ".06em", textTransform: "uppercase",
  color: "var(--faint)", marginBottom: 4,
};

/** The vocabulary, as chips. Clicking one fills the "before" side: that is the value the
 *  estate actually reported, which is the only value a scenario can match. */
function VocabularyChips({ label, values, onPick }: {
  label: string; values: Array<{ value: string; count: number }>; onPick: (value: string) => void;
}) {
  if (!values.length) {
    return (
      <div style={{ fontSize: 11.5, color: "var(--faint)" }}>
        {label}: none reported — a scenario using a value here would match nothing.
      </div>
    );
  }
  return (
    <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
      <span className="kicker" style={{ fontSize: 9.5, marginRight: 2 }}>{label}</span>
      {values.map((item) => (
        <button
          key={item.value}
          type="button"
          onClick={() => onPick(item.value)}
          title={`use ${item.value} as the before value (${item.count} evidence record(s))`}
          style={{
            padding: "3px 9px", borderRadius: 999, fontSize: 11.5, cursor: "pointer",
            background: "var(--panel-2)", border: "1px solid var(--line)",
            color: "var(--text)", fontFamily: "var(--mono)",
          }}
        >
          {item.value} <span style={{ color: "var(--faint)" }}>· {item.count}</span>
        </button>
      ))}
    </div>
  );
}

function changedKeys(before: Record<string, unknown>, after: Record<string, unknown>): string[] {
  const keys = new Set([...Object.keys(before || {}), ...Object.keys(after || {})]);
  return [...keys].filter((key) => JSON.stringify(before?.[key]) !== JSON.stringify(after?.[key]));
}

function EffectRow({ effect }: { effect: SimulationRun["effects"][number] }) {
  const changed = changedKeys(effect.before, effect.after);
  return (
    <div style={{ padding: "8px 12px", borderTop: "1px solid var(--line)" }}>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", fontSize: 12 }}>
        <span style={{ fontFamily: "var(--mono)", fontWeight: 700 }}>{effect.asset_name || effect.asset_id}</span>
        <span style={{ color: "var(--faint)", fontSize: 11 }}>{effect.layer} · {effect.evidence_type} · {effect.evidence_id}</span>
      </div>
      <div style={{ marginTop: 4, fontSize: 11.5, fontFamily: "var(--mono)", color: "var(--dim)", display: "grid", gap: 2 }}>
        {changed.length === 0 ? (
          <span style={{ color: "var(--amber)" }}>
            no fact differs — the selector matched a value the evidence already satisfies
          </span>
        ) : (
          changed.slice(0, 6).map((key) => (
            <span key={key}>
              {key}: <span style={{ color: "var(--faint)" }}>{String(effect.before?.[key] ?? "—")}</span>
              {" → "}
              <span style={{ color: "var(--text)" }}>{String(effect.after?.[key] ?? "—")}</span>
            </span>
          ))
        )}
      </div>
    </div>
  );
}

export default function Simulation() {
  const [catalog, setCatalog] = useState<ApiResult<SimulationCatalog> | null>(null);
  const [kind, setKind] = useState<string>("");
  const [fields, setFields] = useState<Record<string, string>>({});
  const [targets, setTargets] = useState<string[]>([]);
  const [label, setLabel] = useState("");
  const [preview, setPreview] = useState<{ key: string; data: SimulationPreview } | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [result, setResult] = useState<{ key: string; data: SimulationRun } | null>(null);
  const [resultError, setResultError] = useState<string | null>(null);
  const [history, setHistory] = useState<SimulationRuns | null>(null);
  const [busy, setBusy] = useState<"plan" | "run" | null>(null);

  useEffect(() => {
    let live = true;
    void (async () => {
      const response = await apiSimulationCatalog();
      if (!live) return;
      setCatalog(response);
      const first = response.data?.kinds?.[0]?.kind;
      if (first) setKind((current) => current || first);
    })();
    return () => { live = false; };
  }, []);

  const loadHistory = useCallback(async () => {
    const response = await apiSimulationRuns();
    if (response.ok && response.data) setHistory(response.data);
  }, []);

  useEffect(() => { void loadHistory(); }, [loadHistory]);

  const kinds = catalog?.data?.kinds ?? [];
  const entry = useMemo(
    () => kinds.find((item) => item.kind === kind) ?? kinds[0] ?? null,
    [kinds, kind],
  );

  // The form is driven by the catalog, not by a hardcoded kind switch: a new kind on the
  // server renders with its own inputs instead of silently sharing one.
  const requiredFields = (entry?.inputs ?? []).filter((name) => name !== "targets");
  const optionalFields = (entry?.optional ?? []).filter((name) => name !== "targets");
  const knownFields = [...requiredFields, ...optionalFields];

  const scenario: SimulationScenario = useMemo(() => {
    const built: SimulationScenario = { kind: entry?.kind ?? kind };
    for (const name of knownFields) {
      const value = (fields[name] ?? "").trim();
      if (!value) continue;
      if (name === "key_size") built.key_size = Number(value);
      else if (name === "from") built.from = value;
      else if (name === "to") built.to = value;
    }
    if (targets.length) built.targets = targets;
    if (label.trim()) built.label = label.trim();
    return built;
  }, [entry, kind, knownFields, fields, targets, label]);

  const scenarioKey = JSON.stringify(scenario);
  const previewIsCurrent = preview?.key === scenarioKey;
  const missing = requiredFields.filter((name) => !(fields[name] ?? "").trim());

  const selectKind = (next: string) => {
    setKind(next);
    setFields({});
    setTargets([]);
    setPreview(null);
    setPreviewError(null);
    setResult(null);
    setResultError(null);
  };

  const runPreview = async () => {
    setBusy("plan");
    setPreviewError(null);
    const response = await apiSimulationPlan(scenario);
    setBusy(null);
    if (!response.ok || !response.data) {
      setPreview(null);
      setPreviewError(response.error || "the plan request failed");
      return;
    }
    setPreview({ key: scenarioKey, data: response.data });
  };

  const runSimulation = async () => {
    setBusy("run");
    setResultError(null);
    const response = await apiSimulationRun(scenario);
    setBusy(null);
    if (!response.ok || !response.data) {
      setResult(null);
      setResultError(response.error || "the simulation request failed");
      return;
    }
    setResult({ key: scenarioKey, data: response.data });
    void loadHistory();
  };

  const catalogProblem = catalog && !catalog.ok;
  const estate = catalog?.data?.estate;
  const selector = catalog?.data?.selector;

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16, flexWrap: "wrap", gap: 16 }}>
        <div style={{ flex: "1 1 520px", minWidth: 280 }}>
          <div style={{
            display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px", borderRadius: 999,
            background: "color-mix(in srgb, var(--violet) 12%, transparent)", border: "1px solid var(--violet)",
            fontSize: 11, fontFamily: "var(--mono)", color: "var(--violet)", letterSpacing: ".06em",
          }}>
            <span style={{ width: 6, height: 6, borderRadius: 99, background: "var(--violet)" }} />
            INTELLIGENCE · SIMULATION · ASKS A COPY, NEVER THE ESTATE
          </div>
          <h1 style={{ fontSize: 26, fontWeight: 800, margin: "8px 0 6px", letterSpacing: "-0.02em", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ width: 34, height: 34, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--violet)", color: "#fff" }}>
              <IconTarget size={18} />
            </span>
            Simulation workspace
          </h1>
          <p style={{ margin: 0, fontSize: 13.5, color: "var(--dim)", lineHeight: 1.5, maxWidth: 680 }}>
            Ask the twin a question. Pick a scenario kind, choose from the values this estate
            actually reports, preview what it would touch, then run it against a copy —{" "}
            <b style={{ color: "var(--text)" }}>the live projection id must be identical before and after</b>.
          </p>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-start", flexWrap: "wrap" }}>
          {catalog && <LiveBadge source={catalog.source} label={catalog.source === "live" ? "LIVE TWIN" : "BACKEND OFFLINE"} />}
          {estate && (
            <Panel style={{ padding: "10px 14px", minWidth: 180 }}>
              <div className="kicker" style={{ fontSize: 9.5 }}>ESTATE THE ANSWER IS MEASURED AGAINST</div>
              <div style={{ fontSize: 12, fontFamily: "var(--mono)", marginTop: 4 }}>
                {estate.assets} assets · {estate.evidence} evidence
              </div>
              <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 2 }}>
                coverage {estate.coverage_state}
                {estate.collected != null ? ` · ${estate.collected} collected` : ""}
              </div>
              <div style={{ fontSize: 10.5, color: "var(--faint)", fontFamily: "var(--mono)", marginTop: 4 }}>
                {catalog?.data?.base_projection_id ?? "no projection id"}
              </div>
            </Panel>
          )}
        </div>
      </div>

      <div style={{
        display: "flex", gap: 8, alignItems: "center", padding: "10px 14px",
        background: "color-mix(in srgb, var(--violet) 8%, transparent)", border: "1px solid var(--violet)",
        borderRadius: "var(--r)", marginBottom: 14,
      }}>
        <span style={{ width: 28, height: 28, borderRadius: 8, display: "grid", placeItems: "center", background: "var(--violet)", color: "#fff" }}>
          <IconSecurity size={14} />
        </span>
        <div>
          <div style={{ fontSize: 12, fontWeight: 800, color: "var(--violet)" }}>SIMULATION ONLY — NOTHING IS EXECUTED</div>
          <div style={{ fontSize: 11, color: "var(--dim)" }}>
            A run applies the scenario to a snapshot of the twin and re-projects the six BOMs from that copy,
            then reports whether it touched the live state. A stored run is quarantined: it is a record of a
            question, never estate state.
          </div>
        </div>
      </div>

      {catalogProblem && (
        <Panel title="No twin to simulate against" sub="a simulation is asked of this estate's own evidence">
          <div style={{ fontSize: 12.5, color: "var(--dim)", lineHeight: 1.6 }}>
            {String(catalog?.error || "").includes("404")
              ? "Nothing has been discovered yet, so there is no evidence state to copy."
              : `The simulation catalog could not be read: ${catalog?.error}`}
            {" "}
            <Link to="/scanners">Run discovery</Link> — a simulate over an empty estate would report
            zero impact for everything, which is the one answer this page must never give.
          </div>
        </Panel>
      )}

      {!catalog && <Panel title="Reading the estate"><div style={{ fontSize: 12, color: "var(--dim)" }}>Loading the simulation catalog…</div></Panel>}

      {entry && (
        <Panel title="1 · Choose the question" sub="each kind answers a different question, and refuses the ones it cannot">
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))", gap: 8, marginBottom: 12 }}>
            {kinds.map((item) => {
              const selected = item.kind === entry.kind;
              return (
                <button
                  key={item.kind}
                  type="button"
                  onClick={() => selectKind(item.kind)}
                  aria-pressed={selected}
                  style={{
                    textAlign: "left", padding: "10px 12px", borderRadius: "var(--r)", cursor: "pointer",
                    background: selected ? "color-mix(in srgb, var(--violet) 14%, transparent)" : "var(--panel-2)",
                    border: `1px solid ${selected ? "var(--violet)" : "var(--line)"}`,
                    color: "var(--text)",
                  }}
                >
                  <div style={{ fontSize: 12.5, fontWeight: 800 }}>{item.name}</div>
                  <div style={{ fontSize: 11, color: "var(--dim)", marginTop: 3, lineHeight: 1.45 }}>{item.question}</div>
                </button>
              );
            })}
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 12 }}>
            <div>
              <div className="kicker" style={{ fontSize: 9.5, color: "var(--green)" }}>THIS KIND ANSWERS</div>
              <ul style={{ margin: "4px 0 0", paddingLeft: 18, fontSize: 11.5, color: "var(--dim)", lineHeight: 1.6 }}>
                {entry.answers.map((line) => <li key={line}>{line}</li>)}
              </ul>
            </div>
            <div>
              <div className="kicker" style={{ fontSize: 9.5, color: "var(--amber)" }}>AND DOES NOT ANSWER</div>
              <ul style={{ margin: "4px 0 0", paddingLeft: 18, fontSize: 11.5, color: "var(--dim)", lineHeight: 1.6 }}>
                {entry.does_not_answer.map((line) => <li key={line}>{line}</li>)}
              </ul>
            </div>
          </div>
        </Panel>
      )}

      {entry && (
        <Panel title="2 · Build the scenario" sub={selector?.note ?? "the values below are the ones this estate reported"}>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(230px, 1fr))", gap: 12 }}>
            {knownFields.map((name) => {
              const values = [...(selector?.algorithms ?? []), ...(selector?.protocols ?? []), ...(selector?.components ?? [])];
              const listId = `sim-values-${name}`;
              return (
                <label key={name} style={{ display: "block" }}>
                  <span style={labelStyle}>
                    {FIELD_LABEL[name] ?? name}
                    {requiredFields.includes(name) ? " *" : " (optional)"}
                  </span>
                  <input
                    aria-label={FIELD_LABEL[name] ?? name}
                    list={listId}
                    value={fields[name] ?? ""}
                    onChange={(event) => {
                      const value = event.target.value;
                      setFields((current) => ({ ...current, [name]: value }));
                      setPreview(null);
                      setResult(null);
                      setPreviewError(null);
                      setResultError(null);
                    }}
                    placeholder={name === "key_size" ? "e.g. 256" : "value from this estate"}
                    inputMode={name === "key_size" ? "numeric" : undefined}
                    style={inputStyle}
                  />
                  <datalist id={listId}>
                    {[...new Set(values.map((item) => item.value))].map((value) => (
                      <option key={value} value={value} />
                    ))}
                  </datalist>
                </label>
              );
            })}
          </div>

          <div style={{ marginTop: 12, display: "grid", gap: 8 }}>
            <VocabularyChips
              label="algorithms in this estate"
              values={selector?.algorithms ?? []}
              onPick={(value) => { setFields((current) => ({ ...current, from: value })); setPreview(null); setResult(null); }}
            />
            <VocabularyChips
              label="protocols in this estate"
              values={selector?.protocols ?? []}
              onPick={(value) => { setFields((current) => ({ ...current, from: value })); setPreview(null); setResult(null); }}
            />
            <VocabularyChips
              label="components in this estate"
              values={selector?.components ?? []}
              onPick={(value) => { setFields((current) => ({ ...current, from: value })); setPreview(null); setResult(null); }}
            />
          </div>

          <div style={{ marginTop: 14 }}>
            <span style={labelStyle}>
              Narrow to specific assets — no selection means every asset the selector matches
            </span>
            {selector && selector.targets.length > 0 ? (
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {selector.targets.map((target) => {
                  const picked = targets.includes(target.asset_id);
                  return (
                    <button
                      key={target.asset_id}
                      type="button"
                      aria-pressed={picked}
                      onClick={() => {
                        setTargets((current) => picked
                          ? current.filter((id) => id !== target.asset_id)
                          : [...current, target.asset_id]);
                        setPreview(null);
                        setResult(null);
                      }}
                      style={{
                        padding: "4px 10px", borderRadius: 999, fontSize: 11.5, cursor: "pointer",
                        fontFamily: "var(--mono)",
                        background: picked ? "color-mix(in srgb, var(--accent) 16%, transparent)" : "var(--panel-2)",
                        border: `1px solid ${picked ? "var(--accent)" : "var(--line)"}`,
                        color: "var(--text)",
                      }}
                    >
                      {target.name} <span style={{ color: "var(--faint)" }}>· {target.type}</span>
                    </button>
                  );
                })}
              </div>
            ) : (
              <div style={{ fontSize: 11.5, color: "var(--faint)" }}>
                The twin holds no assets that a scenario can be narrowed to.
              </div>
            )}
          </div>

          <div style={{ marginTop: 12, display: "flex", gap: 8, alignItems: "flex-end", flexWrap: "wrap" }}>
            <label style={{ flex: "1 1 240px" }}>
              <span style={labelStyle}>Label this run (optional)</span>
              <input
                aria-label="Label this run (optional)"
                value={label}
                onChange={(event) => setLabel(event.target.value)}
                placeholder="e.g. PQC pilot — payments"
                style={inputStyle}
              />
            </label>
            <button
              type="button"
              onClick={() => void runPreview()}
              disabled={busy !== null || missing.length > 0}
              style={{
                padding: "8px 14px", borderRadius: "var(--r)", fontWeight: 700, fontSize: 12,
                cursor: busy !== null || missing.length ? "not-allowed" : "pointer",
                background: "var(--panel-2)", border: "1px solid var(--accent)", color: "var(--accent)",
                opacity: busy !== null || missing.length ? 0.55 : 1,
              }}
            >
              {busy === "plan" ? "Previewing…" : "Preview match"}
            </button>
            <button
              type="button"
              onClick={() => void runSimulation()}
              disabled={busy !== null || !previewIsCurrent || preview?.data.status !== "WOULD_MATCH"}
              title={previewIsCurrent ? undefined : "preview the scenario first — a run over a selector that matches nothing is not a finding"}
              style={{
                padding: "8px 14px", borderRadius: "var(--r)", fontWeight: 700, fontSize: 12,
                cursor: busy !== null || !previewIsCurrent ? "not-allowed" : "pointer",
                background: "var(--violet)", border: "1px solid var(--violet)", color: "#fff",
                opacity: busy !== null || !previewIsCurrent || preview?.data.status !== "WOULD_MATCH" ? 0.55 : 1,
              }}
            >
              {busy === "run" ? "Running on a copy…" : "Run simulation"}
            </button>
          </div>
          <div style={{ marginTop: 8, fontSize: 11, color: "var(--faint)" }}>
            {missing.length > 0
              ? `Still needed: ${missing.join(", ")}`
              : previewIsCurrent
                ? "Running re-projects the six BOMs from the copy; the live estate is not written to."
                : "Preview first — the run button unlocks once the scenario is known to match something."}
          </div>
        </Panel>
      )}

      {previewError && (
        <Panel title="The scenario cannot be answered">
          <div style={{ fontSize: 12.5, color: "var(--red)" }}>{previewError}</div>
        </Panel>
      )}

      {preview?.data && previewIsCurrent && (
        <Panel
          title="3 · Preview — what this would touch"
          sub={`measured against ${preview.data.base_projection_id ?? "an unknown projection"}`}
          style={{ padding: 0, overflow: "hidden" } as React.CSSProperties}
        >
          <div style={{ padding: "12px 16px", display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
            <Badge tone={preview.data.status === "WOULD_MATCH" ? "green" : "amber"}>{preview.data.status.replace(/_/g, " ")}</Badge>
            <span style={{ fontSize: 12, color: "var(--dim)" }}>{preview.data.note}</span>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 10, padding: "0 16px 12px" }}>
            <Stat label="matched evidence" value={preview.data.matched_evidence} />
            <Stat label="assets affected" value={preview.data.affected_asset_count} />
            <Stat label="evidence considered" value={preview.data.evidence_considered} />
            <Stat label="coverage" value={`${preview.data.coverage?.coverage_percent ?? 0}%`} delta={preview.data.coverage?.coverage_state} />
          </div>
          {preview.data.affected_assets.length > 0 && (
            <div style={{ borderTop: "1px solid var(--line)" }}>
              {preview.data.affected_assets.map((asset) => (
                <div key={asset.asset_id} style={{
                  display: "flex", gap: 8, alignItems: "center", justifyContent: "space-between",
                  padding: "7px 16px", borderBottom: "1px solid var(--line)", fontSize: 12,
                }}>
                  <span>
                    <span style={{ fontWeight: 700 }}>{asset.name}</span>
                    <span style={{ color: "var(--faint)", fontSize: 11 }}> · {asset.type}</span>
                  </span>
                  <span style={{ fontFamily: "var(--mono)", fontSize: 11.5 }}>{asset.evidence_matched} record(s)</span>
                </div>
              ))}
            </div>
          )}
          <div style={{ padding: "10px 16px", display: "grid", gap: 6 }}>
            {Object.entries(preview.data.by_layer || {}).map(([layer, count]) => (
              <div key={layer} style={{ fontSize: 11.5, color: "var(--dim)", fontFamily: "var(--mono)" }}>
                {layer}: {count}
              </div>
            ))}
            {preview.data.unresolved_targets.length > 0 && (
              <div style={{ fontSize: 11.5, color: "var(--amber)" }}>
                Targets the twin does not hold: {preview.data.unresolved_targets.join(", ")} — they were not
                treated as "match everything".
              </div>
            )}
            {(preview.data.limits || []).map((line) => (
              <div key={line} style={{ fontSize: 11, color: "var(--faint)", lineHeight: 1.5 }}>· {line}</div>
            ))}
          </div>
        </Panel>
      )}

      {resultError && (
        <Panel title="The simulation did not run">
          <div style={{ fontSize: 12.5, color: "var(--red)" }}>{resultError}</div>
        </Panel>
      )}

      {result?.data && result.key === scenarioKey && (
        <SimulationResult result={result.data} />
      )}

      <Panel
        title="Run history"
        sub={history?.note ?? "stored runs are quarantined and labelled with the estate they were computed against"}
        style={{ padding: 0, overflow: "hidden" } as React.CSSProperties}
      >
        {history && history.simulations.length > 0 ? (
          history.simulations.map((row) => (
            <div key={row.id} style={{ padding: "9px 16px", borderTop: "1px solid var(--line)" }}>
              <div style={{ display: "flex", gap: 8, alignItems: "center", justifyContent: "space-between", flexWrap: "wrap" }}>
                <span style={{ fontSize: 12 }}>
                  <b>{row.label || row.scenario?.from || row.kind}</b>
                  {row.scenario?.to ? <span style={{ color: "var(--dim)" }}> → {row.scenario.to}</span> : null}
                  <span style={{ color: "var(--faint)", fontSize: 11 }}> · {row.kind} · {row.observations} run(s)</span>
                </span>
                <span style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
                  <Badge tone={row.superseded ? "amber" : "green"}>{row.superseded ? "SUPERSEDED" : "CURRENT"}</Badge>
                  <span style={{ fontSize: 11, color: "var(--faint)", fontFamily: "var(--mono)" }}>
                    {row.matched_evidence} matched · {row.affected_assets?.length ?? 0} asset(s)
                  </span>
                </span>
              </div>
              <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 3, fontFamily: "var(--mono)" }}>
                against {row.computed_against ?? "unknown projection"} · {row.last_run_at ?? "no timestamp"}
              </div>
              {row.superseded && (
                <div style={{ fontSize: 11, color: "var(--amber)", marginTop: 2 }}>
                  the estate has moved to {row.superseded_by} — this describes an estate that no longer exists
                </div>
              )}
            </div>
          ))
        ) : (
          <div style={{ padding: "12px 16px", fontSize: 12, color: "var(--dim)" }}>
            No stored runs yet. A run is only stored when it matched something — "nothing to simulate"
            is not written down as a finding.
          </div>
        )}
        {history?.quarantined && (
          <div style={{ padding: "9px 16px", borderTop: "1px solid var(--line)", fontSize: 11, color: "var(--faint)" }}>
            Quarantined: none of these rows counts as estate state, in a BOM, a posture score or a report.
          </div>
        )}
      </Panel>

      {catalog?.data?.limits && (
        <Panel title="What this workspace cannot tell you">
          <ul style={{ margin: 0, paddingLeft: 18, fontSize: 11.5, color: "var(--dim)", lineHeight: 1.6 }}>
            {catalog.data.limits.map((line) => <li key={line}>{line}</li>)}
          </ul>
          <div style={{ marginTop: 8, fontSize: 11, color: "var(--faint)" }}>{catalog.data.note}</div>
        </Panel>
      )}
    </div>
  );
}

function SimulationResult({ result }: { result: SimulationRun }) {
  const boms = Object.entries(result.bom_diff || {});
  const counts = result.impact?.counts ?? {};
  const unknown = result.unknown ?? {};
  const refused = !result.persisted;

  return (
    <>
      <Panel
        title="4 · Result — what changes on the copy"
        sub={`copy ${result.simulated_projection_id ?? "—"} · measured against ${result.base_projection_id ?? "—"}`}
        style={{ padding: 0, overflow: "hidden" } as React.CSSProperties}
      >
        <div style={{ padding: "12px 16px", display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <Badge tone={result.status === "SIMULATED" ? "green" : result.status === "NO_MATCH" ? "amber" : "red"}>
            {result.status.replace(/_/g, " ")}
          </Badge>
          <Badge tone={result.live_state_modified ? "red" : "green"}>
            {result.live_state_modified ? "LIVE STATE MODIFIED" : "LIVE STATE UNTOUCHED"}
          </Badge>
          <Badge tone={result.live_projection_unchanged ? "green" : "red"}>
            {result.live_projection_unchanged ? "PROJECTION ID UNCHANGED" : "PROJECTION ID MOVED"}
          </Badge>
          <span style={{ fontSize: 11.5, color: "var(--dim)" }}>{result.note}</span>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 10, padding: "0 16px 12px" }}>
          <Stat label="matched evidence" value={result.matched_evidence} />
          <Stat label="assets affected" value={result.affected_assets?.length ?? 0} />
          <Stat label="blast radius" value={counts.total ?? 0} delta={`${counts.direct ?? 0} direct`} />
          <Stat label="blockers" value={result.blockers?.length ?? 0} />
        </div>

        <div style={{ padding: "0 16px 12px", display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <span className="kicker" style={{ fontSize: 9.5 }}>STORAGE</span>
          {result.persisted ? (
            <span style={{ fontSize: 11.5, color: "var(--dim)" }}>
              quarantined run <b style={{ fontFamily: "var(--mono)" }}>{result.simulation_id}</b> — {result.persist_note}
            </span>
          ) : (
            <span style={{ fontSize: 11.5, color: "var(--amber)" }}>
              not stored: {result.persist_refused_because || result.persist_note || "the result was not storable"}
            </span>
          )}
        </div>

        <div style={{ borderTop: "1px solid var(--line)" }}>
          <div style={{ padding: "8px 16px", fontSize: 11, letterSpacing: ".06em", textTransform: "uppercase", color: "var(--faint)" }}>
            evidence that would change
          </div>
          {(result.effects || []).length === 0 ? (
            <div style={{ padding: "8px 16px 12px", fontSize: 12, color: "var(--dim)" }}>
              No evidence record changed. That is the honest answer for a selector that matched nothing —
              not a statement that the change is safe.
            </div>
          ) : (
            result.effects.map((effect) => <EffectRow key={effect.evidence_id + effect.asset_id} effect={effect} />)
          )}
        </div>

        <div style={{ borderTop: "1px solid var(--line)", padding: "10px 16px" }}>
          <div style={{ fontSize: 11, letterSpacing: ".06em", textTransform: "uppercase", color: "var(--faint)", marginBottom: 6 }}>
            six BOMs re-projected from the copy
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 6 }}>
            {boms.map(([bom, diff]) => (
              <div key={bom} style={{ fontSize: 11.5, fontFamily: "var(--mono)", color: "var(--dim)" }}>
                <b style={{ color: "var(--text)" }}>{bom}</b>{" "}
                +{diff.counts?.added ?? 0} −{diff.counts?.removed ?? 0} ~{diff.counts?.changed ?? 0}
                {diff.counts?.unchanged ? ` · ${diff.counts.unchanged} unchanged` : ""}
              </div>
            ))}
          </div>
        </div>

        <div style={{ borderTop: "1px solid var(--line)", padding: "10px 16px", display: "grid", gap: 6 }}>
          <div style={{ fontSize: 11, letterSpacing: ".06em", textTransform: "uppercase", color: "var(--faint)" }}>
            blockers and unknowns
          </div>
          {(result.blockers || []).length === 0 ? (
            <div style={{ fontSize: 11.5, color: "var(--dim)" }}>
              No blocker was reported. A blocker is only raised where the evidence contradicts the target,
              so an empty list is not evidence that the change is safe.
            </div>
          ) : (
            result.blockers.map((blocker, index) => (
              <div key={index} style={{ fontSize: 11.5, color: "var(--amber)", fontFamily: "var(--mono)" }}>
                {Object.entries(blocker).map(([key, value]) => `${key}=${JSON.stringify(value)}`).join(" · ")}
              </div>
            ))
          )}
          {Object.entries(unknown).map(([key, value]) => (
            <div key={key} style={{ fontSize: 11.5, color: "var(--faint)" }}>
              <b style={{ color: "var(--text)" }}>{key.replace(/_/g, " ")}</b>: {typeof value === "string" ? value : JSON.stringify(value)}
            </div>
          ))}
        </div>
      </Panel>

      {refused && result.status === "NO_MATCH" && (
        <Panel title="Nothing to simulate">
          <div style={{ fontSize: 12.5, color: "var(--dim)", lineHeight: 1.6 }}>
            The scenario matched no evidence record, so there is no copy to project and nothing to store.
            Widen the selector — the chips in step 2 are the values this estate actually reports — or
            run discovery if the asset you expected is missing from the twin.
          </div>
        </Panel>
      )}
    </>
  );
}
