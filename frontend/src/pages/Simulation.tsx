/* The simulation workspace.
 *
 * Everything on this page is a question asked *of* the estate, never an action taken on
 * it. Two families share the page because they share the two questions an operator has:
 *
 * - a **scenario** edits an evidence fact on a copy of the twin, re-projects the six BOMs
 *   from that copy and reports the diff ("if AES-256 became ML-KEM…");
 * - a **cascade** propagates a failure through the established dependency edges and
 *   reports what is reached, wave by wave ("if PostgreSQL stopped…"). It changes no
 *   evidence at all, which is why it has no BOM diff and says so instead of printing six
 *   empty ones.
 *
 * Both are previewed before they run: "would this match, would this reach" is cheap, and
 * the answer is what stops an operator from reading a page of nothing as good news.
 */
import { FlowStrip, StackedBar, HBars } from "../components/viz";
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Panel, Badge, Stat } from "../components/ui";
import { IconTarget, IconSecurity } from "../components/icons";
import EstateDiscoveryCta from "../components/EstateDiscoveryCta";
import {
  apiSimulationCatalog, apiSimulationPlan, apiSimulationRun, apiSimulationRuns,
  apiEstateTwinSnapshots, LiveBadge, ApiResult,
} from "../lib/api.js";
import type {
  SimulationCatalog, SimulationPreview, SimulationRun, SimulationRuns, SimulationScenario,
  SimulationPerformanceInput, SimulationPreset, SimulationWave, EstateTwinSnapshotSummary,
} from "../lib/api.js";

const FIELD_LABEL: Record<string, string> = {
  from: "From (the value the evidence holds today)",
  to: "To (the value the scenario would use instead)",
  key_size: "Key size (bits)",
  expression: "Expression (JSON: {\"when\": …, \"then\": {\"set\": …, \"unset\": …}})",
  steps: "Steps (JSON array of scenarios, applied in order — at most 5)",
};

const inputStyle: React.CSSProperties = {
  width: "100%", padding: "7px 10px", borderRadius: "var(--r)", background: "var(--panel-2)",
  border: "1px solid var(--line)", color: "var(--text)", fontSize: 12.5, fontFamily: "var(--mono)",
};

const labelStyle: React.CSSProperties = {
  display: "block", fontSize: 10.5, letterSpacing: ".06em", textTransform: "uppercase",
  color: "var(--faint)", marginBottom: 4,
};

const chipStyle = (active: boolean): React.CSSProperties => ({
  padding: "4px 10px", borderRadius: 999, fontSize: 11.5, cursor: "pointer",
  fontFamily: "var(--mono)", textAlign: "left",
  background: active ? "color-mix(in srgb, var(--accent) 16%, transparent)" : "var(--panel-2)",
  border: `1px solid ${active ? "var(--accent)" : "var(--line)"}`,
  color: "var(--text)",
});

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

/** One wave of a cascade: what arrived, and the edge it arrived by. */
function WaveBlock({ wave }: { wave: SimulationWave }) {
  return (
    <div style={{ borderTop: "1px solid var(--line)" }}>
      <div style={{
        display: "flex", justifyContent: "space-between", alignItems: "center",
        padding: "7px 16px", background: "var(--panel-2)", fontSize: 11,
        letterSpacing: ".06em", textTransform: "uppercase", color: "var(--faint)",
      }}>
        <span>wave {wave.depth}</span>
        <span>{wave.count} asset(s){wave.truncated ? ` · ${wave.truncated} more not listed` : ""}</span>
      </div>
      {wave.assets.map((asset) => (
        <div key={asset.asset_id} style={{
          display: "flex", justifyContent: "space-between", gap: 10, flexWrap: "wrap",
          padding: "7px 16px", borderTop: "1px solid var(--line)", fontSize: 12,
        }}>
          <span>
            <span style={{ fontWeight: 700 }}>{asset.name || asset.asset_id}</span>
            <span style={{ color: "var(--faint)", fontSize: 11 }}> · {asset.type}</span>
          </span>
          <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--dim)" }}
                title={asset.via?.meaning ?? undefined}>
            {asset.via?.predicate} ← {asset.via?.from_name || asset.via?.from_asset}
          </span>
        </div>
      ))}
    </div>
  );
}

export default function Simulation() {
  const [catalog, setCatalog] = useState<ApiResult<SimulationCatalog> | null>(null);
  const [kind, setKind] = useState<string>("");
  const [fields, setFields] = useState<Record<string, string>>({});
  const [targets, setTargets] = useState<string[]>([]);
  const [depth, setDepth] = useState<number>(3);
  const [label, setLabel] = useState("");
  const [performanceText, setPerformanceText] = useState("");
  const [preset, setPreset] = useState<string | null>(null);
  const [preview, setPreview] = useState<{ key: string; data: SimulationPreview } | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [result, setResult] = useState<{ key: string; data: SimulationRun } | null>(null);
  const [resultError, setResultError] = useState<string | null>(null);
  const [history, setHistory] = useState<SimulationRuns | null>(null);
  const [snapshots, setSnapshots] = useState<EstateTwinSnapshotSummary[] | null>(null);
  const [snapshotError, setSnapshotError] = useState<string | null>(null);
  const [copiedSnapshot, setCopiedSnapshot] = useState<string | null>(null);
  const [busy, setBusy] = useState<"plan" | "run" | null>(null);

  const loadCatalog = useCallback(async () => {
    const response = await apiSimulationCatalog();
    setCatalog(response);
    const first = response.data?.kinds?.[0]?.kind;
    if (first) setKind((current) => current || first);
  }, []);

  useEffect(() => { void loadCatalog(); }, [loadCatalog]);

  const loadHistory = useCallback(async () => {
    const response = await apiSimulationRuns();
    if (response.ok && response.data) setHistory(response.data);
  }, []);

  /* A COMPOSITE step may name a stored snapshot with `as_of`. The ids are opaque and a
     typed guess is a 404, so the console lists the snapshots this tenant actually holds
     and offers them as chips — the only ids that can resolve are the ones on screen. */
  const loadSnapshots = useCallback(async () => {
    const response = await apiEstateTwinSnapshots();
    setSnapshots(response.ok ? response.data?.snapshots ?? [] : null);
    if (!response.ok) {
      setSnapshotError("the snapshot list could not be read — that is not 'no snapshots exist'");
    }
  }, []);

  useEffect(() => { void loadHistory(); }, [loadHistory]);
  useEffect(() => { void loadSnapshots(); }, [loadSnapshots]);

  /* A snapshot id is opaque, so the chip copies it rather than editing the JSON: the
     steps field is parsed before it is sent, and splicing an id into a half-typed array
     would turn a valid plan into a syntax error. */
  const copySnapshotId = (identifier: string) => {
    setCopiedSnapshot(identifier);
    void navigator.clipboard?.writeText(identifier).catch(() => undefined);
  };

  const kinds = catalog?.data?.kinds ?? [];
  const modes = catalog?.data?.modes ?? [];
  const entry = useMemo(
    () => kinds.find((item) => item.kind === kind) ?? kinds[0] ?? null,
    [kinds, kind],
  );
  const isCascade = (entry?.mode ?? "SCENARIO") === "CASCADE";
  const modeInfo = modes.find((item) => item.mode === (entry?.mode ?? "SCENARIO"));

  // The form is driven by the catalog, not by a hardcoded kind switch: a new kind on the
  // server renders with its own inputs instead of silently sharing one. `depth` and
  // `targets` are rendered by their own controls.
  const formFields = useMemo(
    () => [...(entry?.inputs ?? []), ...(entry?.optional ?? [])].filter(
      (name) => name !== "targets" && name !== "depth",
    ),
    [entry],
  );
  const requiredFields = (entry?.inputs ?? []).filter((name) => name !== "targets" && name !== "depth");

  /* A CUSTOM expression and a COMPOSITE sequence are both data, so the console parses
     them before sending: a JSON syntax error must be caught here, where it can be
     pointed at, not reported back as an engine refusal. */
  const jsonFieldError = useMemo(() => {
    const errors: Record<string, string> = {};
    const expressionRaw = (fields["expression"] ?? "").trim();
    if (expressionRaw) {
      try {
        const parsed = JSON.parse(expressionRaw);
        if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
          errors.expression = "the expression must be a JSON object with 'when' and 'then'";
        }
      } catch (error) {
        errors.expression = `not valid JSON: ${(error as Error).message}`;
      }
    }
    const stepsRaw = (fields["steps"] ?? "").trim();
    if (stepsRaw) {
      try {
        const parsed = JSON.parse(stepsRaw);
        if (!Array.isArray(parsed)) {
          errors.steps = "steps must be a JSON array of scenarios, applied in order";
        } else if (parsed.length === 0) {
          errors.steps = "a sequence with no steps asks nothing";
        }
      } catch (error) {
        errors.steps = `not valid JSON: ${(error as Error).message}`;
      }
    }
    return errors;
  }, [fields]);

  const performanceInput = useMemo(() => {
    if (!performanceText.trim()) return { value: null, error: null };
    try {
      const parsed: unknown = JSON.parse(performanceText);
      const required = ["tenant_id", "asset_ref", "metric_name", "source_id",
        "change_event_id", "before_start", "before_end", "after_start", "after_end"];
      const optional = ["baseline_benchmark_run_id", "candidate_benchmark_run_id"];
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed) ||
          required.some((key) => typeof (parsed as Record<string, unknown>)[key] !== "string" ||
            !(parsed as Record<string, string>)[key].trim()) ||
          Object.keys(parsed).some((key) => ![...required, ...optional].includes(key))) {
        return { value: null, error: "Provide the exact tenant, asset, source, change and four measurement windows." };
      }
      return { value: parsed as SimulationPerformanceInput, error: null };
    } catch {
      return { value: null, error: "Performance context must be valid JSON." };
    }
  }, [performanceText]);

  const scenario: SimulationScenario = useMemo(() => {
    const built: SimulationScenario = { kind: entry?.kind ?? kind };
    for (const name of formFields) {
      const value = (fields[name] ?? "").trim();
      if (!value) continue;
      if (name === "key_size") built.key_size = Number(value);
      else if (name === "from") built.from = value;
      else if (name === "to") built.to = value;
      else if (name === "expression") {
        try {
          const parsed = JSON.parse(value);
          if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) built.expression = parsed;
        } catch {
          /* left unset: `missing` blocks the run and the parse error is shown on the field */
        }
      } else if (name === "steps") {
        try {
          const parsed = JSON.parse(value);
          if (Array.isArray(parsed)) built.steps = parsed as Array<Record<string, unknown>>;
        } catch {
          /* left unset: the parse error is shown on the field */
        }
      }
    }
    if (targets.length) built.targets = targets;
    if (isCascade) built.depth = depth;
    if (label.trim()) built.label = label.trim();
    if (!isCascade && performanceInput.value) built.performance_context = performanceInput.value;
    return built;
  }, [entry, kind, formFields, fields, targets, depth, isCascade, label, performanceInput]);

  const scenarioKey = JSON.stringify(scenario);
  const previewIsCurrent = preview?.key === scenarioKey;
  const missing = requiredFields.filter((name) =>
    name === "expression" || name === "steps"
      ? !(fields[name] ?? "").trim() || Boolean(jsonFieldError[name])
      : !(fields[name] ?? "").trim());
  const seedsMissing = isCascade && entry?.kind !== "CASCADE_ALGORITHM_BREAK" && targets.length === 0;

  const resetOutputs = () => {
    setPreview(null);
    setPreviewError(null);
    setResult(null);
    setResultError(null);
  };

  const selectKind = (next: string) => {
    setKind(next);
    setFields({});
    setTargets([]);
    setPreset(null);
    resetOutputs();
  };

  const applyPreset = (item: SimulationPreset) => {
    setKind(item.kind);
    setPreset(item.id);
    const next: Record<string, string> = {};
    if (item.scenario.from) next.from = item.scenario.from;
    if (item.scenario.to) next.to = item.scenario.to;
    if (item.scenario.key_size) next.key_size = String(item.scenario.key_size);
    setFields(next);
    setTargets(item.scenario.targets ?? []);
    if (item.scenario.depth) setDepth(item.scenario.depth);
    resetOutputs();
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
  const canRun = !performanceInput.error && previewIsCurrent && preview?.data.status === "WOULD_MATCH";
  const previewNote = performanceInput.error
    ? performanceInput.error
    : missing.length > 0
    ? `Still needed: ${missing.join(", ")}`
    : seedsMissing
      ? "Pick at least one seed asset — a cascade with no starting point has nothing to propagate."
      : previewIsCurrent
        ? (isCascade
          ? "Running walks the live topology from those seeds. Nothing is copied and no evidence changes."
          : "Running re-projects the six BOMs from the copy; the live estate is not written to.")
        : "Preview first — the run button unlocks once the question is known to reach something.";

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16, flexWrap: "wrap", gap: 16 }}>
        <div style={{ flex: "1 1 520px", minWidth: 280 }}>
          <div style={{
            display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px", borderRadius: 999,
            background: "color-mix(in srgb, var(--violet) 12%, transparent)", border: "1px solid color-mix(in srgb, var(--violet) 35%, var(--line))",
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
          <p style={{ margin: 0, fontSize: 13.5, color: "var(--dim)", lineHeight: 1.5, maxWidth: 700 }}>
            Ask the twin what a change or failure would do to the estate.
          </p>
          <p style={{ margin: "6px 0 0", fontSize: 11.5, color: "var(--faint)", maxWidth: 700 }}>
            Ten registered scenarios, four cascades and a bounded sequence of up to five of them —
            not a general simulation engine: nine of the ten scenarios model only part of the
            mechanism, and what each one cannot see is stated rather than assumed away. The per-scenario
            status — and what each one cannot see — is under{" "}
            <Link to="/collector-depth">Collector depth → Simulation</Link>.
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
            <span title={"A scenario is applied to a snapshot of the twin and the six BOMs are re-projected from that copy. A cascade walks the live topology and changes nothing, so it reports no BOM diff at all. Both say whether they touched the live state; neither is counted as estate state."}>{"A scenario is applied to a snapshot of the twin and the six BOMs are re-projected from that copy."}</span>
          </div>
        </div>
      </div>

      <div
        aria-label="How a simulation run works"
        style={{ margin: "0 0 14px", padding: "12px 14px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}
      >
        <div className="kicker" style={{ fontSize: 9.5, marginBottom: 8 }}>HOW A RUN WORKS — SIX STAGES, ONE PROJECTION ID</div>
        <FlowStrip
          label="how a run works"
          stages={[
            { label: "1 ask", state: "active", note: "a registered scenario, cascade, or a bounded sequence — with its selector" },
            { label: "2 match", state: "pending", note: "the selector must match recorded evidence — no match is NO_MATCH, never 'zero impact'" },
            { label: "3 copy", state: "pending", note: "the twin is copied; the live estate is never touched" },
            { label: "4 project", state: "pending", note: "the six BOMs are re-projected from the copy" },
            { label: "5 diff", state: "pending", note: "added/removed/changed per BOM, measured against one projection id" },
            { label: "6 quarantine", state: "pending", note: "a stored run is quarantined and labelled with the estate it was computed against" },
          ]}
        />
      </div>

      {catalogProblem && (
        <Panel title="No twin to simulate against" sub="a simulation is asked of this estate's own evidence">
          <div style={{ fontSize: 12.5, color: "var(--dim)", lineHeight: 1.6 }}>
            {String(catalog?.error || "").includes("404")
              ? "Nothing has been discovered yet, so there is no evidence state to copy."
              : `The simulation catalog could not be read: ${catalog?.error}`}
            {" "}
            A simulate over an undiscovered estate would report zero impact for everything, which is
            the one answer this page must never give.
          </div>
          <EstateDiscoveryCta onDiscovered={loadCatalog} compact />
          <div style={{ fontSize: 11.5, color: "var(--dim)", marginTop: 4 }}>
            Live scanning collects the raw evidence; <Link to="/scanners">scanners</Link> is where that
            happens. Estate discovery is the join that this page reads.
          </div>
        </Panel>
      )}

      {!catalog && <Panel title="Reading the estate"><div style={{ fontSize: 12, color: "var(--dim)" }}>Loading the simulation catalog…</div></Panel>}

      {(catalog?.data?.presets?.length ?? 0) > 0 && (
        <Panel title="Start from a question this estate can already be asked"
               sub="built from the values and the topology the twin actually holds — a starting point, still previewed before it runs">
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            {catalog!.data!.presets.map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => applyPreset(item)}
                aria-pressed={preset === item.id}
                title={item.why}
                style={{
                  padding: "6px 11px", borderRadius: "var(--r)", fontSize: 11.5, cursor: "pointer",
                  textAlign: "left",
                  background: preset === item.id ? "color-mix(in srgb, var(--violet) 16%, transparent)" : "var(--panel-2)",
                  border: `1px solid ${preset === item.id ? "var(--violet)" : "var(--line)"}`,
                  color: "var(--text)",
                }}
              >
                <span style={{ fontWeight: 700 }}>{item.label}</span>
                <span style={{ display: "block", fontSize: 10, color: "var(--faint)" }}>
                  {item.mode === "CASCADE" ? "cascade" : "scenario"} · {item.why}
                </span>
              </button>
            ))}
          </div>
        </Panel>
      )}

      {entry && (
        <Panel title="1 · Choose the question" sub="each kind answers a different question, and refuses the ones it cannot">
          {modes.map((mode) => {
            const family = kinds.filter((item) => item.mode === mode.mode);
            if (!family.length) return null;
            return (
              <div key={mode.mode} style={{ marginBottom: 12 }}>
                <div style={{ display: "flex", gap: 8, alignItems: "baseline", flexWrap: "wrap", marginBottom: 6 }}>
                  <span className="kicker" style={{ fontSize: 10, color: mode.mode === "CASCADE" ? "var(--amber)" : "var(--accent)" }}>
                    {mode.name}
                  </span>
                  <span style={{ fontSize: 11, color: "var(--faint)" }}>{mode.blurb}</span>
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))", gap: 8 }}>
                  {family.map((item) => {
                    const selected = item.kind === entry.kind;
                    return (
                      <button
                        key={item.kind}
                        type="button"
                        onClick={() => selectKind(item.kind)}
                        aria-pressed={selected}
                        style={{
                          textAlign: "left", padding: "10px 12px", borderRadius: "var(--r)", cursor: "pointer",
                          background: selected
                            ? (mode.mode === "CASCADE"
                              ? "color-mix(in srgb, var(--amber) 14%, transparent)"
                              : "color-mix(in srgb, var(--violet) 14%, transparent)")
                            : "var(--panel-2)",
                          border: `1px solid ${selected ? (mode.mode === "CASCADE" ? "var(--amber)" : "var(--violet)") : "var(--line)"}`,
                          color: "var(--text)",
                        }}
                      >
                        <div style={{ fontSize: 12.5, fontWeight: 800 }}>{item.name}</div>
                        <div style={{ fontSize: 11, color: "var(--dim)", marginTop: 3, lineHeight: 1.45 }}>{item.question}</div>
                      </button>
                    );
                  })}
                </div>
              </div>
            );
          })}
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
        <Panel
          title="2 · Build the question"
          sub={isCascade
            ? "a cascade starts from seed assets and follows the declared rules below"
            : (selector?.note ?? "the values below are the ones this estate reported")}
        >
          {formFields.length > 0 && (
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(230px, 1fr))", gap: 12 }}>
              {formFields.map((name) => {
                const values = [...(selector?.algorithms ?? []), ...(selector?.protocols ?? []), ...(selector?.components ?? [])];
                const listId = `sim-values-${name}`;
                const label = isCascade && name === "from"
                  ? "The algorithm that breaks (from)"
                  : FIELD_LABEL[name] ?? name;
                return (
                  <label key={name} style={{ display: "block" }}>
                    <span style={labelStyle}>
                      {label}
                      {requiredFields.includes(name) ? " *" : " (optional)"}
                    </span>
                    {name === "expression" || name === "steps" ? (
                      <textarea
                        aria-label={label}
                        rows={name === "steps" ? 8 : 6}
                        value={fields[name] ?? ""}
                        onChange={(event) => {
                          const value = event.target.value;
                          setFields((current) => ({ ...current, [name]: value }));
                          setPreset(null);
                          resetOutputs();
                        }}
                        placeholder={
                          name === "steps"
                            ? '[{"kind": "DISABLE_PROTOCOL", "from": "TLSv1.0"}, {"kind": "MIGRATE_QUANTUM_VULNERABLE", "to": "ML-KEM-768"}]'
                            : '{"when": {"fact": "algorithm", "op": "eq", "value": "RSA"}, "then": {"set": {"algorithm": "ML-DSA-65"}}}'
                        }
                        style={{ ...inputStyle, lineHeight: 1.5, resize: "vertical" }}
                      />
                    ) : (
                    <input
                      aria-label={label}
                      list={listId}
                      value={fields[name] ?? ""}
                      onChange={(event) => {
                        const value = event.target.value;
                        setFields((current) => ({ ...current, [name]: value }));
                        setPreset(null);
                        resetOutputs();
                      }}
                      placeholder={name === "key_size" ? "e.g. 256" : "value from this estate"}
                      inputMode={name === "key_size" ? "numeric" : undefined}
                      style={inputStyle}
                    />
                    )}
                    {(name === "expression" || name === "steps") && jsonFieldError[name] && (
                      <span style={{ display: "block", fontSize: 10.5, color: "var(--amber)", marginTop: 3 }}>
                        {jsonFieldError[name]}
                      </span>
                    )}
                    {name === "steps" && (
                      <div style={{ marginTop: 6 }}>
                        <div style={{ fontSize: 10.5, color: "var(--faint)", lineHeight: 1.5 }}>
                          A step may carry <code>as_of</code> with one of these ids. The step is then
                          matched against that snapshot&apos;s evidence, while its change lands on the
                          estate as it stands — a plan written in Q2, judged on Q2&apos;s evidence.
                          A step without <code>as_of</code> reads today.
                        </div>
                        {snapshotError && (
                          <div style={{ fontSize: 10.5, color: "var(--amber)", marginTop: 4 }}>{snapshotError}</div>
                        )}
                        {snapshots === null && !snapshotError && (
                          <div style={{ fontSize: 10.5, color: "var(--faint)", marginTop: 4 }}>reading stored snapshots…</div>
                        )}
                        {snapshots !== null && snapshots.length === 0 && (
                          <div style={{ fontSize: 10.5, color: "var(--faint)", marginTop: 4 }}>
                            this tenant holds no stored snapshot, so no step can name one yet. Capture
                            a baseline on the twin chain screen first — a date is not a snapshot.
                          </div>
                        )}
                        {snapshots !== null && snapshots.length > 0 && (
                          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 5, alignItems: "center" }}>
                            {snapshots.slice(0, 6).map((snapshot) => (
                              <button
                                key={snapshot.id}
                                type="button"
                                title={`${snapshot.assets} assets · ${snapshot.evidence} evidence records · ${snapshot.note ?? "no note"}`}
                                onClick={() => copySnapshotId(snapshot.snapshot_id)}
                                style={{ ...chipStyle(false), fontSize: 10.5 }}
                              >
                                {snapshot.snapshot_id}
                              </button>
                            ))}
                            {copiedSnapshot && (
                              <span style={{ fontSize: 10.5, color: "var(--green)" }}>
                                copied {copiedSnapshot} — paste it as <code>as_of</code> in a step
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                    )}
                    <datalist id={listId}>
                      {[...new Set(values.map((item) => item.value))].map((value) => (
                        <option key={value} value={value} />
                      ))}
                    </datalist>
                  </label>
                );
              })}
            </div>
          )}

          {!isCascade && (
            <div style={{ marginTop: 12, display: "grid", gap: 8 }}>
              <VocabularyChips
                label="algorithms in this estate"
                values={selector?.algorithms ?? []}
                onPick={(value) => { setFields((current) => ({ ...current, from: value })); setPreset(null); resetOutputs(); }}
              />
              <VocabularyChips
                label="protocols in this estate"
                values={selector?.protocols ?? []}
                onPick={(value) => { setFields((current) => ({ ...current, from: value })); setPreset(null); resetOutputs(); }}
              />
              <VocabularyChips
                label="components in this estate"
                values={selector?.components ?? []}
                onPick={(value) => { setFields((current) => ({ ...current, from: value })); setPreset(null); resetOutputs(); }}
              />
            </div>
          )}

          {isCascade && (
            <div style={{ marginTop: 12 }}>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
                <span style={{ fontSize: 11.5, color: "var(--dim)" }}>
                  Rules carried: {[...new Set((preview?.data.rules ?? []).map((rule) => rule.predicate))].join(", ") || "declared on the preview"}
                </span>
                <span style={{ fontSize: 11, color: "var(--faint)" }}>
                  a predicate that is not listed does not carry this failure — so the radius below is a
                  floor, and the blind spots say where it stops being one
                </span>
              </div>
            </div>
          )}

          <div style={{ marginTop: 14 }}>
            <span style={labelStyle}>
              {isCascade
                ? (entry.kind === "CASCADE_ALGORITHM_BREAK"
                  ? "Narrow the seeds to specific assets (optional — every use of the value above is a seed)"
                  : "Where the failure starts — pick the seed assets *")
                : "Narrow to specific assets — no selection means every asset the selector matches"}
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
                        setPreset(null);
                        resetOutputs();
                      }}
                      style={chipStyle(picked)}
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

          {isCascade && (
            <label style={{ display: "block", marginTop: 12, maxWidth: 220 }}>
              <span style={labelStyle}>Hops to walk — {depth}</span>
              <input
                aria-label="Hops to walk"
                type="range"
                min={1}
                max={8}
                step={1}
                value={depth}
                onChange={(event) => { setDepth(Number(event.target.value)); setPreset(null); resetOutputs(); }}
                style={{ width: "100%" }}
              />
              <span style={{ fontSize: 10.5, color: "var(--faint)" }}>
                1 hop is direct dependents; 8 is the whole reachable estate
              </span>
            </label>
          )}

          {!isCascade && (
            <div style={{ marginTop: 14 }}>
              <label style={labelStyle} htmlFor="simulation-performance-input">
                Recorded performance context (optional JSON — input to this simulation only)
              </label>
              <textarea id="simulation-performance-input"
                aria-label="Recorded performance context (optional JSON)"
                value={performanceText}
                onChange={(event) => { setPerformanceText(event.target.value); resetOutputs(); }}
                rows={4} style={inputStyle}
                placeholder={'{"tenant_id":"<tenant>","asset_ref":"app:<id>","metric_name":"crypto.tls_handshake_ms","source_id":"<exporter>","change_event_id":"<stored change>","before_start":"<ISO-8601>","before_end":"<ISO-8601>","after_start":"<ISO-8601>","after_end":"<ISO-8601>"}'} />
              <div style={{ marginTop: 4, fontSize: 11, color: "var(--dim)" }}>
                <span title={"The preview checks the Twin selector only. Run checks measurement provenance, the recorded change and exact asset identity; unsigned captures remain provisional. No future performance or migration wave is inferred."}>{"The preview checks the Twin selector only."}</span>
              </div>
              {performanceInput.error && <div role="alert" style={{ fontSize: 11, color: "var(--amber)" }}>{performanceInput.error}</div>}
            </div>
          )}

          <div style={{ marginTop: 12, display: "flex", gap: 8, alignItems: "flex-end", flexWrap: "wrap" }}>
            <label style={{ flex: "1 1 240px" }}>
              <span style={labelStyle}>Label this run (optional)</span>
              <input
                aria-label="Label this run (optional)"
                value={label}
                onChange={(event) => setLabel(event.target.value)}
                placeholder={isCascade ? "e.g. payments DB outage" : "e.g. PQC pilot — payments"}
                style={inputStyle}
              />
            </label>
            <button
              type="button"
              onClick={() => void runPreview()}
              disabled={busy !== null || missing.length > 0 || seedsMissing || Boolean(performanceInput.error)}
              style={{
                padding: "8px 14px", borderRadius: "var(--r)", fontWeight: 700, fontSize: 12,
                cursor: busy !== null || missing.length || seedsMissing || performanceInput.error ? "not-allowed" : "pointer",
                background: "var(--panel-2)", border: "1px solid var(--accent)", color: "var(--accent)",
                opacity: busy !== null || missing.length || seedsMissing || performanceInput.error ? 0.55 : 1,
              }}
            >
              {busy === "plan" ? "Previewing…" : (isCascade ? "Preview reach" : "Preview match")}
            </button>
            <button
              type="button"
              onClick={() => void runSimulation()}
              disabled={busy !== null || !canRun}
              title={previewIsCurrent ? undefined : "preview first — a run over a question that reaches nothing is not a finding"}
              style={{
                padding: "8px 14px", borderRadius: "var(--r)", fontWeight: 700, fontSize: 12,
                cursor: busy !== null || !canRun ? "not-allowed" : "pointer",
                background: "var(--violet)", border: "1px solid var(--violet)", color: "#fff",
                opacity: busy !== null || !canRun ? 0.55 : 1,
              }}
            >
              {busy === "run" ? (isCascade ? "Walking the topology…" : "Running on a copy…") : (isCascade ? "Run cascade" : "Run simulation")}
            </button>
          </div>
          <div style={{ marginTop: 8, fontSize: 11, color: "var(--faint)" }}>{previewNote}</div>
          {modeInfo && (
            <div style={{ marginTop: 6, fontSize: 10.5, color: "var(--faint)" }}>
              {modeInfo.changes_evidence
                ? "this family edits evidence facts on a copy, so it has a BOM diff"
                : "this family edits nothing, so it has no BOM diff — six empty diffs would read as 'nothing changes'"}
            </div>
          )}
        </Panel>
      )}

      {previewError && (
        <Panel title="The question cannot be answered">
          <div style={{ fontSize: 12.5, color: "var(--red)" }}>{previewError}</div>
        </Panel>
      )}

      {preview?.data && previewIsCurrent && (
        <Panel
          title={isCascade ? "3 · Preview — what this would reach" : "3 · Preview — what this would touch"}
          sub={`measured against ${preview.data.base_projection_id ?? "an unknown projection"}`}
          style={{ padding: 0, overflow: "hidden" } as React.CSSProperties}
        >
          <div style={{ padding: "12px 16px", display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
            <Badge tone={preview.data.status === "WOULD_MATCH" ? "green" : "amber"}>{preview.data.status.replace(/_/g, " ")}</Badge>
            <span style={{ fontSize: 12, color: "var(--dim)" }}>{preview.data.note}</span>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 10, padding: "0 16px 12px" }}>
            {isCascade ? (
              <>
                <Stat label="seed assets" value={preview.data.seeds?.length ?? 0} />
                <Stat label="assets reached" value={preview.data.affected_asset_count} />
                <Stat label="waves" value={preview.data.wave_counts?.length ?? 0} />
                <Stat label="business systems" value={preview.data.business_systems_reached ?? 0} />
              </>
            ) : (
              <>
                <Stat label="matched evidence" value={preview.data.matched_evidence} />
                <Stat label="assets affected" value={preview.data.affected_asset_count} />
                <Stat label="evidence considered" value={preview.data.evidence_considered} />
                <Stat label="coverage" value={`${preview.data.coverage?.coverage_percent ?? 0}%`} delta={preview.data.coverage?.coverage_state} />
              </>
            )}
          </div>
          {(preview.data.seeds?.length ?? 0) > 0 && (
            <div style={{ borderTop: "1px solid var(--line)" }}>
              {preview.data.seeds!.map((seed) => (
                <div key={seed.asset_id} style={{
                  display: "flex", gap: 8, justifyContent: "space-between", flexWrap: "wrap",
                  padding: "7px 16px", borderBottom: "1px solid var(--line)", fontSize: 12,
                }}>
                  <span><b>{seed.name}</b><span style={{ color: "var(--faint)", fontSize: 11 }}> · {seed.type}</span></span>
                  <span style={{ fontSize: 11, color: "var(--faint)" }}>{seed.reason}</span>
                </div>
              ))}
            </div>
          )}
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
                  <span style={{ fontFamily: "var(--mono)", fontSize: 11.5 }}>
                    {isCascade
                      ? `hop ${asset.hops}${asset.via_predicate ? ` · ${asset.via_predicate}` : ""}`
                      : `${asset.evidence_matched} record(s)`}
                  </span>
                </div>
              ))}
            </div>
          )}
          <div style={{ padding: "10px 16px", display: "grid", gap: 6 }}>
            {isCascade
              ? (preview.data.wave_counts ?? []).map((wave) => (
                <div key={wave.depth} style={{ fontSize: 11.5, color: "var(--dim)", fontFamily: "var(--mono)" }}>
                  wave {wave.depth}: {wave.count} asset(s)
                </div>
              ))
              : Object.entries(preview.data.by_layer || {}).map(([layer, count]) => (
                <div key={layer} style={{ fontSize: 11.5, color: "var(--dim)", fontFamily: "var(--mono)" }}>
                  {layer}: {count}
                </div>
              ))}
            {preview.data.unresolved_targets.length > 0 && (
              <div style={{ fontSize: 11.5, color: "var(--amber)" }}>
                Named but not held by the twin: {preview.data.unresolved_targets.join(", ")} — they were not
                treated as "match everything".
              </div>
            )}
            {(preview.data.rules ?? []).length > 0 && (
              <details style={{ fontSize: 11.5, color: "var(--dim)" }}>
                <summary style={{ cursor: "pointer", color: "var(--accent)" }}>
                  the {preview.data.rules!.length} edge rules this cascade follows
                </summary>
                <div style={{ marginTop: 6, display: "grid", gap: 3 }}>
                  {preview.data.rules!.map((rule) => (
                    <div key={rule.predicate} style={{ fontFamily: "var(--mono)", fontSize: 11 }}>
                      <b style={{ color: "var(--text)" }}>{rule.predicate}</b>
                      <span style={{ color: "var(--faint)" }}> · {rule.direction.replace(/_/g, " ")}</span>
                      {" — "}{rule.meaning}
                    </div>
                  ))}
                </div>
              </details>
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
        result.data.mode === "CASCADE"
          ? <CascadeResult result={result.data} />
          : <SimulationResult result={result.data} />
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
                    {row.kind.startsWith("CASCADE")
                      ? `${row.affected_assets?.length ?? 0} asset(s) reached`
                      : `${row.matched_evidence} matched · ${row.affected_assets?.length ?? 0} asset(s)`}
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
            No stored runs yet. A run is only stored when it reached something — "nothing to simulate"
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
  const performance = result.performance_context && !("state" in result.performance_context)
    ? result.performance_context : null;

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
        {(counts.total ?? 0) > 0 && (
          <div style={{ padding: "0 16px 12px", maxWidth: 420 }}>
            <HBars
              rows={[
                { key: "direct", label: "direct blast radius", value: counts.direct ?? 0, tone: "red" },
                {
                  key: "indirect",
                  label: "indirect",
                  value: Math.max(0, (counts.total ?? 0) - (counts.direct ?? 0)),
                  tone: "amber",
                },
              ]}
              unit=""
              emptyTitle="no blast radius"
              emptyNote="waves out from the seeds — counted, never estimated"
            />
          </div>
        )}

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
              <span title={"No evidence record changed. That is the honest answer for a selector that matched nothing — not a statement that the change is safe."}>{"No evidence record changed."}</span>
            </div>
          ) : (
            result.effects.map((effect) => <EffectRow key={effect.evidence_id + effect.asset_id} effect={effect} />)
          )}
        </div>

        <div style={{ borderTop: "1px solid var(--line)", padding: "10px 16px" }}>
          <div style={{ fontSize: 11, letterSpacing: ".06em", textTransform: "uppercase", color: "var(--faint)", marginBottom: 6 }}>
            six BOMs re-projected from the copy
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 10 }}>
            {boms.map(([bom, diff]) => (
              <div key={bom} style={{ fontSize: 11.5 }}>
                <div style={{ fontFamily: "var(--mono)", color: "var(--dim)", marginBottom: 4 }}>
                  <b style={{ color: "var(--text)" }}>{bom}</b>{" "}
                  +{diff.counts?.added ?? 0} −{diff.counts?.removed ?? 0} ~{diff.counts?.changed ?? 0}
                  {diff.counts?.unchanged ? ` · ${diff.counts.unchanged} unchanged` : ""}
                </div>
                <StackedBar
                  height={8}
                  segments={[
                    { key: "added", label: "added", value: diff.counts?.added ?? 0, tone: "green" },
                    { key: "removed", label: "removed", value: diff.counts?.removed ?? 0, tone: "red" },
                    { key: "changed", label: "changed", value: diff.counts?.changed ?? 0, tone: "amber" },
                    { key: "unchanged", label: "unchanged", value: diff.counts?.unchanged ?? 0, tone: "slate" },
                  ]}
                  note={`${bom} re-projected from the copy — counts, never a quality judgement`}
                />
              </div>
            ))}
            {boms.length === 0 && (
              <div style={{ fontSize: 11.5, color: "var(--faint)" }}>
                no BOM diff in this result — the scenario touched no projected
                component, which is not the same as a clean estate
              </div>
            )}
          </div>
        </div>

        <div style={{ borderTop: "1px solid var(--line)", padding: "10px 16px", display: "grid", gap: 6 }}>
          <div style={{ fontSize: 11, letterSpacing: ".06em", textTransform: "uppercase", color: "var(--faint)" }}>
            blockers and unknowns
          </div>
          {(result.blockers || []).length === 0 ? (
            <div style={{ fontSize: 11.5, color: "var(--dim)" }}>
              <span title={"No blocker was reported. A blocker is only raised where the evidence contradicts the target, so an empty list is not evidence that the change is safe."}>{"No blocker was reported."}</span>
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

      {result.performance_context && (
        <Panel title="Measured performance context — not a migration verdict"
          sub="Observed before/after measurements stay separate from the hypothetical BOM changes">
          {!performance ? (
            <p style={{ fontSize: 12 }}>{"reason" in result.performance_context ? result.performance_context.reason : "No performance context was attached."}</p>
          ) : (
            <div style={{ display: "grid", gap: 9, fontSize: 12 }}>
              <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                <Badge tone="slate">{performance.status}</Badge>
                <span>Identity link: {performance.link.state} — {performance.link.reason}</span>
              </div>
              <div style={{ overflowX: "auto" }}>
                <table className="tbl"><thead><tr><th>Window</th><th>Valid</th><th>Signed capture samples</th><th>p95 ({performance.unit})</th></tr></thead>
                  <tbody>{(["before", "after"] as const).map((period) => <tr key={period}>
                    <td>{period}</td><td>{performance[period].valid}</td>
                    <td>{performance[period].signed_capture_samples}</td>
                    <td>{performance[period].p95 ?? "not derivable"}</td>
                  </tr>)}</tbody></table>
              </div>
              <p>Measured difference: {performance.delta_p95 ?? "not derivable"} {performance.unit}.
                Causation {performance.causation}. {performance.note}</p>
              <p>Controlled benchmark: {performance.benchmark.status} — {performance.benchmark.note}</p>
            </div>
          )}
        </Panel>
      )}

      {refused && result.status === "NO_MATCH" && (
        <Panel title="Nothing to simulate">
          <div style={{ fontSize: 12.5, color: "var(--dim)", lineHeight: 1.6 }}>
            <span title={"The scenario matched no evidence record, so there is no copy to project and nothing to store. Widen the selector — the chips in step 2 are the values this estate actually reports — or run discovery if the asset you expected is missing from the twin."}>{"The scenario matched no evidence record, so there is no copy to project and nothing to store."}</span>
          </div>
        </Panel>
      )}
    </>
  );
}

/** A cascade result is a route map, not a diff: waves out from the seeds, and the edge each
 *  asset was reached by. There is no BOM diff because no evidence changed. */
function CascadeResult({ result }: { result: SimulationRun }) {
  const counts = result.impact?.counts ?? {};
  const systems = (result.impact?.business_systems as Array<{
    asset_id: string; name: string; hops: number;
    path: Array<{ asset_id: string; name: string | null; via_predicate: string | null }>;
  }> | undefined) ?? [];
  const unknown = result.unknown ?? {};
  const refused = !result.persisted;

  return (
    <>
      <Panel
        title="4 · Result — what this reaches"
        sub={`walked ${result.depth ?? "?"} hop(s) from ${result.seeds?.length ?? 0} seed(s) · measured against ${result.base_projection_id ?? "—"}`}
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
          <Badge tone="amber">NO BOM DIFF — NOTHING CHANGED</Badge>
          <span style={{ fontSize: 11.5, color: "var(--dim)" }}>{result.note}</span>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 10, padding: "0 16px 12px" }}>
          <Stat label="seed assets" value={counts.seed ?? result.seeds?.length ?? 0} />
          <Stat label="assets reached" value={counts.total ?? 0} delta={`${counts.direct ?? 0} at one hop`} />
          <Stat label="waves" value={result.wave_count ?? result.waves?.length ?? 0} />
          <Stat label="business systems" value={systems.length} />
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

        {(result.seeds?.length ?? 0) > 0 && (
          <div style={{ borderTop: "1px solid var(--line)" }}>
            <div style={{ padding: "8px 16px", fontSize: 11, letterSpacing: ".06em", textTransform: "uppercase", color: "var(--faint)" }}>
              seeds — where the failure starts
            </div>
            {result.seeds!.map((seed) => (
              <div key={seed.asset_id} style={{
                display: "flex", gap: 8, justifyContent: "space-between", flexWrap: "wrap",
                padding: "7px 16px", borderTop: "1px solid var(--line)", fontSize: 12,
              }}>
                <span><b>{seed.name}</b><span style={{ color: "var(--faint)", fontSize: 11 }}> · {seed.type}</span></span>
                <span style={{ fontSize: 11, color: "var(--faint)" }}>{seed.reason}</span>
              </div>
            ))}
          </div>
        )}

        {(result.waves ?? []).map((wave) => <WaveBlock key={wave.depth} wave={wave} />)}

        {systems.length > 0 && (
          <div style={{ borderTop: "1px solid var(--line)", padding: "10px 16px" }}>
            <div style={{ fontSize: 11, letterSpacing: ".06em", textTransform: "uppercase", color: "var(--faint)", marginBottom: 6 }}>
              business systems reached, with the route
            </div>
            {systems.map((system) => (
              <div key={system.asset_id} style={{ fontSize: 11.5, fontFamily: "var(--mono)", color: "var(--dim)", marginBottom: 4 }}>
                <b style={{ color: "var(--text)" }}>{system.name}</b> · {system.hops} hop(s):{" "}
                {system.path.map((hop, index) => (
                  <span key={`${hop.asset_id}-${index}`}>
                    {index > 0 ? ` → (${hop.via_predicate}) ` : ""}{hop.name}
                  </span>
                ))}
              </div>
            ))}
          </div>
        )}

        <div style={{ borderTop: "1px solid var(--line)", padding: "10px 16px", display: "grid", gap: 6 }}>
          <div style={{ fontSize: 11, letterSpacing: ".06em", textTransform: "uppercase", color: "var(--faint)" }}>
            blind spots and limits
          </div>
          {(result.blockers || []).length === 0 ? (
            <div style={{ fontSize: 11.5, color: "var(--dim)" }}>
              <span title={"No refused edge touches this radius. That does not make the radius complete: it means the topology the collectors established had no contradiction inside it."}>{"No refused edge touches this radius."}</span>
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
          {(result.limits ?? []).map((line) => (
            <div key={line} style={{ fontSize: 11, color: "var(--faint)", lineHeight: 1.5 }}>· {line}</div>
          ))}
          {result.bom_diff_note && (
            <div style={{ fontSize: 11, color: "var(--faint)", lineHeight: 1.5 }}>· {result.bom_diff_note}</div>
          )}
        </div>

        {(result.rules ?? []).length > 0 && (
          <details style={{ borderTop: "1px solid var(--line)", padding: "10px 16px", fontSize: 11.5, color: "var(--dim)" }}>
            <summary style={{ cursor: "pointer", color: "var(--accent)" }}>
              the {result.rules!.length} edge rules this cascade followed
            </summary>
            <div style={{ marginTop: 6, display: "grid", gap: 3 }}>
              {result.rules!.map((rule) => (
                <div key={rule.predicate} style={{ fontFamily: "var(--mono)", fontSize: 11 }}>
                  <b style={{ color: "var(--text)" }}>{rule.predicate}</b>
                  <span style={{ color: "var(--faint)" }}> · {rule.direction.replace(/_/g, " ")}</span>
                  {" — "}{rule.meaning}
                </div>
              ))}
            </div>
          </details>
        )}
      </Panel>

      {refused && result.status === "NO_MATCH" && (
        <Panel title="Nothing reached">
          <div style={{ fontSize: 12.5, color: "var(--dim)", lineHeight: 1.6 }}>
            {result.detail || "The cascade reached nothing."} A seed that resolves and reaches nothing is
            reported as such: it is not a clean bill of health, and it is not stored as one. Widen the
            depth, pick a different seed, or run discovery if the dependency you expected is missing.
          </div>
        </Panel>
      )}
    </>
  );
}
