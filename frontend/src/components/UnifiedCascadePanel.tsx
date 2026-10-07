import React, { useEffect, useState } from "react";
import { Badge, Panel } from "./ui";
import {
  apiCascadeRunDiff,
  apiCascadeRuns,
  apiUnifiedCascade,
  CascadeRunDiff,
  CascadeRunSummary,
  UnifiedCascadeResult,
} from "../lib/api";

const KINDS = [
  "auto", "algorithm", "certificate", "endpoint", "system",
  "vendor", "device", "library", "process",
];

/** Cross-BOM cascade: one target, every layer — code, network, system graph,
 *  process, hardware, vendor, library — with honest unknowns and run history. */
export default function UnifiedCascadePanel() {
  const [target, setTarget] = useState("");
  const [kind, setKind] = useState("auto");
  const [depth, setDepth] = useState(6);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<UnifiedCascadeResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [runs, setRuns] = useState<CascadeRunSummary[]>([]);
  const [diff, setDiff] = useState<CascadeRunDiff | null>(null);
  const [diffError, setDiffError] = useState<string | null>(null);

  const loadRuns = async () => {
    const r = await apiCascadeRuns(10);
    if (r.source === "live" && r.data) setRuns(r.data.runs);
  };

  useEffect(() => { loadRuns(); }, []);

  const run = async () => {
    if (!target.trim()) return;
    setRunning(true);
    setError(null);
    setDiff(null);
    setDiffError(null);
    const r = await apiUnifiedCascade(target.trim(), kind === "auto" ? undefined : kind, depth);
    setRunning(false);
    if (r.source === "live" && r.data) {
      setResult(r.data);
      loadRuns();
    } else {
      setResult(null);
      setError(r.error || "cascade request failed");
    }
  };

  const showDiff = async (runId: string) => {
    setDiff(null);
    setDiffError(null);
    const r = await apiCascadeRunDiff(runId);
    if (r.source === "live" && r.data) setDiff(r.data);
    else setDiffError(r.error || "no earlier run of this target to diff against");
  };

  const verdictTone = (v: string) =>
    v === "AFFECTED" ? "danger" : v === "INSUFFICIENT_DATA" ? "warning" : "neutral";
  const verdictVariant = (v: string) =>
    v === "AFFECTED" ? "warning" : v === "INSUFFICIENT_DATA" ? "warning" : "neutral";

  const layers = result?.layers || {};
  const impact = result?.impact || ({} as UnifiedCascadeResult["impact"]);
  const dependents = layers.system?.dependents_by_depth || {};
  const downstream = layers.system?.downstream_by_depth || {};
  const dependentsCount = Object.values(dependents).reduce(
    (n: number, v: any) => n + (Array.isArray(v) ? v.length : 0), 0);
  const downstreamCount = Object.values(downstream).reduce(
    (n: number, v: any) => n + (Array.isArray(v) ? v.length : 0), 0);

  return (
    <Panel
      title="Cross-BOM cascade"
      sub="POST /api/v1/technology-bom/cascade — what breaks if X changes: one target fanned out across code, network, system graph, process, hardware, vendor and library layers"
      className="mt"
    >
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center", marginBottom: 12 }}>
        <input
          className="inp sm"
          style={{ minWidth: 260, fontSize: 12 }}
          placeholder="Target: RSA-2048 · CN=…/fingerprint · host:port · system · vendor · device · library · process"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && run()}
          aria-label="cascade target"
        />
        <select value={kind} onChange={(e) => setKind(e.target.value)} style={{ fontSize: 12, padding: "4px 8px" }} aria-label="target kind">
          {KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
        </select>
        <label style={{ fontSize: 12, color: "var(--dim)" }}>
          depth
          <input
            type="number" min={1} max={12} value={depth}
            onChange={(e) => setDepth(Math.max(1, Math.min(12, Number(e.target.value) || 6)))}
            style={{ width: 52, marginLeft: 6, fontSize: 12, padding: "4px 6px" }}
            aria-label="max depth"
          />
        </label>
        <button className="btn sm primary" onClick={run} disabled={running || !target.trim()}>
          {running ? "Cascading…" : "Run cascade"}
        </button>
      </div>

      {error && (
        <div style={{ fontSize: 12, color: "var(--red)", marginBottom: 10 }}>{error}</div>
      )}

      {result && (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
            <Badge variant={verdictVariant(result.verdict)} tone={verdictTone(result.verdict)}>
              {result.verdict}
            </Badge>
            <span style={{ fontSize: 12, color: "var(--dim)" }}>
              matched as <b style={{ color: "var(--text)" }}>{result.target.kind}</b>
              {" · "}run {result.run_id?.slice(0, 8)}
              {" · "}as of {result.as_of?.replace("T", " ").slice(0, 19)}
            </span>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 10 }}>
            <div style={{ padding: 10, background: "var(--bg-2)", borderRadius: "var(--r)" }}>
              <div style={{ fontSize: 11, color: "var(--dim)" }}>Affected systems</div>
              <div style={{ fontSize: 22, fontWeight: 700, color: "var(--red)" }}>
                {impact.affected_system_count ?? 0}
              </div>
            </div>
            <div style={{ padding: 10, background: "var(--bg-2)", borderRadius: "var(--r)" }}>
              <div style={{ fontSize: 11, color: "var(--dim)" }}>Dependents / downstream</div>
              <div style={{ fontSize: 22, fontWeight: 700 }}>
                {dependentsCount} / {downstreamCount}
              </div>
            </div>
            <div style={{ padding: 10, background: "var(--bg-2)", borderRadius: "var(--r)" }}>
              <div style={{ fontSize: 11, color: "var(--dim)" }}>Processes affected</div>
              <div style={{ fontSize: 22, fontWeight: 700 }}>
                {impact.affected_processes?.length ?? 0}
              </div>
            </div>
            <div style={{ padding: 10, background: "var(--bg-2)", borderRadius: "var(--r)" }}>
              <div style={{ fontSize: 11, color: "var(--dim)" }}>Code evidence</div>
              <div style={{ fontSize: 22, fontWeight: 700 }}>
                {layers.code?.evidence_ids?.length ?? 0}
              </div>
            </div>
            <div style={{ padding: 10, background: "var(--bg-2)", borderRadius: "var(--r)" }}>
              <div style={{ fontSize: 11, color: "var(--dim)" }}>Wire endpoints</div>
              <div style={{ fontSize: 22, fontWeight: 700 }}>
                {layers.network?.endpoints?.length ?? 0}
              </div>
            </div>
            <div style={{ padding: 10, background: "var(--bg-2)", borderRadius: "var(--r)" }}>
              <div style={{ fontSize: 11, color: "var(--dim)" }}>Max propagation</div>
              <div style={{ fontSize: 22, fontWeight: 700 }}>
                {impact.max_propagation_depth ?? 0} hops
              </div>
            </div>
          </div>

          {(impact.affected_systems?.length ?? 0) > 0 && (
            <div style={{ fontSize: 12 }}>
              <div style={{ color: "var(--faint)", marginBottom: 4 }}>Affected systems</div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {impact.affected_systems.map((s: string) => (
                  <span key={s} style={{ padding: "3px 8px", background: "var(--bg-2)", borderRadius: "var(--r)", fontSize: 11 }}>
                    {s}
                  </span>
                ))}
              </div>
            </div>
          )}

          {impact.migration_waves && Object.keys(impact.migration_waves).length > 0 && (
            <div style={{ fontSize: 12 }}>
              <div style={{ color: "var(--faint)", marginBottom: 4 }}>Migration waves (when the roadmap fixes them)</div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {Object.entries(impact.migration_waves).map(([wave, sids]) => (
                  <span key={wave} style={{ padding: "3px 8px", background: "var(--bg-2)", borderRadius: "var(--r)", fontSize: 11 }}>
                    wave {wave}: {sids.length}
                  </span>
                ))}
              </div>
            </div>
          )}

          {impact.affected_processes && impact.affected_processes.length > 0 && (
            <div style={{ fontSize: 12 }}>
              <div style={{ color: "var(--faint)", marginBottom: 4 }}>Business processes</div>
              {impact.affected_processes.map((p, i) => (
                <span key={i} style={{ marginRight: 8, fontSize: 12 }}>{p.name}</span>
              ))}
            </div>
          )}

          {layers.library && (
            <div style={{ fontSize: 12, padding: 10, background: "var(--bg-2)", borderRadius: "var(--r)" }}>
              <b>Library:</b> {layers.library.name}
              {" · "}catalog: {layers.library.in_catalog ? `knows it (${(layers.library.catalog_algorithms || []).length} algorithms)` : "unknown to the fingerprint catalog"}
              {layers.library.deprecated ? " · DEPRECATED" : ""}
              {" · "}observed: {(layers.library.observed_algorithms || []).join(", ") || "—"}
            </div>
          )}

          {layers.vendor?.crypto_inventory?.length > 0 && (
            <div style={{ fontSize: 12, padding: 10, background: "var(--bg-2)", borderRadius: "var(--r)" }}>
              <b>Vendor crypto (discovered):</b>{" "}
              {layers.vendor.crypto_inventory.map((row: any, i: number) => (
                <span key={i} style={{ marginRight: 8 }}>
                  {row.algorithm}
                  {row.crypto_use_case ? ` (${row.crypto_use_case})` : ""}
                  <span style={{ color: row.pqc_ready ? "var(--green)" : "var(--red)" }}>
                    {row.pqc_ready ? " PQC-ready" : " not PQC-ready"}
                  </span>
                </span>
              ))}
            </div>
          )}

          {result.honest_unknowns?.length > 0 && (
            <div style={{ fontSize: 11.5, color: "var(--dim)" }}>
              <div style={{ marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.06em" }}>
                Honest unknowns
              </div>
              <ul style={{ margin: 0, paddingLeft: 18 }}>
                {result.honest_unknowns.map((u, i) => <li key={i}>{u}</li>)}
              </ul>
            </div>
          )}
        </div>
      )}

      {runs.length > 0 && (
        <div style={{ marginTop: 14 }}>
          <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 6, color: "var(--faint)" }}>
            Run history
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            {runs.map((r) => (
              <div key={r.id} style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 12, padding: "5px 8px", background: "var(--bg-2)", borderRadius: "var(--r)" }}>
                <Badge variant={verdictVariant(r.verdict)}>{r.verdict}</Badge>
                <span style={{ fontWeight: 600 }}>{r.target}</span>
                <span style={{ color: "var(--dim)" }}>
                  {r.target_kind || "?"} · {r.affected_system_count ?? 0} systems · {(r.created_at || "").replace("T", " ").slice(0, 19)}
                </span>
                <button className="btn sm outline" style={{ marginLeft: "auto", fontSize: 11 }} onClick={() => showDiff(r.id)}>
                  diff vs previous
                </button>
              </div>
            ))}
          </div>
          {diffError && <div style={{ fontSize: 11.5, color: "var(--dim)", marginTop: 6 }}>{diffError}</div>}
          {diff && (
            <div style={{ marginTop: 8, padding: 10, background: "var(--bg-2)", borderRadius: "var(--r)", fontSize: 12 }}>
              <div style={{ marginBottom: 4 }}>
                <b>Diff</b> {diff.run.created_at?.replace("T", " ").slice(0, 19)} vs {diff.against.created_at?.replace("T", " ").slice(0, 19)}
                {diff.verdict_changed && <span style={{ color: "var(--red)" }}> · verdict changed</span>}
              </div>
              <div>
                systems: {diff.affected_systems.before} → {diff.affected_systems.after}
                {diff.affected_systems.removed.length > 0 && (
                  <span style={{ color: "var(--green)" }}> · removed: {diff.affected_systems.removed.join(", ")}</span>
                )}
                {diff.affected_systems.added.length > 0 && (
                  <span style={{ color: "var(--red)" }}> · added: {diff.affected_systems.added.join(", ")}</span>
                )}
                {diff.affected_systems.removed.length === 0 && diff.affected_systems.added.length === 0 && (
                  <span style={{ color: "var(--dim)" }}> · unchanged</span>
                )}
              </div>
              <div style={{ color: "var(--dim)", marginTop: 2 }}>
                processes: {diff.affected_processes.before} → {diff.affected_processes.after}
              </div>
            </div>
          )}
        </div>
      )}
    </Panel>
  );
}
