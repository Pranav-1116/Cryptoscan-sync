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

import ProcessImpactPanel from "./ProcessImpactPanel";
import TraversalEvidencePanel from "./TraversalEvidencePanel";

const KINDS = [
  "auto", "algorithm", "certificate", "endpoint", "system",
  "vendor", "device", "library", "process", "package", "artifact",
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
  const scope = impact.system_classification;
  const categories = scope ? [
    { label: "Direct exposure", value: scope.direct_exposure,
      description: "Systems directly linked to the selected target." },
    { label: "Dependent consumers", value: scope.dependent_consumers,
      description: "Other systems reached through reverse dependency links." },
    { label: "Supporting context", value: scope.supporting_context,
      description: "Forward-only dependencies; excluded from consumer exposure." },
  ] : [];

  return (
    <Panel
      title="Cross-BOM cascade"
      sub="Review modeled dependencies across BOM layers — not confirmed failures or outage predictions"
      className="mt"
    >
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center", marginBottom: 12 }}>
        <input
          className="inp sm"
          style={{ minWidth: 260, fontSize: 12 }}
          placeholder="Target: RSA-2048 · CN=…/fingerprint · host:port · system · vendor · device · library · process · exact PURL · sha256:digest"
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

          <div style={{ fontSize: 12, color: "var(--dim)" }}>
            {result.relationship_policy
              ? `Relationship policy: ${result.relationship_policy.version}. System propagation: ${result.relationship_policy.propagating_relations.join(", ")}. Unknown/context labels do not propagate.`
              : "Relationship policy unavailable for this stored answer; do not assume traversal parity."}
          </div>

          <TraversalEvidencePanel evidence={result.traversal_evidence} />

          <section aria-label="Relationship lifecycle" role="status" style={{ marginBottom: 12 }}>
            {result.relationship_lifecycle ? <>
              <strong>Relationship eligibility as of {result.relationship_lifecycle.as_of}</strong>
              <div>{Object.entries(result.relationship_lifecycle.counts).map(([state, count]) => `${state}: ${count}`).join(" · ") || "No relationship records"}</div>
              <div>{result.relationship_lifecycle.excluded_count} non-current records retained and excluded from active traversal. Fewer active links are not proof of remediation or safety.</div>
              {result.relationship_lifecycle.unbounded_active_count > 0 && <div>{result.relationship_lifecycle.unbounded_active_count} active relationships have no expiry deadline. Legacy/unbounded eligibility is not verified freshness.</div>}
              {impact.lifecycle_uncertainty && <div>Potential additional systems through uncertain nonterminal links: {impact.lifecycle_uncertainty.count}. Separate from active exposure and not proven failure.
                <ul>{impact.lifecycle_uncertainty.possible_additional_systems.slice(0, 20).map(id => <li key={id}>{id}</li>)}</ul>
                {impact.lifecycle_uncertainty.count > 20 && <span>Showing first 20 potential systems.</span>}
              </div>}
              <ul>{result.relationship_lifecycle.excluded_records.slice(0, 20).map((record, i) => <li key={`${record.id}-${i}`}>
                {record.kind || "relationship"} {record.id || "unidentified"}: {record.state}
                {record.valid_until && ` · valid until ${record.valid_until}`}
              </li>)}</ul>
              {(result.relationship_lifecycle.excluded_records.length > 20 || result.relationship_lifecycle.excluded_records_truncated) && <div>Lifecycle evidence listing is bounded; not all retained records are shown.</div>}
            </> : <div>Lifecycle metadata unavailable for this stored answer. Do not assume its links are current.</div>}
          </section>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 10 }}>
            {categories.map(({ label, value, description }) => (
              <section key={label} aria-label={label}
                style={{ padding: 10, background: "var(--bg-2)", borderRadius: "var(--r)" }}>
                <div style={{ fontSize: 11, color: "var(--dim)" }}>{label}</div>
                <div style={{ fontSize: 22, fontWeight: 700 }}>{value.count}</div>
                <div style={{ fontSize: 11, color: "var(--dim)" }}>{description}</div>
                <ul style={{ fontSize: 11, paddingLeft: 16 }}>
                  {value.systems.map((id) => <li key={id}>{id}</li>)}
                </ul>
              </section>
            ))}
            <section aria-label="System totals"
              style={{ padding: 10, background: "var(--bg-2)", borderRadius: "var(--r)" }}>
              {scope ? <>
                <div>Modeled exposure: {scope.exposure_system_count}</div>
                <div>Review scope: {scope.review_system_count}</div>
                <div style={{ fontSize: 11, color: "var(--dim)" }}>
                  Exposure = direct + consumers. Review = exposure + context.
                  Buckets are disjoint; direct takes precedence over consumers, then context.
                </div>
              </> : <>
                <div>Legacy review scope: {impact.affected_system_count ?? "unknown"}</div>
                <div style={{ fontSize: 11, color: "var(--dim)" }}>
                  Classification unavailable for this answer. Do not interpret the legacy total as exposed consumers.
                </div>
              </>}
            </section>
            <div style={{ padding: 10, background: "var(--bg-2)", borderRadius: "var(--r)" }}>
              <div style={{ fontSize: 11, color: "var(--dim)" }}>Linked processes (coverage may be partial)</div>
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

          <div style={{ fontSize: 12, color: "var(--dim)" }}>
            These are modeled relationships, not confirmed failures. Zero linked systems is not proof of no consumers.
            {layers.hardware?.inventory_only && " Hardware linkage is inventory-only; consumer coverage may be missing."}
          </div>

          {impact.migration_waves && Object.keys(impact.migration_waves).length > 0 && (
            <div style={{ fontSize: 12 }}>
              <div style={{ color: "var(--faint)", marginBottom: 4 }}>Migration planning waves (review scope)</div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {Object.entries(impact.migration_waves).map(([wave, sids]) => (
                  <span key={wave} style={{ padding: "3px 8px", background: "var(--bg-2)", borderRadius: "var(--r)", fontSize: 11 }}>
                    wave {wave}: {sids.length}
                  </span>
                ))}
              </div>
            </div>
          )}

          <ProcessImpactPanel impact={impact.process_impact} legacy={impact.affected_processes} />

          {layers.software && (
            <section aria-label="Software release and deployment evidence" style={{ fontSize: 12, padding: 10, background: "var(--bg-2)", borderRadius: "var(--r)" }}>
              <b>Package SBOM → release artifact → application</b>
              <div>{layers.software.packages.length} package rows · {layers.software.artifacts.length} release artifacts · {layers.software.deployments.length} deployment declarations</div>
              <div>{layers.software.deployment_evidence}. SBOM document hashes are not release artifact digests.</div>
              {layers.software.artifacts.slice(0, 20).map((artifact) => (
                <div key={artifact.id} style={{ overflowWrap: "anywhere", marginTop: 6 }}>
                  Release: {artifact.digest} · identity: {artifact.identity_source} · evidence: {artifact.evidence_ref}
                </div>
              ))}
              {layers.software.sbom_bindings.slice(0, 20).map((binding) => (
                <div key={binding.id} style={{ overflowWrap: "anywhere", marginTop: 6 }}>
                  SBOM: {binding.sbom_artifact_id} · document SHA-256: {binding.sbom_sha256}
                  {" · "}{binding.assertion_source} · {binding.effective_state || binding.lifecycle_state || "legacy/unbounded"} · evidence: {binding.evidence_ref}
                  {binding.unresolved_component_count > 0 && ` · ${binding.unresolved_component_count} components lack an exact usable package identity`}
                </div>
              ))}
              {layers.software.packages.slice(0, 20).map((pkg, index) => (
                <div key={`${pkg.sbom_binding_id}:${index}`} style={{ overflowWrap: "anywhere" }}>
                  Package: {pkg.package_identity || `${pkg.name || "unknown"} (unresolved identity)`}
                </div>
              ))}
              {layers.software.deployments.slice(0, 20).map((deployment) => (
                <div key={deployment.id} style={{ overflowWrap: "anywhere", marginTop: 6 }}>
                  Application: {deployment.system_id} · {deployment.environment} · {deployment.deployment_key}
                  {" · "}{deployment.assertion_source} · {deployment.effective_state || deployment.lifecycle_state || "legacy/unbounded"} · evidence: {deployment.evidence_ref}
                </div>
              ))}
              {(layers.software.artifacts.length > 20 || layers.software.deployments.length > 20 || layers.software.sbom_bindings.length > 20 || layers.software.packages.length > 20) && <div>Showing first 20 records per collection; full returned evidence remains in the stored result.</div>}
              {layers.software.unbound_artifact_ids.length > 0 && <div role="status">Release artifacts without valid deployment bindings: {layers.software.unbound_artifact_ids.length}. Consumers remain unknown, not safe.</div>}
              {layers.software.unlinked_deployment_ids.length > 0 && <div role="status">Some deployment declarations have missing systems or conflicting environments; they do not seed exposure.</div>}
              {layers.software.coverage?.truncated && <div role="status">Software supply-chain input was truncated. This is not a complete deployment inventory.</div>}
            </section>
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
                  {r.target_kind || "?"} · {r.system_classification
                    ? `${r.system_classification.direct_exposure.count} direct / ${r.system_classification.dependent_consumers.count} consumers / ${r.system_classification.supporting_context.count} context · ${r.system_classification.review_system_count} review`
                    : `legacy review scope: ${r.affected_system_count ?? "unknown"} · breakdown unavailable`}
                  {" · "}{(r.created_at || "").replace("T", " ").slice(0, 19)}
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
                Review scope: {diff.affected_systems.before} → {diff.affected_systems.after}
                {diff.affected_systems.removed.length > 0 && (
                  <span style={{ color: "var(--dim)" }}> · removed: {diff.affected_systems.removed.join(", ")}</span>
                )}
                {diff.affected_systems.added.length > 0 && (
                  <span style={{ color: "var(--red)" }}> · added: {diff.affected_systems.added.join(", ")}</span>
                )}
                {diff.affected_systems.removed.length === 0 && diff.affected_systems.added.length === 0 && (
                  <span style={{ color: "var(--dim)" }}> · unchanged</span>
                )}
              </div>
              {diff.policy_comparison && !diff.policy_comparison.comparable && (
                <div role="status">Relationship policy differs or is unknown. Count changes are not evidence of remediation.</div>
              )}
              {diff.system_classification?.available ? (
                <div aria-label="Classification changes">
                  {([ ["Direct exposure", diff.system_classification.direct_exposure],
                      ["Dependent consumers", diff.system_classification.dependent_consumers],
                      ["Supporting context", diff.system_classification.supporting_context] ] as const).map(([label, delta]) => (
                    delta && <div key={label}>{label}: {delta.before} → {delta.after}
                      {delta.added.length > 0 && ` · added: ${delta.added.join(", ")}`}
                      {delta.removed.length > 0 && ` · removed: ${delta.removed.join(", ")}`}
                    </div>
                  ))}
                </div>
              ) : <div>Classification comparison unavailable for these stored runs.
                {diff.system_classification?.reason && ` ${diff.system_classification.reason}`}</div>}
              <div style={{ color: "var(--dim)", marginTop: 2 }}>
                {diff.process_comparison?.comparable
                  ? `linked process review scope: ${diff.affected_processes.before} → ${diff.affected_processes.after}`
                  : "Process comparison unavailable: legacy or different process projection/system policy. Do not interpret changed counts as business change."}
              </div>
            </div>
          )}
        </div>
      )}
    </Panel>
  );
}
