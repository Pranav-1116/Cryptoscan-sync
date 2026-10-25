import React, { useEffect, useRef, useState } from "react";
import { activeTenantId, getToken, tenantFetch } from "../lib/api";
import { watchPrivateScope } from "../lib/privateScope";

type Surface = { approved_inputs: number; parsed_inputs: number; failed_inputs: number; fact_count: number; outcome: string; approved_input_parse_percent: number | null; complete_surface_coverage_verified: false; inputs: { input_id: string; fact_count: number; status: string; reason: string; local_basis_counts: { OBSERVED: number; DECLARED: number } }[] };
type Report = { finished_at: string; schema_version: string; job_id: string; envelope_sha256: string; surfaces: Record<string, Surface>; bom_observation_counts: Record<string, number>; whole_host_percent: null; whole_host_coverage_verified: false; asset_absence_proven: false; materialized_without_collection: true; production_execution_qualified: false };
const SURFACES = ["os", "software", "certificates", "crypto_configuration", "processes_and_libraries", "services", "network_listeners", "hardware_metadata"];
function valid(value: Report, id: string) {
  return value?.schema_version === "cryptoscan.collection-surface-coverage/v1" && value.job_id === id
    && /^[0-9a-f]{64}$/.test(value.envelope_sha256) && value.whole_host_percent === null && value.whole_host_coverage_verified === false
    && value.asset_absence_proven === false && value.materialized_without_collection === true && value.production_execution_qualified === false
    && value.surfaces && Object.keys(value.surfaces).length === SURFACES.length && SURFACES.every(key => {
      const s = value.surfaces[key];
      return s && Number.isInteger(s.approved_inputs) && s.approved_inputs >= 0 && s.approved_inputs <= 100
        && Number.isInteger(s.parsed_inputs) && s.parsed_inputs >= 0 && s.parsed_inputs <= s.approved_inputs
        && s.failed_inputs === s.approved_inputs - s.parsed_inputs && s.complete_surface_coverage_verified === false
        && Array.isArray(s.inputs) && s.inputs.length === s.approved_inputs
        && Number.isInteger(s.fact_count) && s.fact_count >= 0 && s.fact_count <= 1000
        && s.inputs.every(i => typeof i.input_id === "string" && typeof i.reason === "string"
          && ["PARSED", "DENIED", "UNSUPPORTED", "INVALID", "BUDGET_EXCEEDED", "UNAVAILABLE"].includes(i.status)
          && Number.isInteger(i.fact_count) && i.fact_count >= 0 && i.fact_count <= 1000
          && i.local_basis_counts && Number.isInteger(i.local_basis_counts.OBSERVED) && i.local_basis_counts.OBSERVED >= 0
          && Number.isInteger(i.local_basis_counts.DECLARED) && i.local_basis_counts.DECLARED >= 0
          && i.local_basis_counts.OBSERVED + i.local_basis_counts.DECLARED === i.fact_count
          && (i.status === "PARSED" || i.fact_count === 0))
        && new Set(s.inputs.map(i => i.input_id)).size === s.inputs.length
        && s.inputs.filter(i => i.status === "PARSED").length === s.parsed_inputs
        && s.inputs.reduce((n, i) => n + i.fact_count, 0) === s.fact_count
        && s.outcome === (!s.approved_inputs ? "NOT_REQUESTED" : !s.parsed_inputs ? "FAILED" : s.failed_inputs ? "PARTIAL" : s.fact_count ? "PARSED_WITH_FACTS" : "PARSED_NO_FACTS")
        && (s.approved_inputs ? typeof s.approved_input_parse_percent === "number" && Number.isFinite(s.approved_input_parse_percent)
          && Math.abs(s.approved_input_parse_percent - 100 * s.parsed_inputs / s.approved_inputs) <= 0.0051 : s.approved_input_parse_percent === null);
    }) && value.bom_observation_counts && Object.keys(value.bom_observation_counts).length === 6 && ["SBOM", "CBOM", "NBOM", "HBOM", "VBOM", "TechBOM"].every(k => Number.isInteger(value.bom_observation_counts[k]) && value.bom_observation_counts[k] >= 0);
}

/** Reads the committed job only. No implicit registration, authorization or scan. */
export default function CollectionCoveragePanel() {
  const [job, setJob] = useState(""), [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState(""), [busy, setBusy] = useState(false);
  const epoch = useRef(0), active = useRef<AbortController | null>(null);
  const invalidate = () => { epoch.current++; active.current?.abort(); active.current = null; setReport(null); setError(""); setBusy(false); };
  useEffect(() => { const stop = watchPrivateScope(() => { invalidate(); setJob(""); }); return () => { stop(); epoch.current++; active.current?.abort(); active.current = null; }; }, []);
  const inspect = async () => {
    if (active.current || !job.trim()) return;
    const id = job.trim(), generation = epoch.current, tenant = activeTenantId(), token = getToken();
    const controller = new AbortController(); active.current = controller;
    const current = () => generation === epoch.current && active.current === controller && tenant === activeTenantId() && token === getToken();
    setBusy(true); setError(""); setReport(null);
    let timeout: ReturnType<typeof setTimeout> | undefined;
    try {
      const data = await Promise.race([
        (async () => {
          const response = await tenantFetch(`/api/v1/collection/jobs/${encodeURIComponent(id)}/coverage/surfaces`, { signal: controller.signal });
          if (!response.ok) throw new Error(`Coverage unavailable (${response.status}); no coverage inferred.`);
          return await response.json();
        })(),
        new Promise<never>((_, reject) => { timeout = setTimeout(() => { controller.abort(); reject(new Error("Coverage read timed out; no scan or retry performed.")); }, 20000); }),
      ]);
      if (current()) { if (!valid(data, id)) throw new Error("Coverage response is inconsistent; no completeness inferred."); setReport(data); }
    } catch (e) { if (current()) setError(e instanceof Error ? e.message : "Coverage unavailable"); }
    finally { if (timeout) clearTimeout(timeout); if (current()) { active.current = null; setBusy(false); } }
  };
  return <section aria-label="Collection surface coverage" style={{ marginTop: 24 }}>
    <h3>Phase 1 · Evidence-backed collection coverage</h3>
    <p>Read a completed universal collection job. This does not start collection. Percentages describe parsed approved inputs, not whole-host, surface or bank inventory completeness.</p>
    <label>Collection job ID<input maxLength={36} value={job} onChange={e => { invalidate(); setJob(e.target.value); }} /></label>
    <button disabled={busy || !job.trim()} onClick={() => void inspect()}>Inspect collection coverage</button>
    {busy && <p role="status">Reading committed evidence…</p>}{error && <p role="alert">{error}</p>}
    {!report && !busy && !error && <p>No committed coverage loaded. Unrequested scope is UNKNOWN, not zero assets.</p>}
    {report && <>
      <p>Original evidence finish time: {report.finished_at || "UNKNOWN"} (operator-supplied, not attested UTC). Historical scope, not a current estate inventory.</p>
      <p>IMPORTED evidence · envelope {report.envelope_sha256}. Host identity, operational use and production qualification remain unverified.</p>
      <table><thead><tr><th>Surface</th><th>Scoped input outcome</th><th>Parsed / approved inputs</th><th>Facts</th><th>Gaps / provenance</th></tr></thead><tbody>
        {Object.entries(report.surfaces).map(([name, s]) => <tr key={name}><td>{name}</td><td>{s.outcome}</td><td>{s.approved_inputs ? `${s.parsed_inputs}/${s.approved_inputs} (${s.approved_input_parse_percent}% input parsing only)` : "Not requested — no denominator"}</td><td>{s.fact_count}</td><td>{s.inputs.map(i => <p key={i.input_id}>{i.input_id}: {i.status} · {i.reason} · local OBSERVED {i.local_basis_counts.OBSERVED}, DECLARED {i.local_basis_counts.DECLARED}</p>)}</td></tr>)}
      </tbody></table>
      <p>All six projections reuse the same evidence (counts are not six collections): {Object.entries(report.bom_observation_counts).map(([name, count]) => `${name}: ${count}`).join(" · ")}. Zero references prove neither absence nor unsupported scope.</p>
      <p>Failed or unrequested inputs never prove asset absence. Parsed configuration remains DECLARED; library presence does not prove cryptographic use; a listener does not prove negotiated TLS.</p>
    </>}
  </section>;
}
