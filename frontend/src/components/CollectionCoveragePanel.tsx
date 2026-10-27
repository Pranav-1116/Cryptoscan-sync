import LinuxEvidenceOutputs from "./LinuxEvidenceOutputs";
import LinuxSoftwarePanel from "./LinuxSoftwarePanel";
import { Badge, Bar } from "./ui";
import { IconComponent, IconSearch, IconTarget, IconHardware } from "./icons";
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
  return <section className="panel" aria-label="Collection surface coverage" style={{ marginTop: 16, padding: 16, borderTop: "2px solid var(--cyan)" }}>
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10, flexWrap: "wrap", marginBottom: 10 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <span style={{ width: 32, height: 32, borderRadius: 8, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--accent) 14%, transparent)", border: "1px solid var(--accent)" }}><IconTarget size={14} style={{ color: "var(--accent)" }} /></span>
        <div>
          <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700 }}>Phase 1 · Collection Coverage</h3>
          <div style={{ fontSize: 11, color: "var(--dim)" }}>Committed job read-only · parsed / approved · not whole-host completeness</div>
        </div>
        <Badge tone="cyan">EVIDENCE</Badge><Badge tone="slate">READ ONLY</Badge>
      </div>
      <span style={{ fontSize: 11, color: "var(--dim)" }}>Unrequested = UNKNOWN · does not start collection</span>
    </div>
    <div style={{ display: "flex", gap: 8, alignItems: "end", flexWrap: "wrap", marginBottom: 12 }}>
      <label style={{ flex: 1, minWidth: 200, display: "flex", flexDirection: "column", gap: 4, fontSize: 11, color: "var(--dim)" }}>Collection job ID<input style={{ padding: "7px 10px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg-2)", color: "var(--text)", fontFamily: "var(--mono)", fontSize: 12.5 }} maxLength={36} value={job} onChange={e => { invalidate(); setJob(e.target.value); }} /></label>
      <button className="btn primary sm" disabled={busy || !job.trim()} onClick={() => void inspect()}>{busy ? "Reading…" : "Inspect collection coverage"}</button>
    </div>
    {busy && <div style={{ padding: "8px 10px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", fontSize: 12, display: "flex", gap: 8, alignItems: "center" }}><span style={{ width: 8, height: 8, borderRadius: 99, background: "var(--accent)" }} />Reading committed evidence…</div>}{error && <div role="alert" style={{ padding: "8px 10px", background: "color-mix(in srgb, var(--red) 10%, transparent)", border: "1px solid var(--red)", borderRadius: "var(--r)", fontSize: 12, color: "var(--red)" }}>{error}</div>}
    {!report && !busy && !error && <div style={{ padding: "12px", textAlign: "center", background: "var(--bg-2)", border: "1px dashed var(--line)", borderRadius: "var(--r)", fontSize: 12, color: "var(--dim)" }}><IconSearch size={16} style={{ color: "var(--faint)" }} /><div style={{ marginTop: 4 }}>No committed coverage loaded — enter a job ID above</div><div style={{ fontSize: 11, color: "var(--faint)" }}>Unrequested scope is <strong>UNKNOWN</strong>, not zero assets</div></div>}
    {report && <>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 10, padding: "8px 10px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", alignItems: "center" }}>
        <Badge tone="slate">{report.job_id.slice(0,8)}…</Badge><span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--dim)", overflowWrap: "anywhere" }}>envelope {report.envelope_sha256.slice(0,16)}… · {report.finished_at || "UNKNOWN"}</span><Badge tone="amber">NOT ATTESTED</Badge><Badge tone="slate">HISTORICAL</Badge>
      </div>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 8 }}>
        <span style={{ fontSize: 10, padding: "4px 8px", borderRadius: "var(--r)", background: "var(--panel-2)", border: "1px solid var(--line)", color: "var(--dim)" }}>IMPORTED evidence</span><span style={{ fontSize: 10, padding: "4px 8px", borderRadius: "var(--r)", background: "var(--panel-2)", border: "1px solid var(--line)", color: "var(--dim)" }}>Host identity unverified</span><span style={{ fontSize: 10, padding: "4px 8px", borderRadius: "var(--r)", background: "var(--panel-2)", border: "1px solid var(--line)", color: "var(--dim)" }}>Production not qualified</span>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 8, marginTop: 10 }}>
        {Object.entries(report.surfaces).map(([name, s]) => (
          <div key={name} style={{ padding: "10px 12px", background: "var(--panel-2)", border: "1px solid var(--line)", borderTop: `2px solid ${s.outcome === "PARSED_WITH_FACTS" ? "var(--green)" : s.outcome === "FAILED" ? "var(--red)" : s.outcome === "PARTIAL" ? "var(--amber)" : "var(--line-strong)"}`, borderRadius: "var(--r)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}><span style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: .06 }}>{name.replaceAll("_"," ")}</span><Badge tone={s.outcome === "PARSED_WITH_FACTS" ? "green" : s.outcome === "PARTIAL" ? "amber" : s.outcome === "FAILED" ? "red" : "slate"}>{s.outcome}</Badge></div>
            <div style={{ fontSize: 12, marginTop: 6, fontFamily: "var(--mono)" }}>{s.approved_inputs ? `${s.parsed_inputs}/${s.approved_inputs} · ${s.approved_input_parse_percent}%` : "— / — · not requested"}</div>
            <Bar value={s.approved_inputs ? s.parsed_inputs / s.approved_inputs : 0} tone={s.outcome === "FAILED" ? "red" : s.outcome === "PARTIAL" ? "amber" : "cyan"} />
            <div style={{ fontSize: 11, color: "var(--dim)", marginTop: 4 }}>{s.fact_count} facts · {s.inputs.length} inputs</div>
          </div>
        ))}
      </div>
      <details style={{ marginTop: 10 }}><summary style={{ fontSize: 12, color: "var(--accent)", cursor: "pointer" }}>Provenance per surface (inputs · reasons)</summary><div style={{ marginTop: 8, maxHeight: 240, overflow: "auto", padding: "8px 10px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>{Object.entries(report.surfaces).map(([name, s]) => (<div key={name} style={{ marginBottom: 10 }}><div style={{ fontSize: 11, fontWeight: 700, color: "var(--dim)" }}>{name}</div>{s.inputs.map(i => <div key={i.input_id} style={{ fontSize: 11, color: "var(--dim)", padding: "2px 0", borderBottom: "1px solid var(--line)" }}>{i.input_id}: <Badge tone={i.status === "PARSED" ? "green" : i.status === "FAILED" ? "red" : "slate"}>{i.status}</Badge> {i.reason} · OBS {i.local_basis_counts.OBSERVED} / DECL {i.local_basis_counts.DECLARED}</div>)}</div>))}</div></details>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 10, padding: "8px 10px", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>{Object.entries(report.bom_observation_counts).map(([name, count]) => (<span key={name} style={{ fontSize: 11, padding: "4px 8px", borderRadius: "var(--r)", background: "var(--bg-2)", border: "1px solid var(--line)", fontFamily: "var(--mono)" }}>{name}: <strong>{count}</strong></span>))}<span style={{ fontSize: 11, color: "var(--faint)", marginLeft: 6 }}>Same evidence · 6 projections · zero ≠ absence</span></div>
      <p>Failed or unrequested inputs never prove asset absence. Parsed configuration remains DECLARED; library presence does not prove cryptographic use; a listener does not prove negotiated TLS.</p>
      <LinuxSoftwarePanel job={report.job_id} envelope={report.envelope_sha256} />
      <LinuxEvidenceOutputs job={report.job_id} envelope={report.envelope_sha256} />
    </>}
  </section>;
}
