import React, { useEffect, useRef, useState } from "react";
import AuthenticatedDownload from "./AuthenticatedDownload";
import { activeTenantId, getToken, tenantFetch } from "../lib/api";
import { watchPrivateScope } from "../lib/privateScope";

type Node = { observation_id: string; evidence_id: string; fact_sha256: string; provenance: string; fact: { kind: string; local_basis: string } };
type Edge = { edge_id: string; relation: string; source_observation_id: string; target_observation_id: string; supporting_observation_ids: string[]; evidence_ids: string[]; basis: string; local_basis: string; runtime_use: string; production_traffic_proven: false };
type Unresolved = { observation_id: string; relation: string; reason: string; candidate_count: number; candidate_observation_ids: string[]; candidate_list_truncated: boolean; asset_absence_proven: false };
type Graph = { schema_version: string; coverage: { job_id: string; envelope_sha256: string; bom_observation_counts: { TechBOM: number } }; nodes: Node[]; edges: Edge[]; unresolved: Unresolved[]; unsupported_relationships: string[]; provenance: string; identity_basis: string; relationship_completeness_proven: false; host_identity_attested: false; production_execution_qualified: false; materialized_without_collection: true };
const relations = ["PROCESS_HAS_MAPPED_PATH", "PROCESS_REPORTS_SERVICE_UNIT"];
const unsupported = ["SERVICE_MAINPID_TO_PROCESS_INCARNATION", "LISTENER_TO_PROCESS", "CONFIGURATION_TO_SERVICE", "CERTIFICATE_TO_LISTENER", "HARDWARE_TO_APPLICATION_OR_KEY", "PACKAGE_TO_BINARY_OR_LIBRARY"];
function valid(v: Graph, job: string, envelope: string) {
  if (!(v?.schema_version === "cryptoscan.linux-relationships/v1" && v.coverage?.job_id === job && v.coverage.envelope_sha256 === envelope
    && v.provenance === "IMPORTED" && v.identity_basis === "SCOPED_METADATA_SLOT_NOT_ATTESTED_ASSET" && v.relationship_completeness_proven === false && v.host_identity_attested === false && v.production_execution_qualified === false && v.materialized_without_collection === true
    && Array.isArray(v.nodes) && v.nodes.length <= 1000 && v.nodes.length === v.coverage.bom_observation_counts?.TechBOM && new Set(v.nodes.map(n => n.observation_id)).size === v.nodes.length
    && v.nodes.every(n => typeof n.observation_id === "string" && typeof n.evidence_id === "string" && /^[0-9a-f]{64}$/.test(n.fact_sha256) && n.provenance === "IMPORTED" && ["OBSERVED", "DECLARED"].includes(n.fact?.local_basis))
    && Array.isArray(v.unsupported_relationships) && JSON.stringify(v.unsupported_relationships) === JSON.stringify(unsupported))) return false;
  const nodes = new Map(v.nodes.map(n => [n.observation_id, n]));
  return Array.isArray(v.edges) && v.edges.length <= 1000 && new Set(v.edges.map(e => e.edge_id)).size === v.edges.length && v.edges.every(e => {
    const s = nodes.get(e.source_observation_id), t = nodes.get(e.target_observation_id);
    return s && t && /^[0-9a-f]{64}$/.test(e.edge_id) && relations.includes(e.relation) && e.basis === "EXACT_CAPTURED_FIELDS_NOT_ATTESTED_USAGE" && e.local_basis === "INFERRED" && e.runtime_use === "UNKNOWN" && e.production_traffic_proven === false
      && JSON.stringify(e.supporting_observation_ids) === JSON.stringify([s.observation_id, t.observation_id])
      && JSON.stringify(e.evidence_ids) === JSON.stringify([...new Set([s.evidence_id, t.evidence_id])].sort())
      && s.fact.kind === "PROCESS" && t.fact.kind === (e.relation === "PROCESS_HAS_MAPPED_PATH" ? "LOADED_LIBRARY" : "SERVICE");
  }) && Array.isArray(v.unresolved) && v.unresolved.length <= 1000 && v.unresolved.every(u => nodes.has(u.observation_id) && relations.includes(u.relation) && ["NO_MATCHING_OBSERVATION", "AMBIGUOUS_MATCH", "SERVICE_UNIT_NOT_RECORDED"].includes(u.reason)
    && Number.isInteger(u.candidate_count) && u.candidate_count >= 0 && u.candidate_count <= 1000 && Array.isArray(u.candidate_observation_ids) && u.candidate_observation_ids.length === Math.min(u.candidate_count, 20) && u.candidate_observation_ids.every(id => nodes.has(id)) && u.candidate_list_truncated === (u.candidate_count > 20) && u.asset_absence_proven === false);
}

export default function LinuxEvidenceOutputs({ job, envelope }: { job: string; envelope: string }) {
  const [value, setValue] = useState<Graph | null>(null), [error, setError] = useState(""), [busy, setBusy] = useState(false);
  const epoch = useRef(0), active = useRef<AbortController | null>(null);
  useEffect(() => {
    const clear = () => { epoch.current++; active.current?.abort(); active.current = null; setValue(null); setError(""); setBusy(false); };
    clear(); const stop = watchPrivateScope(clear);
    return () => { stop(); epoch.current++; active.current?.abort(); active.current = null; };
  }, [job, envelope]);
  async function read() {
    if (active.current) return;
    const generation = epoch.current, tenant = activeTenantId(), token = getToken(), controller = new AbortController(); active.current = controller;
    const current = () => generation === epoch.current && active.current === controller && tenant === activeTenantId() && token === getToken();
    setBusy(true); setError(""); setValue(null);
    let timeout: ReturnType<typeof setTimeout> | undefined;
    try {
      const data = await Promise.race([
        (async () => { const r = await tenantFetch(`/api/v1/collection/jobs/${encodeURIComponent(job)}/relationships/linux`, { signal: controller.signal }); if (!r.ok) throw new Error(`Linux relationships unavailable (${r.status}); no relationship inferred.`); return r.json(); })(),
        new Promise<never>((_, reject) => { timeout = setTimeout(() => { controller.abort(); reject(new Error("Relationship read timed out; no retry or collection performed.")); }, 20000); }),
      ]);
      if (current()) { if (!valid(data, job, envelope)) throw new Error("Relationship response inconsistent with this evidence; no graph inferred."); setValue(data); }
    } catch (e) { if (current()) setError(e instanceof Error ? e.message : "Relationships unavailable"); }
    finally { if (timeout) clearTimeout(timeout); if (current()) { active.current = null; setBusy(false); } }
  }
  return <section aria-label="Linux evidence outputs"><h4>Linux relationships and standard software export</h4>
    <p>Download an officially schema-validated CycloneDX 1.6 SBOM with explicit incomplete composition. Package type uses the specification default, not observed application classification. Schema validity does not prove completeness, authenticity, dependencies, runtime use or production qualification.</p>
    <AuthenticatedDownload key={job + envelope} path={`/api/v1/collection/jobs/${encodeURIComponent(job)}/software/linux/cyclonedx-1.6`} filename="linux-software.cdx.json">Download Linux CycloneDX 1.6 SBOM</AuthenticatedDownload>
    <button disabled={busy} onClick={() => void read()}>Read Linux evidence relationships</button>
    {busy && <p role="status">Reading relationship evidence…</p>}{error && <p role="alert">{error}</p>}
    {value && <><p>{value.nodes.length} original observation nodes · {value.edges.length} exact metadata joins · {value.unresolved.length} unresolved joins. No rescan. Separate captures do not prove simultaneous or continuous operation.</p>
      <p>Unsupported with captured fields: {value.unsupported_relationships.join(" · ")}. Service MainPID alone does not identify a process incarnation; a listener does not prove a TLS or certificate relationship.</p>
      <p>Showing up to 50 joins and 50 unresolved records; full bounded details remain in the authorized API.</p>
      {value.edges.slice(0, 50).map(e => <p key={e.edge_id}>{e.relation}: {e.source_observation_id} → {e.target_observation_id} · evidence {e.evidence_ids.join(", ")} · runtime use UNKNOWN · local INFERRED</p>)}
      {value.unresolved.slice(0, 50).map(u => <p key={u.observation_id + u.relation}>{u.observation_id}: {u.relation} · {u.reason} · candidates {u.candidate_count} (not an absence conclusion)</p>)}
    </>}
  </section>;
}
