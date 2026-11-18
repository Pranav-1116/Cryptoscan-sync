import React, { useEffect, useRef, useState } from "react";
import { activeTenantId, getToken, tenantFetch } from "../lib/api";
import { watchPrivateScope } from "../lib/privateScope";

type RecordRow = { observation_id: string; evidence_id: string; fact_sha256: string; source: { kind: string; path: string; input_content_sha256: string }; fact: { kind: string; software_name: string | null; software_version: string | null; local_basis: string } };
type Package = { identity_slot: string; identity_status: string; package_manager: string; name: string; version: string | null; records: RecordRow[]; architecture: "UNKNOWN"; licenses: "UNKNOWN"; dependencies: "UNKNOWN"; runtime_use: "UNKNOWN"; cryptographic_use: "UNKNOWN"; purl: null; package_artifact_sha256: null };
type Inventory = { schema_version: string; coverage: { job_id: string; envelope_sha256: string; bom_observation_counts: { SBOM: number } }; packages: Package[]; package_inputs: { input_id: string; status: string; reason: string }[]; binary_presence: RecordRow[]; mapped_library_paths: RecordRow[]; provenance: "IMPORTED"; standard_document: false; dependencies_complete: false; installed_package_inventory_complete: false; host_identity_attested: false; production_execution_qualified: false; materialized_without_collection: true };
const hash = (s: string) => typeof s === "string" && /^[0-9a-f]{64}$/.test(s);
const record = (r: RecordRow) => r && typeof r.observation_id === "string" && typeof r.evidence_id === "string" && hash(r.fact_sha256) && r.source && typeof r.source.path === "string" && hash(r.source.input_content_sha256) && r.fact && ["OBSERVED", "DECLARED"].includes(r.fact.local_basis);
function valid(v: Inventory, job: string, envelope: string) {
  return v?.schema_version === "cryptoscan.linux-software-inventory/v1" && v.coverage?.job_id === job && hash(envelope) && v.coverage.envelope_sha256 === envelope
    && v.provenance === "IMPORTED" && v.standard_document === false && v.dependencies_complete === false && v.installed_package_inventory_complete === false && v.host_identity_attested === false && v.production_execution_qualified === false && v.materialized_without_collection === true
    && Array.isArray(v.packages) && v.packages.length <= 1000 && v.packages.every(p => typeof p.name === "string" && typeof p.identity_slot === "string" && ["dpkg", "apk", "rpm"].includes(p.package_manager)
      && [p.architecture, p.licenses, p.dependencies, p.runtime_use, p.cryptographic_use].every(x => x === "UNKNOWN") && p.purl === null && p.package_artifact_sha256 === null
      && Array.isArray(p.records) && p.records.length > 0 && p.records.length <= 1000 && p.records.every(r => record(r) && r.fact.kind === "SOFTWARE" && r.fact.software_name === p.name)
      && p.identity_status === (p.records.length === 1 ? "SINGLE_RECORD" : "MULTIPLE_RECORDS_UNRESOLVED") && p.version === (p.records.length === 1 ? p.records[0].fact.software_version : null))
    && Array.isArray(v.package_inputs) && v.package_inputs.length <= 100 && v.package_inputs.every(i => typeof i.input_id === "string" && typeof i.reason === "string" && ["PARSED", "INVALID", "UNAVAILABLE", "DENIED", "UNSUPPORTED", "BUDGET_EXCEEDED"].includes(i.status))
    && Array.isArray(v.binary_presence) && v.binary_presence.every(r => record(r) && r.fact.kind === "BINARY" && r.source.kind === "BINARY_METADATA")
    && Array.isArray(v.mapped_library_paths) && v.mapped_library_paths.every(r => record(r) && r.fact.kind === "LOADED_LIBRARY" && r.source.kind === "LINUX_PROCESS_MAPS")
    && v.packages.reduce((n, p) => n + p.records.length, 0) + v.binary_presence.length + v.mapped_library_paths.length === v.coverage.bom_observation_counts?.SBOM && v.coverage.bom_observation_counts.SBOM <= 1000;
}

/** Explicit read inside the existing coverage drilldown, never executes a collector. */
export default function LinuxSoftwarePanel({ job, envelope }: { job: string; envelope: string }) {
  const [value, setValue] = useState<Inventory | null>(null), [error, setError] = useState(""), [busy, setBusy] = useState(false);
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
        (async () => { const response = await tenantFetch(`/api/v1/collection/jobs/${encodeURIComponent(job)}/software/linux`, { signal: controller.signal }); if (!response.ok) throw new Error(`Linux software evidence unavailable (${response.status}); no absence inferred.`); return response.json(); })(),
        new Promise<never>((_, reject) => { timeout = setTimeout(() => { controller.abort(); reject(new Error("Software read timed out; no scan or retry performed.")); }, 20000); }),
      ]);
      if (current()) { if (!valid(data, job, envelope)) throw new Error("Software evidence is inconsistent with this job; no inventory inferred."); setValue(data); }
    } catch (e) { if (current()) setError(e instanceof Error ? e.message : "Software evidence unavailable"); }
    finally { if (timeout) clearTimeout(timeout); if (current()) { active.current = null; setBusy(false); } }
  }
  return <section aria-label="Linux software evidence"><h4>Phase 2 · Linux software metadata</h4>
    <p><span title={"Intermediate metadata, not a standard CycloneDX SBOM. Packages, binary presence and mapped paths are separate; none proves cryptographic invocation. No collection starts here."}>{"Intermediate metadata, not a standard CycloneDX SBOM."}</span></p>
    <button disabled={busy} onClick={() => void read()}>Read Linux software evidence</button>
    {busy && <p role="status">Reading software evidence…</p>}{error && <p role="alert">{error}</p>}
    {value && <><p>IMPORTED software metadata · {value.packages.length} scoped package groups · binary-presence records: {value.binary_presence.length} · mapped-library-path records: {value.mapped_library_paths.length}.</p>
      <p><span title={"Architecture, licenses, dependencies, runtime and cryptographic use remain UNKNOWN. No package artifact digest or purl supplied. Incomplete inventory; hashes are not authenticity or host attestation."}>{"Architecture, licenses, dependencies, runtime and cryptographic use remain UNKNOWN."}</span></p>
      {!value.package_inputs.length && <p><span title={"No package inputs requested — no denominator or package-absence conclusion."}>{"No package inputs requested"}</span></p>}
      {value.package_inputs.map(i => <p key={i.input_id}>{i.input_id}: {i.status} · {i.reason}</p>)}
      <p><span title={"Showing up to 50 package groups. Full original records remain available in the authorized API response."}>{"Showing up to 50 package groups."}</span></p>
      <table><thead><tr><th>Metadata slot / manager</th><th>Package / version</th><th>Evidence / provenance</th></tr></thead><tbody>{value.packages.slice(0, 50).map(p => <tr key={p.identity_slot}><td>{p.identity_slot} · {p.package_manager}</td><td>{p.name} · {p.version ?? "UNKNOWN"} · {p.identity_status}</td><td>{p.records.slice(0, 5).map(r => <p key={r.observation_id}>{r.evidence_id} · local {r.fact.local_basis} · {r.source.path} · source-content SHA256 {r.source.input_content_sha256}</p>)}{p.records.length > 5 && <p>Additional records retained in the API; no winning version selected.</p>}</td></tr>)}</tbody></table>
    </>}
  </section>;
}
