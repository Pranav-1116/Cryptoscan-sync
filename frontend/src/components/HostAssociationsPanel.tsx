import React, { useEffect, useRef, useState } from "react";
import { apiHostAssociationTarget, apiProposeHostAssociation, apiDecideHostAssociation, apiHostEstateGraph, HostAssociationTargetType, HostAssociationTarget, HostEstateGraph, HostSnapshotInspection } from "../lib/api";
import { usePrivateScopeCurrent } from "./PrivateScope";
import AuthenticatedDownload from "./AuthenticatedDownload";
const domains = ["SBOM", "CBOM", "NBOM", "HBOM", "VBOM", "TechBOM"];
const types: HostAssociationTargetType[] = ["sbom_binding", "phase_receipt", "hardware", "vendor", "deployment"];
const sha = (value: unknown) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
function validGraph(g: HostEstateGraph, detail: HostSnapshotInspection) {
  return g?.schema_version === "cryptoscan.host-estate-graph/v1" && g.approval_id === detail.approval_id
    && g.system_id === detail.system_id && g.snapshot_sha256 === detail.snapshot_sha256 && sha(g.graph_sha256)
    && g.whole_host_coverage_verified === false && g.host_identity_attested === false && g.operational_dependency_verified === false && g.pqc_use === "UNKNOWN"
    && Array.isArray(g.nodes) && g.nodes.length >= 2 && g.nodes.length <= 1202 && Array.isArray(g.edges) && g.edges.length <= 1252
    && g.nodes.every(n => n && typeof n.id === "string" && domains.includes(n.bom) && ["DECLARED", "IMPORTED"].includes(n.evidence_status))
    && g.edges.every(e => e && ["APPROVED_COLLECTION_SCOPE", "REPORT_CONTAINS_RECEIPT", "RECEIPT_CONTAINS_METADATA", "CUSTOMER_REVIEWED_METADATA_ASSOCIATION"].includes(e.predicate)
      && g.nodes.some(n => n.id === e.from) && g.nodes.some(n => n.id === e.to) && ["DECLARED", "IMPORTED"].includes(e.evidence_status)
      && e.operational_dependency_verified === false && e.runtime_use === "UNKNOWN" && e.provenance && typeof e.provenance === "object" && !Array.isArray(e.provenance) && Object.keys(e.provenance).length > 0)
    && Array.isArray(g.associations) && g.associations.length <= 50 && g.associations.every(a => a && typeof a.id === "string" && Number.isInteger(a.revision) && a.revision >= 1 && a.revision <= 3
      && types.includes(a.target_type) && domains.includes(a.bom) && ["PROPOSED", "REVIEWED", "STALE", "RETRACTED"].includes(a.state)
      && a.evidence_status === "DECLARED" && sha(a.payload_sha256) && typeof a.proposal_reason === "string" && typeof a.evidence_ref === "string")
    && g.domains && Object.keys(g.domains).length === 6 && domains.every(d => typeof g.domains[d]?.represented === "boolean" && g.domains[d].operational_use === "UNKNOWN");
}

/** Deliberate requests only; parent source/scope changes unmount all drafts. */
export default function HostAssociationsPanel({ detail }: { detail: HostSnapshotInspection }) {
  const current = usePrivateScopeCurrent(), generation = useRef(0), alive = useRef(true);
  const [type, setType] = useState<HostAssociationTargetType>("hardware"), [id, setId] = useState(""), [purl, setPurl] = useState(""), [fact, setFact] = useState("");
  const [reference, setReference] = useState(""), [reason, setReason] = useState("");
  const [target, setTarget] = useState<HostAssociationTarget | null>(null), [graph, setGraph] = useState<HostEstateGraph | null>(null);
  const [busy, setBusy] = useState(false), [message, setMessage] = useState("");
  const facts = detail.snapshot.receipts.flatMap(r => r.status === "PARSED" ? r.facts.map((f, i) => ({ input_id: r.input_id, fact_ordinal: i, kind: f.kind })) : []);
  useEffect(() => { alive.current = true; return () => { alive.current = false; generation.current++; }; }, []);
  const valid = (token: number) => alive.current && current() && token === generation.current;
  const invalidate = () => { generation.current++; setTarget(null); setMessage(""); };
  const decisionReady = reference.trim().length > 0 && reason.trim().length >= 20;
  async function resolve() {
    if (busy || !id.trim() || (type === "sbom_binding" && !purl.trim())) return;
    const token = ++generation.current; if (!valid(token)) return;
    setBusy(true); setTarget(null); setMessage("");
    const result = await apiHostAssociationTarget(detail.approval_id, type, id.trim(), type === "sbom_binding" ? purl.trim() : undefined);
    if (!valid(token)) return; setBusy(false);
    const v = result.data;
    if (result.source === "live" && result.ok && v?.target_type === type && v.target_id === id.trim() && sha(v.target_sha256) && domains.includes(v.bom) && v.evidence_status === "DECLARED" && v.runtime_use === "UNKNOWN") setTarget(v);
    else setMessage(`${result.error || "Target unavailable or unverified"}. No association assumed.`);
  }
  async function loadGraph() {
    if (busy) return;
    const token = ++generation.current; if (!valid(token)) return;
    setBusy(true); setGraph(null); setMessage("");
    const result = await apiHostEstateGraph(detail.approval_id); if (!valid(token)) return;
    setBusy(false);
    if (result.source === "live" && result.ok && result.data && validGraph(result.data, detail)) setGraph(result.data);
    else setMessage(`${result.error || "Graph unavailable or unverified"}. No complete or secure estate assumed.`);
  }
  async function propose() {
    const selected = facts[Number(fact) - 1]; if (busy || !target || !fact || !selected || !decisionReady) return;
    const token = ++generation.current; if (!valid(token)) return;
    setBusy(true); setGraph(null); setMessage("");
    const result = await apiProposeHostAssociation(detail.approval_id, { input_id: selected.input_id, fact_ordinal: selected.fact_ordinal,
      target_type: type, target_id: target.target_id, package_identity: type === "sbom_binding" ? purl.trim() : null, expected_target_sha256: target.target_sha256,
      expires_at: new Date(Date.now() + 24 * 3600 * 1000).toISOString(), evidence_ref: reference.trim(), reason: reason.trim() });
    if (!valid(token)) return; setBusy(false); setTarget(null);
    setMessage(result.source === "live" && result.ok ? "Proposal recorded, not an active edge. A different admin/CISO must review. Load the graph to inspect history." : `${result.error || "Proposal unavailable"}. No success assumed; inspect before intentionally retrying.`);
  }
  async function decide(id: string, revision: number, action: "review" | "retract") {
    if (busy || !decisionReady) return;
    const token = ++generation.current; if (!valid(token)) return;
    setBusy(true); setGraph(null); setMessage("");
    const result = await apiDecideHostAssociation(detail.approval_id, id, action, revision, reference.trim(), reason.trim()); if (!valid(token)) return;
    setBusy(false);
    setMessage(result.source === "live" && result.ok ? "Decision recorded. Load the graph to revalidate its current state; runtime and PQC use remain UNKNOWN." : `${result.error || "Decision unavailable"}. No review or retraction assumed; inspect before intentionally retrying.`);
  }
  return <section aria-label="Host six-BOM associations" style={{ marginTop: 20, overflowWrap: "anywhere" }}>
    <h4>Six-BOM provenance graph · reviewed metadata only</h4>
    <p><span title={"No relationship is created from matching names or co-existence. A customer-reviewed association is DECLARED, not proof of operational dependency, endpoint identity, firmware, HSM/KMS use or PQC use. Failed observations and missing domains remain UNKNOWN."}>{"No relationship is created from matching names or co-existence."}</span></p>
    <p>Analysts propose; a different admin/CISO reviews. Auditors/viewers read and export only. API enforces current roles. Proposals expire after 24 hours in this console; stale and retracted assertions are not active graph edges.</p>
    <label>Association source fact<select disabled={busy} value={fact} onChange={e => { invalidate(); setFact(e.target.value); }}><option value="">Select an imported fact</option>{facts.map((f, i) => <option key={i} value={String(i + 1)}>{f.input_id} · fact {f.fact_ordinal} · {f.kind}</option>)}</select></label>
    <label>Association target type<select disabled={busy} value={type} onChange={e => { invalidate(); setType(e.target.value as HostAssociationTargetType); setId(""); setPurl(""); }}>{types.map(t => <option key={t} value={t}>{t}</option>)}</select></label>
    <label>Association target ID<input maxLength={36} value={id} disabled={busy} onChange={e => { invalidate(); setId(e.target.value); }} /></label>
    {type === "sbom_binding" && <label>Exact versioned package identity<input maxLength={500} value={purl} disabled={busy} onChange={e => { invalidate(); setPurl(e.target.value); }} /></label>}
    <button disabled={busy || !id.trim() || (type === "sbom_binding" && !purl.trim())} onClick={() => void resolve()}>Inspect association target</button>
    {target && <p>Current {target.bom} identity SHA-256: {target.target_sha256} · metadata only; runtime UNKNOWN.</p>}
    <label>Association evidence reference<input maxLength={180} disabled={busy} value={reference} onChange={e => setReference(e.target.value)} /></label>
    <label>Association rationale<textarea maxLength={500} disabled={busy} value={reason} onChange={e => setReason(e.target.value)} /></label>
    <button disabled={busy || !target || !fact || !decisionReady} onClick={() => void propose()}>Propose metadata association</button>
    <button disabled={busy} onClick={() => void loadGraph()}>Load six-BOM graph</button>
    {busy && <p role="status">Checking scoped association evidence…</p>}{message && <p role="status">{message}</p>}
    {graph && <><p>Evaluated {graph.evaluated_at}. Graph SHA-256: {graph.graph_sha256}. This is CryptoScan graph JSON, not a CycloneDX dependency document.</p>
      <ul>{domains.map(d => <li key={d}>{d}: {graph.domains[d].represented ? "metadata represented" : "no resolved metadata"} · operational use UNKNOWN</li>)}</ul>
      <table><caption>Current provenance edges — no operational dependency verified</caption><thead><tr><th>From</th><th>To</th><th>Predicate / basis</th><th>Provenance</th></tr></thead><tbody>{graph.edges.map((e, i) => <tr key={i}><td>{e.from}</td><td>{e.to}</td><td>{e.predicate} · {e.evidence_status}</td><td><code>{JSON.stringify(e.provenance)}</code></td></tr>)}</tbody></table>
      <table><caption>Association history heads · stale and retracted are excluded from edges</caption><thead><tr><th>Target / fact</th><th>State</th><th>Customer evidence</th><th>Decision</th></tr></thead><tbody>{graph.associations.map(a => <tr key={a.id}><td>{a.bom} · {a.target_id} · {a.package_identity || ""} · {a.input_id} fact {a.fact_ordinal}</td><td>{a.state} · revision {a.revision}{a.reason ? ` · ${a.reason}` : ""}</td><td>{a.evidence_ref} · {a.proposal_reason}<br />Expires {a.expires_at} · proposer {a.proposed_by} · reviewer {a.reviewed_by || "not reviewed"}<br />{a.decision_reason || ""}</td><td>{a.state === "PROPOSED" && <button disabled={busy || !decisionReady} onClick={() => void decide(a.id, a.revision, "review")}>Review association {a.id}</button>}{a.state !== "RETRACTED" && <button disabled={busy || !decisionReady} onClick={() => void decide(a.id, a.revision, "retract")}>Retract association {a.id}</button>}</td></tr>)}</tbody></table>
      <AuthenticatedDownload path={`/api/v1/host-evidence/approvals/${encodeURIComponent(detail.approval_id)}/graph/export`} filename={`host-${detail.approval_id}-graph-v1.json`}>Export provenance graph JSON</AuthenticatedDownload>
    </>}
  </section>;
}
