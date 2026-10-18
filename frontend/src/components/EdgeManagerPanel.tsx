import React, { useEffect, useState } from "react";
import { Badge, Panel } from "./ui";
import { apiGraphDeleteEdge, apiGraphEdges, apiGraphRegisterEdge, apiGraphUpdateOperationalDependency, OperationalDependencyAssertion, OperationalMode, RegisteredDependencyEdge } from "../lib/api";

const RELATIONS = ["CALLS", "CONTAINS", "USES", "HOSTS", "BACKS_UP"];

/** Dependency-edge management: the graph's input side. Register, list and
 *  remove the system→system edges every walk (twin, cascade, blast radius)
 *  reads — nothing else writes them. */
export default function EdgeManagerPanel() {
  const [edges, setEdges] = useState<RegisteredDependencyEdge[]>([]);
  const [state, setState] = useState<"loading" | "ready" | "offline">("loading");
  const [parentId, setParentId] = useState("");
  const [childId, setChildId] = useState("");
  const [relation, setRelation] = useState("CALLS");
  const [mode, setMode] = useState<OperationalMode>("UNKNOWN");
  const [alternatives, setAlternatives] = useState("");
  const [capacity, setCapacity] = useState("");
  const [retention, setRetention] = useState("");
  const [assumptions, setAssumptions] = useState("");
  const [modeEvidence, setModeEvidence] = useState("");
  const [modeReason, setModeReason] = useState("");
  const [editing, setEditing] = useState<RegisteredDependencyEdge | null>(null);
  const [retirementReason, setRetirementReason] = useState("");
  const [retirementEvidence, setRetirementEvidence] = useState("");
  const [evidenceRef, setEvidenceRef] = useState("");
  const [confidenceMeaning, setConfidenceMeaning] = useState("");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  const load = async () => {
    const r = await apiGraphEdges();
    if (r.source === "live" && r.data) {
      setEdges(r.data.edges);
      setState("ready");
    } else {
      setState("offline");
    }
  };

  useEffect(() => { load(); }, []);

  const assertion = (): OperationalDependencyAssertion => ({
    mode, evidence_ref: modeEvidence.trim() || undefined,
    assumptions: assumptions.split("\n").map(v => v.trim()).filter(Boolean),
    ...(mode === "FAILOVER" ? { failover_system_ids: alternatives.split(",").map(v => v.trim()).filter(Boolean) } : {}),
    ...(mode === "ASYNC_BUFFERED" ? { buffer_capacity_messages: capacity === "" ? undefined : Number(capacity), buffer_retention_seconds: retention === "" ? undefined : Number(retention) } : {}),
  });

  const editMode = (edge: RegisteredDependencyEdge) => {
    const value = edge.operational_dependency;
    setEditing(edge); setParentId(edge.parent_id); setChildId(edge.child_id);
    setMode(value?.mode || "UNKNOWN"); setAlternatives(value?.failover_system_ids?.join(", ") || "");
    setCapacity(value?.buffer_capacity_messages == null ? "" : String(value.buffer_capacity_messages));
    setRetention(value?.buffer_retention_seconds == null ? "" : String(value.buffer_retention_seconds));
    setAssumptions(value?.assumptions?.join("\n") || ""); setModeEvidence(value?.evidence_ref || ""); setModeReason("");
  };

  const saveMode = async () => {
    if (!editing || editing.lifecycle_revision == null || !modeReason.trim() || !modeEvidence.trim()) return;
    setBusy(true); setNote(null);
    const r = await apiGraphUpdateOperationalDependency(editing.parent_id, editing.child_id, {
      expected_revision: editing.lifecycle_revision, operational_dependency: assertion(), reason: modeReason.trim(), evidence_ref: modeEvidence.trim(),
    });
    setBusy(false);
    if (r.source === "live" && r.data) { setNote("Operational declaration saved; no observation or confirmation refreshed."); setEditing(null); setParentId(""); setChildId(""); setMode("UNKNOWN"); load(); }
    else setNote(r.error || "Mode update failed; reload the edge revision before retrying.");
  };

  const register = async () => {
    if (!parentId.trim() || !childId.trim()) return;
    setBusy(true);
    setNote(null);
    const r = evidenceRef.trim() || confidenceMeaning.trim() || mode !== "UNKNOWN" || modeEvidence.trim() || assumptions.trim()
      ? await apiGraphRegisterEdge(parentId.trim(), childId.trim(), relation, { evidence_ref: evidenceRef.trim() || undefined, confidence_meaning: confidenceMeaning.trim() || undefined, operational_dependency: assertion() })
      : await apiGraphRegisterEdge(parentId.trim(), childId.trim(), relation);
    setBusy(false);
    if (r.source === "live" && r.data) {
      setNote(`registered ${r.data.edge.parent_name || r.data.edge.parent_id} → ${r.data.edge.child_name || r.data.edge.child_id}`);
      setParentId("");
      setChildId("");
      setEvidenceRef(""); setConfidenceMeaning("");
      load();
    } else {
      setNote(r.error || "register failed (unknown system id? duplicate edge?)");
    }
  };

  const remove = async (edge: RegisteredDependencyEdge) => {
    if (edge.lifecycle_revision == null || !retirementReason.trim() || !retirementEvidence.trim()) return;
    setBusy(true);
    setNote(null);
    const r = await apiGraphDeleteEdge(edge.parent_id, edge.child_id, { expected_revision: edge.lifecycle_revision, reason: retirementReason.trim(), evidence_ref: retirementEvidence.trim() });
    setBusy(false);
    if (r.source === "live" && r.data) {
      setNote(`retired (evidence retained) ${edge.parent_name || edge.parent_id} → ${edge.child_name || edge.child_id}`);
      load();
    } else {
      setNote(r.error || "delete failed");
    }
  };

  return (
    <Panel
      title="Dependency edges"
      sub="Manage the registered system dependencies used by cascade and blast-radius analysis"
      className="mt"
    >
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center", marginBottom: 12 }}>
        <input className="inp sm" style={{ width: 170, fontSize: 12 }} placeholder="parent system id or name"
          disabled={!!editing} value={parentId} onChange={(e) => setParentId(e.target.value)} aria-label="parent system" />
        <span style={{ color: "var(--dim)" }}>→</span>
        <input className="inp sm" style={{ width: 170, fontSize: 12 }} placeholder="child system id or name"
          disabled={!!editing} value={childId} onChange={(e) => setChildId(e.target.value)} aria-label="child system" />
        <select disabled={!!editing} value={relation} onChange={(e) => setRelation(e.target.value)} style={{ fontSize: 12, padding: "4px 8px" }} aria-label="relation">
          {RELATIONS.map((rel) => <option key={rel} value={rel}>{rel}</option>)}
        </select>
        <input className="inp sm" aria-label="relationship evidence reference" placeholder="Optional relationship evidence reference" maxLength={500} value={evidenceRef} onChange={e => setEvidenceRef(e.target.value)} />
        <input className="inp sm" aria-label="confidence meaning" placeholder="Optional confidence meaning" maxLength={200} value={confidenceMeaning} onChange={e => setConfidenceMeaning(e.target.value)} />
        <button className="btn sm primary" onClick={register} disabled={!!editing || busy || !parentId.trim() || !childId.trim()}>
          Register edge
        </button>
      </div>

      <div style={{ marginBottom: 12 }}>
        <div>Retirement retains an audited tombstone; it does not prove remediation or failure.</div>
        <input className="inp sm" aria-label="retirement reason" placeholder="Approved retirement reason" maxLength={500}
          value={retirementReason} onChange={e => setRetirementReason(e.target.value)} />
        <input className="inp sm" aria-label="retirement evidence reference" placeholder="Evidence/change reference" maxLength={500}
          value={retirementEvidence} onChange={e => setRetirementEvidence(e.target.value)} />
      </div>

      <fieldset style={{ marginBottom: 10 }}>
        <legend>Operational declaration — not a failure or safety guarantee</legend>
        <label>Mode <select aria-label="operational mode" value={mode} onChange={e => setMode(e.target.value as OperationalMode)}>
          {["UNKNOWN", "HARD", "OPTIONAL", "FAILOVER", "ASYNC_BUFFERED"].map(m => <option key={m}>{m}</option>)}
        </select></label>
        <input aria-label="operational evidence reference" placeholder="Operational-mode evidence pointer (not reverified)" value={modeEvidence} onChange={e => setModeEvidence(e.target.value)} />
        <textarea aria-label="operational assumptions" placeholder="Declared assumptions, one per line" value={assumptions} onChange={e => setAssumptions(e.target.value)} />
        {mode === "FAILOVER" && <input aria-label="failover alternative system IDs" placeholder="Exact alternative system IDs, comma separated" value={alternatives} onChange={e => setAlternatives(e.target.value)} />}
        {mode === "ASYNC_BUFFERED" && <>
          <input type="number" min={0} step={1} aria-label="buffer capacity messages" placeholder="Declared capacity (messages)" value={capacity} onChange={e => setCapacity(e.target.value)} />
          <input type="number" min={0} step="any" aria-label="buffer retention seconds" placeholder="Declared retention (seconds)" value={retention} onChange={e => setRetention(e.target.value)} />
          <div>No safe buffering duration is inferred from capacity or retention.</div>
        </>}
        {editing && <>
          <input aria-label="operational change reason" placeholder="Required reason for this revision" value={modeReason} onChange={e => setModeReason(e.target.value)} />
          <button onClick={saveMode} disabled={busy || !modeReason.trim() || !modeEvidence.trim()}>Save operational mode</button>
          <button onClick={() => { setEditing(null); setParentId(""); setChildId(""); setMode("UNKNOWN"); }}>Cancel mode edit</button>
        </>}
        <div>Missing modes remain UNKNOWN. Optional/failover/buffered dependencies remain in change review. Editing requires manual lifecycle ownership and the current revision.</div>
      </fieldset>

      {note && <div style={{ fontSize: 12, color: "var(--dim)", marginBottom: 8 }}>{note}</div>}

      {state === "loading" && <div style={{ fontSize: 12, color: "var(--dim)" }}>loading edges…</div>}
      {state === "offline" && <div style={{ fontSize: 12, color: "var(--dim)" }}>edge list unavailable (backend offline)</div>}

      {state === "ready" && edges.length === 0 && (
        <div style={{ fontSize: 12, color: "var(--dim)" }}>
          No dependency edges registered yet — every cascade and blast radius walks an empty graph until some exist.
        </div>
      )}

      {state === "ready" && edges.length > 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: 4, maxHeight: 320, overflowY: "auto" }}>
          {edges.map((e) => (
            <div key={`${e.parent_id}:${e.child_id}:${e.relation}`}
              style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 12, padding: "5px 8px", background: "var(--bg-2)", borderRadius: "var(--r)" }}>
              <span style={{ fontWeight: 600 }}>{e.parent_name || e.parent_id}</span>
              <span style={{ color: "var(--cyan)" }}>→</span>
              <span style={{ fontWeight: 600 }}>{e.child_name || e.child_id}</span>
              <Badge variant="neutral">{e.relation}</Badge>
              <span>Mode: {e.operational_condition?.mode || e.operational_dependency?.mode || "UNKNOWN"} (unverified declaration)</span>
              <button onClick={() => editMode(e)} disabled={busy || e.lifecycle_revision == null || e.lifecycle_source !== "manual" || ["DELETED", "SUPERSEDED"].includes(e.effective_state || "")}>Edit mode</button>
              <span>{e.source || "source unknown"} · reference: {e.evidence_ref || "missing"}{e.confidence_meaning ? ` · ${e.confidence_meaning}` : " · confidence meaning unspecified"}</span>
              <span>{e.effective_state || "lifecycle unknown"}{e.valid_until ? ` · expires ${e.valid_until}` : " · no expiry deadline"}</span>
              <button className="btn sm outline" style={{ marginLeft: "auto", fontSize: 11 }} disabled={busy || e.lifecycle_revision == null || ["DELETED", "SUPERSEDED"].includes(e.effective_state || "") || !retirementReason.trim() || !retirementEvidence.trim()}
                onClick={() => remove(e)}>
                retire
              </button>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}
