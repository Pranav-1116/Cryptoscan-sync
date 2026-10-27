import React, { useEffect, useState } from "react";
import { Badge, Panel, Bar } from "./ui";
import { IconComponent, IconSearch, IconTarget, IconHardware, IconCertificate, IconCloud } from "./icons";
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
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

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
      title={<span style={{ display: "flex", alignItems: "center", gap: 8 }}><IconTarget size={14} style={{ color: "var(--accent)" }} /> Dependency edges <Badge tone="cyan">MANUAL</Badge> <Badge tone="slate">BFS SOURCE</Badge></span>}
      sub="Registered system→system edges — the only input every cascade/blast walk reads"
      className="mt"
      style={{ borderTop: "2px solid var(--accent)" }}
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

      <div style={{ marginBottom: 12, padding: "8px 10px", background: "color-mix(in srgb, var(--amber) 8%, transparent)", border: "1px solid var(--line)", borderRadius: "var(--r)", display: "flex", gap: 8, alignItems: "center" }}>
        <Badge tone="amber">TOMBSTONE</Badge><div style={{ fontSize: 11, color: "var(--dim)" }}>Retirement retains audited tombstone — does not prove remediation or failure.</div>
      </div>
      <div style={{ marginBottom: 12 }}>
        <div style={{ display: "none" }}></div>
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

      {note && <div style={{ fontSize: 12, color: "var(--dim)", marginBottom: 8, padding: "8px 10px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>{note}</div>}

      {/* Visual Graph — [+]/[−] tree with [brackets] */}
      {state === "ready" && edges.length > 0 && (() => {
        const childrenByParent = new Map<string, typeof edges>();
        const allIds = new Set<string>();
        edges.forEach(e => {
          allIds.add(e.parent_id); allIds.add(e.child_id);
          if (!childrenByParent.has(e.parent_id)) childrenByParent.set(e.parent_id, []);
          childrenByParent.get(e.parent_id)!.push(e);
        });
        const childSet = new Set(edges.map(e => e.child_id));
        const roots = [...childrenByParent.keys()].filter(id => !childSet.has(id));
        const startNodes = roots.length ? roots : [...childrenByParent.keys()].slice(0, 5);
        const isExpanded = (id: string) => expanded.has(id) || expanded.size === 0;
        const toggle = (id: string) => setExpanded(prev => {
          const n = new Set(prev);
          if (n.has(id)) n.delete(id);
          else n.add(id);
          // if first interaction, expand set was empty meaning all expanded; now we need explicit set
          if (prev.size === 0 && !n.has(id)) {
            // was all-expanded, now collapse one: need to fill with all except that
            const allParents = [...childrenByParent.keys()];
            const filled = new Set(allParents.filter(x => x !== id));
            return filled;
          }
          return n;
        });
        const kindIcon = (id: string) => null;
        const renderNode = (nodeId: string, depth: number, prefix: string[], isLast: boolean, visited: Set<string>): React.ReactNode[] => {
          if (visited.has(nodeId)) return [<div key={nodeId + depth} style={{ paddingLeft: depth * 14, fontFamily: "var(--mono)", fontSize: 12, color: "var(--amber)" }}>{prefix.join("") + (depth ? (isLast ? "└─ " : "├─ ") : "")}[{nodeId}] <span style={{ color: "var(--amber)" }}>[cycle]</span></div>];
          visited.add(nodeId);
          const kids = childrenByParent.get(nodeId) || [];
          const expandedNow = isExpanded(nodeId);
          const hasKids = kids.length > 0;
          const label = edges.find(e => e.parent_id === nodeId)?.parent_name || edges.find(e => e.child_id === nodeId)?.child_name || nodeId;
          const line = (
            <div key={nodeId + "-row-" + depth} style={{ display: "flex", alignItems: "center", gap: 6, padding: "4px 6px", background: depth === 0 ? "var(--panel)" : "transparent", borderLeft: depth ? "1px dashed var(--line)" : "none", marginLeft: depth ? 8 : 0 }}>
              <span style={{ color: "var(--faint)", fontFamily: "var(--mono)", fontSize: 11 }}>{prefix.join("")}{depth ? (isLast ? "└─" : "├─") : ""}</span>
              {hasKids && <button onClick={() => toggle(nodeId)} style={{ width: 18, height: 18, display: "grid", placeItems: "center", border: "1px solid var(--line)", borderRadius: "var(--r)", background: expandedNow ? "var(--panel-2)" : "var(--accent)", color: expandedNow ? "var(--text)" : "var(--on-accent)", fontSize: 10, fontWeight: 700, cursor: "pointer", flexShrink: 0 }}>{expandedNow ? "−" : "+"}</button>}
              {!hasKids && <span style={{ width: 18, height: 18, display: "inline-block" }} />}
              <span style={{ fontFamily: "var(--mono)", fontSize: 12, fontWeight: 600, color: "var(--text)", border: "1px solid var(--line)", padding: "1px 6px", borderRadius: "var(--r)", background: "var(--panel-2)" }}>[{label}]</span>
              {hasKids && <span style={{ fontSize: 11, color: "var(--dim)", fontFamily: "var(--mono)" }}>—{kids.length}×</span>}
            </div>
          );
          const out: React.ReactNode[] = [line];
          if (hasKids && expandedNow) {
            kids.forEach((e, idx) => {
              const last = idx === kids.length - 1;
              const childLabel = e.child_name || e.child_id;
              const edgeBadge = (
                <div key={e.parent_id + ":" + e.child_id + ":" + idx} style={{ paddingLeft: depth * 14 + 18, display: "flex", alignItems: "center", gap: 6, fontSize: 11, color: "var(--dim)", fontFamily: "var(--mono)" }}>
                  <span style={{ color: "var(--faint)" }}>{[...prefix, depth ? (isLast ? "   " : "│  ") : ""].join("")}{last ? "└─" : "├─"}─[{e.relation}]─►</span>
                  <span style={{ border: "1px solid var(--line)", padding: "0 5px", borderRadius: "var(--r)", background: "var(--bg-2)", color: "var(--text)" }}>[{childLabel}]</span>
                  <Badge tone={e.operational_dependency?.mode === "HARD" ? "red" : e.operational_dependency?.mode === "FAILOVER" ? "amber" : "slate"}>{e.operational_dependency?.mode || "UNKNOWN"}</Badge>
                  {e.effective_state && <span style={{ fontSize: 10, color: "var(--faint)" }}>{e.effective_state}</span>}
                </div>
              );
              out.push(edgeBadge);
              const childKids = childrenByParent.get(e.child_id) || [];
              if (childKids.length > 0 && expandedNow) {
                const nextPrefix = [...prefix, depth ? (isLast ? "   " : "│  ") : ""];
                out.push(...renderNode(e.child_id, depth + 1, nextPrefix, last, new Set(visited)));
              }
            });
          }
          return out;
        };
        return (
          <div style={{ marginBottom: 12, padding: 12, background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8, flexWrap: "wrap", gap: 8 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}><IconComponent size={12} style={{ color: "var(--accent)" }} /><span style={{ fontSize: 11, fontWeight: 700, letterSpacing: .06 }}>VISUAL GRAPH — [+]/[−] expand · [brackets] = nodes</span><Badge tone="cyan">{edges.length} edges</Badge><Badge tone="slate">{startNodes.length} roots</Badge></div>
              <div style={{ display: "flex", gap: 6 }}>
                <button className="btn sm" onClick={() => setExpanded(new Set([...childrenByParent.keys()]))} style={{ fontSize: 10, padding: "4px 8px" }}>Expand all [+]</button>
                <button className="btn sm outline" onClick={() => setExpanded(new Set())} style={{ fontSize: 10, padding: "4px 8px" }}>Collapse all [−]</button>
              </div>
            </div>
            <div style={{ maxHeight: 360, overflowY: "auto", padding: "6px", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>
              {startNodes.map((id, idx) => renderNode(id, 0, [], idx === startNodes.length - 1, new Set()))}
            </div>
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6, fontFamily: "var(--mono)" }}>[System] ─[RELATION]─► [System] · +/− toggles children · dashed lines = tree depth · cycle guarded</div>
          </div>
        );
      })()}

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
