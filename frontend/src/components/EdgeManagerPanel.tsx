import React, { useEffect, useState } from "react";
import { Badge, Panel } from "./ui";
import { apiGraphDeleteEdge, apiGraphEdges, apiGraphRegisterEdge, GraphEdge } from "../lib/api";

const RELATIONS = ["CALLS", "CONTAINS", "USES", "HOSTS", "BACKS_UP"];

/** Dependency-edge management: the graph's input side. Register, list and
 *  remove the system→system edges every walk (twin, cascade, blast radius)
 *  reads — nothing else writes them. */
export default function EdgeManagerPanel() {
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [state, setState] = useState<"loading" | "ready" | "offline">("loading");
  const [parentId, setParentId] = useState("");
  const [childId, setChildId] = useState("");
  const [relation, setRelation] = useState("CALLS");
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

  const register = async () => {
    if (!parentId.trim() || !childId.trim()) return;
    setBusy(true);
    setNote(null);
    const r = await apiGraphRegisterEdge(parentId.trim(), childId.trim(), relation);
    setBusy(false);
    if (r.source === "live" && r.data) {
      setNote(`registered ${r.data.edge.parent_name || r.data.edge.parent_id} → ${r.data.edge.child_name || r.data.edge.child_id}`);
      setParentId("");
      setChildId("");
      load();
    } else {
      setNote(r.error || "register failed (unknown system id? duplicate edge?)");
    }
  };

  const remove = async (edge: GraphEdge) => {
    setBusy(true);
    setNote(null);
    const r = await apiGraphDeleteEdge(edge.parent_id, edge.child_id);
    setBusy(false);
    if (r.source === "live" && r.data) {
      setNote(`removed ${edge.parent_name || edge.parent_id} → ${edge.child_name || edge.child_id}`);
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
          value={parentId} onChange={(e) => setParentId(e.target.value)} aria-label="parent system" />
        <span style={{ color: "var(--dim)" }}>→</span>
        <input className="inp sm" style={{ width: 170, fontSize: 12 }} placeholder="child system id or name"
          value={childId} onChange={(e) => setChildId(e.target.value)} aria-label="child system" />
        <select value={relation} onChange={(e) => setRelation(e.target.value)} style={{ fontSize: 12, padding: "4px 8px" }} aria-label="relation">
          {RELATIONS.map((rel) => <option key={rel} value={rel}>{rel}</option>)}
        </select>
        <button className="btn sm primary" onClick={register} disabled={busy || !parentId.trim() || !childId.trim()}>
          Register edge
        </button>
      </div>

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
              <button className="btn sm outline" style={{ marginLeft: "auto", fontSize: 11 }} disabled={busy}
                onClick={() => remove(e)}>
                remove
              </button>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}
