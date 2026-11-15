import React, { useEffect, useState } from "react";
import { Badge, Panel, Bar } from "./ui";
import { RequireRole } from "../lib/auth";
import { EDGE_WRITE_ROLES } from "../lib/rbac";
import {
  IconComponent,
  IconSearch,
  IconTarget,
  IconHardware,
  IconCertificate,
  IconCloud,
  IconSettings,
  IconInfo,
  IconWarn,
  ICON_SM,
} from "./icons";
import {
  apiGraphDeleteEdge,
  apiGraphEdges,
  apiGraphRegisterEdge,
  apiGraphUpdateOperationalDependency,
  OperationalDependencyAssertion,
  OperationalMode,
  RegisteredDependencyEdge,
} from "../lib/api";

const RELATIONS = ["CALLS", "CONTAINS", "USES", "HOSTS", "BACKS_UP"] as const;

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

  useEffect(() => {
    load();
  }, []);

  const assertion = (): OperationalDependencyAssertion => ({
    mode,
    evidence_ref: modeEvidence.trim() || undefined,
    assumptions: assumptions.split("\n").map((v) => v.trim()).filter(Boolean),
    ...(mode === "FAILOVER"
      ? { failover_system_ids: alternatives.split(",").map((v) => v.trim()).filter(Boolean) }
      : {}),
    ...(mode === "ASYNC_BUFFERED"
      ? {
          buffer_capacity_messages: capacity === "" ? undefined : Number(capacity),
          buffer_retention_seconds: retention === "" ? undefined : Number(retention),
        }
      : {}),
  });

  const editMode = (edge: RegisteredDependencyEdge) => {
    const value = edge.operational_dependency;
    setEditing(edge);
    setParentId(edge.parent_id);
    setChildId(edge.child_id);
    setMode(value?.mode || "UNKNOWN");
    setAlternatives(value?.failover_system_ids?.join(", ") || "");
    setCapacity(value?.buffer_capacity_messages == null ? "" : String(value.buffer_capacity_messages));
    setRetention(value?.buffer_retention_seconds == null ? "" : String(value.buffer_retention_seconds));
    setAssumptions(value?.assumptions?.join("\n") || "");
    setModeEvidence(value?.evidence_ref || "");
    setModeReason("");
  };

  const saveMode = async () => {
    if (!editing || editing.lifecycle_revision == null || !modeReason.trim() || !modeEvidence.trim()) return;
    setBusy(true);
    setNote(null);
    const r = await apiGraphUpdateOperationalDependency(editing.parent_id, editing.child_id, {
      expected_revision: editing.lifecycle_revision,
      operational_dependency: assertion(),
      reason: modeReason.trim(),
      evidence_ref: modeEvidence.trim(),
    });
    setBusy(false);
    if (r.source === "live" && r.data) {
      setNote("Operational declaration saved — no observation or confirmation refreshed.");
      setEditing(null);
      setParentId("");
      setChildId("");
      setMode("UNKNOWN");
      load();
    } else setNote(r.error || "Mode update failed — reload the edge revision before retrying.");
  };

  const register = async () => {
    if (!parentId.trim() || !childId.trim()) return;
    setBusy(true);
    setNote(null);
    const r =
      evidenceRef.trim() ||
      confidenceMeaning.trim() ||
      mode !== "UNKNOWN" ||
      modeEvidence.trim() ||
      assumptions.trim()
        ? await apiGraphRegisterEdge(parentId.trim(), childId.trim(), relation, {
            evidence_ref: evidenceRef.trim() || undefined,
            confidence_meaning: confidenceMeaning.trim() || undefined,
            operational_dependency: assertion(),
          })
        : await apiGraphRegisterEdge(parentId.trim(), childId.trim(), relation);
    setBusy(false);
    if (r.source === "live" && r.data) {
      setNote(`Registered ${r.data.edge.parent_name || r.data.edge.parent_id} → ${r.data.edge.child_name || r.data.edge.child_id}`);
      setParentId("");
      setChildId("");
      setEvidenceRef("");
      setConfidenceMeaning("");
      load();
    } else {
      setNote(r.error || "Register failed — unknown system id or duplicate edge");
    }
  };

  const remove = async (edge: RegisteredDependencyEdge) => {
    if (edge.lifecycle_revision == null || !retirementReason.trim() || !retirementEvidence.trim()) return;
    setBusy(true);
    setNote(null);
    const r = await apiGraphDeleteEdge(edge.parent_id, edge.child_id, {
      expected_revision: edge.lifecycle_revision,
      reason: retirementReason.trim(),
      evidence_ref: retirementEvidence.trim(),
    });
    setBusy(false);
    if (r.source === "live" && r.data) {
      setNote(`Retired (evidence retained) ${edge.parent_name || edge.parent_id} → ${edge.child_name || edge.child_id}`);
      load();
    } else {
      setNote(r.error || "Delete failed");
    }
  };

  return (
    <Panel
      title={
        <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <IconTarget size={14} style={{ color: "var(--accent)" }} /> Dependency edges{" "}
          <Badge tone="cyan">MANUAL</Badge> <Badge tone="slate">BFS SOURCE</Badge>
        </span>
      }
      sub="Registered system → system edges. Only input every cascade and blast walk reads."
      className="mt"
      style={{ borderTop: "2px solid var(--accent)", padding: 0, overflow: "hidden" }}
    >
      {/* Create edge — primary workspace */}
      <div style={{ padding: "16px 16px 14px", background: "var(--panel)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
          <span style={{ width: 22, height: 22, borderRadius: "var(--r)", background: "var(--accent)", color: "var(--on-accent)", display: "grid", placeItems: "center", fontSize: 11, fontWeight: 700 }}>1</span>
          <h4 style={{ margin: 0, fontSize: 12, fontWeight: 600, letterSpacing: "0.01em" }}>Create dependency</h4>
          <span style={{ fontSize: 11, color: "var(--faint)" }}>— directed system edge, audited</span>
          {editing && <Badge tone="amber">Editing mode for {editing.parent_id} → {editing.child_id}</Badge>}
        </div>

        {/* Primary identity row */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 28px 1fr 140px", gap: 10, alignItems: "end" }}>
          <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <span style={{ fontSize: 10, fontWeight: 600, letterSpacing: "0.08em", color: "var(--dim)", textTransform: "uppercase" }}>Parent system</span>
            <input
              className="inp"
              placeholder="ID or name — e.g. payments-api"
              disabled={!!editing}
              value={parentId}
              onChange={(e) => setParentId(e.target.value)}
              aria-label="parent system"
              style={{ fontFamily: "var(--mono)", fontSize: 12.5 }}
            />
          </label>
          <div style={{ display: "grid", placeItems: "center", paddingBottom: 9, color: "var(--accent)", fontWeight: 700 }}>→</div>
          <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <span style={{ fontSize: 10, fontWeight: 600, letterSpacing: "0.08em", color: "var(--dim)", textTransform: "uppercase" }}>Child system</span>
            <input
              className="inp"
              placeholder="ID or name — e.g. hsm-vault"
              disabled={!!editing}
              value={childId}
              onChange={(e) => setChildId(e.target.value)}
              aria-label="child system"
              style={{ fontFamily: "var(--mono)", fontSize: 12.5 }}
            />
          </label>
          <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <span style={{ fontSize: 10, fontWeight: 600, letterSpacing: "0.08em", color: "var(--dim)", textTransform: "uppercase" }}>Relation</span>
            <select
              className="inp"
              disabled={!!editing}
              value={relation}
              onChange={(e) => setRelation(e.target.value)}
              aria-label="relation"
              style={{ fontSize: 12, fontWeight: 600 }}
            >
              {RELATIONS.map((rel) => (
                <option key={rel} value={rel}>
                  {rel}
                </option>
              ))}
            </select>
          </label>
        </div>

        {/* Evidence row */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginTop: 12 }}>
          <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <span style={{ fontSize: 10, fontWeight: 600, letterSpacing: "0.06em", color: "var(--faint)", textTransform: "uppercase" }}>Relationship evidence <span style={{ fontWeight: 400, textTransform: "none", letterSpacing: 0 }}>— optional</span></span>
            <input
              className="inp"
              aria-label="relationship evidence reference"
              placeholder="Ticket, commit, discovery run — e.g. JIRA-4821 / sha256:…"
              maxLength={500}
              value={evidenceRef}
              onChange={(e) => setEvidenceRef(e.target.value)}
            />
          </label>
          <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <span style={{ fontSize: 10, fontWeight: 600, letterSpacing: "0.06em", color: "var(--faint)", textTransform: "uppercase" }}>Confidence meaning <span style={{ fontWeight: 400, textTransform: "none", letterSpacing: 0 }}>— optional</span></span>
            <input
              className="inp"
              aria-label="confidence meaning"
              placeholder="What this confidence level means for this edge"
              maxLength={200}
              value={confidenceMeaning}
              onChange={(e) => setConfidenceMeaning(e.target.value)}
            />
          </label>
        </div>

        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 14, gap: 12, flexWrap: "wrap" }}>
          <span style={{ fontSize: 11, color: "var(--faint)", lineHeight: 1.4 }}>
            Edge is a manual declaration. Provenance is recorded; it is not an observed traffic proof.
          </span>
          <RequireRole anyOf={[...EDGE_WRITE_ROLES]}>
            <button className="btn primary" onClick={register} disabled={!!editing || busy || !parentId.trim() || !childId.trim()} style={{ minWidth: 132 }}>
              {busy ? "Registering…" : "Register edge"}
            </button>
          </RequireRole>
        </div>
      </div>

      {/* Operational declaration — secondary card */}
      <div style={{ padding: "14px 16px", background: "var(--bg-2)", borderTop: "1px solid var(--line)", borderBottom: "1px solid var(--line)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
          <IconSettings size={12} style={{ color: "var(--dim)" }} />
          <h4 style={{ margin: 0, fontSize: 11, fontWeight: 600, letterSpacing: "0.06em", textTransform: "uppercase", color: "var(--dim)" }}>
            Operational declaration
          </h4>
          <Badge tone="slate">Not a failure or safety guarantee</Badge>
          <span style={{ marginLeft: "auto", fontSize: 11, color: "var(--faint)" }}>Applies at registration — editable via Edit mode</span>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "160px 1fr", gap: 10, alignItems: "start" }}>
          <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <span style={{ fontSize: 10, fontWeight: 600, letterSpacing: "0.06em", color: "var(--dim)", textTransform: "uppercase" }}>Mode</span>
            <select
              className="inp"
              aria-label="operational mode"
              value={mode}
              onChange={(e) => setMode(e.target.value as OperationalMode)}
              style={{ fontWeight: 600 }}
            >
              {["UNKNOWN", "HARD", "OPTIONAL", "FAILOVER", "ASYNC_BUFFERED"].map((m) => (
                <option key={m}>{m}</option>
              ))}
            </select>
          </label>
          <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <span style={{ fontSize: 10, fontWeight: 600, letterSpacing: "0.06em", color: "var(--dim)", textTransform: "uppercase" }}>Evidence pointer <span style={{ color: "var(--red)", fontWeight: 600 }}>*</span></span>
            <input
              className="inp"
              aria-label="operational evidence reference"
              placeholder="Pointer to evidence (not reverified) — e.g. runbook:…"
              value={modeEvidence}
              onChange={(e) => setModeEvidence(e.target.value)}
            />
          </label>
        </div>

        <label style={{ display: "flex", flexDirection: "column", gap: 6, marginTop: 10 }}>
          <span style={{ fontSize: 10, fontWeight: 600, letterSpacing: "0.06em", color: "var(--dim)", textTransform: "uppercase" }}>Declared assumptions — one per line</span>
          <textarea
            className="inp"
            aria-label="operational assumptions"
            placeholder="e.g. Retry budget 3x / Circuit breaks after 5s / Fallback is read-only"
            value={assumptions}
            onChange={(e) => setAssumptions(e.target.value)}
            rows={2}
            style={{ resize: "vertical", minHeight: 42, fontFamily: "var(--mono)", fontSize: 12 }}
          />
        </label>

        {mode === "FAILOVER" && (
          <label style={{ display: "flex", flexDirection: "column", gap: 6, marginTop: 10 }}>
            <span style={{ fontSize: 10, fontWeight: 600, letterSpacing: "0.06em", color: "var(--dim)", textTransform: "uppercase" }}>Failover alternatives — exact system IDs</span>
            <input
              className="inp"
              aria-label="failover alternative system IDs"
              placeholder="Comma separated — e.g. payments-api-b, payments-api-c"
              value={alternatives}
              onChange={(e) => setAlternatives(e.target.value)}
              style={{ fontFamily: "var(--mono)" }}
            />
          </label>
        )}

        {mode === "ASYNC_BUFFERED" && (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginTop: 10 }}>
            <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              <span style={{ fontSize: 10, fontWeight: 600, letterSpacing: "0.06em", color: "var(--dim)", textTransform: "uppercase" }}>Buffer capacity (messages)</span>
              <input
                className="inp"
                type="number"
                min={0}
                step={1}
                aria-label="buffer capacity messages"
                placeholder="e.g. 10000"
                value={capacity}
                onChange={(e) => setCapacity(e.target.value)}
              />
            </label>
            <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              <span style={{ fontSize: 10, fontWeight: 600, letterSpacing: "0.06em", color: "var(--dim)", textTransform: "uppercase" }}>Retention (seconds)</span>
              <input
                className="inp"
                type="number"
                min={0}
                step="any"
                aria-label="buffer retention seconds"
                placeholder="e.g. 3600"
                value={retention}
                onChange={(e) => setRetention(e.target.value)}
              />
            </label>
            <div style={{ gridColumn: "1 / -1", fontSize: 11, color: "var(--faint)", display: "flex", gap: 6, alignItems: "center" }}>
              <IconInfo size={12} /> No safe buffering duration is inferred from capacity or retention.
            </div>
          </div>
        )}

        {editing ? (
          <div style={{ marginTop: 12, padding: 12, background: "var(--panel)", border: "1px solid var(--line-strong)", borderRadius: "var(--r)" }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: "var(--amber)", marginBottom: 8, display: "flex", alignItems: "center", gap: 6 }}>
              <IconWarn size={12} /> Editing revision {editing.lifecycle_revision} — change is audited
            </div>
            <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              <span style={{ fontSize: 10, fontWeight: 600, letterSpacing: "0.06em", color: "var(--dim)", textTransform: "uppercase" }}>Reason for this revision <span style={{ color: "var(--red)" }}>*</span></span>
              <input
                className="inp"
                aria-label="operational change reason"
                placeholder="Why this mode/assumption change is required"
                value={modeReason}
                onChange={(e) => setModeReason(e.target.value)}
              />
            </label>
            <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
              <RequireRole anyOf={[...EDGE_WRITE_ROLES]}>
                <button className="btn primary sm" onClick={saveMode} disabled={busy || !modeReason.trim() || !modeEvidence.trim()}>
                  Save operational mode
                </button>
              </RequireRole>
              <button
                className="btn sm"
                onClick={() => {
                  setEditing(null);
                  setParentId("");
                  setChildId("");
                  setMode("UNKNOWN");
                }}
              >
                Cancel edit
              </button>
            </div>
          </div>
        ) : (
          <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 10, lineHeight: 1.5 }}>
            Missing modes remain <b style={{ color: "var(--text)" }}>UNKNOWN</b>. Optional / failover / buffered links remain in change-review. Edit requires manual ownership and the current revision.
          </div>
        )}
      </div>

      {/* Tombstone / retirement */}
      <div style={{ padding: "14px 16px", background: "var(--panel)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
          <Badge tone="amber">TOMBSTONE</Badge>
          <span style={{ fontSize: 11, color: "var(--dim)" }}>
            Retirement keeps an audited tombstone — it does not prove remediation or failure.
          </span>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
          <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <span style={{ fontSize: 10, fontWeight: 600, letterSpacing: "0.06em", color: "var(--dim)", textTransform: "uppercase" }}>Approved retirement reason</span>
            <input
              className="inp"
              aria-label="retirement reason"
              placeholder="e.g. Decommissioned — replaced by v2 (T-892)"
              maxLength={500}
              value={retirementReason}
              onChange={(e) => setRetirementReason(e.target.value)}
            />
          </label>
          <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <span style={{ fontSize: 10, fontWeight: 600, letterSpacing: "0.06em", color: "var(--dim)", textTransform: "uppercase" }}>Evidence / change reference</span>
            <input
              className="inp"
              aria-label="retirement evidence reference"
              placeholder="e.g. CHANGE-1042 / ADR-17"
              maxLength={500}
              value={retirementEvidence}
              onChange={(e) => setRetirementEvidence(e.target.value)}
            />
          </label>
        </div>
        <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 6 }}>Required per-edge at Retire. Use Retire on the edge row below.</div>
      </div>

      {note && (
        <div
          style={{
            margin: "0 16px 14px",
            fontSize: 12,
            color: note.startsWith("Registered") || note.startsWith("Retired") || note.startsWith("Operational") ? "var(--accent)" : "var(--amber)",
            background: "var(--bg-2)",
            border: "1px solid var(--line)",
            borderLeft: `2px solid ${note.startsWith("Registered") ? "var(--accent)" : "var(--amber)"}`,
            padding: "8px 10px",
            borderRadius: "var(--r)",
          }}
        >
          {note}
        </div>
      )}

      {/* Visual Graph — [+]/[−] tree with [brackets] */}
      {state === "ready" && edges.length > 0 && (
        <div style={{ margin: "0 16px 14px" }}>
          {(() => {
            const childrenByParent = new Map<string, typeof edges>();
            edges.forEach((e) => {
              if (!childrenByParent.has(e.parent_id)) childrenByParent.set(e.parent_id, []);
              childrenByParent.get(e.parent_id)!.push(e);
            });
            const childSet = new Set(edges.map((e) => e.child_id));
            const roots = [...childrenByParent.keys()].filter((id) => !childSet.has(id));
            const startNodes = roots.length ? roots : [...childrenByParent.keys()].slice(0, 6);
            const isExpanded = (id: string) => expanded.has(id) || expanded.size === 0;
            const toggle = (id: string) =>
              setExpanded((prev) => {
                const n = new Set(prev);
                if (n.has(id)) n.delete(id);
                else n.add(id);
                if (prev.size === 0 && !n.has(id)) {
                  const allParents = [...childrenByParent.keys()];
                  return new Set(allParents.filter((x) => x !== id));
                }
                return n;
              });

            const renderNode = (
              nodeId: string,
              depth: number,
              prefix: string[],
              isLast: boolean,
              visited: Set<string>
            ): React.ReactNode[] => {
              if (visited.has(nodeId))
                return [
                  <div
                    key={nodeId + depth}
                    style={{ paddingLeft: depth * 14, fontFamily: "var(--mono)", fontSize: 11, color: "var(--amber)", padding: "2px 0" }}
                  >
                    {prefix.join("") + (depth ? (isLast ? "└─ " : "├─ ") : "")}[{nodeId}] <span>[cycle]</span>
                  </div>,
                ];
              visited.add(nodeId);
              const kids = childrenByParent.get(nodeId) || [];
              const expandedNow = isExpanded(nodeId);
              const hasKids = kids.length > 0;
              const label = edges.find((e) => e.parent_id === nodeId)?.parent_name || nodeId;
              const line = (
                <div
                  key={nodeId + "-row-" + depth}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 7,
                    padding: "5px 8px",
                    background: depth === 0 ? "var(--panel)" : "transparent",
                    border: "1px solid var(--line)",
                    borderLeft: depth === 0 ? "2px solid var(--accent)" : "1px solid var(--line)",
                    borderRadius: "var(--r)",
                    marginLeft: depth ? 10 : 0,
                    marginTop: 4,
                  }}
                >
                  <span style={{ color: "var(--faint)", fontFamily: "var(--mono)", fontSize: 10, minWidth: 18 }}>{prefix.join("")}{depth ? (isLast ? "└─" : "├─") : ""}</span>
                  {hasKids ? (
                    <button
                      onClick={() => toggle(nodeId)}
                      aria-label={expandedNow ? "collapse" : "expand"}
                      style={{
                        width: 18,
                        height: 18,
                        display: "grid",
                        placeItems: "center",
                        border: "1px solid var(--line-strong)",
                        borderRadius: 4,
                        background: expandedNow ? "var(--panel-2)" : "var(--accent)",
                        color: expandedNow ? "var(--dim)" : "var(--on-accent)",
                        fontSize: 10,
                        fontWeight: 700,
                        cursor: "pointer",
                        flexShrink: 0,
                      }}
                    >
                      {expandedNow ? "−" : "+"}
                    </button>
                  ) : (
                    <span style={{ width: 18, height: 18, display: "inline-block" }} />
                  )}
                  <span
                    style={{
                      fontFamily: "var(--mono)",
                      fontSize: 11.5,
                      fontWeight: 600,
                      color: "var(--text)",
                      background: "var(--panel-2)",
                      border: "1px solid var(--line)",
                      padding: "2px 7px",
                      borderRadius: "var(--r)",
                    }}
                  >
                    [{label}]
                  </span>
                  {hasKids && (
                    <span style={{ fontSize: 10, color: "var(--dim)", fontFamily: "var(--mono)", background: "var(--bg-2)", padding: "1px 6px", borderRadius: 99, border: "1px solid var(--line)" }}>
                      {kids.length} {kids.length === 1 ? "child" : "children"}
                    </span>
                  )}
                </div>
              );
              const out: React.ReactNode[] = [line];
              if (hasKids && expandedNow) {
                kids.forEach((e, idx) => {
                  const last = idx === kids.length - 1;
                  const childLabel = e.child_name || e.child_id;
                  const edgeBadge = (
                    <div
                      key={e.parent_id + ":" + e.child_id + ":" + idx}
                      style={{
                        paddingLeft: depth * 14 + 22,
                        display: "flex",
                        alignItems: "center",
                        gap: 6,
                        fontSize: 10.5,
                        color: "var(--dim)",
                        fontFamily: "var(--mono)",
                        marginTop: 4,
                      }}
                    >
                      <span style={{ color: "var(--line-strong)" }}>
                        {[...prefix, depth ? (isLast ? "   " : "│  ") : ""].join("")}
                        {last ? "└─" : "├─"}─[{e.relation}]─►
                      </span>
                      <span
                        style={{
                          border: "1px solid var(--line)",
                          padding: "1px 6px",
                          borderRadius: "var(--r)",
                          background: "var(--bg-2)",
                          color: "var(--text)",
                          fontWeight: 600,
                        }}
                      >
                        [{childLabel}]
                      </span>
                      <Badge tone={e.operational_dependency?.mode === "HARD" ? "red" : e.operational_dependency?.mode === "FAILOVER" ? "amber" : "slate"}>
                        {e.operational_dependency?.mode || "UNKNOWN"}
                      </Badge>
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
              <div
                style={{
                  background: "var(--bg-2)",
                  border: "1px solid var(--line)",
                  borderRadius: "var(--r)",
                  overflow: "hidden",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    padding: "10px 12px",
                    borderBottom: "1px solid var(--line)",
                    background: "var(--panel)",
                    flexWrap: "wrap",
                    gap: 8,
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <IconComponent size={13} style={{ color: "var(--accent)" }} />
                    <span style={{ fontSize: 10.5, fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase", color: "var(--text)" }}>
                      Graph visual
                    </span>
                    <span style={{ fontSize: 11, color: "var(--faint)" }}>— [+]/[−] expand · [brackets] = nodes</span>
                    <Badge tone="cyan">{edges.length} edges</Badge>
                    <Badge tone="slate">{startNodes.length} roots</Badge>
                  </div>
                  <div style={{ display: "flex", gap: 6 }}>
                    <button className="btn sm" onClick={() => setExpanded(new Set([...childrenByParent.keys()]))} style={{ fontSize: 10, height: 24, padding: "0 8px" }}>
                      Expand all [+]
                    </button>
                    <button
                      className="btn sm"
                      onClick={() => setExpanded(new Set())}
                      style={{ fontSize: 10, height: 24, padding: "0 8px", background: "transparent" }}
                    >
                      Collapse [−]
                    </button>
                  </div>
                </div>
                <div
                  style={{
                    maxHeight: 360,
                    overflowY: "auto",
                    padding: 10,
                    background: "var(--panel)",
                  }}
                >
                  {startNodes.map((id, idx) => renderNode(id, 0, [], idx === startNodes.length - 1, new Set()))}
                </div>
                <div
                  style={{
                    fontSize: 10,
                    color: "var(--faint)",
                    padding: "7px 12px",
                    borderTop: "1px solid var(--line)",
                    background: "var(--bg-2)",
                    fontFamily: "var(--mono)",
                  }}
                >
                  [System] ─[RELATION]─► [System] · +/− toggles children · dashed lines = depth · cycle guarded
                </div>
              </div>
            );
          })()}
        </div>
      )}

      {state === "loading" && (
        <div style={{ margin: "0 16px 16px", fontSize: 12, color: "var(--dim)", display: "flex", gap: 8, alignItems: "center" }}>
          <span style={{ width: 10, height: 10, border: "2px solid var(--line-strong)", borderTopColor: "var(--accent)", borderRadius: "50%", display: "inline-block", animation: "spin 0.8s linear infinite" }} /> Loading edges…
        </div>
      )}
      {state === "offline" && (
        <div style={{ margin: "0 16px 16px", padding: "12px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", fontSize: 12, color: "var(--dim)", textAlign: "center" }}>
          Edge list unavailable — backend offline. No edges rendered.
        </div>
      )}

      {state === "ready" && edges.length === 0 && (
        <div
          style={{
            margin: "0 16px 16px",
            padding: "18px",
            background: "var(--bg-2)",
            border: "1px dashed var(--line-strong)",
            borderRadius: "var(--r)",
            textAlign: "center",
          }}
        >
          <IconSearch size={20} style={{ color: "var(--faint)", marginBottom: 6 }} />
          <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text)" }}>No edges registered</div>
          <div style={{ fontSize: 11, color: "var(--dim)", marginTop: 4, maxWidth: 420, marginInline: "auto" }}>
            Every cascade and blast radius walks an empty graph until at least one system → system edge exists. Register one above.
          </div>
        </div>
      )}

      {state === "ready" && edges.length > 0 && (
        <div style={{ margin: "0 16px 16px" }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
            <span style={{ fontSize: 10, fontWeight: 600, letterSpacing: "0.06em", color: "var(--dim)", textTransform: "uppercase" }}>
              Inventory — {edges.length} edges
            </span>
            <span style={{ fontSize: 11, color: "var(--faint)" }}>Newest first · lifecycle-aware</span>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 6, maxHeight: 380, overflowY: "auto", paddingRight: 2 }}>
            {edges.map((e) => (
              <div
                key={`${e.parent_id}:${e.child_id}:${e.relation}`}
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr auto",
                  gap: 10,
                  padding: "10px 12px",
                  background: "var(--panel-2)",
                  border: "1px solid var(--line)",
                  borderLeft: "2px solid var(--line-strong)",
                  borderRadius: "var(--r)",
                }}
              >
                <div style={{ minWidth: 0 }}>
                  <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
                    <span style={{ fontFamily: "var(--mono)", fontSize: 12, fontWeight: 600 }}>[{e.parent_name || e.parent_id}]</span>
                    <span style={{ color: "var(--accent)", fontWeight: 700, fontSize: 12 }}>→</span>
                    <span style={{ fontFamily: "var(--mono)", fontSize: 12, fontWeight: 600 }}>[{e.child_name || e.child_id}]</span>
                    <Badge tone="slate">{e.relation}</Badge>
                    <Badge tone={e.operational_dependency?.mode === "HARD" ? "red" : e.operational_dependency?.mode === "FAILOVER" ? "amber" : "slate"}>
                      {e.operational_condition?.mode || e.operational_dependency?.mode || "UNKNOWN"}
                    </Badge>
                  </div>
                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 6, fontSize: 11 }}>
                    <span style={{ color: "var(--faint)" }}>
                      Source: <b style={{ color: "var(--dim)" }}>{e.source || "unknown"}</b> · Ref:{" "}
                      <span style={{ fontFamily: "var(--mono)" }}>{e.evidence_ref || "missing"}</span>
                      {e.confidence_meaning ? ` · ${e.confidence_meaning}` : " · confidence unspecified"}
                    </span>
                  </div>
                  <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 2 }}>
                    {e.effective_state || "lifecycle unknown"}
                    {e.valid_until ? ` · expires ${e.valid_until}` : " · no expiry"} · rev {e.lifecycle_revision ?? "—"} · {e.lifecycle_source || "—"}
                  </div>
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 6, alignItems: "flex-end", justifyContent: "center" }}>
                  <button
                    className="btn sm"
                    onClick={() => editMode(e)}
                    disabled={busy || e.lifecycle_revision == null || e.lifecycle_source !== "manual" || ["DELETED", "SUPERSEDED"].includes(e.effective_state || "")}
                    style={{ minWidth: 92 }}
                  >
                    Edit mode
                  </button>
                  <RequireRole anyOf={[...EDGE_WRITE_ROLES]}>
                  <button
                    className="btn sm"
                    style={{ minWidth: 92, color: "var(--red)", borderColor: "var(--line)" }}
                    disabled={
                      busy ||
                      e.lifecycle_revision == null ||
                      ["DELETED", "SUPERSEDED"].includes(e.effective_state || "") ||
                      !retirementReason.trim() ||
                      !retirementEvidence.trim()
                    }
                    onClick={() => remove(e)}
                    title={!retirementReason.trim() || !retirementEvidence.trim() ? "Enter retirement reason + evidence above" : "Retire edge"}
                  >
                    Retire
                  </button>
                  </RequireRole>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </Panel>
  );
}
