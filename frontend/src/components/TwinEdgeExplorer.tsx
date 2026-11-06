import React, { useEffect, useMemo, useState } from "react";
import { Panel, Badge } from "./ui.jsx";
import { apiEstateTwinGraph, apiEstateTwinWhy, type EstateTwinGraphExport, type EstateTwinWhy } from "../lib/api.js";

/* ─── Edge-first evidence explorer ────────────────────────────────────────────
   Spec §9 asks for one action above all others: select an edge and be told why
   the twin believes it. The asset drill-down answers that per asset; the
   Relationship Graph draws edges but had no way to ask about one.

   This panel is edge-first. It reads the twin's own graph export — where the ids
   are canonical asset ids and the types are the twin's relationship vocabulary —
   and asks `GET …/twin/why` about the *selected* subject/predicate/object. The
   answer is rendered as the evidence, or as the refusal, and the two are never
   blended: "no evidence returned" is not "no evidence exists".
──────────────────────────────────────────────────────────────────────────── */

const MAX_EDGES = 200;

interface TwinEdge {
  key: string;
  subject: string;
  object: string;
  predicate: string;
  subjectName: string;
  objectName: string;
  evidenceCount: number;
}

export default function TwinEdgeExplorer() {
  const [exported, setExported] = useState<EstateTwinGraphExport | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [answer, setAnswer] = useState<{ key: string; data: EstateTwinWhy | null } | null>(null);
  const [asking, setAsking] = useState(false);

  useEffect(() => {
    let live = true;
    void (async () => {
      const result = await apiEstateTwinGraph();
      if (!live) return;
      if (result.ok) setExported(result.data as EstateTwinGraphExport);
      // a failed read is a fact about the read, not an empty graph
      else setLoadError("the twin's graph export is unavailable — this is not 'no relationships'");
    })();
    return () => { live = false; };
  }, []);

  const names = useMemo(() => {
    const map = new Map<string, string>();
    for (const node of exported?.nodes ?? []) {
      map.set(node.id, String((node.properties as Record<string, unknown>)?.name ?? node.id));
    }
    return map;
  }, [exported]);

  const edges = useMemo<TwinEdge[]>(() => {
    const rows: TwinEdge[] = [];
    for (const edge of exported?.relationships ?? []) {
      const evidenceIds = (edge.properties as Record<string, unknown>)?.evidence_ids;
      rows.push({
        key: `${edge.type}|${edge.from}|${edge.to}`,
        subject: edge.from,
        object: edge.to,
        predicate: String(edge.type).toLowerCase(),
        subjectName: names.get(edge.from) ?? edge.from,
        objectName: names.get(edge.to) ?? edge.to,
        evidenceCount: Array.isArray(evidenceIds) ? evidenceIds.length : 0,
      });
    }
    return rows;
  }, [exported, names]);

  const shown = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const filtered = needle
      ? edges.filter((edge) =>
          `${edge.subjectName} ${edge.predicate} ${edge.objectName}`.toLowerCase().includes(needle))
      : edges;
    return filtered.slice(0, MAX_EDGES);
  }, [edges, query]);

  const askWhy = async (edge: TwinEdge) => {
    setSelected(edge.key);
    setAsking(true);
    setAnswer({ key: edge.key, data: null });
    const result = await apiEstateTwinWhy({
      subject: edge.subject, predicate: edge.predicate, object: edge.object,
    });
    setAnswer({
      key: edge.key,
      data: result.ok
        ? (result.data as EstateTwinWhy)
        : { schema: "", status: "NO_SUCH_RELATIONSHIP",
            detail: "the why route could not be read — that is not 'this edge has no evidence'" },
    });
    setAsking(false);
  };

  const current = answer && answer.key === selected ? answer.data : null;

  return (
    <Panel
      title="Edge-first evidence"
      sub="select a relationship and read the evidence behind it — or the reason it was refused"
      style={{ padding: "12px 14px" }}
    >
      {loadError && <div className="dim" style={{ fontSize: 11 }}>{loadError}</div>}
      {!exported && !loadError && <div className="dim" style={{ fontSize: 11 }}>loading the twin's relationships…</div>}

      {exported && (
        <>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginBottom: 8 }}>
            <Badge tone="violet">{edges.length} edges</Badge>
            <Badge tone="slate">{exported.counts.unresolved ?? 0} refused candidates</Badge>
            <input
              aria-label="Filter relationships"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="filter by asset or relationship"
              style={{
                flex: "1 1 200px", padding: "6px 9px", borderRadius: "var(--r)",
                background: "var(--panel-2)", border: "1px solid var(--line)",
                color: "var(--text)", fontSize: 12, fontFamily: "var(--mono)",
              }}
            />
          </div>

          {edges.length === 0 && (
            <div className="dim" style={{ fontSize: 11 }}>
              the twin holds no established relationship for this estate. That is a collection
              result, not a statement that nothing depends on anything.
            </div>
          )}

          <div style={{ maxHeight: 190, overflow: "auto", display: "flex", flexDirection: "column", gap: 3 }}>
            {shown.map((edge) => (
              <button
                key={edge.key}
                type="button"
                onClick={() => void askWhy(edge)}
                style={{
                  display: "flex", gap: 6, alignItems: "center", textAlign: "left", cursor: "pointer",
                  padding: "5px 8px", borderRadius: "var(--r)",
                  background: selected === edge.key ? "var(--panel-2)" : "transparent",
                  border: `1px solid ${selected === edge.key ? "var(--line)" : "transparent"}`,
                  color: "var(--text)", fontSize: 11, fontFamily: "var(--mono)",
                }}
              >
                <span>{edge.subjectName}</span>
                <span style={{ color: "var(--cyan)" }}>{edge.predicate}</span>
                <span>{edge.objectName}</span>
                <span className="faint" style={{ marginLeft: "auto", fontSize: 9.5 }}>
                  {edge.evidenceCount} evidence
                </span>
              </button>
            ))}
          </div>
          {edges.length > MAX_EDGES && (
            <div className="faint" style={{ fontSize: 9.5, marginTop: 4 }}>
              showing the first {MAX_EDGES} of {edges.length} edges — narrow the filter rather than
              reading a truncated list as the whole graph
            </div>
          )}

          {current && (
            <div style={{ marginTop: 10, padding: "9px 10px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>
              <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
                <Badge tone={current.status === "ESTABLISHED" ? "cyan" : "amber"}>{current.status}</Badge>
                {current.answer && <span className="dim" style={{ fontSize: 10.5 }}>{current.answer}</span>}
              </div>

              {current.status === "ESTABLISHED" && (current.matches?.length ?? 0) > 0 && (
                <div style={{ marginTop: 6, display: "flex", flexDirection: "column", gap: 3 }}>
                  {current.matches?.[0]?.evidence.slice(0, 6).map((ev) => (
                    <div key={ev.evidence_id} className="mono" style={{ fontSize: 9.5, color: "var(--dim)" }}>
                      {ev.evidence_type} · {ev.collector ?? "unknown collector"} ·{" "}
                      {ev.source ?? "unknown source"} · {ev.observed_at ?? "no timestamp"} ·{" "}
                      hash {String(ev.hash).slice(0, 12)}
                    </div>
                  ))}
                </div>
              )}

              {current.status !== "ESTABLISHED" && (
                <div className="dim" style={{ fontSize: 10.5, marginTop: 4 }}>
                  {current.detail
                    ?? current.refused?.[0]?.reason
                    ?? "no evidence was returned. That is not the same as 'no evidence exists' — the record may live in a source that was never collected."}
                </div>
              )}
            </div>
          )}

          {asking && <div className="faint" style={{ fontSize: 9.5, marginTop: 6 }}>asking the twin…</div>}

          <div className="faint" style={{ fontSize: 9.5, marginTop: 8, lineHeight: 1.5 }}>
            An edge cites evidence ids when they exist; assertion-only placement edges state why
            they are uncited. Refused candidates are not drawn: {exported.counts.unresolved ?? 0}
            ship separately instead of becoming relationships without proof.
          </div>
        </>
      )}
    </Panel>
  );
}
