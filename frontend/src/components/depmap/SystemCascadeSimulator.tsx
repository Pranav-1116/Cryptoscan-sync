import React, { useEffect, useMemo, useState } from "react";
import { Badge } from "../ui";
import {
  apiDependencyCascade, apiDependencyMap, type CascadeResult, type DependencyMap, type DepSystemEdge,
} from "../../lib/api";
import { CRIT_TONE, RISK_SHORT, RISK_TONE, needsMigration, riskColor, truncate } from "./shared";

/* System cascade — which system depends on which, and what a change or
   compromise at the systems / algorithms you pick reaches.

   Arrows read consumer → provider ("A → B": A calls / depends on B). Only
   ACTIVE CALLS / DEPENDS_ON / IMPORTS edges propagate; stale or retired
   edges are drawn dashed and never extend a cascade. Every reached system
   carries the exact chain of edges that reaches it. */

type Direction = "dependents" | "providers" | "both";

const NODE_W = 190;
const NODE_H = 34;
const COL_GAP = 70;
const ROW_GAP = 16;

export default function SystemCascadeSimulator() {
  const [map, setMap] = useState<DependencyMap | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [pickedAlgos, setPickedAlgos] = useState<Set<string>>(new Set());
  const [direction, setDirection] = useState<Direction>("dependents");
  const [hops, setHops] = useState(6);
  const [result, setResult] = useState<CascadeResult | null>(null);
  const [running, setRunning] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);
  const [focus, setFocus] = useState<string | null>(null);

  useEffect(() => {
    apiDependencyMap().then((res) => {
      if (res.source === "live" && res.data) setMap(res.data);
      else setError(res.detail || res.error || "dependency map unavailable");
    });
  }, []);

  const systems = useMemo(() => (map?.systems || []).filter((s) => s.kind === "system"), [map]);
  const sysById = useMemo(() => new Map(systems.map((s) => [s.id, s])), [systems]);
  const edges = useMemo(() => (map?.edges.depends_on || []).filter((e) => sysById.has(e.from) && sysById.has(e.to)), [map, sysById]);

  /* layered layout: consumers on the left, providers on the right (longest
     path from a pure consumer), so every arrow points rightwards */
  const layout = useMemo(() => {
    const ids = systems.map((s) => s.id);
    const out = new Map<string, string[]>(); const indeg = new Map<string, number>(ids.map((i) => [i, 0]));
    edges.forEach((e) => { out.set(e.from, [...(out.get(e.from) || []), e.to]); indeg.set(e.to, (indeg.get(e.to) || 0) + 1); });
    const level = new Map<string, number>(ids.map((i) => [i, 0]));
    // longest-path layering via Kahn order (cycles fall back to their current level)
    const queue = ids.filter((i) => (indeg.get(i) || 0) === 0);
    const deg = new Map(indeg);
    const seen = new Set<string>();
    while (queue.length) {
      const cur = queue.shift()!; seen.add(cur);
      for (const nxt of out.get(cur) || []) {
        level.set(nxt, Math.max(level.get(nxt) || 0, (level.get(cur) || 0) + 1));
        deg.set(nxt, (deg.get(nxt) || 0) - 1);
        if ((deg.get(nxt) || 0) === 0) queue.push(nxt);
      }
    }
    const cols = new Map<number, string[]>();
    ids.forEach((i) => { const l = level.get(i) || 0; cols.set(l, [...(cols.get(l) || []), i]); });
    const levels = Array.from(cols.keys()).sort((a, b) => a - b);
    const maxRows = Math.max(1, ...levels.map((l) => cols.get(l)!.length));
    const pos = new Map<string, { x: number; y: number }>();
    levels.forEach((l, li) => {
      const col = cols.get(l)!.sort((a, b) => (sysById.get(a)?.label || "").localeCompare(sysById.get(b)?.label || ""));
      const offset = ((maxRows - col.length) * (NODE_H + ROW_GAP)) / 2;
      col.forEach((id, r) => pos.set(id, { x: 10 + li * (NODE_W + COL_GAP), y: 30 + offset + r * (NODE_H + ROW_GAP) }));
    });
    const width = 20 + levels.length * (NODE_W + COL_GAP) - COL_GAP;
    const height = 40 + maxRows * (NODE_H + ROW_GAP);
    return { pos, width: Math.max(width, 400), height, cyclic: seen.size < ids.length };
  }, [systems, edges, sysById]);

  const impactedHop = useMemo(() => new Map((result?.impacted || []).map((r) => [r.id, r.hops || 0])), [result]);
  const seedIds = useMemo(() => new Set((result?.seeds || []).map((s) => s.id)), [result]);
  const pathEdges = useMemo(() => {
    const s = new Set<string>();
    const rows = focus ? (result?.impacted || []).filter((r) => r.id === focus) : (result?.impacted || []);
    rows.forEach((r) => (r.path_edges || []).forEach((e) => s.add(`${e.from}|${e.to}`)));
    return s;
  }, [result, focus]);

  const run = async () => {
    if (!picked.size && !pickedAlgos.size) { setRunError("Select at least one system or algorithm."); return; }
    setRunning(true); setRunError(null); setFocus(null);
    const res = await apiDependencyCascade({
      system_ids: Array.from(picked).map((s) => s.replace(/^system:/, "")),
      algorithm_ids: Array.from(pickedAlgos), direction, hops,
    });
    setRunning(false);
    if (res.source === "live" && res.data) setResult(res.data);
    else { setResult(null); setRunError(res.detail || res.error || "cascade failed"); }
  };

  const toggle = (id: string) => setPicked((p) => { const n = new Set(p); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const toggleAlgo = (id: string) => setPickedAlgos((p) => { const n = new Set(p); n.has(id) ? n.delete(id) : n.add(id); return n; });

  if (error) return <div className="panel" style={{ padding: 18 }}><b>System cascade</b><div style={{ color: "var(--dim)", fontSize: 12.5 }}>Unavailable — {error}</div></div>;
  if (!map) return <div className="panel" style={{ padding: 18, color: "var(--dim)" }}>Loading system dependencies…</div>;

  const name = (id: string) => sysById.get(id)?.label || id.replace(/^system:/, "");
  const nodeFill = (id: string) => (seedIds.has(id) ? "var(--violet)" : "var(--panel)");
  const nodeStroke = (id: string) => {
    if (seedIds.has(id)) return "var(--violet)";
    const h = impactedHop.get(id);
    if (h === 1) return "var(--red)";
    if (h === 2) return "var(--orange)";
    if (h != null) return "var(--amber)";
    return picked.has(id) ? "var(--violet)" : "var(--line-strong)";
  };
  const edgeD = (e: DepSystemEdge) => {
    const a = layout.pos.get(e.from)!, b = layout.pos.get(e.to)!;
    const forward = b.x > a.x;
    const x1 = forward ? a.x + NODE_W : a.x + NODE_W / 2, y1 = forward ? a.y + NODE_H / 2 : a.y + NODE_H;
    const x2 = forward ? b.x : b.x + NODE_W / 2, y2 = forward ? b.y + NODE_H / 2 : b.y;
    if (!forward) return `M${x1},${y1} C${x1},${y1 + 40} ${x2},${y2 - 40} ${x2},${y2}`;
    const mx = (x1 + x2) / 2;
    return `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`;
  };
  const algos = map.algorithms.filter((a) => a.system_ids.some((s) => sysById.has(`system:${s}`)));
  const byHop = new Map<number, CascadeResult["impacted"]>();
  (result?.impacted || []).forEach((r) => byHop.set(r.hops || 0, [...(byHop.get(r.hops || 0) || []), r]));

  return (
    <div className="panel" style={{ padding: "14px 16px", marginBottom: 16, borderTop: "2px solid var(--red)" }} data-testid="system-cascade">
      <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap", marginBottom: 10 }}>
        <div>
          <div style={{ fontSize: 10, letterSpacing: ".12em", fontFamily: "var(--mono)", color: "var(--red)" }}>CASCADE SIMULATION · SELECT SYSTEMS / ALGORITHMS · WITNESS PATHS</div>
          <h3 style={{ margin: "2px 0", fontSize: 17 }}>System dependencies &amp; cascade</h3>
          <div style={{ fontSize: 12, color: "var(--dim)" }}>{systems.length} systems · {edges.length} dependency edges ({edges.filter((e) => e.propagates).length} propagating) · arrow <b>A → B</b> = A depends on B</div>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "minmax(260px, 320px) 1fr", gap: 14 }} className="cascade-grid">
        {/* selection */}
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <div style={{ padding: 10, background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
              <b style={{ fontSize: 12 }}>1 · Systems to analyse ({picked.size})</b>
              <span style={{ display: "flex", gap: 4 }}>
                <button className="btn sm" onClick={() => setPicked(new Set(systems.map((s) => s.id)))}>all</button>
                <button className="btn sm" onClick={() => setPicked(new Set())}>none</button>
              </span>
            </div>
            <div style={{ maxHeight: 260, overflowY: "auto", display: "flex", flexDirection: "column", gap: 2 }}>
              {systems.map((s) => (
                <label key={s.id} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, padding: "4px 4px", borderRadius: 6, cursor: "pointer", background: picked.has(s.id) ? "var(--panel-2)" : undefined }}>
                  <input type="checkbox" checked={picked.has(s.id)} onChange={() => toggle(s.id)} aria-label={`analyse ${s.label}`} />
                  <span style={{ width: 8, height: 8, borderRadius: 99, background: riskColor(s.risk), flex: "none" }} title={s.risk ? RISK_SHORT[s.risk] : "no crypto recorded"} />
                  <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.label}</span>
                  {s.criticality && <Badge tone={CRIT_TONE[s.criticality] || "slate"}>{s.criticality}</Badge>}
                </label>
              ))}
            </div>
          </div>

          <div style={{ padding: 10, background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
              <b style={{ fontSize: 12 }}>2 · …or algorithms ({pickedAlgos.size})</b>
              <span style={{ display: "flex", gap: 4 }}>
                <button className="btn sm" onClick={() => setPickedAlgos(new Set(algos.filter((a) => needsMigration(a.risk)).map((a) => a.id)))}>needs migration</button>
                <button className="btn sm" onClick={() => setPickedAlgos(new Set())}>none</button>
              </span>
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 4, maxHeight: 150, overflowY: "auto" }}>
              {algos.map((a) => {
                const on = pickedAlgos.has(a.id);
                return (
                  <button key={a.id} onClick={() => toggleAlgo(a.id)} aria-pressed={on} title={`${a.risk_label} · used by ${a.system_ids.length} systems`}
                    style={{ fontSize: 11, fontFamily: "var(--mono)", padding: "2px 8px", borderRadius: 99, cursor: "pointer", border: `1px solid ${on ? riskColor(a.risk) : "var(--line)"}`, background: on ? "var(--panel-2)" : "var(--panel)", color: "var(--text)" }}>
                    <span style={{ display: "inline-block", width: 7, height: 7, borderRadius: 99, background: riskColor(a.risk), marginRight: 5 }} />{a.label}
                  </button>
                );
              })}
            </div>
            <div style={{ fontSize: 10.5, color: "var(--dim)", marginTop: 6 }}>An algorithm seeds every system whose components use it.</div>
          </div>

          <div style={{ padding: 10, background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>
            <b style={{ fontSize: 12 }}>3 · Direction &amp; depth</b>
            <div style={{ display: "flex", gap: 4, margin: "6px 0", flexWrap: "wrap" }}>
              {([["dependents", "Who is affected"], ["providers", "What it relies on"], ["both", "Both"]] as [Direction, string][]).map(([d, l]) => (
                <button key={d} className={`btn sm${direction === d ? " primary" : ""}`} aria-pressed={direction === d} onClick={() => setDirection(d)}>{l}</button>
              ))}
            </div>
            <label style={{ fontSize: 11.5, color: "var(--dim)", display: "flex", alignItems: "center", gap: 8 }}>
              max hops <input type="range" min={1} max={12} value={hops} onChange={(e) => setHops(Number(e.target.value))} aria-label="maximum hops" style={{ flex: 1 }} /> <b style={{ color: "var(--text)", fontFamily: "var(--mono)" }}>{hops}</b>
            </label>
            <button className="btn primary" style={{ width: "100%", marginTop: 8 }} onClick={run} disabled={running}>{running ? "Simulating…" : "Simulate cascade"}</button>
            {runError && <div style={{ color: "var(--red)", fontSize: 11.5, marginTop: 6 }}>{runError}</div>}
          </div>
        </div>

        {/* diagram */}
        <div style={{ minWidth: 0 }}>
          <div style={{ overflow: "auto", border: "1px solid var(--line)", borderRadius: "var(--r)", background: "var(--bg-2)" }}>
            {systems.length === 0 ? (
              <div style={{ padding: 30, color: "var(--dim)", textAlign: "center", fontSize: 13 }}>No systems registered yet.</div>
            ) : (
              <svg viewBox={`0 0 ${layout.width} ${layout.height}`} width="100%" style={{ minWidth: Math.min(layout.width, 900), display: "block" }} role="img" aria-label="system dependency diagram">
                <defs>
                  {["line", "hot"].map((k) => (
                    <marker key={k} id={`dep-arrow-${k}`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                      <path d="M0,0 L10,5 L0,10 z" fill={k === "hot" ? "var(--red)" : "var(--line-strong)"} />
                    </marker>
                  ))}
                </defs>
                <text x={10} y={16} fontSize={10} fill="var(--dim)" fontFamily="var(--mono)">CONSUMERS</text>
                <text x={layout.width - 10} y={16} fontSize={10} fill="var(--dim)" fontFamily="var(--mono)" textAnchor="end">PROVIDERS →</text>
                {edges.map((e) => {
                  const hot = pathEdges.has(`${e.from}|${e.to}`);
                  return (
                    <path key={e.id} d={edgeD(e)} fill="none" stroke={hot ? "var(--red)" : "var(--line-strong)"} strokeWidth={hot ? 2.2 : 1.2}
                      strokeDasharray={e.propagates ? undefined : "5 4"} opacity={result && !hot ? 0.35 : 0.9} markerEnd={`url(#dep-arrow-${hot ? "hot" : "line"})`}>
                      <title>{`${name(e.from)} → ${name(e.to)} · ${e.relation} · ${e.provenance || "UNATTRIBUTED"}${e.evidence_ref ? ` · ${e.evidence_ref}` : ""}${e.propagates ? "" : ` · ${e.lifecycle_state} (does not propagate)`}`}</title>
                    </path>
                  );
                })}
                {systems.map((s) => {
                  const p = layout.pos.get(s.id)!;
                  const seed = seedIds.has(s.id);
                  const hop = impactedHop.get(s.id);
                  return (
                    <g key={s.id} transform={`translate(${p.x},${p.y})`} style={{ cursor: "pointer" }} onClick={() => toggle(s.id)} role="button" tabIndex={0} aria-label={`toggle ${s.label}`}
                      onKeyDown={(ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); toggle(s.id); } }}>
                      <title>{`${s.label}${s.criticality ? ` · ${s.criticality}` : ""} — click to ${picked.has(s.id) ? "deselect" : "select"}`}</title>
                      <rect width={NODE_W} height={NODE_H} rx={7} fill={nodeFill(s.id)} stroke={nodeStroke(s.id)} strokeWidth={seed || hop != null || picked.has(s.id) ? 2 : 1} />
                      <rect x={0} y={0} width={4} height={NODE_H} rx={2} fill={riskColor(s.risk)} />
                      <text x={12} y={15} fontSize={11.5} fontWeight={600} fill={seed ? "var(--on-accent, #fff)" : "var(--text)"}>{truncate(s.label, 25)}</text>
                      <text x={12} y={28} fontSize={9.5} fill={seed ? "var(--on-accent, #fff)" : "var(--dim)"} fontFamily="var(--mono)">
                        {seed ? "SEED" : hop != null ? `IMPACT · hop ${hop}` : picked.has(s.id) ? "selected" : (s.criticality || "").toLowerCase()}
                      </text>
                    </g>
                  );
                })}
              </svg>
            )}
          </div>
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap", fontSize: 11, color: "var(--dim)", marginTop: 6 }}>
            <span><span style={{ display: "inline-block", width: 10, height: 10, background: "var(--violet)", borderRadius: 2, marginRight: 4 }} />seed</span>
            <span><span style={{ display: "inline-block", width: 10, height: 10, border: "2px solid var(--red)", borderRadius: 2, marginRight: 4 }} />hop 1</span>
            <span><span style={{ display: "inline-block", width: 10, height: 10, border: "2px solid var(--orange)", borderRadius: 2, marginRight: 4 }} />hop 2</span>
            <span><span style={{ display: "inline-block", width: 10, height: 10, border: "2px solid var(--amber)", borderRadius: 2, marginRight: 4 }} />hop 3+</span>
            <span>dashed edge = not ACTIVE / non-propagating · left bar = worst algorithm risk · click a box to select it</span>
          </div>

          {/* results */}
          {result && (
            <div style={{ marginTop: 12 }} data-testid="cascade-result">
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 8 }}>
                <Badge tone="violet">{result.summary.seed_systems} seed system{result.summary.seed_systems === 1 ? "" : "s"}</Badge>
                <Badge tone={result.summary.impacted_systems ? "red" : "green"}>{result.summary.impacted_systems} impacted</Badge>
                <Badge tone="slate">max depth {result.summary.max_depth}</Badge>
                {Object.entries(result.summary.by_criticality).map(([k, v]) => <Badge key={k} tone={CRIT_TONE[k] || "slate"}>{v} {k}</Badge>)}
                {result.summary.edges_not_propagating > 0 && <Badge tone="amber">{result.summary.edges_not_propagating} edges not propagating</Badge>}
              </div>
              {result.algorithm_seeds.length > 0 && (
                <div style={{ fontSize: 12, marginBottom: 8 }}>
                  {result.algorithm_seeds.map((a) => (
                    <div key={a.id}><span style={{ fontFamily: "var(--mono)", fontWeight: 700 }}>{a.algorithm}</span> <Badge tone={RISK_TONE[a.risk]}>{RISK_SHORT[a.risk]}</Badge> used at {a.locations} location{a.locations === 1 ? "" : "s"} in {a.systems.length ? a.systems.join(", ") : <i>no attributed system</i>}</div>
                  ))}
                </div>
              )}
              <div style={{ fontSize: 12, marginBottom: 4 }}><b>Seeds:</b> {result.seeds.map((s) => `${s.name} (${(s.reasons || []).join("; ")})`).join(" · ") || "none"}</div>
              {result.impacted.length === 0 ? (
                <div style={{ fontSize: 12.5, color: "var(--dim)", padding: 10, border: "1px dashed var(--line)", borderRadius: "var(--r)" }}>
                  No other system is reached over ACTIVE dependency edges in this direction.
                </div>
              ) : (
                Array.from(byHop.keys()).sort((a, b) => a - b).map((h) => (
                  <div key={h} style={{ marginBottom: 8 }}>
                    <div style={{ fontSize: 11, color: "var(--dim)", fontFamily: "var(--mono)", margin: "6px 0 4px" }}>HOP {h}</div>
                    {byHop.get(h)!.map((r) => (
                      <div key={r.id} onMouseEnter={() => setFocus(r.id)} onMouseLeave={() => setFocus(null)}
                        style={{ padding: "8px 10px", marginBottom: 4, background: focus === r.id ? "var(--panel-2)" : "var(--bg-2)", border: "1px solid var(--line)", borderLeft: `3px solid ${h === 1 ? "var(--red)" : h === 2 ? "var(--orange)" : "var(--amber)"}`, borderRadius: "var(--r)" }}>
                        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                          <b style={{ fontSize: 12.5 }}>{r.name}</b>
                          {r.criticality && <Badge tone={CRIT_TONE[r.criticality] || "slate"}>{r.criticality}</Badge>}
                          <span style={{ fontSize: 11, color: "var(--dim)" }}>{r.direction === "dependents" ? "depends on the seed" : "the seed depends on it"}</span>
                        </div>
                        <div style={{ fontSize: 11.5, fontFamily: "var(--mono)", marginTop: 4, color: "var(--text)" }}>
                          {(r.chain_names || []).map((n, i) => {
                            const edgesOnPath = r.direction === "dependents" ? [...(r.path_edges || [])].reverse() : (r.path_edges || []);
                            const e = edgesOnPath[i];
                            return <span key={i}>{n}{i < (r.chain_names || []).length - 1 && <span style={{ color: "var(--dim)" }}> —{e?.relation?.toLowerCase().replace("_", " ")}→ </span>}</span>;
                          })}
                        </div>
                        <div style={{ fontSize: 11, color: "var(--dim)", marginTop: 3 }}>
                          evidence: {(r.path_edges || []).map((e) => `${e.provenance || "UNATTRIBUTED"}${e.evidence_ref ? ` (${e.evidence_ref.replace(/^meridian-architecture: /, "")})` : ""}`).join(" · ")}
                        </div>
                        {r.weak_algorithms.length > 0 && <div style={{ fontSize: 11, marginTop: 3 }}>its own crypto needing migration: <span style={{ fontFamily: "var(--mono)", color: "var(--orange)" }}>{r.weak_algorithms.join(", ")}</span></div>}
                      </div>
                    ))}
                  </div>
                ))
              )}
              <div style={{ fontSize: 10.5, color: "var(--faint, var(--dim))", marginTop: 4 }}>{result.semantics}</div>
            </div>
          )}
        </div>
      </div>

      {/* dependency matrix */}
      <div style={{ marginTop: 14 }}>
        <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 6 }}>Who depends on whom</div>
        <div style={{ overflowX: "auto" }}>
          <table className="table" style={{ width: "100%", fontSize: 12 }}>
            <thead><tr><th style={{ textAlign: "left" }}>System</th><th style={{ textAlign: "left" }}>Depends on (providers)</th><th style={{ textAlign: "left" }}>Depended on by (consumers)</th><th style={{ textAlign: "left" }}>Worst crypto</th></tr></thead>
            <tbody>
              {systems.map((s) => {
                const prov = edges.filter((e) => e.from === s.id);
                const cons = edges.filter((e) => e.to === s.id);
                const cell = (list: DepSystemEdge[], other: (e: DepSystemEdge) => string) => list.length ? list.map((e) => (
                  <span key={e.id} title={`${e.relation} · ${e.provenance || "UNATTRIBUTED"}${e.evidence_ref ? ` · ${e.evidence_ref}` : ""}`}
                    style={{ display: "inline-block", fontSize: 11, padding: "1px 7px", margin: "1px 4px 1px 0", borderRadius: 99, border: `1px ${e.propagates ? "solid" : "dashed"} var(--line)`, background: "var(--panel-2)" }}>
                    {name(other(e))} <span style={{ color: "var(--dim)", fontFamily: "var(--mono)", fontSize: 9.5 }}>{e.relation}</span>
                  </span>)) : <span style={{ color: "var(--dim)" }}>—</span>;
                return (
                  <tr key={s.id}>
                    <td style={{ fontWeight: 600, whiteSpace: "nowrap" }}>{s.label}</td>
                    <td>{cell(prov, (e) => e.to)}</td>
                    <td>{cell(cons, (e) => e.from)}</td>
                    <td>{s.risk ? <Badge tone={RISK_TONE[s.risk]}>{RISK_SHORT[s.risk]}</Badge> : <span style={{ color: "var(--dim)" }}>none recorded</span>}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {layout.cyclic && <div style={{ fontSize: 11, color: "var(--amber)", marginTop: 4 }}>The dependency graph contains a cycle — the cascade walk visits each system once.</div>}
      </div>
    </div>
  );
}
