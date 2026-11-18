import React, { useEffect, useMemo, useState } from "react";
import { Badge } from "../ui";
import { apiDependencyMap, type DependencyMap, type DepRisk } from "../../lib/api";
import {
  COMPONENT_KIND_LABEL, CRIT_TONE, RISK_ORDER, RISK_SHORT, RISK_TONE, isWeak, needsMigration, riskColor, truncate,
} from "./shared";

/* Crypto dependency map — every system, the software components it owns, the
   libraries those components resolve crypto through, and the algorithms in
   use. Columns read left → right: System → Component → Library → Algorithm.
   Each edge is a stored record (system_assets link, crypto_assets row,
   recorded library); nothing is laid down by name matching. Click any node
   to trace its full chain; the table below answers "which software uses
   this algorithm" with file:line evidence. */

type Col = "system" | "component" | "library" | "algorithm";
type RiskFilter = "all" | "migration" | "weak";

const W = 1200;
const ROW = 28;
const BOX_H = 22;
const TOP = 34;
const COLS: Record<Col, { x: number; w: number; title: string; chars: number }> = {
  system: { x: 0, w: 230, title: "SYSTEMS", chars: 30 },
  component: { x: 300, w: 270, title: "SOFTWARE COMPONENTS", chars: 36 },
  library: { x: 650, w: 180, title: "LIBRARIES / PROVIDERS", chars: 23 },
  algorithm: { x: 910, w: 290, title: "ALGORITHMS", chars: 26 },
};

interface Placed { id: string; col: Col; label: string; y: number; risk?: DepRisk | null; sub?: string; }

export default function CryptoDependencyMap({ compact = false }: { compact?: boolean }) {
  const [map, setMap] = useState<DependencyMap | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<string | null>(null);
  const [hover, setHover] = useState<string | null>(null);
  const [systemFilter, setSystemFilter] = useState<Set<string>>(new Set());
  const [riskFilter, setRiskFilter] = useState<RiskFilter>("all");
  const [query, setQuery] = useState("");

  const load = () => {
    setLoading(true);
    apiDependencyMap().then((res) => {
      if (res.source === "live" && res.data) { setMap(res.data); setError(null); }
      else setError(res.detail || res.error || "dependency map unavailable");
      setLoading(false);
    });
  };
  useEffect(load, []);

  const idx = useMemo(() => {
    if (!map) return null;
    const algo = new Map(map.algorithms.map((a) => [a.id, a]));
    const comp = new Map(map.components.map((c) => [c.id, c]));
    const lib = new Map(map.libraries.map((l) => [l.id, l]));
    const sys = new Map(map.systems.map((s) => [s.id, s]));
    return { algo, comp, lib, sys };
  }, [map]);

  /* visible subgraph after filters */
  const view = useMemo(() => {
    if (!map || !idx) return null;
    const riskOk = (r?: DepRisk | null) => riskFilter === "all" || (riskFilter === "weak" ? isWeak(r) : needsMigration(r));
    const sysOk = (sid: string) => systemFilter.size === 0 || systemFilter.has(sid);
    const uses = map.edges.uses.filter((e) => {
      const c = idx.comp.get(e.from); const a = idx.algo.get(e.to);
      if (!c || !a || !riskOk(a.risk)) return false;
      return c.system_ids.some((s) => sysOk(`system:${s}`));
    });
    const compIds = new Set(uses.map((e) => e.from));
    const algoIds = new Set(uses.map((e) => e.to));
    const libIds = new Set(uses.flatMap((e) => e.library_ids));
    const contains = map.edges.contains.filter((e) => compIds.has(e.to) && sysOk(e.from));
    const sysIds = new Set(contains.map((e) => e.from));
    if (systemFilter.size === 0) map.systems.forEach((s) => sysIds.add(s.id)); // show systems with no crypto too
    const links = map.edges.links.filter((e) => compIds.has(e.from) && libIds.has(e.to));
    const provides = map.edges.provides.filter((e) => libIds.has(e.from) && algoIds.has(e.to));
    return { uses, contains, links, provides, compIds, algoIds, libIds, sysIds };
  }, [map, idx, riskFilter, systemFilter]);

  /* deterministic layered layout, ordered by barycentre to limit crossings */
  const layout = useMemo(() => {
    if (!map || !idx || !view) return null;
    const systems = map.systems.filter((s) => view.sysIds.has(s.id));
    const sysPos = new Map(systems.map((s, i) => [s.id, i]));
    const comps = map.components.filter((c) => view.compIds.has(c.id)).map((c) => {
      const owners = c.system_ids.map((s) => sysPos.get(`system:${s}`)).filter((v): v is number => v != null);
      return { c, key: owners.length ? Math.min(...owners) : 1e6 };
    }).sort((a, b) => a.key - b.key || a.c.location.localeCompare(b.c.location)).map((x) => x.c);
    const compPos = new Map(comps.map((c, i) => [c.id, i]));
    const bary = (ids: string[]) => { const v = ids.map((i) => compPos.get(i)).filter((n): n is number => n != null); return v.length ? v.reduce((a, b) => a + b, 0) / v.length : 1e6; };
    const algos = map.algorithms.filter((a) => view.algoIds.has(a.id))
      .map((a) => ({ a, key: bary(view.uses.filter((e) => e.to === a.id).map((e) => e.from)) }))
      .sort((x, y) => x.key - y.key).map((x) => x.a);
    const libs = map.libraries.filter((l) => view.libIds.has(l.id))
      .map((l) => ({ l, key: bary(l.component_ids) })).sort((x, y) => x.key - y.key).map((x) => x.l);
    const maxRows = Math.max(systems.length, comps.length, algos.length, libs.length, 1);
    const place = (n: number, i: number) => TOP + ((maxRows - n) * ROW) / 2 + i * ROW;
    const placed: Placed[] = [
      ...systems.map((s, i) => ({ id: s.id, col: "system" as Col, label: s.label, y: place(systems.length, i), risk: s.risk, sub: s.criticality || undefined })),
      ...comps.map((c, i) => ({ id: c.id, col: "component" as Col, label: c.label, y: place(comps.length, i), risk: c.risk, sub: c.kind })),
      ...libs.map((l, i) => ({ id: l.id, col: "library" as Col, label: l.label, y: place(libs.length, i) })),
      ...algos.map((a, i) => ({ id: a.id, col: "algorithm" as Col, label: a.label, y: place(algos.length, i), risk: a.risk })),
    ];
    return { placed, byId: new Map(placed.map((p) => [p.id, p])), height: TOP + maxRows * ROW + 12 };
  }, [map, idx, view]);

  /* chain highlighted for the selected/hovered node */
  const focus = selected || hover;
  const lit = useMemo(() => {
    if (!focus || !view || !idx) return null;
    const nodes = new Set<string>([focus]);
    const edges = new Set<string>();
    const k = (a: string, b: string) => `${a}|${b}`;
    const kind = focus.split(":")[0];
    const useEdges = view.uses.filter((e) => {
      if (kind === "algorithm") return e.to === focus;
      if (kind === "component") return e.from === focus;
      if (kind === "library") return e.library_ids.includes(focus);
      if (kind === "system") return (idx.comp.get(e.from)?.system_ids || []).some((s) => `system:${s}` === focus);
      return false;
    });
    for (const e of useEdges) {
      nodes.add(e.from); nodes.add(e.to); edges.add(k(e.from, e.to));
      for (const l of e.library_ids) { nodes.add(l); edges.add(k(e.from, l)); edges.add(k(l, e.to)); }
      for (const s of idx.comp.get(e.from)?.system_ids || []) {
        const sid = `system:${s}`;
        if (kind === "system" && sid !== focus) continue;
        nodes.add(sid); edges.add(k(sid, e.from));
      }
    }
    return { nodes, edges };
  }, [focus, view, idx]);

  if (loading && !map) return <div className="panel" style={{ padding: 18, color: "var(--dim)" }}>Loading crypto dependency map…</div>;
  if (error || !map || !idx || !view || !layout) {
    return (
      <div className="panel" style={{ padding: 18 }}>
        <div style={{ fontWeight: 700, marginBottom: 4 }}>Crypto dependency map</div>
        <div style={{ color: "var(--dim)", fontSize: 12.5 }}>Unavailable — {error || "no data"}. <button className="btn sm" onClick={load}>Retry</button></div>
      </div>
    );
  }

  const q = query.trim().toLowerCase();
  const matches = (p: Placed) => !q || p.label.toLowerCase().includes(q);
  const dimNode = (id: string, p: Placed) => (lit ? !lit.nodes.has(id) : q ? !matches(p) : false);
  const edgePath = (a: Placed, b: Placed) => {
    const x1 = COLS[a.col].x + COLS[a.col].w, y1 = a.y + BOX_H / 2;
    const x2 = COLS[b.col].x, y2 = b.y + BOX_H / 2;
    const mx = (x1 + x2) / 2;
    return `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`;
  };
  const renderEdge = (from: string, to: string, opts: { dashed?: boolean; color?: string }) => {
    const a = layout.byId.get(from), b = layout.byId.get(to);
    if (!a || !b) return null;
    const on = lit?.edges.has(`${from}|${to}`);
    const op = lit ? (on ? 0.9 : 0.04) : 0.16;
    return <path key={`${from}|${to}`} d={edgePath(a, b)} fill="none" stroke={on ? (opts.color || "var(--accent)") : "var(--line-strong)"} strokeWidth={on ? 1.6 : 1} strokeDasharray={opts.dashed ? "4 3" : undefined} opacity={op} />;
  };

  const sel = selected ? (idx.algo.get(selected) || idx.comp.get(selected) || idx.lib.get(selected) || idx.sys.get(selected)) : null;
  const toggleSystem = (id: string) => setSystemFilter((prev) => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const sysName = (sid: string) => idx.sys.get(`system:${sid}`)?.label || sid;
  const cov = map.coverage;
  const realSystems = map.systems.filter((s) => s.kind === "system");

  /* algorithm → software rows (the evidence table) */
  const algoRows = map.algorithms.filter((a) => view.algoIds.has(a.id)).sort((x, y) => RISK_ORDER.indexOf(x.risk) - RISK_ORDER.indexOf(y.risk) || x.label.localeCompare(y.label));

  return (
    <div className="panel" style={{ padding: "14px 16px", marginBottom: 16, borderTop: "2px solid var(--violet)" }} data-testid="crypto-dependency-map">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12, flexWrap: "wrap", marginBottom: 10 }}>
        <div>
          <div style={{ fontSize: 10, letterSpacing: ".12em", fontFamily: "var(--mono)", color: "var(--violet)" }}>SYSTEM → COMPONENT → LIBRARY → ALGORITHM · STORED RECORDS ONLY</div>
          <h3 style={{ margin: "2px 0", fontSize: 17 }}>Crypto dependency map</h3>
          <div style={{ fontSize: 12, color: "var(--dim)" }}>
            {realSystems.length} systems · {map.components.length} components · {map.libraries.length} libraries · {map.algorithms.length} algorithms · {cov.attributed_assets}/{cov.assets} assets attributed to a system
            {cov.unattributed_assets > 0 && <> · <span style={{ color: "var(--amber)" }}>{cov.unattributed_assets} unattributed (shown, not guessed)</span></>}
          </div>
        </div>
        <div className="row" style={{ gap: 6, flexWrap: "wrap", alignItems: "center" }}>
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="find node…" aria-label="find node in dependency map"
            style={{ background: "var(--bg-2)", border: "1px solid var(--line)", color: "var(--text)", borderRadius: "var(--r)", padding: "6px 10px", fontSize: 12, width: 160 }} />
          {(["all", "migration", "weak"] as RiskFilter[]).map((r) => (
            <button key={r} className={`btn sm${riskFilter === r ? " primary" : ""}`} onClick={() => setRiskFilter(r)} aria-pressed={riskFilter === r}>
              {r === "all" ? "All algorithms" : r === "migration" ? "Needs migration" : "Weak only"}
            </button>
          ))}
          <button className="btn sm" onClick={() => { setSelected(null); setSystemFilter(new Set()); setRiskFilter("all"); setQuery(""); }}>Reset</button>
          <button className="btn sm" onClick={load} disabled={loading}>{loading ? "Refreshing…" : "Refresh"}</button>
        </div>
      </div>

      {/* system filter chips */}
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 10 }} aria-label="filter by system">
        <span style={{ fontSize: 11, color: "var(--dim)", alignSelf: "center", marginRight: 4 }}>Systems:</span>
        {map.systems.map((s) => {
          const on = systemFilter.has(s.id);
          return (
            <button key={s.id} onClick={() => toggleSystem(s.id)} aria-pressed={on}
              style={{ fontSize: 11, padding: "3px 9px", borderRadius: 99, cursor: "pointer", border: `1px solid ${on ? "var(--violet)" : "var(--line)"}`, background: on ? "var(--violet)" : "var(--panel-2)", color: on ? "var(--on-accent, #fff)" : "var(--text)" }}>
              <span style={{ display: "inline-block", width: 7, height: 7, borderRadius: 99, background: riskColor(s.risk), marginRight: 6 }} />{s.label}
            </button>
          );
        })}
        {systemFilter.size > 0 && <button className="btn sm" onClick={() => setSystemFilter(new Set())}>all systems</button>}
      </div>

      {/* legend */}
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", fontSize: 11, color: "var(--dim)", marginBottom: 6 }}>
        {RISK_ORDER.map((r) => <span key={r} style={{ display: "inline-flex", alignItems: "center", gap: 5 }}><span style={{ width: 9, height: 9, borderRadius: 2, background: riskColor(r) }} />{RISK_SHORT[r].toLowerCase()}</span>)}
        <span>— solid: owns / uses · dashed: through library</span>
      </div>

      {view.uses.length === 0 ? (
        <div style={{ padding: 30, textAlign: "center", color: "var(--dim)", fontSize: 13, border: "1px dashed var(--line)", borderRadius: "var(--r)" }}>
          No algorithm usage matches these filters. {cov.assets === 0 ? "Run a scan (Scanners, or CBOM → Live network collection) to record crypto assets." : ""}
        </div>
      ) : (
        <div style={{ overflowX: "auto", border: "1px solid var(--line)", borderRadius: "var(--r)", background: "var(--bg-2)", maxHeight: compact ? 520 : 900, overflowY: "auto" }}>
          <svg viewBox={`0 0 ${W} ${layout.height}`} width="100%" style={{ minWidth: 980, display: "block" }} role="img" aria-label="crypto dependency map">
            {(Object.keys(COLS) as Col[]).map((c) => (
              <text key={c} x={COLS[c].x + 4} y={18} fontSize={10} letterSpacing="1.2" fill="var(--dim)" fontFamily="var(--mono)">{COLS[c].title}</text>
            ))}
            <g>
              {view.contains.map((e) => renderEdge(e.from, e.to, { color: "var(--violet)" }))}
              {view.links.map((e) => renderEdge(e.from, e.to, { dashed: true, color: "var(--accent)" }))}
              {view.provides.map((e) => renderEdge(e.from, e.to, { dashed: true, color: "var(--accent)" }))}
              {view.uses.map((e) => renderEdge(e.from, e.to, { color: riskColor(idx.algo.get(e.to)?.risk) }))}
            </g>
            {layout.placed.map((p) => {
              const c = COLS[p.col];
              const dim = dimNode(p.id, p);
              const isSel = selected === p.id;
              const unattributed = p.id === "system:unattributed";
              return (
                <g key={p.id} transform={`translate(${c.x},${p.y})`} style={{ cursor: "pointer" }} opacity={dim ? 0.22 : 1}
                  onClick={() => setSelected(isSel ? null : p.id)} onMouseEnter={() => setHover(p.id)} onMouseLeave={() => setHover(null)}
                  role="button" aria-label={`${p.col} ${p.label}`} tabIndex={0}
                  onKeyDown={(ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); setSelected(isSel ? null : p.id); } }}>
                  <title>{p.label}{p.sub ? ` — ${p.sub}` : ""}</title>
                  <rect width={c.w} height={BOX_H} rx={5} fill={isSel ? "var(--panel-2)" : "var(--panel)"} stroke={isSel ? "var(--violet)" : "var(--line)"} strokeWidth={isSel ? 1.6 : 1} strokeDasharray={unattributed ? "4 3" : undefined} />
                  <rect width={4} height={BOX_H} rx={2} fill={p.col === "library" ? "var(--accent)" : riskColor(p.risk)} />
                  <text x={11} y={15} fontSize={11.5} fill="var(--text)" fontFamily={p.col === "algorithm" || p.col === "component" ? "var(--mono)" : undefined} fontWeight={p.col === "system" || p.col === "algorithm" ? 600 : 400}>
                    {truncate(p.label, c.chars)}
                  </text>
                  {p.col === "system" && p.sub && <text x={c.w - 6} y={15} fontSize={9} textAnchor="end" fill="var(--dim)" fontFamily="var(--mono)">{p.sub}</text>}
                  {p.col === "component" && p.sub === "tls_endpoint" && <text x={c.w - 6} y={15} fontSize={9} textAnchor="end" fill="var(--accent)" fontFamily="var(--mono)">LIVE</text>}
                </g>
              );
            })}
          </svg>
        </div>
      )}

      {/* inspector */}
      {sel && <Inspector id={selected!} map={map} idx={idx} sysName={sysName} onSelect={setSelected} />}

      {/* algorithm → software evidence table */}
      {!compact && (
        <div style={{ marginTop: 14 }}>
          <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 6 }}>Which software uses each algorithm</div>
          <div style={{ overflowX: "auto" }}>
            <table className="table" style={{ width: "100%", fontSize: 12 }}>
              <thead><tr><th style={{ textAlign: "left" }}>Algorithm</th><th style={{ textAlign: "left" }}>Status</th><th style={{ textAlign: "left" }}>Systems</th><th style={{ textAlign: "right" }}>Components</th><th style={{ textAlign: "right" }}>Locations</th><th style={{ textAlign: "left" }}>Libraries</th></tr></thead>
              <tbody>
                {algoRows.map((a) => (
                  <tr key={a.id} onClick={() => setSelected(a.id)} style={{ cursor: "pointer", background: selected === a.id ? "var(--panel-2)" : undefined }}>
                    <td style={{ fontFamily: "var(--mono)", fontWeight: 600 }}>{a.label}</td>
                    <td><Badge tone={RISK_TONE[a.risk]}>{RISK_SHORT[a.risk]}</Badge></td>
                    <td style={{ maxWidth: 420 }}>{a.system_ids.map(sysName).join(", ")}</td>
                    <td style={{ textAlign: "right", fontFamily: "var(--mono)" }}>{a.component_ids.length}</td>
                    <td style={{ textAlign: "right", fontFamily: "var(--mono)" }}>{a.asset_count}</td>
                    <td>{a.library_ids.map((l) => idx.lib.get(l)?.label || l).join(", ") || <span style={{ color: "var(--dim)" }}>none recorded</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

function Inspector({ id, map, idx, sysName, onSelect }: {
  id: string; map: DependencyMap; sysName: (s: string) => string; onSelect: (id: string) => void;
  idx: { algo: Map<string, any>; comp: Map<string, any>; lib: Map<string, any>; sys: Map<string, any> };
}) {
  const kind = id.split(":")[0];
  const box: React.CSSProperties = { marginTop: 12, padding: 12, background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" };
  const chip = (key: string, label: string, target: string, color?: string) => (
    <button key={key} onClick={() => onSelect(target)} style={{ fontSize: 11, padding: "2px 8px", margin: "2px 4px 2px 0", borderRadius: 99, border: "1px solid var(--line)", background: "var(--panel)", color: "var(--text)", cursor: "pointer" }}>
      {color && <span style={{ display: "inline-block", width: 7, height: 7, borderRadius: 99, background: color, marginRight: 5 }} />}{label}
    </button>
  );

  if (kind === "algorithm") {
    const a = idx.algo.get(id);
    const rows = map.edges.uses.filter((e) => e.to === id).flatMap((e) => {
      const c = idx.comp.get(e.from);
      return e.locations.map((loc) => ({ c, loc, libs: e.library_ids }));
    });
    return (
      <div style={box}>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <span style={{ fontFamily: "var(--mono)", fontSize: 15, fontWeight: 700 }}>{a.label}</span>
          <Badge tone={RISK_TONE[a.risk as DepRisk]}>{RISK_SHORT[a.risk as DepRisk]}</Badge>
          <span style={{ fontSize: 11.5, color: "var(--dim)" }}>{a.risk_label} · registry status {a.status}{a.quantum_impact ? ` · quantum: ${a.quantum_impact}` : ""} · purposes {a.purposes.join(", ") || "—"}</span>
        </div>
        <div style={{ fontSize: 12, margin: "8px 0 6px" }}>Used by <b>{a.system_ids.length}</b> system{a.system_ids.length === 1 ? "" : "s"} across <b>{a.component_ids.length}</b> component{a.component_ids.length === 1 ? "" : "s"} at <b>{rows.length}</b> recorded location{rows.length === 1 ? "" : "s"}:</div>
        <div style={{ overflowX: "auto", maxHeight: 300, overflowY: "auto" }}>
          <table className="table" style={{ width: "100%", fontSize: 11.5 }}>
            <thead><tr><th style={{ textAlign: "left" }}>System</th><th style={{ textAlign: "left" }}>Component</th><th style={{ textAlign: "left" }}>Location</th><th style={{ textAlign: "left" }}>Purpose</th><th style={{ textAlign: "left" }}>Library</th><th style={{ textAlign: "left" }}>Confidence</th></tr></thead>
            <tbody>
              {rows.map(({ c, loc, libs }, i) => (
                <tr key={`${loc.asset_id}-${i}`}>
                  <td>{(c?.system_ids || []).map(sysName).join(", ")}</td>
                  <td>{COMPONENT_KIND_LABEL[c?.kind] || c?.kind}</td>
                  <td style={{ fontFamily: "var(--mono)" }}>{loc.file_path}{loc.line_number ? `:${loc.line_number}` : ""}{loc.is_hardcoded_key && <span style={{ color: "var(--red)", marginLeft: 6 }}>hardcoded key</span>}</td>
                  <td>{loc.purpose || "—"}{loc.mode ? ` · ${loc.mode}` : ""}</td>
                  <td>{libs.map((l) => idx.lib.get(l)?.label || l).join(", ") || "—"}</td>
                  <td>{loc.confidence || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  }
  if (kind === "system") {
    const s = idx.sys.get(id);
    const providers = map.edges.depends_on.filter((e) => e.from === id);
    const consumers = map.edges.depends_on.filter((e) => e.to === id);
    return (
      <div style={box}>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <span style={{ fontSize: 15, fontWeight: 700 }}>{s.label}</span>
          {s.criticality && <Badge tone={CRIT_TONE[s.criticality] || "slate"}>{s.criticality}</Badge>}
          <span style={{ fontSize: 11.5, color: "var(--dim)" }}>{s.business_unit || ""}{s.owner ? ` · ${s.owner}` : ""} · {s.component_count} components</span>
        </div>
        <div style={{ fontSize: 12, marginTop: 8 }}><b>Algorithms ({s.algorithm_ids.length}):</b> {s.algorithm_ids.length ? s.algorithm_ids.map((a: string) => { const al = idx.algo.get(a); return chip(a, al?.label || a, a, al ? riskColor(al.risk) : undefined); }) : <span style={{ color: "var(--dim)" }}>none recorded</span>}</div>
        <div style={{ fontSize: 12, marginTop: 6 }}><b>Depends on:</b> {providers.length ? providers.map((e) => chip(e.id, `${idx.sys.get(e.to)?.label || e.to} · ${e.relation}`, e.to)) : <span style={{ color: "var(--dim)" }}>no recorded providers</span>}</div>
        <div style={{ fontSize: 12, marginTop: 6 }}><b>Depended on by:</b> {consumers.length ? consumers.map((e) => chip(e.id, `${idx.sys.get(e.from)?.label || e.from} · ${e.relation}`, e.from)) : <span style={{ color: "var(--dim)" }}>no recorded consumers</span>}</div>
      </div>
    );
  }
  if (kind === "component") {
    const c = idx.comp.get(id);
    const edges = map.edges.uses.filter((e) => e.from === id);
    return (
      <div style={box}>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <span style={{ fontFamily: "var(--mono)", fontSize: 14, fontWeight: 700 }}>{c.location}</span>
          <Badge tone={c.kind === "tls_endpoint" ? "cyan" : "slate"}>{COMPONENT_KIND_LABEL[c.kind] || c.kind}</Badge>
          <span style={{ fontSize: 11.5, color: "var(--dim)" }}>owned by {c.system_ids.map(sysName).join(", ")}{c.languages.length ? ` · ${c.languages.join(", ")}` : ""}</span>
        </div>
        <table className="table" style={{ width: "100%", fontSize: 11.5, marginTop: 8 }}>
          <thead><tr><th style={{ textAlign: "left" }}>Algorithm</th><th style={{ textAlign: "left" }}>Status</th><th style={{ textAlign: "left" }}>Lines / purposes</th><th style={{ textAlign: "left" }}>Library</th></tr></thead>
          <tbody>
            {edges.map((e) => { const a = idx.algo.get(e.to); return (
              <tr key={e.to} onClick={() => onSelect(e.to)} style={{ cursor: "pointer" }}>
                <td style={{ fontFamily: "var(--mono)", fontWeight: 600 }}>{a?.label}</td>
                <td><Badge tone={RISK_TONE[a?.risk as DepRisk] || "slate"}>{RISK_SHORT[a?.risk as DepRisk] || "—"}</Badge></td>
                <td style={{ fontFamily: "var(--mono)" }}>{e.locations.map((l) => `${l.line_number ? `L${l.line_number}` : "—"} ${l.purpose || ""}`).join(" · ")}</td>
                <td>{e.library_ids.map((l) => idx.lib.get(l)?.label || l).join(", ") || "—"}</td>
              </tr>); })}
          </tbody>
        </table>
      </div>
    );
  }
  const l = idx.lib.get(id);
  return (
    <div style={box}>
      <div style={{ fontSize: 14, fontWeight: 700 }}>{l.label}</div>
      <div style={{ fontSize: 12, marginTop: 6 }}><b>Provides:</b> {l.algorithm_ids.map((a: string) => { const al = idx.algo.get(a); return chip(a, al?.label || a, a, al ? riskColor(al.risk) : undefined); })}</div>
      <div style={{ fontSize: 12, marginTop: 6 }}><b>Linked by {l.component_ids.length} components in:</b> {l.system_ids.map(sysName).join(", ")}</div>
    </div>
  );
}
