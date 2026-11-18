import { Link } from "react-router-dom";
import React from "react";
import { Panel, Badge, Bar, Ring } from "../components/ui";
import { IconTarget, IconClock, IconSecurity, IconComponent, IconInfo } from "../components/icons";
import { useLive, LiveStatus } from "../lib/useLive.js";

interface Wave { focus?: string; sites?: any[]; site_count?: number }
interface SystemWaveRow { system_id: string; name?: string; wave: number; position?: number; rationale?: string | null; unscored?: boolean; readiness_score?: number | null; source?: string; constrained_by?: string[]; cycle_group?: string; code_cascade?: { providers?: number; weak_parameters?: number; earliest_wave?: number | null; algorithms?: string[] } | null; }
interface SystemWaves { waves?: Record<string, SystemWaveRow[]>; wave_order?: number[]; total_systems?: number; cycle_groups?: number; systems_bumped?: string[]; unscored_systems?: number; code_only_systems?: number; import_edges?: number; systems_delayed_by_imports?: string[]; }
interface Plan { inventory?: { total_sites?: number; vulnerable_sites?: number; pqc_ready_sites?: number; by_family?: Record<string, number> }; workstreams?: any[]; waves?: Record<string, Wave>; mosca?: { computable?: boolean; reason?: string; threat_year?: number; z_years_to_crqc?: number }; summary?: string; }

const WAVE_META: Record<string, { label: string; tone: string; accent: string }> = {
  "1": { label: "WAVE 1 · HARVEST-NOW", tone: "red", accent: "var(--red)" },
  "2": { label: "WAVE 2 · SHOR-VULNERABLE", tone: "amber", accent: "var(--amber)" },
  "3": { label: "WAVE 3 · GROVER SYMMETRIC", tone: "violet", accent: "var(--violet)" },
};

export default function Migration() {
  const { data, loading, error } = useLive<Plan>("/api/v1/quantum/plan", {});
  const sysWaves = useLive<SystemWaves>("/api/v1/graph/migration-waves", {});
  const sysRows: SystemWaveRow[] = Object.values(sysWaves.data.waves ?? {}).flat();
  const inv = data.inventory ?? {};
  const waves = data.waves ?? {};
  const workstreams = data.workstreams ?? [];
  const total = inv.total_sites ?? 0;
  const vulnerable = inv.vulnerable_sites ?? 0;
  const ready = inv.pqc_ready_sites ?? 0;
  const progressPct = total ? Math.round((ready / total) * 100) : 0;
  // No sites read ⇒ no readiness ratio. Slate, not red: an unmeasured estate is
  // not a failing one.
  const progressTone = total === 0 ? "slate" as const : progressPct >= 60 ? "green" as const : progressPct >= 25 ? "amber" as const : "red" as const;

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      {/* Hero */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16, flexWrap: "wrap", gap: 16 }}>
        <div style={{ flex: "1 1 520px", minWidth: 280 }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px", borderRadius: 999, background: "color-mix(in srgb, var(--amber) 12%, transparent)", border: "1px solid color-mix(in srgb, var(--amber) 35%, var(--line))", fontSize: 11, fontFamily: "var(--mono)", color: "var(--amber)", letterSpacing: ".06em" }}>
            <span style={{ width: 6, height: 6, borderRadius: 99, background: "var(--amber)" }} /> OUTPUT · MIGRATION PLANNING · 3-WAVE ROADMAP
          </div>
          <h1 style={{ fontSize: 26, fontWeight: 800, margin: "8px 0 6px", letterSpacing: "-0.02em", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ width: 34, height: 34, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--amber)", color: "#fff" }}><IconTarget size={18} /></span>
            Migration Planning
          </h1>
          <p style={{ margin: 0, fontSize: 13.5, color: "var(--dim)", lineHeight: 1.5, maxWidth: 640 }}>
            Post-quantum migration plan in three waves, HNDL-critical first.
          </p>
          <div style={{ display: "flex", gap: 8, marginTop: 12, flexWrap: "wrap", alignItems: "center" }}>
            <span style={{ fontSize: 11, color: "var(--dim)" }}>{total} total sites · {vulnerable} vulnerable</span>
          </div>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-start", flexWrap: "wrap" }}>
          <Panel style={{ padding: "10px 14px", minWidth: 165, display: "flex", alignItems: "center", gap: 12 }}>
            <Ring pct={progressPct / 100} label={total ? `${progressPct}%` : "—"} sub="pqc-ready" tone={progressTone} />
            <div>
              <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)" }}>MIGRATION PROGRESS</div>
              <div style={{ fontSize: 12, color: "var(--dim)", maxWidth: 135, lineHeight: 1.4 }}>{total ? `${ready}/${total} ready · ${vulnerable} still vulnerable` : "No sites returned — readiness not measured"}</div>
              <div style={{ marginTop: 6 }}><Bar value={progressPct / 100} tone={progressTone} /></div>
            </div>
          </Panel>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <span style={{ fontSize: 11, color: "var(--faint)", textAlign: "center" }}>{loading ? "loading…" : error ? "offline" : "live engine"}</span>
            <Link to="/what-if" style={{ fontSize: 12, padding: "7px 12px", borderRadius: "var(--r)", background: "var(--amber)", color: "#fff", textDecoration: "none", textAlign: "center", fontWeight: 700 }}>What-If Simulator →</Link>
          </div>
        </div>
      </div>

      <div style={{ marginBottom: 14 }}><LiveStatus loading={loading} error={error} /></div>

      {/* KPI cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 14, marginBottom: 18 }}>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid var(--red)` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>WAVE 1 · HARVEST-NOW</div><div style={{ fontSize: 26, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{(waves["1"]?.site_count ?? waves["1"]?.sites?.length ?? 0) as number}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>{waves["1"]?.focus ?? "HNDL-critical first"}</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--red) 14%, transparent)", border: "1px solid color-mix(in srgb, var(--red) 35%, var(--line))", color: "var(--red)" }}><IconClock size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={total ? ((waves["1"]?.site_count ?? waves["1"]?.sites?.length ?? 0) as number) / Math.max(1, total) : 0} tone="red" /></div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid var(--amber)` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>WAVE 2 · SHOR-VULNERABLE</div><div style={{ fontSize: 26, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{(waves["2"]?.site_count ?? waves["2"]?.sites?.length ?? 0) as number}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>{waves["2"]?.focus ?? "asymmetric at risk"}</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--amber) 14%, transparent)", border: "1px solid color-mix(in srgb, var(--amber) 35%, var(--line))", color: "var(--amber)" }}><IconSecurity size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={total ? ((waves["2"]?.site_count ?? waves["2"]?.sites?.length ?? 0) as number) / Math.max(1, total) : 0} tone="amber" /></div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid var(--violet)` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>WAVE 3 · GROVER SYMMETRIC</div><div style={{ fontSize: 26, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{(waves["3"]?.site_count ?? waves["3"]?.sites?.length ?? 0) as number}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>{waves["3"]?.focus ?? "symmetric / Grover"}</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--violet) 14%, transparent)", border: "1px solid color-mix(in srgb, var(--violet) 35%, var(--line))", color: "var(--violet)" }}><IconComponent size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={total ? ((waves["3"]?.site_count ?? waves["3"]?.sites?.length ?? 0) as number) / Math.max(1, total) : 0} tone="violet" /></div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${data.mosca?.computable ? "var(--green)" : "var(--slate)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>MOSCA RISK MODEL</div><div style={{ fontSize: 16, fontWeight: 800, margin: "6px 0 2px", lineHeight: 1 }}>{data.mosca?.computable ? `CRQC in ${data.mosca?.z_years_to_crqc ?? "?"}y` : "NOT COMPUTABLE"}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>{data.mosca?.threat_year ? `threat year ${data.mosca.threat_year}` : data.mosca?.reason ?? "shelf-life vs migration time"}</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: data.mosca?.computable ? "color-mix(in srgb, var(--green) 14%, transparent)" : "var(--panel-2)", border: `1px solid color-mix(in srgb, ${data.mosca?.computable ? "var(--green)" : "var(--line)"} 35%, var(--line))`, color: data.mosca?.computable ? "var(--green)" : "var(--faint)" }}><IconInfo size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><div style={{ fontSize: 10, color: "var(--faint)" }}>{data.mosca?.computable ? "years until a cryptographically relevant quantum computer, from the model — no fixed scale" : "not computable from the returned inputs"}</div></div>
        </div>
      </div>

      {/* Kanban */}
      <div className="kanban" style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 14, marginBottom: 18 }}>
        {["1", "2", "3"].map((w) => {
          const wave: Wave = waves[w] ?? { sites: [], site_count: 0 };
          const sites = wave.sites ?? [];
          const meta = WAVE_META[w];
          return (
            <div key={w} className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${meta.accent}`, display: "flex", flexDirection: "column" }}>
              <div style={{ padding: "12px 14px", background: `color-mix(in srgb, ${meta.accent} 8%, transparent)`, borderBottom: "1px solid var(--line)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: 11, fontWeight: 800, letterSpacing: ".04em", color: meta.accent }}>{meta.label}</span>
                <Badge tone={meta.tone as any}>{wave.site_count ?? sites.length}</Badge>
              </div>
              <div style={{ padding: 10, display: "grid", gap: 8, minHeight: 120 }}>
                <div className="dim" style={{ fontSize: 11 }}>{wave.focus ?? ""}</div>
                {sites.map((s: any, i: number) => (
                  <div key={s.id ?? s.site ?? s.name ?? i} style={{ padding: "10px 12px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", borderLeft: `3px solid ${meta.accent}` }}>
                    <div style={{ fontWeight: 700, fontSize: 12 }}>{s.name ?? s.site ?? s.asset_id ?? s.id}</div>
                    <div style={{ fontSize: 11, color: "var(--dim)", display: "flex", gap: 6, alignItems: "center", marginTop: 4 }}>
                      <span style={{ fontFamily: "var(--mono)" }}>{s.algorithm ?? s.family ?? s.system ?? "site"}</span>
                      <Badge tone={meta.tone as any}>{w === "1" ? "HIGH" : w === "2" ? "MEDIUM" : "LOW"}</Badge>
                    </div>
                    {(s.owner || s.workstream) && <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 4 }}>owner: {s.owner ?? s.workstream}</div>}
                  </div>
                ))}
                {sites.length === 0 && <div style={{ textAlign: "center", padding: 16, color: "var(--faint)", fontSize: 12, background: "var(--bg)", border: "1px dashed var(--line)", borderRadius: "var(--r)" }}>no sites in this wave yet</div>}
              </div>
            </div>
          );
        })}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 14 }}>
        <Panel title="Inventory" sub="live quantum-risk inventory">
          <div style={{ display: "grid", gap: 6 }}>
            {[
              { k: "total sites", v: total, tone: "slate" },
              { k: "quantum-vulnerable", v: vulnerable, tone: vulnerable ? "red" : "green" },
              { k: "PQC-ready", v: ready, tone: ready ? "green" : "slate" },
              ...Object.entries(inv.by_family ?? {}).map(([fam, n]) => ({ k: fam, v: n as number, tone: "violet" })),
            ].map(r => (
              <div key={r.k} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "6px 10px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>
                <span style={{ fontSize: 12 }}>{r.k}</span><span style={{ fontFamily: "var(--mono)", fontWeight: 700, fontSize: 12, color: `var(--${r.tone})` }}>{String(r.v)}</span>
              </div>
            ))}
          </div>
          <div style={{ marginTop: 10 }}><Bar value={total ? ready / total : 0} tone={progressTone} /><div style={{ fontSize: 10, color: "var(--faint)", marginTop: 4 }}>{progressPct}% PQC-ready · {vulnerable} vulnerable</div></div>
        </Panel>
        <Panel title="Mosca risk model" sub="shelf-life vs migration time vs crypto-agility">
          <div style={{ display: "grid", gap: 8 }}>
            <div style={{ display: "flex", justifyContent: "space-between", padding: "8px 10px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}><span style={{ fontSize: 12, color: "var(--faint)" }}>computable</span><Badge tone={data.mosca?.computable ? "green" : "amber"}>{data.mosca?.computable ? "yes" : "no"}</Badge></div>
            <div style={{ display: "flex", justifyContent: "space-between", padding: "8px 10px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}><span style={{ fontSize: 12, color: "var(--faint)" }}>threat year</span><span style={{ fontFamily: "var(--mono)", fontWeight: 700 }}>{data.mosca?.threat_year ?? "—"}</span></div>
            <div style={{ display: "flex", justifyContent: "space-between", padding: "8px 10px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}><span style={{ fontSize: 12, color: "var(--faint)" }}>years to CRQC</span><span style={{ fontFamily: "var(--mono)", fontWeight: 700 }}>{data.mosca?.z_years_to_crqc ?? "—"}</span></div>
            {data.mosca?.reason && <div style={{ fontSize: 11, color: "var(--dim)", background: "color-mix(in srgb, var(--amber) 8%, transparent)", border: "1px solid var(--amber)", borderRadius: "var(--r)", padding: "8px 10px" }}>{data.mosca.reason}</div>}
          </div>
        </Panel>
        <Panel title="Replacement workstreams" sub="ordered by the deterministic planner">
          {workstreams.length ? (
            <div style={{ display: "grid", gap: 6 }}>
              {workstreams.map((ws: any, i: number) => (
                <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 10px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>
                  <span style={{ fontFamily: "var(--mono)", fontWeight: 700, fontSize: 12 }}>{ws.name ?? ws.id ?? ws.workstream ?? `workstream ${i + 1}`}</span>
                  <span style={{ fontSize: 11, color: "var(--dim)" }}>{ws.target_algorithm ?? ws.target ?? ws.family ?? "—"}</span>
                  <Badge tone="amber">{ws.site_count ?? ws.sites ?? (Array.isArray(ws.sites) ? ws.sites.length : "—")}</Badge>
                </div>
              ))}
            </div>
          ) : <p className="dim" style={{ fontSize: 12, background: "var(--panel-2)", border: "1px dashed var(--line)", borderRadius: "var(--r)", padding: 12, textAlign: "center" }}>No workstreams yet.</p>}
        </Panel>
        <Panel title="Plan summary" sub="engine output">
          <p style={{ fontSize: 12.5, color: "var(--text)", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: 10, marginTop: 0 }}>{data.summary ?? "No migration plan yet."}</p>
          <p style={{ fontSize: 11, color: "var(--faint)", marginTop: 8 }}>Run a <Link to="/what-if" style={{ color: "var(--amber)" }}>what-if analysis</Link> on a target algorithm; waves populate as vulnerable sites are discovered.</p>
        </Panel>
      </div>

      <Panel title="System migration order" sub="Readiness waves reflect dependency cycles and code-level imports. A system that depends on cryptography in another system cannot migrate first." style={{ marginTop: 14, padding: 0, overflow: "hidden" } as any}>
        <div style={{ padding: "10px 14px", background: "var(--bg-2)", borderBottom: "1px solid var(--line)", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 8 }}>
          <span style={{ fontSize: 11, color: "var(--dim)" }}>{sysWaves.data.total_systems ?? 0} systems · {sysWaves.data.code_only_systems ?? 0} declared only in code · {sysWaves.data.import_edges ?? 0} code import edges · {(sysWaves.data.systems_delayed_by_imports ?? []).length} delayed by imports · {sysWaves.data.cycle_groups ?? 0} cycles · {sysWaves.data.unscored_systems ?? 0} unscored</span>
          <Badge tone="violet">{sysRows.length} rows</Badge>
        </div>
        {sysRows.length === 0 ? <p className="dim" style={{ fontSize: 12, padding: 16 }}>{sysWaves.loading ? "Loading…" : "No systems in the graph yet — register systems (CMDB) or add cryptoscan-systems.yml to scanned repositories."}</p> : (
          <div style={{ overflowX: "auto" }}>
            <table className="tbl" style={{ width: "100%" }}>
              <thead><tr><th>Wave</th><th>#</th><th>System</th><th>Code crypto</th><th>Constraint</th><th>Why</th></tr></thead>
              <tbody>
                {sysRows.map((r) => (
                  <tr key={r.system_id}>
                    <td><Badge tone={r.wave === 1 ? "red" : r.wave === 2 ? "amber" : "violet"}>wave {r.wave}</Badge></td>
                    <td style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{r.position ?? ""}</td>
                    <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.name || r.system_id}{r.source === "cryptoscan-systems.yml" && <span style={{ fontSize: 9, marginLeft: 6, background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "2px 6px", color: "var(--faint)" }}>code-declared</span>}</span></td>
                    <td style={{ fontSize: 11, color: "var(--dim)" }}>{r.code_cascade ? `${r.code_cascade.providers ?? 0} providers${r.code_cascade.weak_parameters ? ` · ${r.code_cascade.weak_parameters} weak` : ""}${r.code_cascade.earliest_wave ? ` · code wave ${r.code_cascade.earliest_wave}` : ""}` : "—"}</td>
                    <td style={{ fontSize: 11, color: r.constrained_by?.length ? "var(--amber)" : "var(--faint)" }}>{r.constrained_by?.length ? `after ${r.constrained_by.join(", ")}` : r.cycle_group ? r.cycle_group : "—"}</td>
                    <td style={{ fontSize: 11 }}>{r.rationale || ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
