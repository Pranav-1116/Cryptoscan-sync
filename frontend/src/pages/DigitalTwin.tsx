import React, { useMemo, useState } from "react";
import { Panel, Badge, Bar, Ring } from "../components/ui";
import { LiveBadge, ApiResult } from "../lib/api.js";
import { apiDigitalTwinOverview, apiDigitalTwinFidelity, apiDigitalTwinReconciliation, apiDigitalTwinScenarios, apiDigitalTwinSimulate, apiDigitalTwinTimeline, TwinScenarioDescriptor } from "../lib/api.js";
import { ICON_LG, ICON_MD, IconTarget, IconWarn, IconClock, IconSecurity, IconComponent, IconInfo } from "../components/icons";
import { useApi } from "../lib/apiUi.jsx";

interface TwinOverview { schema?: string; twin_assets?: number; systems?: number; certificates?: number; evidence_records?: number; dependency_edges?: number; dependency_source?: string; network_endpoints?: number; network_endpoints_observed?: number; hardware_assets?: number; hardware_hsms?: number; quantum_mix?: Record<string, number>; scenarios_available?: string[]; fidelity?: TwinFidelity; }
interface TwinReconciliation { schema?: string; verdict?: string; twin_algorithm_families?: Record<string, number>; evidence_algorithm_families?: Record<string, number>; families_in_both?: string[]; families_only_in_twin?: string[]; families_only_in_evidence?: string[]; honest_unknowns?: string[]; }
interface TwinFidelity { schema?: string; twin?: { assets?: number; systems_known?: number; systems_with_twin_state?: number; journal_events?: number; cbom_versions?: Record<string, number> }; staleness?: { assets_fresh?: number; assets_stale?: number; staleness_pct?: number | null; age_seconds_p50?: number | null; age_seconds_max?: number | null }; coverage?: { systems_covered_pct?: number | null; network_endpoints?: number; network_endpoints_observed?: number; network_observed_pct?: number | null }; honest_unknowns?: string[]; }
interface SimulateResp { scenario?: string; deterministic?: boolean; mutates_nothing?: boolean; verdict?: string; affected?: Record<string, unknown>; impact?: Record<string, unknown>; honest_unknowns?: string[]; inputs?: Record<string, unknown>; }
interface TimelineResp { asset_id?: string; current_cbom_version?: number | null; risk?: { score?: number | null; level?: string | null } | null; events?: Array<{ event_type?: string; source?: string; observed_at?: string | null; cbom_version?: number; risk_score?: number | null }>; truncated_to?: number; }

const INPUT_DEFAULTS: Record<string, string> = { from_algo: "RSA", to_algo: "ML-KEM-768", horizon_days: "90", algorithm: "RSA", vendor: "thales", protocol: "TLS", min_version: "1.2", min_key_bits: "3072", seed_asset: "", max_depth: "5", system_id: "", actions: "move_to_kms" };

export default function DigitalTwin() {
  const overview = useApi<Record<string, unknown>>(apiDigitalTwinOverview);
  const scenarios = useApi<{ scenario_count: number; scenarios: TwinScenarioDescriptor[] }>(apiDigitalTwinScenarios);
  const reconciliation = useApi<Record<string, unknown>>(apiDigitalTwinReconciliation);
  const [selected, setSelected] = useState<string>(""); const [params, setParams] = useState<Record<string, string>>({}); const [result, setResult] = useState<ApiResult<SimulateResp> | null>(null); const [busy, setBusy] = useState(false);
  const [timelineAsset, setTimelineAsset] = useState(""); const [timeline, setTimeline] = useState<ApiResult<TimelineResp> | null>(null);
  const ov = overview.data as TwinOverview | null; const rec = reconciliation.data as TwinReconciliation | null; const fid = (overview.data as TwinOverview | null)?.fidelity ?? ({} as TwinFidelity); const scen = scenarios.data?.scenarios ?? []; const active = scen.find((s) => s.id === selected);
  const choose = (id: string) => { setSelected(id); setResult(null); const inputs = scen.find((s) => s.id === id)?.inputs ?? {}; const next: Record<string, string> = {}; for (const k of Object.keys(inputs)) next[k] = INPUT_DEFAULTS[k] ?? ""; setParams(next); };
  const simulate = async () => { if (!selected) return; setBusy(true); const payload: Record<string, unknown> = {}; for (const [k, v] of Object.entries(params)) { if (v === "") continue; if (k === "actions") payload[k] = v.split(",").map((x) => x.trim()).filter(Boolean); else if (/^\d+(\.\d+)?$/.test(v)) payload[k] = Number(v); else payload[k] = v; } setResult(await apiDigitalTwinSimulate(selected, payload) as ApiResult<SimulateResp>); setBusy(false); };
  const loadTimeline = async () => { if (!timelineAsset.trim()) return; setTimeline(await apiDigitalTwinTimeline(timelineAsset.trim()) as ApiResult<TimelineResp>); };
  const res = result?.data; const unknowns = res?.honest_unknowns ?? []; const fidelityUnknowns = fid.honest_unknowns ?? []; const quantum = ov?.quantum_mix ?? {}; const timelineEvents = timeline?.data?.events ?? [];
  // A twin that was never read is not a twin holding zero assets: every figure
  // below renders "—" until the overview read returned.
  const ovRead = overview.source === "live" && ov != null;
  const n = (v: number | undefined | null) => (ovRead ? String(v ?? 0) : "—");
  const overviewCards = useMemo(() => [
    { k: "twin assets", v: n(ov?.twin_assets), sub: ovRead ? "live crypto replicas" : "overview not read", accent: "var(--cyan)" },
    { k: "systems", v: n(ov?.systems), sub: ovRead ? "registered estate systems" : "overview not read", accent: "var(--violet)" },
    { k: "certificates", v: n(ov?.certificates), sub: ovRead ? "inventory certificates" : "overview not read", accent: "var(--amber)" },
    { k: "evidence records", v: n(ov?.evidence_records), sub: ovRead ? "source-scan findings" : "overview not read", accent: "var(--green)" },
    { k: "dependency edges", v: n(ov?.dependency_edges), sub: ovRead ? (ov?.dependency_source && ov.dependency_source !== "none" ? `from ${ov.dependency_source.replace(/_/g, " ")}` : "no graph yet") : "overview not read", accent: "var(--slate)" },
    { k: "network observed", v: ovRead ? `${ov?.network_endpoints_observed ?? 0}/${ov?.network_endpoints ?? 0}` : "—", sub: ovRead ? "observed / total incl. targets" : "overview not read", accent: "var(--cyan)" },
    { k: "hardware fleet", v: ovRead ? `${ov?.hardware_hsms ?? 0} HSMs` : "—", sub: ovRead ? `${ov?.hardware_assets ?? 0} hardware assets` : "overview not read", accent: "var(--green)" },
  ], [ov, ovRead]);
  const fidelityPct = fid.coverage?.systems_covered_pct != null ? fid.coverage.systems_covered_pct / 100 : fid.staleness?.staleness_pct != null ? 1 - fid.staleness.staleness_pct / 100 : 0;

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 12, flexWrap: "wrap", gap: 16 }}>
        <div style={{ flex: "1 1 520px", minWidth: 280 }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px", borderRadius: 999, background: "color-mix(in srgb, var(--violet) 12%, transparent)", border: "1px solid var(--violet)", fontSize: 11, fontFamily: "var(--mono)", color: "var(--violet)", letterSpacing: ".06em" }}>
            <span style={{ width: 6, height: 6, borderRadius: 99, background: "var(--violet)" }} /> OUTPUT · CRYPTOGRAPHIC DIGITAL TWIN · REPLICA
          </div>
          <h1 style={{ fontSize: 26, fontWeight: 800, margin: "8px 0 6px", letterSpacing: "-0.02em", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ width: 34, height: 34, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--violet)", color: "#fff" }}><IconComponent size={18} /></span>
            Cryptographic Digital Twin
          </h1>
          <p style={{ margin: 0, fontSize: 13.5, color: "var(--dim)", lineHeight: 1.5, maxWidth: 640 }}>
            The live replica of the crypto estate — <b style={{ color: "var(--text)" }}>what it holds, how faithfully it tracks reality, and what happens under stress</b>. Scenarios project, never act.
          </p>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-start", flexWrap: "wrap" }}>
          <Panel style={{ padding: "10px 14px", minWidth: 155, display: "flex", alignItems: "center", gap: 12 }}>
            <Ring pct={fidelityPct} label={fid.coverage?.systems_covered_pct != null ? `${fid.coverage.systems_covered_pct}%` : ov?.twin_assets ? String(ov.twin_assets) : "—"} sub="fidelity" tone={fidelityPct >= 0.6 ? "green" : fidelityPct > 0 ? "amber" : "slate"} />
            <div>
              <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)" }}>REPLICA FIDELITY</div>
              <div style={{ fontSize: 12, color: "var(--dim)", maxWidth: 135, lineHeight: 1.4 }}>{!ovRead ? "overview not read" : `${fid.twin?.assets ?? ov?.twin_assets ?? 0} replicas · ${fid.staleness?.assets_fresh ?? 0} fresh · ${fid.staleness?.assets_stale ?? 0} stale`}</div>
              <div style={{ marginTop: 6 }}><Bar value={fidelityPct} tone={fidelityPct >= 0.6 ? "green" : fidelityPct > 0 ? "amber" : "slate"} /></div>
            </div>
          </Panel>
          {overview.data && <LiveBadge source={overview.source} label={overview.source === "live" ? "live replica" : "offline"} />}
        </div>
      </div>

      <div style={{ display: "flex", gap: 10, alignItems: "center", padding: "10px 14px", background: "color-mix(in srgb, var(--violet) 8%, transparent)", border: "1px solid var(--violet)", borderRadius: "var(--r)", marginBottom: 14 }}>
        <span style={{ width: 28, height: 28, borderRadius: 8, display: "grid", placeItems: "center", background: "var(--violet)", color: "#fff" }}><IconTarget size={14} /></span>
        <div><div style={{ fontSize: 12, fontWeight: 800, color: "var(--violet)" }}>REPLICA VIEW — SCENARIOS PROJECT, NEVER ACT</div><div style={{ fontSize: 11, color: "var(--dim)" }}>Every scenario runs deterministically over a read-only snapshot. Nothing is re-keyed, deployed or written. Gaps are honest unknowns.</div></div>
        <span style={{ marginLeft: "auto", fontSize: 11, color: "var(--faint)" }}>{scenarios.data?.scenario_count ?? 0} scenario types</span>
      </div>

      {overview.error && <div style={{ padding: "10px 14px", background: "color-mix(in srgb, var(--red) 8%, transparent)", border: "1px solid var(--red)", borderRadius: "var(--r)", fontSize: 12, color: "var(--red)", marginBottom: 14 }}>{overview.error}</div>}

      <Panel title="Twin overview" sub="What the replica currently holds" style={{ padding: 0, overflow: "hidden" } as any}>
        <div style={{ padding: "10px 14px", background: "var(--bg-2)", borderBottom: "1px solid var(--line)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          {ov?.schema ? <Badge tone="slate">{ov.schema}</Badge> : <span style={{ fontSize: 11, color: "var(--faint)" }}>schema —</span>}
          <span style={{ fontSize: 11, color: "var(--dim)" }}>{Object.entries(quantum).map(([k, n]) => `${k}: ${n}`).join(" · ") || "no quantum mix yet"}</span>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))", gap: 10, padding: 14 }}>
          {overviewCards.map((c) => (
            <div key={c.k} style={{ padding: 12, background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", borderTop: `2px solid ${c.accent}` }}>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>{c.k.toUpperCase()}</div>
              <div style={{ fontSize: 22, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", color: c.accent }}>{String(c.v)}</div>
              <div style={{ fontSize: 11, color: "var(--dim)" }}>{c.sub}</div>
            </div>
          ))}
        </div>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap", padding: "10px 14px", background: "var(--bg-2)", borderTop: "1px solid var(--line)" }}>
          {Object.entries(quantum).map(([k, n]) => <Badge key={k} tone={k === "vulnerable" ? "red" : k === "ready" ? "green" : "slate"}>{k}: {String(n)}</Badge>)}
          {!Object.keys(quantum).length && <span style={{ fontSize: 11, color: "var(--faint)" }}>No quantum-mix yet — twin populates from evidence</span>}
        </div>
      </Panel>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(360px, 1fr))", gap: 14, marginTop: 14 }}>
        <Panel title="Twin fidelity" sub="Measured against the real estate — staleness, coverage, journal" style={{ padding: 0, overflow: "hidden" } as any}>
          <div style={{ padding: 14 }}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
              {[
                ["assets fresh", fid.twin == null ? "—" : String(fid.staleness?.assets_fresh ?? 0)],
                ["assets stale", fid.twin == null ? "—" : String(fid.staleness?.assets_stale ?? 0)],
                ["staleness", fid.staleness?.staleness_pct == null ? "—" : `${fid.staleness.staleness_pct}%`],
                ["journal events", fid.twin == null ? "—" : String(fid.twin.journal_events ?? 0)],
                ["max CBOM version", fid.twin == null ? "—" : String(fid.twin.cbom_versions?.max ?? "—")],
                ["systems with twin state", fid.twin == null ? "—" : `${fid.twin.systems_with_twin_state ?? 0} / ${fid.twin.systems_known ?? 0}`],
                ["coverage", fid.coverage?.systems_covered_pct == null ? "unknown" : `${fid.coverage.systems_covered_pct}%`],
                ["network observed", fid.coverage?.network_observed_pct == null ? "no endpoints" : `${fid.coverage.network_endpoints_observed ?? 0}/${fid.coverage.network_endpoints ?? 0} (${fid.coverage.network_observed_pct}%)`],
              ].map(([k, v]) => <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "7px 10px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}><span style={{ fontSize: 11, color: "var(--faint)" }}>{k}</span><span style={{ fontWeight: 700, fontSize: 12, fontFamily: "var(--mono)" }}>{v}</span></div>)}
            </div>
            <div style={{ marginTop: 10 }}><Bar value={fid.coverage?.systems_covered_pct != null ? fid.coverage.systems_covered_pct / 100 : 0} tone="violet" /><div style={{ fontSize: 10, color: "var(--faint)", marginTop: 4 }}>systems coverage</div></div>
            {fidelityUnknowns.length > 0 && <div style={{ marginTop: 10, padding: "8px 10px", background: "color-mix(in srgb, var(--amber) 8%, transparent)", border: "1px solid var(--amber)", borderRadius: "var(--r)", fontSize: 11, color: "var(--amber)" }}><Badge tone="amber">honest unknowns</Badge> {fidelityUnknowns.join(" · ")}</div>}
          </div>
        </Panel>
        <Panel title="Asset journal (time-travel)" sub="Immutable crypto_live_events history for one asset" style={{ padding: 0, overflow: "hidden" } as any}>
          <div style={{ padding: 14 }}>
            <div style={{ display: "flex", gap: 8 }}>
              <input placeholder="asset id, e.g. hsm-core-01" value={timelineAsset} onChange={(e) => setTimelineAsset(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") void loadTimeline(); }} style={{ flex: 1, padding: "7px 10px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)", color: "var(--text)", fontFamily: "var(--mono)", fontSize: 12 }} />
              <button onClick={() => void loadTimeline()} style={{ padding: "7px 14px", borderRadius: "var(--r)", background: "var(--violet)", color: "#fff", border: "1px solid var(--violet)", fontWeight: 700, fontSize: 12, cursor: "pointer" }}>Load journal</button>
            </div>
            {timeline?.error && <p style={{ fontSize: 12, color: "var(--red)", background: "color-mix(in srgb, var(--red) 8%, transparent)", border: "1px solid var(--red)", borderRadius: "var(--r)", padding: "8px 10px", marginTop: 10 }}>{timeline.error}</p>}
            {timeline?.data && (
              <>
                <div style={{ display: "flex", gap: 6, marginTop: 12, flexWrap: "wrap" }}>
                  <Badge tone="slate">CBOM v{timeline.data.current_cbom_version ?? "—"}</Badge>
                  {timeline.data.risk?.level && <Badge tone={timeline.data.risk.level === "HIGH" || timeline.data.risk.level === "CRITICAL" ? "red" : "green"}>risk {timeline.data.risk.level}</Badge>}
                  <Badge tone="violet">{timelineEvents.length} events</Badge>
                </div>
                <div style={{ overflowX: "auto", marginTop: 10 }}>
                  <table className="tbl" style={{ width: "100%" }}><thead><tr><th>Observed</th><th>Event</th><th>Source</th><th>CBOM</th></tr></thead><tbody>{timelineEvents.slice(0, 25).map((e, i) => <tr key={i}><td style={{ fontSize: 11 }}>{e.observed_at ? new Date(e.observed_at).toLocaleString() : "—"}</td><td style={{ fontSize: 11 }}>{e.event_type ?? "—"}</td><td style={{ fontSize: 11, color: "var(--faint)" }}>{e.source ?? "—"}</td><td style={{ fontFamily: "var(--mono)", fontSize: 11 }}>v{e.cbom_version ?? "—"}</td></tr>)}</tbody></table>
                </div>
              </>
            )}
            {!timeline && <p style={{ fontSize: 12, color: "var(--faint)", background: "var(--panel-2)", border: "1px dashed var(--line)", borderRadius: "var(--r)", padding: 12, textAlign: "center", marginTop: 10 }}>Enter an asset id to read its journal — the twin's memory of every observed change.</p>}
          </div>
        </Panel>
      </div>

      <Panel title="Twin ↔ evidence reconciliation" sub="Twin's algorithm inventory diffed against its own evidence store — twin-vs-sources, not twin-vs-reality" style={{ marginTop: 14, padding: 0, overflow: "hidden" } as any}>
        {reconciliation.error && <p style={{ fontSize: 12, color: "var(--red)", padding: 14 }}>{reconciliation.error}</p>}
        {rec ? (
          <>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "14px 16px", background: `color-mix(in srgb, ${rec.verdict === "IN_SYNC" ? "var(--green)" : rec.verdict === "INSUFFICIENT_DATA" ? "var(--amber)" : "var(--red)"} 8%, transparent)`, borderBottom: "1px solid var(--line)" }}>
              <span style={{ fontSize: 20, fontWeight: 800, color: rec.verdict === "IN_SYNC" ? "var(--green)" : rec.verdict === "INSUFFICIENT_DATA" ? "var(--amber)" : "var(--red)" }}>{rec.verdict ?? "—"}</span>
              <div style={{ display: "flex", gap: 8 }}><Badge tone="slate">{Object.keys(rec.twin_algorithm_families ?? {}).length} twin families</Badge><Badge tone="slate">{Object.keys(rec.evidence_algorithm_families ?? {}).length} evidence families</Badge><Badge tone="green">{(rec.families_in_both ?? []).length} in both</Badge></div>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, padding: 14 }}>
              <div>
                <div style={{ fontSize: 11, fontWeight: 700, color: "var(--faint)", marginBottom: 6 }}>only in evidence (twin lags) → only in twin (unbacked)</div>
                <div style={{ overflowX: "auto" }}>
                  <table className="tbl" style={{ width: "100%" }}><thead><tr><th>only in evidence</th><th>only in twin</th></tr></thead><tbody>{Array.from({ length: Math.max((rec.families_only_in_evidence ?? []).length, (rec.families_only_in_twin ?? []).length) || 1 }).map((_, i) => <tr key={i}><td style={{ fontSize: 11, fontFamily: "var(--mono)" }}>{(rec.families_only_in_evidence ?? [])[i] ?? "—"}</td><td style={{ fontSize: 11, fontFamily: "var(--mono)" }}>{(rec.families_only_in_twin ?? [])[i] ?? "—"}</td></tr>)}</tbody></table>
                </div>
              </div>
              {(rec.honest_unknowns ?? []).length > 0 && <div style={{ fontSize: 11, color: "var(--amber)", background: "color-mix(in srgb, var(--amber) 8%, transparent)", border: "1px solid var(--amber)", borderRadius: "var(--r)", padding: 10 }}><Badge tone="amber">honest unknowns</Badge><ul style={{ marginTop: 6, paddingLeft: 16 }}>{(rec.honest_unknowns ?? []).map((u, i) => <li key={i} style={{ margin: "4px 0" }}>{u}</li>)}</ul></div>}
            </div>
          </>
        ) : !reconciliation.running ? <p style={{ fontSize: 12, color: "var(--dim)", padding: 14 }}>No reconciliation data returned.</p> : null}
      </Panel>

      <Panel title="Scenario launcher" sub={`${scenarios.data?.scenario_count ?? 0} deterministic scenario types from the engine — no hardcoded templates`} style={{ marginTop: 14 }}>
        {scen.length === 0 && !scenarios.running && <p style={{ fontSize: 12, color: "var(--faint)", background: "var(--panel-2)", border: "1px dashed var(--line)", borderRadius: "var(--r)", padding: 12, textAlign: "center" }}>{scenarios.error ?? "No scenarios returned by the engine."}</p>}
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 8 }}>
          {scen.map((s) => <button key={s.id} onClick={() => choose(s.id)} style={{ padding: "6px 14px", borderRadius: 999, fontSize: 12, fontWeight: s.id === selected ? 700 : 500, cursor: "pointer", background: s.id === selected ? "var(--violet)" : "var(--panel-2)", color: s.id === selected ? "#fff" : "var(--text)", border: `1px solid ${s.id === selected ? "var(--violet)" : "var(--line)"}` }}>{s.name}</button>)}
        </div>
        {active && (
          <div style={{ marginTop: 14, padding: 12, background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>
            <div style={{ fontSize: 12, color: "var(--dim)", marginBottom: 10 }}>{active.description}</div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              {Object.keys(active.inputs).map((k) => <label key={k} style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 11, color: "var(--faint)" }}>{k}<input value={params[k] ?? ""} placeholder={INPUT_DEFAULTS[k] ?? ""} onChange={(e) => setParams({ ...params, [k]: e.target.value })} style={{ width: 170, padding: "6px 8px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)", color: "var(--text)", fontFamily: "var(--mono)", fontSize: 12 }} /></label>)}
            </div>
            <div style={{ marginTop: 12 }}><button onClick={() => void simulate()} disabled={busy} style={{ padding: "7px 14px", borderRadius: "var(--r)", background: "var(--violet)", color: "#fff", border: "1px solid var(--violet)", fontWeight: 700, fontSize: 12, cursor: busy ? "not-allowed" : "pointer", opacity: busy ? 0.6 : 1 }}>{busy ? "Running scenario…" : "Run against the twin"}</button></div>
          </div>
        )}
      </Panel>

      {result?.error && <div style={{ marginTop: 14, padding: "10px 14px", background: "color-mix(in srgb, var(--red) 8%, transparent)", border: "1px solid var(--red)", borderRadius: "var(--r)", fontSize: 12, color: "var(--red)" }}>{result.error}</div>}

      {res && (
        <Panel title="Scenario result" sub={`${res.scenario} · deterministic · read-only`} style={{ marginTop: 14, padding: 0, overflow: "hidden" } as any}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "14px 16px", background: `color-mix(in srgb, ${res.verdict === "AFFECTED" || res.verdict === "AT_RISK" ? "var(--red)" : res.verdict === "INSUFFICIENT_DATA" ? "var(--amber)" : "var(--green)"} 8%, transparent)`, borderBottom: "1px solid var(--line)" }}>
            <span style={{ fontSize: 20, fontWeight: 800, color: res.verdict === "AFFECTED" || res.verdict === "AT_RISK" ? "var(--red)" : res.verdict === "INSUFFICIENT_DATA" ? "var(--amber)" : "var(--green)" }}>{res.verdict ?? "—"}</span>
            <div style={{ display: "flex", gap: 8 }}><Badge tone="green">deterministic</Badge><Badge tone="green">mutates nothing</Badge></div>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 14, padding: 14 }}>
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, color: "var(--faint)", marginBottom: 6 }}>affected</div>
              <div style={{ display: "grid", gap: 6 }}>{Object.entries(res.affected ?? {}).map(([k, v]) => { const items = Array.isArray(v) ? v as unknown[] : null; const label = (x: unknown): string => typeof x === "object" && x !== null ? String((x as Record<string, unknown>).asset_id ?? (x as Record<string, unknown>).system_id ?? JSON.stringify(x)) : String(x); return <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "7px 10px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}><span style={{ fontSize: 11, color: "var(--faint)" }}>{k}</span><span style={{ fontSize: 11, fontWeight: 600 }}>{items === null ? String(v ?? "—") : `${items.length}${items.length ? `: ${items.slice(0, 4).map(label).join(", ")}${items.length > 4 ? "…" : ""}` : ""}`}</span></div>; })}</div>
            </div>
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, color: "var(--faint)", marginBottom: 6 }}>impact</div>
              <div style={{ display: "grid", gap: 6 }}>{Object.entries(res.impact ?? {}).map(([k, v]) => <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "7px 10px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}><span style={{ fontSize: 11, color: "var(--faint)" }}>{k}</span><span style={{ fontSize: 11, fontWeight: 600 }}>{typeof v === "object" && v !== null ? JSON.stringify(v) : String(v ?? "—")}</span></div>)}</div>
            </div>
          </div>
          {unknowns.length > 0 && <div style={{ margin: "0 14px 14px", padding: "10px 14px", background: "color-mix(in srgb, var(--amber) 8%, transparent)", border: "1px solid var(--amber)", borderRadius: "var(--r)", fontSize: 11, color: "var(--amber)" }}><Badge tone="amber">honest unknowns</Badge> the twin could not verify — never assumed true:<ul style={{ marginTop: 6, paddingLeft: 16 }}>{unknowns.map((u, i) => <li key={i} style={{ margin: "4px 0" }}>{u}</li>)}</ul></div>}
        </Panel>
      )}
    </div>
  );
}
