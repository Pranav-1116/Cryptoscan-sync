import React, { useState } from "react";
import { Panel, Badge, Bar, Ring } from "../components/ui";
import { Donut, HBars, StepRail } from "../components/viz";
import { IconTarget, IconClock, IconSecurity, IconComponent, IconInfo } from "../components/icons";
import { apiWhatIf, LiveBadge, ApiResult } from "../lib/api.js";

const SCENARIOS = [
  { label: "RSA-2048 → ML-KEM-768", from: "RSA-2048", to: "ML-KEM-768" },
  { label: "ECDSA-P-256 → ML-DSA-65", from: "ECDSA-P-256", to: "ML-DSA-65" },
  { label: "X25519 → ML-KEM-768", from: "X25519", to: "ML-KEM-768" },
  { label: "DH-2048 → ML-KEM-768", from: "DH-2048", to: "ML-KEM-768" },
];
interface WhatIfResp { checks?: { dependencies?: { affected_libraries?: number; libraries?: string[] }; libraries?: { supporting?: string[]; supported?: boolean }; hardware?: { pqc_capable_devices?: number; devices?: string[]; supported?: boolean }; vendor?: { pqc_positive?: number; vendors?: string[]; supported?: boolean }; cloud?: { pqc_ready_services?: number; services?: string[]; supported?: boolean }; impact?: { projected_quantum_status?: string; protocol_compatibility?: Record<string, string> } }; feasible?: boolean; migration_plan?: { steps?: string[]; risk?: string }; honest_unknowns?: string[]; impact?: Record<string, number>; }

export default function WhatIf() {
  const [sel, setSel] = useState(0);
  const [live, setLive] = useState<ApiResult<WhatIfResp> | null>(null);
  const [busy, setBusy] = useState(false);
  const s = SCENARIOS[sel];
  const simulate = async () => { setBusy(true); setLive(await apiWhatIf(s.from, s.to, ["TLS", "SSH", "IPsec"]) as ApiResult<WhatIfResp>); setBusy(false); };
  const d = live?.data; const c = d?.checks ?? {}; const steps = d?.migration_plan?.steps ?? []; const unknowns = d?.honest_unknowns ?? []; const projected = c.impact?.projected_quantum_status ?? "UNKNOWN";
  const checkCards: Array<{ key: string; name: string; ok?: boolean; n: number; sub: string; items: string[] }> = [
    { key: "dependencies", name: "affected libraries", ok: (c.dependencies?.affected_libraries ?? 0) === 0, n: c.dependencies?.affected_libraries ?? 0, sub: "dependencies referencing current algorithm", items: c.dependencies?.libraries ?? [] },
    { key: "libraries", name: "libraries support target", ok: c.libraries?.supported, n: (c.libraries?.supporting ?? []).length, sub: c.libraries?.supported ? "target supported in use" : "no library verified for target", items: c.libraries?.supporting ?? [] },
    { key: "hardware", name: "PQC-capable hardware", ok: c.hardware?.supported, n: c.hardware?.pqc_capable_devices ?? 0, sub: c.hardware?.supported ? "hardware supports target" : "no HSM/TPM/accelerator verified", items: c.hardware?.devices ?? [] },
    { key: "vendor", name: "vendor roadmap", ok: c.vendor?.supported, n: c.vendor?.pqc_positive ?? 0, sub: c.vendor?.supported ? "vendors roadmap-positive" : "no vendor confirmation", items: c.vendor?.vendors ?? [] },
    { key: "cloud", name: "cloud PQC-ready", ok: c.cloud?.supported, n: c.cloud?.pqc_ready_services ?? 0, sub: c.cloud?.supported ? "services PQC-ready" : "no cloud service verified", items: c.cloud?.services ?? [] },
  ];
  const cardCls = (ok: boolean | undefined, n: number) => ok ? "ok" : n === 0 && ok === undefined ? "unknown" : ok === false ? "blocked" : "unknown";
  const feasibleTone = d?.feasible ? "green" as const : projected === "UNKNOWN" ? "amber" as const : "red" as const;

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16, flexWrap: "wrap", gap: 16 }}>
        <div style={{ flex: "1 1 520px", minWidth: 280 }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px", borderRadius: 999, background: "color-mix(in srgb, var(--violet) 12%, transparent)", border: "1px solid color-mix(in srgb, var(--violet) 35%, var(--line))", fontSize: 11, fontFamily: "var(--mono)", color: "var(--violet)", letterSpacing: ".06em" }}>
            <span style={{ width: 6, height: 6, borderRadius: 99, background: "var(--violet)" }} /> OUTPUT · WHAT-IF SIMULATOR · READ-ONLY ANALYSIS
          </div>
          <h1 style={{ fontSize: 26, fontWeight: 800, margin: "8px 0 6px", letterSpacing: "-0.02em", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ width: 34, height: 34, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--violet)", color: "#fff" }}><IconTarget size={18} /></span>
            What-If Migration Simulator
          </h1>
          <p style={{ margin: 0, fontSize: 13.5, color: "var(--dim)", lineHeight: 1.5, maxWidth: 640 }}>
            Model a crypto transition against the live estate — <b style={{ color: "var(--text)" }}>analysis only, nothing changed or deployed</b>. Five feasibility checks, projected status, ordered plan, honest unknowns.
          </p>
          <div style={{ display: "flex", gap: 8, marginTop: 12, flexWrap: "wrap", alignItems: "center" }}>
            <span className="kicker" style={{ fontSize: 10 }}>DETERMINISTIC ENGINE · DEPENDENCIES · LIBS · HW · VENDOR · CLOUD</span>
          </div>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-start", flexWrap: "wrap" }}>
          <Panel style={{ padding: "10px 14px", minWidth: 160, display: "flex", alignItems: "center", gap: 12 }}>
            <Ring pct={d ? (d.feasible ? 1 : projected === "UNKNOWN" ? 0.45 : 0.2) : 0} label={d ? (d.feasible ? "FEASIBLE" : projected === "UNKNOWN" ? "UNKNOWN" : "BLOCKED") : "—"} sub="verdict" tone={d ? feasibleTone : "slate"} />
            <div>
              <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)" }}>FEASIBILITY</div>
              <div style={{ fontSize: 12, color: "var(--dim)", maxWidth: 130, lineHeight: 1.4 }}>{d ? `→ ${projected}${d.migration_plan?.risk ? ` · risk ${d.migration_plan.risk}` : ""}` : "Run a scenario against live estate"}</div>
              <div style={{ marginTop: 6 }}><Bar value={d ? (d.feasible ? 1 : 0.35) : 0} tone={d ? feasibleTone : "slate"} /></div>
            </div>
          </Panel>
          {live && <Badge tone={live.source === "live" ? "green" : "amber"}>{live.source === "live" ? "LIVE ENGINE" : "OFFLINE"}</Badge>}
        </div>
      </div>

      <div style={{ display: "flex", gap: 8, alignItems: "center", padding: "10px 14px", background: "color-mix(in srgb, var(--violet) 8%, transparent)", border: "1px solid var(--violet)", borderRadius: "var(--r)", marginBottom: 14 }}>
        <span style={{ width: 28, height: 28, borderRadius: 8, display: "grid", placeItems: "center", background: "var(--violet)", color: "#fff" }}><IconSecurity size={14} /></span>
        <div><div style={{ fontSize: 12, fontWeight: 800, color: "var(--violet)" }}>SIMULATION ONLY — NO EXECUTION</div><div style={{ fontSize: 11, color: "var(--dim)" }}>Read-only deterministic engine. Never re-keys, deploys, writes config, or touches a live system. Execution is separate, governed.</div></div>
      </div>

      <Panel title="Scenario" sub="Choose a cryptographic transition — the engine checks the whole estate" style={{ padding: 0, overflow: "hidden" } as any}>
        <div style={{ padding: "14px 16px" }}>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {SCENARIOS.map((sc, i) => (
              <button key={sc.label} onClick={() => { setSel(i); setLive(null); }} style={{ padding: "7px 14px", borderRadius: 999, fontSize: 12, fontWeight: i === sel ? 700 : 500, cursor: "pointer", background: i === sel ? "var(--violet)" : "var(--panel-2)", color: i === sel ? "#fff" : "var(--text)", border: `1px solid ${i === sel ? "var(--violet)" : "var(--line)"}` }}>{sc.label}</button>
            ))}
          </div>
          <div style={{ marginTop: 12, fontSize: 12, background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "8px 12px", display: "inline-flex", gap: 8, alignItems: "center" }}>
            migrating <span style={{ fontFamily: "var(--mono)", fontWeight: 800, color: "var(--violet)" }}>{s.from}</span> → <span style={{ fontFamily: "var(--mono)", fontWeight: 800, color: "var(--green)" }}>{s.to}</span>
          </div>
          <div style={{ marginTop: 12 }}><button onClick={() => void simulate()} disabled={busy} style={{ padding: "8px 14px", borderRadius: "var(--r)", background: "var(--violet)", color: "#fff", border: "1px solid var(--violet)", fontWeight: 700, fontSize: 12, cursor: busy ? "not-allowed" : "pointer", opacity: busy ? 0.6 : 1 }}>{busy ? "Running engine…" : "Simulate against live estate"}</button></div>
        </div>
      </Panel>

      {live?.error && <div style={{ marginTop: 14, padding: "10px 14px", background: "color-mix(in srgb, var(--red) 8%, transparent)", border: "1px solid var(--red)", borderRadius: "var(--r)", fontSize: 13, color: "var(--red)" }}>{live.error}</div>}

      {d && (
        <>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 14, marginTop: 14 }}>
            <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid var(--${feasibleTone})` }}>
              <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>FEASIBILITY VERDICT</div><div style={{ fontSize: 20, fontWeight: 800, margin: "6px 0 2px", lineHeight: 1, color: `var(--${feasibleTone})` }}>{d.feasible ? "FEASIBLE" : projected === "UNKNOWN" ? "UNKNOWN" : "BLOCKED"}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>{s.from} → {s.to} · deterministic</div></div>
                <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: `color-mix(in srgb, var(--${feasibleTone}) 14%, transparent)`, border: `1px solid var(--${feasibleTone})`, color: `var(--${feasibleTone})` }}><IconTarget size={16} /></span>
              </div>
              <div style={{ padding: "0 16px 12px" }}><Bar value={d.feasible ? 1 : projected === "UNKNOWN" ? 0.45 : 0.2} tone={feasibleTone} /></div>
            </div>
            <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${projected === "SAFE" || projected === "PQC_SAFE" ? "var(--green)" : projected === "UNKNOWN" ? "var(--amber)" : "var(--red)"}` }}>
              <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>PROJECTED QUANTUM STATUS</div><div style={{ fontSize: 16, fontWeight: 800, margin: "6px 0 2px", lineHeight: 1 }}><Badge tone={projected === "SAFE" || projected === "PQC_SAFE" ? "green" : projected === "UNKNOWN" ? "amber" : "red"}>{projected}</Badge></div><div style={{ fontSize: 11, color: "var(--dim)" }}>post-migration inventory</div></div>
                <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--panel-2)", border: "1px solid var(--line)", color: "var(--faint)" }}><IconInfo size={16} /></span>
              </div>
              <div style={{ padding: "0 16px 12px" }}><Bar value={projected === "SAFE" ? 1 : projected === "UNKNOWN" ? 0.45 : 0.25} tone={projected === "SAFE" ? "green" : projected === "UNKNOWN" ? "amber" : "red"} /></div>
            </div>
            <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${d.migration_plan?.risk === "HIGH" ? "var(--red)" : d.migration_plan?.risk === "MEDIUM" ? "var(--amber)" : "var(--green)"}` }}>
              <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>MIGRATION RISK</div><div style={{ fontSize: 20, fontWeight: 800, margin: "6px 0 2px", lineHeight: 1 }}>{d.migration_plan?.risk ?? "UNKNOWN"}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>{steps.length} ordered steps</div></div>
                <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: d.migration_plan?.risk === "HIGH" ? "color-mix(in srgb, var(--red) 14%, transparent)" : "var(--panel-2)", border: `1px solid color-mix(in srgb, ${d.migration_plan?.risk === "HIGH" ? "var(--red)" : "var(--line)"} 35%, var(--line))`, color: d.migration_plan?.risk === "HIGH" ? "var(--red)" : "var(--faint)" }}><IconClock size={16} /></span>
              </div>
              <div style={{ padding: "0 16px 12px" }}><Bar value={d.migration_plan?.risk === "HIGH" ? 0.9 : d.migration_plan?.risk === "MEDIUM" ? 0.55 : 0.3} tone={d.migration_plan?.risk === "HIGH" ? "red" : d.migration_plan?.risk === "MEDIUM" ? "amber" : "green"} /></div>
            </div>
          </div>

          {unknowns.length > 0 && <div style={{ marginTop: 14, padding: "10px 14px", background: "color-mix(in srgb, var(--amber) 8%, transparent)", border: "1px solid var(--amber)", borderRadius: "var(--r)", fontSize: 12, color: "var(--amber)" }}><Badge tone="amber">honest unknowns</Badge> engine could not verify — never assumed true: {unknowns.join(", ")}</div>}

          <Panel title="Feasibility checks" sub="Every dependency, library, device, vendor and service is inventoried before a change" style={{ marginTop: 14 }}>
            <div style={{ display: "flex", gap: 20, flexWrap: "wrap", alignItems: "center", marginBottom: 12 }}>
              <Donut
                size={104}
                segments={[
                  { label: "ready", value: checkCards.filter((c) => c.ok === true).length, tone: "green" },
                  { label: "blocked", value: checkCards.filter((c) => c.ok === false && c.n > 0).length, tone: "red" },
                  { label: "unknown", value: checkCards.filter((c) => c.ok === undefined || (c.ok === false && c.n === 0)).length, tone: "slate" },
                ]}
                centerLabel={checkCards.length}
                centerSub="checks"
              />
              {Object.keys(d.impact ?? {}).length > 0 && (
                <div style={{ flex: 1, minWidth: 240, maxWidth: 420 }}>
                  <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>
                    ENGINE IMPACT COUNTS
                  </div>
                  <HBars
                    rows={Object.entries(d.impact ?? {}).map(([label, value]) => ({
                      key: label,
                      label: label.replace(/_/g, " "),
                      value: Number(value) || 0,
                      tone: "violet",
                    }))}
                    unit=""
                    emptyTitle="no impact counts"
                    emptyNote="the engine reports no counts for this scenario"
                  />
                </div>
              )}
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12 }}>
              {checkCards.map((cc) => {
                const cls = cardCls(cc.ok, cc.n); const tone = cls === "ok" ? "green" as const : cls === "blocked" ? "red" as const : "slate" as const;
                const accent = tone === "green" ? "var(--green)" : tone === "red" ? "var(--red)" : "var(--slate)";
                return (
                  <div key={cc.key} style={{ padding: 12, background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", borderTop: `2px solid ${accent}` }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}><span style={{ fontSize: 11, fontWeight: 700 }}>{cc.name}</span><Badge tone={tone}>{cls === "ok" ? "ready" : cls === "blocked" ? "blocked" : "unknown"}</Badge></div>
                    <div style={{ fontSize: 22, fontWeight: 800, margin: "8px 0 2px", fontFamily: "var(--mono)", color: accent }}>{cc.n}</div>
                    <div style={{ fontSize: 11, color: "var(--dim)" }}>{cc.sub}</div>
                    <div style={{ marginTop: 8 }}><Bar value={cc.n ? Math.min(1, cc.n / 10) : cls === "ok" ? 1 : 0} tone={tone} /></div>
                    {cc.items.length > 0 && <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 8 }}>{cc.items.slice(0, 6).map((x) => <span key={x} style={{ fontSize: 10, background: "var(--panel)", border: "1px solid var(--line)", borderRadius: 999, padding: "2px 8px", fontFamily: "var(--mono)" }}>{x}</span>)}</div>}
                  </div>
                );
              })}
            </div>
          </Panel>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 14, marginTop: 14 }}>
            <Panel title="Protocol compatibility" sub="projected post-migration">
              {Object.keys(c.impact?.protocol_compatibility ?? {}).length ? (
                <div style={{ display: "grid", gap: 6 }}>{Object.entries(c.impact?.protocol_compatibility ?? {}).map(([p, st]) => <div key={p} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "7px 10px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}><span style={{ fontSize: 12, fontWeight: 700 }}>{p}</span><Badge tone={st === "SUPPORTED" ? "green" : "amber"}>{st}</Badge></div>)}</div>
              ) : <div style={{ fontSize: 12, color: "var(--faint)", background: "var(--panel-2)", border: "1px dashed var(--line)", borderRadius: "var(--r)", padding: 12, textAlign: "center" }}>No protocol compatibility data for this scenario.</div>}
            </Panel>
            <Panel title="Migration plan" sub="Ordered, deterministic steps — executed separately and under change control">
              {steps.length ? (
                <div style={{ display: "grid", gap: 6 }}>
                  <StepRail
                    label="ordered migration plan"
                    steps={steps.map((p, i) => ({
                      n: i + 1,
                      title: p.replace(/^\d+\.\s*/, ""),
                      state: "pending" as const,
                      note: "planned — not executed",
                    }))}
                  />
                </div>
              ) : <div style={{ fontSize: 12, color: "var(--faint)", background: "var(--panel-2)", border: "1px dashed var(--line)", borderRadius: "var(--r)", padding: 12, textAlign: "center" }}>No plan steps returned.</div>}
            </Panel>
          </div>
        </>
      )}

      {!d && !busy && (
        <Panel title="No simulation yet" sub="Results are computed live against the discovered estate" style={{ marginTop: 14 }}>
          <p style={{ fontSize: 12, color: "var(--dim)", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: 12, margin: 0 }}>Run a scenario to query the deterministic feasibility engine. With an empty estate the engine honestly reports zero verified dependencies/support and an UNKNOWN verdict — nothing is estimated or fabricated, and no change is ever applied from this page.</p>
        </Panel>
      )}
    </div>
  );
}
