import React, { useState } from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import { apiWhatIf, LiveBadge, ApiResult } from "../lib/api.js";

/* What-if migration simulator — SEPARATED FROM EXECUTION. This surface only
   READS the estate and runs the deterministic feasibility engine
   (POST /platform/whatif): it never applies, deploys or re-keys anything.
   Results show the five feasibility checks (dependencies, libraries,
   hardware, vendor, cloud), projected quantum status, protocol compatibility,
   an ordered migration plan, and — crucially — the engine's HONEST UNKNOWNS.
   An empty estate yields an honest NOT-FEASIBLE/UNKNOWN verdict, not a guess. */

const SCENARIOS = [
  { label: "RSA-2048 → ML-KEM-768", from: "RSA-2048", to: "ML-KEM-768" },
  { label: "ECDSA-P-256 → ML-DSA-65", from: "ECDSA-P-256", to: "ML-DSA-65" },
  { label: "X25519 → ML-KEM-768", from: "X25519", to: "ML-KEM-768" },
  { label: "DH-2048 → ML-KEM-768", from: "DH-2048", to: "ML-KEM-768" },
];

interface WhatIfResp {
  checks?: {
    dependencies?: { affected_libraries?: number; libraries?: string[] };
    libraries?: { supporting?: string[]; supported?: boolean };
    hardware?: { pqc_capable_devices?: number; devices?: string[]; supported?: boolean };
    vendor?: { pqc_positive?: number; vendors?: string[]; supported?: boolean };
    cloud?: { pqc_ready_services?: number; services?: string[]; supported?: boolean };
    impact?: { projected_quantum_status?: string; protocol_compatibility?: Record<string, string> };
  };
  feasible?: boolean;
  migration_plan?: { steps?: string[]; risk?: string };
  honest_unknowns?: string[];
  impact?: Record<string, number>;
}

export default function WhatIf() {
  const [sel, setSel] = useState(0);
  const [live, setLive] = useState<ApiResult<WhatIfResp> | null>(null);
  const [busy, setBusy] = useState(false);
  const s = SCENARIOS[sel];

  const simulate = async () => {
    setBusy(true);
    setLive(await apiWhatIf(s.from, s.to, ["TLS", "SSH", "IPsec"]) as ApiResult<WhatIfResp>);
    setBusy(false);
  };

  const d = live?.data;
  const c = d?.checks ?? {};
  const steps = d?.migration_plan?.steps ?? [];
  const unknowns = d?.honest_unknowns ?? [];
  const projected = c.impact?.projected_quantum_status ?? "UNKNOWN";

  const checkCards: Array<{ key: string; name: string; ok?: boolean; n: number; sub: string; items: string[] }> = [
    { key: "dependencies", name: "affected libraries", ok: (c.dependencies?.affected_libraries ?? 0) === 0,
      n: c.dependencies?.affected_libraries ?? 0, sub: "dependencies referencing the current algorithm", items: c.dependencies?.libraries ?? [] },
    { key: "libraries", name: "libraries support target", ok: c.libraries?.supported,
      n: (c.libraries?.supporting ?? []).length, sub: c.libraries?.supported ? "target supported in use" : "no library verified for target", items: c.libraries?.supporting ?? [] },
    { key: "hardware", name: "PQC-capable hardware", ok: c.hardware?.supported,
      n: c.hardware?.pqc_capable_devices ?? 0, sub: c.hardware?.supported ? "hardware supports target" : "no HSM/TPM/accelerator verified", items: c.hardware?.devices ?? [] },
    { key: "vendor", name: "vendor roadmap", ok: c.vendor?.supported,
      n: c.vendor?.pqc_positive ?? 0, sub: c.vendor?.supported ? "vendors roadmap-positive" : "no vendor confirmation", items: c.vendor?.vendors ?? [] },
    { key: "cloud", name: "cloud PQC-ready", ok: c.cloud?.supported,
      n: c.cloud?.pqc_ready_services ?? 0, sub: c.cloud?.supported ? "services PQC-ready" : "no cloud service verified", items: c.cloud?.services ?? [] },
  ];

  const cardCls = (ok: boolean | undefined, n: number) =>
    ok ? "ok" : n === 0 && ok === undefined ? "unknown" : ok === false ? "blocked" : "unknown";

  return (
    <>
      <PageHead
        crumb="plan / what-if simulator"
        title="What-if migration simulator"
        sub="Model a crypto transition against the live estate — analysis only, nothing is changed or deployed"
        right={live && <LiveBadge source={live.source} label={live.source === "live" ? "live engine" : "offline"} />}
      />

      {/* simulation-only banner — this surface never executes */}
      <div className="sim-banner">
        <span className="sim-ico">▣</span>
        <div>
          <div className="sim-t">SIMULATION ONLY — NO EXECUTION</div>
          <div className="sim-d">
            This runs the deterministic feasibility engine in read-only mode. It never re-keys, deploys,
            writes configuration, or touches a live system. Execution is a separate, governed workflow.
          </div>
        </div>
      </div>

      <Panel title="Scenario" sub="choose a cryptographic transition — the engine checks the whole estate">
        <div className="row" style={{ flexWrap: "wrap" }}>
          {SCENARIOS.map((sc, i) => (
            <button key={sc.label} className="btn sm"
              style={i === sel ? { borderColor: "var(--cyan)", color: "#aef3ff", background: "rgba(0,212,255,0.10)" } : {}}
              onClick={() => { setSel(i); setLive(null); }}>
              {sc.label}
            </button>
          ))}
        </div>
        <div className="mono" style={{ marginTop: 16, fontSize: 13, color: "var(--dim)" }}>
          migrating <span className="grad-text" style={{ fontWeight: 700 }}>{s.from}</span> → <span className="grad-text" style={{ fontWeight: 700 }}>{s.to}</span>
        </div>
        <div className="row" style={{ marginTop: 14 }}>
          <button className="btn primary" onClick={() => void simulate()} disabled={busy}>
            {busy ? "Running engine…" : "Simulate against live estate"}
          </button>
        </div>
      </Panel>

      {live?.error && <Panel title="Engine unavailable" className="mt"><p className="dim" style={{ fontSize: 13 }}>{live.error}</p></Panel>}

      {d && (
        <>
          {/* verdict */}
          <Panel className="mt" title="Feasibility verdict" sub={`${s.from} → ${s.to} · deterministic, read-only`}>
            <div className="feas-verdict">
              <span className="feas-big" style={{ color: d.feasible ? "var(--green)" : projected === "UNKNOWN" ? "var(--amber)" : "var(--red)" }}>
                {d.feasible ? "FEASIBLE" : projected === "UNKNOWN" ? "UNKNOWN" : "BLOCKED"}
              </span>
              <div>
                <div style={{ fontSize: 12.5, color: "var(--dim)", marginBottom: 6 }}>projected post-migration quantum status</div>
                <Badge tone={projected === "SAFE" || projected === "PQC_SAFE" ? "green" : projected === "UNKNOWN" ? "amber" : "red"}>
                  {projected}
                </Badge>
                {d.migration_plan?.risk && (
                  <Badge tone={d.migration_plan.risk === "HIGH" ? "red" : d.migration_plan.risk === "MEDIUM" ? "amber" : "green"}>
                    migration risk {d.migration_plan.risk}
                  </Badge>
                )}
              </div>
            </div>
            {unknowns.length > 0 && (
              <div className="mono" style={{ marginTop: 14, fontSize: 12, color: "var(--amber)" }}>
                ⚠ honest unknowns (engine could not verify — never assumed true): {unknowns.join(", ")}
              </div>
            )}
          </Panel>

          {/* five feasibility checks */}
          <Panel className="mt" title="Feasibility checks" sub="every dependency, library, device, vendor and service is inventoried before a change">
            <div className="check-grid">
              {checkCards.map((cc) => {
                const cls = cardCls(cc.ok, cc.n);
                const tone = cls === "ok" ? "green" : cls === "blocked" ? "red" : "slate";
                return (
                  <div key={cc.key} className={`check-card ${cls}`}>
                    <div className="chk-head">
                      <span className="chk-name">{cc.name}</span>
                      <Badge tone={tone}>{cls === "ok" ? "ready" : cls === "blocked" ? "blocked" : "unknown"}</Badge>
                    </div>
                    <div className="chk-n" style={{ color: cls === "ok" ? "var(--green)" : cls === "blocked" ? "var(--red)" : "var(--slate)" }}>{cc.n}</div>
                    <div className="chk-sub">{cc.sub}</div>
                    {cc.items.length > 0 && (
                      <div className="chk-items">{cc.items.slice(0, 6).map((x) => <span key={x} className="cap-chip">{x}</span>)}</div>
                    )}
                  </div>
                );
              })}
            </div>
          </Panel>

          <div className="grid cols-2 mt">
            <Panel title="Protocol compatibility" sub="projected post-migration">
              <Table
                head={["protocol", "status"]}
                rows={Object.entries(c.impact?.protocol_compatibility ?? {}).map(([p, st]) => [
                  p, <Badge key={p} tone={st === "SUPPORTED" ? "green" : "amber"}>{st}</Badge>,
                ])}
              />
              {!Object.keys(c.impact?.protocol_compatibility ?? {}).length && (
                <div className="dim" style={{ fontSize: 13 }}>No protocol compatibility data for this scenario.</div>
              )}
            </Panel>
            <Panel title="Migration plan" sub="ordered, deterministic steps — executed separately and under change control">
              {steps.length ? (
                <ol className="plan-steps">
                  {steps.map((p, i) => <li key={i}>{p.replace(/^\d+\.\s*/, "")}</li>)}
                </ol>
              ) : (
                <div className="dim" style={{ fontSize: 13 }}>No plan steps returned.</div>
              )}
            </Panel>
          </div>
        </>
      )}

      {!d && !busy && (
        <Panel title="No simulation yet" sub="results are computed live against the discovered estate" className="mt">
          <p className="dim" style={{ fontSize: 13 }}>
            Run a scenario to query the deterministic feasibility engine. With an empty estate the engine honestly
            reports zero verified dependencies/support and an UNKNOWN verdict — nothing is estimated or fabricated,
            and no change is ever applied from this page.
          </p>
        </Panel>
      )}
    </>
  );
}
