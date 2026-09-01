import React, { useState } from "react";
import { Panel, Badge, Table, PageHead, Code } from "../components/ui.jsx";
import { whatif, cost } from "../data/demo.js";
import { apiWhatIf, LiveBadge, ApiResult } from "../lib/api.js";

const SCENARIOS = [
  { label: "RSA-2048 → ML-KEM-768", from: "RSA-2048", to: "ML-KEM-768" },
  { label: "ECDSA-P-256 → ML-DSA-65", from: "ECDSA-P-256", to: "ML-DSA-65" },
  { label: "X25519 → ML-KEM-768", from: "X25519", to: "ML-KEM-768" },
  { label: "DH-2048 → ML-KEM-768", from: "DH-2048", to: "ML-KEM-768" },
];

export default function WhatIf() {
  const [sel, setSel] = useState(0);
  const [simulated, setSimulated] = useState(false);
  const [live, setLive] = useState<ApiResult<Record<string, unknown>> | null>(null);
  const [busy, setBusy] = useState(false);
  const s = SCENARIOS[sel];

  const simulate = async (liveCall: boolean) => {
    setSimulated(true);
    if (liveCall) {
      setBusy(true);
      const res = await apiWhatIf(s.from, s.to, ["TLS", "SSH", "IPsec"]);
      setLive(res);
      setBusy(false);
    } else {
      setLive(null);
    }
  };

  return (
    <>
      <PageHead
        crumb="plan / what-if simulator"
        title="What-if simulator"
        sub="Current state → create scenario → change crypto → simulate → impact → cost → risk → migration plan"
        right={
          <div className="row">
            <Badge tone="green"><span className="dot" /> CONNECTED TO FEASIBILITY ENGINE</Badge>
            {live && <LiveBadge source={live.source} label={live.source === "live" ? "LIVE API RESULT" : "BACKEND OFFLINE — DEMO"} />}
          </div>
        }
      />
      {live?.data && (
        <Panel title="POST /api/v1/platform/whatif — engine response" sub={`${s.from} → ${s.to} across libraries, hardware, vendors, cloud and protocols`} className="mt">
          <Code>{JSON.stringify(live.data, null, 2)}</Code>
        </Panel>
      )}
      <Panel title="Scenario" sub="choose a cryptographic transition — the engine checks the whole estate">
        <div className="row">
          {SCENARIOS.map((sc, i) => (
            <button key={sc.label} className={`btn sm ${i === sel ? "" : ""}`}
              style={i === sel ? { borderColor: "var(--cyan)", color: "var(--cyan)", boxShadow: "0 0 18px rgba(34,211,238,.35)" } : {}}
              onClick={() => { setSel(i); setSimulated(false); setLive(null); }}>
              {sc.label}
            </button>
          ))}
        </div>
        <div className="mono dim" style={{ marginTop: 16, fontSize: 13 }}>
          migrating <span className="grad-text" style={{ fontWeight: 700 }}>{s.from}</span> → <span className="grad-text" style={{ fontWeight: 700 }}>{s.to}</span>
        </div>
        <div className="row" style={{ marginTop: 14 }}>
          <button className="btn primary" onClick={() => simulate(false)} disabled={busy}>▶ Simulate (demo)</button>
          <button className="btn" onClick={() => void simulate(true)} disabled={busy}>{busy ? "Running engine…" : "Simulate (live engine)"}</button>
        </div>
      </Panel>

      {simulated && (
        <>
          <div className="grid cols-5 mt">
            {[
              ["applications", whatif.impact.applications], ["apis", whatif.impact.apis],
              ["certificates", whatif.impact.certificates], ["vendors", whatif.impact.vendors],
              ["hardware", whatif.impact.hardware],
            ].map(([k, v]) => (
              <div className="kpi" key={k}><span className="k">{k}</span><span className="v">{v}</span></div>
            ))}
          </div>

          <div className="grid cols-3 mt">
            <Panel title="Compatibility" sub="feasibility engine output">
              <div className="grad-text" style={{ fontSize: 34, fontWeight: 700 }}>{whatif.compatibility}%</div>
              <div className="dim" style={{ fontSize: 12.5 }}>projected quantum status: <Badge tone="green">{whatif.checks.impact.projectedQuantumStatus}</Badge></div>
            </Panel>
            <Panel title="Estimated migration complexity" sub="deterministic estimate">
              <div style={{ fontSize: 26, fontWeight: 700 }} className="grad-text">{whatif.complexity}</div>
              <div className="dim" style={{ fontSize: 12.5 }}>6 libraries · 2 HSMs · 3 cloud KMS verified</div>
            </Panel>
            <Panel title="Cloud support" sub="KMS / managed services">
              {whatif.checks.cloud.services.map((c) => <Badge key={c} tone="green">{c}</Badge>)}
              <div className="dim" style={{ marginTop: 10, fontSize: 12.5 }}>{whatif.checks.cloud.pqcReadyServices} services PQC-ready</div>
            </Panel>
          </div>

          <div className="grid cols-4 mt">
            <Panel title="Cost estimate" sub="deterministic effort model">
              <div className="grad-text" style={{ fontSize: 30, fontWeight: 700 }}>${(cost.totalCostUsd / 1000).toFixed(0)}k</div>
              <div className="dim" style={{ fontSize: 12.5 }}>estimated total · {cost.effortPersonWeeks} person-weeks</div>
            </Panel>
            <Panel title="Duration" sub="program timeline">
              <div className="grad-text" style={{ fontSize: 30, fontWeight: 700 }}>{cost.durationWeeks} wks</div>
              <div className="dim" style={{ fontSize: 12.5 }}>{cost.teams.length} teams involved</div>
            </Panel>
            <Panel title="Risk reduction" sub="projected exposure drop">
              <div className="grad-text" style={{ fontSize: 30, fontWeight: 700 }}>-{cost.riskReductionPct}%</div>
              <div className="dim" style={{ fontSize: 12.5 }}>quantum exposure after migration</div>
            </Panel>
            <Panel title="Teams" sub="owners of the migration">
              {cost.teams.map((t) => <Badge key={t} tone="violet">{t}</Badge>)}
            </Panel>
          </div>

          <div className="grid cols-2 mt">
            <Panel title="Dependency checks" sub="every dependent inventoried before the change — no silent breakage">
              <Table
                head={["check", "result"]}
                rows={[
                  ["libraries affected", <Badge tone="amber">{whatif.checks.dependencies.affectedLibraries}</Badge>],
                  ["libraries supporting", <span className="row">{whatif.checks.libraries.supporting.map((l) => <Badge key={l} tone="green">{l}</Badge>)}</span>],
                  ["hardware devices", <span className="row">{whatif.checks.hardware.devices.map((d) => <Badge key={d} tone="green">{d}</Badge>)}</span>],
                  ["vendors roadmap-positive", <span className="row">{whatif.checks.vendor.vendors.map((v) => <Badge key={v} tone="green">{v}</Badge>)}</span>],
                ]}
              />
            </Panel>
            <Panel title="Protocol compatibility" sub="projected post-migration">
              <Table
                head={["protocol", "status"]}
                rows={Object.entries(whatif.checks.impact.protocolCompatibility).map(([p, st]) => [p, <Badge tone="green">{st}</Badge>])}
              />
              <div className="tree mt" style={{ marginTop: 14 }}>
                Verdict: <Badge tone={whatif.feasible ? "green" : "red"}>{whatif.feasible ? "FEASIBLE" : "NOT FEASIBLE"}</Badge>
              </div>
            </Panel>
          </div>

          <Panel title="Migration plan" sub="ordered, deterministic steps" className="mt">
            <ol className="dim" style={{ fontSize: 13.5, paddingLeft: 18, display: "flex", flexDirection: "column", gap: 7 }}>
              {whatif.plan.map((p) => <li key={p}>{p}</li>)}
            </ol>
            <a href="#/migration" className="btn sm">open migration planner →</a>
          </Panel>
        </>
      )}
    </>
  );
}
