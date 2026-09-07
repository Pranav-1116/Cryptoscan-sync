import React, { useState } from "react";
import { Panel, Badge, Table, PageHead, Code } from "../components/ui.jsx";
import { apiWhatIf, LiveBadge, ApiResult } from "../lib/api.js";

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
  migration_plan?: string[];
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

  return (
    <>
      <PageHead
        crumb="plan / what-if simulator"
        title="What-if simulator"
        sub="Current state → create scenario → change crypto → simulate → impact → risk — from the live feasibility engine"
        right={
          <div className="row">
            {live && <LiveBadge source={live.source} label={live.source === "live" ? "LIVE ENGINE RESULT" : "BACKEND OFFLINE"} />}
          </div>
        }
      />
      <Panel title="Scenario" sub="choose a cryptographic transition — the engine checks the whole estate">
        <div className="row">
          {SCENARIOS.map((sc, i) => (
            <button key={sc.label} className="btn sm"
              style={i === sel ? { borderColor: "var(--cyan)", color: "#cfe4ff", background: "rgba(77,159,255,0.10)" } : {}}
              onClick={() => { setSel(i); setLive(null); }}>
              {sc.label}
            </button>
          ))}
        </div>
        <div className="mono dim" style={{ marginTop: 16, fontSize: 13 }}>
          migrating <span className="grad-text" style={{ fontWeight: 700 }}>{s.from}</span> → <span className="grad-text" style={{ fontWeight: 700 }}>{s.to}</span>
        </div>
        <div className="row" style={{ marginTop: 14 }}>
          <button className="btn primary" onClick={() => void simulate()} disabled={busy}>{busy ? "Running engine…" : "Simulate against live estate"}</button>
        </div>
      </Panel>

      {live?.error && <Panel title="Engine unavailable" className="mt"><p className="dim" style={{ fontSize: 13 }}>{live.error}</p></Panel>}

      {d && (
        <>
          {live?.data && (
            <Panel title="POST /api/v1/platform/whatif — engine response" sub={`${s.from} → ${s.to} across libraries, hardware, vendors, cloud and protocols`} className="mt">
              <Code>{JSON.stringify(d, null, 2)}</Code>
            </Panel>
          )}
          <div className="grid cols-3 mt">
            <Panel title="Projected quantum status" sub="feasibility engine output">
              <div className="grad-text" style={{ fontSize: 28, fontWeight: 700 }}>{c.impact?.projected_quantum_status ?? "UNKNOWN"}</div>
              <div className="dim" style={{ fontSize: 12.5, marginTop: 8 }}>
                verdict: <Badge tone={d.feasible ? "green" : "red"}>{d.feasible ? "FEASIBLE" : "NOT FEASIBLE / UNKNOWN"}</Badge>
              </div>
            </Panel>
            <Panel title="Affected libraries" sub="dependencies that reference the current algorithm">
              <div className="grad-text" style={{ fontSize: 30, fontWeight: 700 }}>{c.dependencies?.affected_libraries ?? 0}</div>
              <div className="dim" style={{ fontSize: 12.5 }}>{(c.libraries?.supporting ?? []).length} library/libraries support the target</div>
            </Panel>
            <Panel title="PQC-capable hardware" sub="devices verified to support the target algorithm">
              <div className="grad-text" style={{ fontSize: 30, fontWeight: 700 }}>{c.hardware?.pqc_capable_devices ?? 0}</div>
              <div className="dim" style={{ fontSize: 12.5 }}>{(c.cloud?.pqc_ready_services ?? 0)} cloud service(s) PQC-ready · {c.vendor?.pqc_positive ?? 0} vendor(s) roadmap-positive</div>
            </Panel>
          </div>

          <div className="grid cols-2 mt">
            <Panel title="Dependency checks" sub="every dependent inventoried before the change — no silent breakage">
              <Table
                head={["check", "result"]}
                rows={[
                  ["libraries affected", <Badge key="a" tone={(c.dependencies?.affected_libraries ?? 0) ? "amber" : "green"}>{c.dependencies?.affected_libraries ?? 0}</Badge>],
                  ["libraries supporting target", <span key="b" className="row">{(c.libraries?.supporting ?? []).map((l) => <Badge key={l} tone="green">{l}</Badge>)}{(c.libraries?.supporting ?? []).length === 0 && <span className="dim">none</span>}</span>],
                  ["hardware devices supporting", <span key="c" className="row">{(c.hardware?.devices ?? []).map((x) => <Badge key={x} tone="green">{x}</Badge>)}{(c.hardware?.devices ?? []).length === 0 && <span className="dim">none</span>}</span>],
                  ["vendors roadmap-positive", <span key="d" className="row">{(c.vendor?.vendors ?? []).map((v) => <Badge key={v} tone="green">{v}</Badge>)}{(c.vendor?.vendors ?? []).length === 0 && <span className="dim">none</span>}</span>],
                  ["cloud services PQC-ready", <span key="e" className="row">{(c.cloud?.services ?? []).map((x) => <Badge key={x} tone="green">{x}</Badge>)}{(c.cloud?.services ?? []).length === 0 && <span className="dim">none</span>}</span>],
                ]}
              />
            </Panel>
            <Panel title="Protocol compatibility" sub="projected post-migration">
              <Table
                head={["protocol", "status"]}
                rows={Object.entries(c.impact?.protocol_compatibility ?? {}).map(([p, st]) => [p, <Badge key={p} tone={st === "SUPPORTED" ? "green" : "amber"}>{st}</Badge>])}
              />
              {(d.migration_plan ?? []).length > 0 && (
                <Panel title="Migration plan" sub="ordered, deterministic steps" className="mt">
                  <ol className="dim" style={{ fontSize: 13.5, paddingLeft: 18, display: "flex", flexDirection: "column", gap: 7 }}>
                    {(d.migration_plan ?? []).map((p, i) => <li key={i}>{p}</li>)}
                  </ol>
                </Panel>
              )}
            </Panel>
          </div>
        </>
      )}
      {!d && !busy && (
        <Panel title="No simulation yet" sub="results are computed live against the discovered estate" className="mt">
          <p className="dim" style={{ fontSize: 13 }}>Run a scenario to query the deterministic feasibility engine. With an empty estate the engine honestly reports zero affected dependencies and an UNKNOWN/ NOT-FEASIBLE verdict — nothing is estimated or fabricated.</p>
        </Panel>
      )}
    </>
  );
}
