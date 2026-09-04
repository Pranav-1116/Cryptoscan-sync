import React, { useState } from "react";
import { Panel, Badge, Bar, Table, PageHead, Code } from "../components/ui.jsx";
import { scanners, globalState, agents } from "../data/initial.js";
import { apiDiscover, LiveBadge, ApiResult } from "../lib/api.js";

export default function Scanners() {
  const [states, setStates] = useState(scanners.map((s) => s.status));
  const [live, setLive] = useState<ApiResult<Record<string, unknown>> | null>(null);
  const [busy, setBusy] = useState(false);
  const toggle = (i: number) => {
    setStates((prev) => prev.map((st, j) => {
      if (j !== i) return st;
      return st === "RUNNING" ? "PAUSED" : st === "PAUSED" ? "RUNNING" : "RUNNING";
    }));
  };

  const runDiscovery = async () => {
    setBusy(true);
    const res = await apiDiscover({ network: {}, cloud: {}, vendor: {}, hardware: {}, crypto: {} });
    setLive(res);
    setBusy(false);
  };

  return (
    <>
      <PageHead
        crumb="operate / scanners"
        title="Scanner control center"
        sub="Start · pause · resume · stop · schedule · scope · policy · depth"
        right={
          <div className="row">
            <Badge tone="green"><span className="dot" /> {globalState.agentsHealthy}/{globalState.agentsTotal} AGENTS HEALTHY</Badge>
            <button className="btn sm" onClick={() => void runDiscovery()} disabled={busy}>
              {busy ? "Discovering…" : "Run discovery (live)"}
            </button>
            {live && <LiveBadge source={live.source} label={live.source === "live" ? "LIVE API RESULT" : "BACKEND OFFLINE"} />}
          </div>
        }
      />
      {live?.data && (
        <Panel title="POST /api/v1/platform/discover — engine response" sub="unified discovery across all five domains" className="mt">
          <Code>{JSON.stringify(live.data, null, 2)}</Code>
        </Panel>
      )}
      <div className="grid cols-3" style={{ marginBottom: 16 }}>
        {scanners.map((s, i) => (
          <Panel key={s.name} title={s.name} sub={`last run ${s.lastRun} · ${s.findings.toLocaleString()} findings`}>
            <div className="spread" style={{ marginBottom: 10 }}>
              <Badge tone={states[i] === "RUNNING" ? "green" : "amber"}>{states[i]}</Badge>
              <span className="mono">{s.health}% health</span>
            </div>
            <Bar value={s.health / 100} tone="green" />
            <div className="row mt" style={{ marginTop: 12 }}>
              <button className="btn sm" onClick={() => toggle(i)}>{states[i] === "RUNNING" ? "Pause" : "Resume"}</button>
              <button className="btn sm">Schedule</button>
              <button className="btn sm">Scope</button>
            </div>
          </Panel>
        ))}
      </div>
      <div className="grid cols-2">
        <Panel title="Scanner health" sub="network · cloud · vendor · hardware · crypto">
          <Table
            head={["scanner", "health", "status"]}
            rows={scanners.map((s, i) => [
              s.name,
              <div style={{ minWidth: 140 }}>
                <span className="mono" style={{ fontSize: 11.5 }}>{s.health}%</span>
                <Bar value={s.health / 100} tone="green" />
              </div>,
              <Badge tone={states[i] === "RUNNING" ? "green" : "amber"}>{states[i]}</Badge>,
            ])}
          />
        </Panel>
        <Panel title="Agents" sub={`${globalState.agentsHealthy} healthy · ${globalState.agentsTotal - globalState.agentsHealthy} degraded`}>
          <Table
            head={["agent", "scanner", "host", "version", "status", "last seen"]}
            rows={agents.map((a) => [
              <span className="mono">{a.id}</span>,
              a.scanner,
              <span className="mono">{a.host}</span>,
              <span className="num">{a.version}</span>,
              <Badge tone={a.status === "HEALTHY" ? "green" : "red"}>{a.status}</Badge>,
              <span className="mono">{a.lastSeen}</span>,
            ])}
          />
        </Panel>
        <Panel title="Scan policy" sub="safe by default — read-only, scoped, scheduled">
          <div className="mono" style={{ fontSize: 12.5, display: "flex", flexDirection: "column", gap: 8 }}>
            <div><span className="faint">policy:</span> SAFE · READ_ONLY</div>
            <div><span className="faint">scope:</span> not configured — add targets in Onboarding</div>
            <div><span className="faint">excluded:</span> none configured</div>
            <div><span className="faint">schedule:</span> set during onboarding · targeted rescans on drift</div>
            <div><span className="faint">depth:</span> full (config · binaries · firmware)</div>
            <div><Badge tone="green">CREDENTIALS IN VAULT · NEVER STORED IN STATE</Badge></div>
          </div>
        </Panel>
      </div>
    </>
  );
}
