import React, { useState } from "react";
import { Panel, Badge, Table, PageHead, Code } from "../components/ui.jsx";
import { risk } from "../data/initial.js";
import { apiRisk, LiveBadge, ApiResult } from "../lib/api.js";

export default function Risk() {
  const [sel, setSel] = useState(-1);
  const [live, setLive] = useState<ApiResult<Record<string, unknown>> | null>(null);
  const [busy, setBusy] = useState(false);
  const c = risk.counts;

  const scoreEstate = async () => {
    setBusy(true);
    const res = await apiRisk();
    setLive(res);
    setBusy(false);
  };

  return (
    <>
      <PageHead
        crumb="post-quantum / risk"
        title="Risk"
        sub="Weighted risk model 0–100 · CRITICAL ≥ 80 · HIGH ≥ 60 · MEDIUM ≥ 40"
        right={
          <div className="row">
            <Badge tone="red">{c.CRITICAL} CRITICAL</Badge>
            <button className="btn sm" onClick={() => void scoreEstate()} disabled={busy}>
              {busy ? "Scoring…" : "Score estate (live)"}
            </button>
            {live && <LiveBadge source={live.source} label={live.source === "live" ? "LIVE API RESULT" : "BACKEND OFFLINE"} />}
          </div>
        }
      />
      {live?.data && (
        <Panel title="POST /api/v1/platform/risk — engine response" sub="eight-factor weighted score from the control plane" className="mt">
          <Code>{JSON.stringify(live.data, null, 2)}</Code>
        </Panel>
      )}
      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        {[["critical", c.CRITICAL, "red"], ["high", c.HIGH, "red"], ["medium", c.MEDIUM, "amber"], ["low", c.LOW, "green"]].map(([k, v, tone]) => (
          <div className="kpi" key={k}><span className="k">{k}</span><span className="v" style={{ color: `var(--${tone})` }}>{v}</span></div>
        ))}
      </div>

      <div className="grid cols-2" style={{ marginBottom: 16 }}>
        <Panel title="Risk map" sub="impact × exposure">
          <div className="matrix">
            <div className="cell hh"><b className="grad-text">{risk.matrix["impact:high/exposure:high"]}</b><span>critical</span></div>
            <div className="cell hl"><b className="grad-text">{risk.matrix["impact:high/exposure:low"]}</b><span>high impact · low exposure</span></div>
            <div className="cell lh"><b className="grad-text">{risk.matrix["impact:low/exposure:high"]}</b><span>low impact · high exposure</span></div>
            <div className="cell ll"><b className="grad-text">{risk.matrix["impact:low/exposure:low"]}</b><span>low</span></div>
          </div>
        </Panel>
        <Panel title="Blast radius view" sub="select a finding to see affected assets">
          <Table
            clickable
            selected={sel}
            onSelect={setSel}
            head={["finding", "severity", "assets", "evidence"]}
            rows={risk.topFindings.map((f) => [
              <span style={{ fontSize: 13 }}>{f.title}</span>,
              <Badge>{f.severity}</Badge>,
              <span className="num">{f.assets}</span>,
              <span className="num">{f.evidence}</span>,
            ])}
          />
          {sel >= 0 && (
            <div className="tree mt" style={{ marginTop: 14 }}>
              Blast radius — {risk.topFindings[sel].title}:<br />
              {" ├── 12 applications"}<br />
              {" ├── 4 APIs"}<br />
              {" ├── 2 load balancers"}<br />
              {" ├── 3 cloud resources"}<br />
              {" └── 1 HSM"}
            </div>
          )}
        </Panel>
      </div>

      <Panel title="Weighted risk model" sub="the deterministic scoring weights">
        <Table
          head={["factor", "weight"]}
          rows={[
            ["quantum vulnerability", "0.20"], ["algorithm strength", "0.20"], ["key size", "0.15"],
            ["protocol exposure", "0.10"], ["trust chain", "0.15"], ["library risk", "0.10"],
            ["hardware capability", "0.05"], ["vendor posture", "0.05"],
          ].map(([k, v]) => [k, <span className="num">{v}</span>])}
        />
      </Panel>
    </>
  );
}
