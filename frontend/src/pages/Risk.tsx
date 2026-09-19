import React, { useEffect, useState } from "react";
import { Panel, Badge, Table, PageHead, Code } from "../components/ui.jsx";
import { apiRisk, apiStatsSummary, ApiResult } from "../lib/api.js";

interface RiskResp { score?: number; level?: string; count?: number; }
interface StatsResp { open_drift?: Record<string, number>; total_findings?: number; }

export default function Risk() {
  const [live, setLive] = useState<ApiResult<RiskResp> | null>(null);
  const [stats, setStats] = useState<StatsResp | null>(null);
  const [busy, setBusy] = useState(false);

  const scoreEstate = async () => {
    setBusy(true);
    const [r, s] = await Promise.all([apiRisk(), apiStatsSummary()]);
    setLive(r as ApiResult<RiskResp>);
    if (s.ok && s.data) setStats(s.data as StatsResp);
    setBusy(false);
  };

  useEffect(() => { void scoreEstate(); /* live on mount — no static fallback */ }, []);

  const drift = stats?.open_drift ?? {};
  const level = live?.data?.level ?? "—";

  return (
    <>
      <PageHead
        crumb="post-quantum / risk"
        title="Risk"
        sub="Weighted risk model 0–100 · CRITICAL ≥ 80 · HIGH ≥ 60 · MEDIUM ≥ 40"
        right={
          <div className="row">
            <Badge tone={live?.data?.score && live.data.score >= 80 ? "red" : "green"}>
              SCORE {live?.data?.score ?? "—"} · {level}
            </Badge>
            <button className="btn sm" onClick={() => void scoreEstate()} disabled={busy}>
              {busy ? "Scoring…" : "Re-score estate (live)"}
            </button>
          </div>
        }
      />
      {live?.data && (
        <Panel title="POST /api/v1/platform/risk — live engine response" sub="eight-factor weighted score from the control plane" className="mt">
          <Code>{JSON.stringify(live.data, null, 2)}</Code>
        </Panel>
      )}
      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        {[["critical", drift.CRITICAL ?? 0, "red"], ["high", drift.HIGH ?? 0, "red"],
          ["medium", drift.MEDIUM ?? 0, "amber"], ["low", drift.INFO ?? 0, "green"]].map(([k, v, tone]) => (
          <div className="kpi" key={k as string}><span className="k">{k}</span><span className="v" style={{ color: `var(--${tone})` }}>{v}</span></div>
        ))}
      </div>

      <Panel title="Open drift / findings" sub="live counts from the evidence store">
        <Table
          head={["severity bucket", "open items", "source"]}
          rows={[
            ["CRITICAL drift", drift.CRITICAL ?? 0, "stats summary"],
            ["HIGH drift", drift.HIGH ?? 0, "stats summary"],
            ["MEDIUM drift", drift.MEDIUM ?? 0, "stats summary"],
            ["INFO drift", drift.INFO ?? 0, "stats summary"],
            ["total findings", stats?.total_findings ?? 0, "scans"],
          ].map(([k, v, src]) => [
            <span style={{ fontSize: 13 }}>{k}</span>,
            <Badge tone={(v as number) > 0 ? "red" : "green"}>{v}</Badge>,
            <span className="dim mono" style={{ fontSize: 12 }}>{src}</span>,
          ])}
        />
        {!stats && <p className="dim" style={{ fontSize: 13 }}>Run a scan to populate risk findings and their blast radius.</p>}
      </Panel>

      <Panel title="Weighted risk model" sub="the deterministic scoring weights" className="mt">
        <Table
          head={["factor", "weight"]}
          rows={[
            ["quantum vulnerability", "0.20"], ["algorithm strength", "0.20"], ["key size", "0.15"],
            ["protocol exposure", "0.10"], ["trust chain", "0.15"], ["library risk", "0.10"],
            ["hardware capability", "0.05"], ["vendor posture", "0.05"],
          ].map(([k, v]) => [k, <span className="num" key={k}>{v}</span>])}
        />
      </Panel>
    </>
  );
}
