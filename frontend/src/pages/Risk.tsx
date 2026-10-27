import React, { useEffect, useState } from "react";
import { Panel, Badge, Bar, Kpi, Table, PageHead, Code } from "../components/ui.jsx";
import {
  apiRisk,
  apiRiskSystems,
  apiStatsSummary,
  ApiResult,
  SystemRiskAssessment,
  SystemsRiskResponse,
} from "../lib/api.js";

interface RiskResp { score?: number; level?: string; count?: number; }
interface StatsResp { open_drift?: Record<string, number>; total_findings?: number; }

/* Per-system explainability (§4.6): every score decomposes into the same 8
   blueprint factors, each factor level is a pure function of persisted
   observations, and the raw signals that produced the levels travel with the
   response. Nothing here is invented — "—" means the platform has no value. */

const FACTOR_LABELS: Record<string, string> = {
  technical: "Technical (failing findings + drift)",
  crypto: "Crypto strength",
  pqc: "PQC exposure",
  exposure: "Exposure",
  business_criticality: "Business criticality",
  dependency_impact: "Dependency impact (blast radius)",
  evidence_confidence: "Evidence confidence",
  threat: "Threat (CVEs)",
};

const FACTOR_ORDER = [
  "technical", "crypto", "pqc", "exposure",
  "business_criticality", "dependency_impact", "evidence_confidence", "threat",
];

const SIGNAL_ROWS: Array<[keyof SystemRiskAssessment["signals"], string]> = [
  ["evidence_rows", "evidence rows scored (latest scan)"],
  ["fail_rows", "FAIL compliance rows"],
  ["fail_ratio", "fail ratio → technical factor"],
  ["quantum_weighted_ratio", "Shor=1.0 / Grover=0.5 weighted ratio → pqc factor"],
  ["unknown_algorithms", "algorithms not in the registry"],
  ["open_drift_events", "open drift events → technical factor"],
  ["worst_open_drift_severity", "worst open drift severity"],
  ["worst_cve_severity", "worst CVE severity → threat factor"],
  ["outgoing_dependencies", "outgoing dependencies → dependency factor"],
  ["environment", "environment → exposure factor"],
  ["criticality", "criticality → business factor"],
  ["cloud_provider", "cloud provider → exposure factor"],
];

function topDriver(a: SystemRiskAssessment): string {
  let best = "—";
  let bestPts = -1;
  for (const key of FACTOR_ORDER) {
    const f = a.factors?.[key];
    if (f && f.points > bestPts) {
      bestPts = f.points;
      best = `${FACTOR_LABELS[key] ?? key} (+${f.points.toFixed(1)})`;
    }
  }
  return bestPts > 0 ? best : "no contributing factors";
}

function SystemDetail({ a, onClose }: { a: SystemRiskAssessment; onClose: () => void }) {
  const sig = a.signals;
  return (
    <Panel
      title={`${a.system_name} — score decomposition`}
      sub={`deterministic, ${a.calculation_version} · weights: ${a.weights_source}`}
    >
      <button className="btn" onClick={onClose} style={{ position: "absolute", right: 12, top: 12 }}>close</button>
      <div className="row" style={{ gap: 12, flexWrap: "wrap", margin: "8px 0" }}>
        <Kpi k="Score" v={a.score.toFixed(1)} tone={a.score >= 80 ? "var(--red)" : a.score >= 60 ? "var(--amber)" : "var(--green)"} />
        <Kpi k="Level" v={a.level} />
        <Kpi k="Evidence rows" v={a.evidence_count} />
        <Kpi k="Open drift" v={a.open_drift_events} />
        <Kpi k="CVEs" v={a.vulnerability_count} />
      </div>
      <div className="row" style={{ gap: 12, flexWrap: "wrap", margin: "8px 0", fontSize: 13 }}>
        <span><strong>owner:</strong> {a.owner ?? "—"}</span>
        <span><strong>technical:</strong> {a.technical_owner ?? "—"}</span>
        <span><strong>security:</strong> {a.security_owner ?? "—"}</span>
        <span>
          <strong>evidence lineage:</strong>{" "}
          {a.scan_id
            ? <code style={{ fontSize: 11 }}>{a.scan_id}</code>
            : "never scanned — factors rest on system attributes only"}
        </span>
      </div>
      <Table
        head={["factor", "level (0–4)", "points", "weight"]}
        rows={FACTOR_ORDER.map((key) => {
          const f = a.factors?.[key];
          return [
            FACTOR_LABELS[key] ?? key,
            <div key={`l${key}`} style={{ minWidth: 100 }}>
              <Bar value={(f?.level ?? 0) / 4} tone={(f?.level ?? 0) >= 3 ? "warn" : ""} />
            </div>,
            <span key={`p${key}`} className="num">{(f?.points ?? 0).toFixed(1)}</span>,
            <span key={`w${key}`} className="num">{(f?.weight ?? 0).toFixed(2)}</span>,
          ];
        })}
      />
      <p className="sub" style={{ fontSize: 12, margin: "10px 0 4px" }}>
        Raw signals the levels were derived from — every factor level is a pure
        function of these persisted observations:
      </p>
      <div className="grid cols-2" style={{ gap: 4 }}>
        {SIGNAL_ROWS.map(([k, label]) => (
          <div key={k} style={{ fontSize: 12, display: "flex", justifyContent: "space-between", gap: 8 }}>
            <span className="dim">{label}</span>
            <span className="mono">{sig ? String(sig[k] ?? "—") : "—"}</span>
          </div>
        ))}
      </div>
      <p className="sub" style={{ fontSize: 12, marginTop: 10 }}>
        The score says what the persisted observations are — it is not a claim
        that every row was observed first-hand. Verify the evidence behind this
        system in the Evidence workspace. Scan: <code>{a.scan_id ?? "—"}</code>
        {a.scan_id ? "" : " (no scan yet)"}.
      </p>
    </Panel>
  );
}

export default function Risk() {
  const [live, setLive] = useState<ApiResult<RiskResp> | null>(null);
  const [stats, setStats] = useState<StatsResp | null>(null);
  const [systems, setSystems] = useState<ApiResult<SystemsRiskResponse> | null>(null);
  const [selected, setSelected] = useState<number>(-1);
  const [busy, setBusy] = useState(false);

  const scoreEstate = async () => {
    setBusy(true);
    const [r, s, sys] = await Promise.all([apiRisk(), apiStatsSummary(), apiRiskSystems()]);
    setLive(r as ApiResult<RiskResp>);
    if (s.ok && s.data) setStats(s.data as StatsResp);
    setSystems(sys as ApiResult<SystemsRiskResponse>);
    if (!sys.ok) setSelected(-1);
    setBusy(false);
  };

  useEffect(() => { void scoreEstate(); /* live on mount — no static fallback */ }, []);

  const drift = stats?.open_drift ?? {};
  const level = live?.data?.level ?? "—";
  const ranked = systems?.data?.systems ?? [];
  const selectedSys = selected >= 0 && selected < ranked.length ? ranked[selected] : null;
  const estate = systems?.data?.estate;

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
        <Panel title="Live risk assessment" sub="eight-factor weighted score from the control plane" className="mt">
          <Code>{JSON.stringify(live.data, null, 2)}</Code>
        </Panel>
      )}

      {selectedSys ? (
        <SystemDetail a={selectedSys} onClose={() => setSelected(-1)} />
      ) : (
        <Panel
          title="Per-system risk, explained"
          sub="every system scored with the same 8-factor model — click a row for the full decomposition (§4.6)"
          className="mt"
        >
          {systems && !systems.ok && (
            <p className="sub" style={{ fontSize: 13, color: "var(--red)" }}>
              Live risk engine unavailable — {String(systems.error ?? "request failed")}.
            </p>
          )}
          {ranked.length === 0 ? (
            <p className="sub">
              No systems scored yet — systems appear once registered in the CMDB;
              factor levels derive from each system's persisted observations
              (latest-scan evidence, open drift, CVEs, dependencies).
            </p>
          ) : (
            <>
              {estate && (
                <div className="row" style={{ gap: 12, margin: "8px 0 12px", flexWrap: "wrap" }}>
                  <Kpi k="Systems scored" v={systems?.data?.count ?? 0} />
                  <Kpi k="Estate mean" v={estate.score} tone={estate.score >= 60 ? "var(--amber)" : "var(--green)"} />
                  <Kpi k="Critical" v={estate.by_level.CRITICAL ?? 0} tone="var(--red)" />
                  <Kpi k="High" v={estate.by_level.HIGH ?? 0} tone="var(--amber)" />
                </div>
              )}
              <Table
                clickable
                selected={selected}
                onSelect={(i: number) => setSelected(i)}
                head={["system", "owner", "score", "level", "evidence", "scan lineage", "top driver"]}
                rows={ranked.map((a, i) => [
                  <span key={`n${i}`} style={{ fontSize: 13 }}>{a.system_name}</span>,
                  <span key={`o${i}`} className="dim" style={{ fontSize: 12 }}>{a.owner ?? "—"}</span>,
                  <span key={`s${i}`} style={{ fontWeight: 600 }}>{a.score.toFixed(1)}</span>,
                  <Badge key={`lv${i}`} tone={a.level === "CRITICAL" ? "bad" : a.level === "HIGH" ? "warn" : "ok"}>{a.level}</Badge>,
                  <span key={`e${i}`} className="num">{a.evidence_count}</span>,
                  a.scan_id
                    ? <code key={`sc${i}`} style={{ fontSize: 11 }}>{a.scan_id.slice(0, 13)}…</code>
                    : <span key={`sc${i}`} className="dim" style={{ fontSize: 11 }}>never scanned</span>,
                  <span key={`d${i}`} className="dim" style={{ fontSize: 12 }}>{topDriver(a)}</span>,
                ])}
              />
            </>
          )}
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
