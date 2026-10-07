import React, { useMemo, useState } from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import { LiveBadge, ApiResult } from "../lib/api.js";
import {
  apiDigitalTwinOverview,
  apiDigitalTwinFidelity,
  apiDigitalTwinScenarios,
  apiDigitalTwinSimulate,
  apiDigitalTwinTimeline,
  TwinScenarioDescriptor,
} from "../lib/api.js";
import { ICON_LG, ICON_MD, IconTarget, IconWarn } from "../components/icons";
import { useApi } from "../lib/apiUi.jsx";

/* Cryptographic Digital Twin — the replica surface. Three panels:
   (1) the twin overview: what the replica holds and how it classifies it;
   (2) twin fidelity: measured staleness/coverage against the real estate,
       with the engine's honest unknowns — never a fabricated "in sync";
   (3) the scenario launcher: all ten deterministic, read-only scenario
       types from the engine (GET /digital-twin/scenarios — no hardcoded
       templates), each runnable against the live replica;
   (4) per-asset journal timeline (time-travel) from crypto_live_events.
   This surface only READS: a scenario is a projection, never an action. */

interface TwinOverview {
  schema?: string;
  twin_assets?: number;
  systems?: number;
  certificates?: number;
  evidence_records?: number;
  dependency_edges?: number;
  network_endpoints?: number;
  quantum_mix?: Record<string, number>;
  scenarios_available?: string[];
  fidelity?: TwinFidelity;
}

interface TwinFidelity {
  schema?: string;
  twin?: { assets?: number; systems_known?: number; systems_with_twin_state?: number; journal_events?: number; cbom_versions?: Record<string, number> };
  staleness?: { assets_fresh?: number; assets_stale?: number; staleness_pct?: number | null; age_seconds_p50?: number | null; age_seconds_max?: number | null };
  coverage?: { systems_covered_pct?: number | null };
  honest_unknowns?: string[];
}

interface SimulateResp {
  scenario?: string;
  deterministic?: boolean;
  mutates_nothing?: boolean;
  verdict?: string;
  affected?: Record<string, unknown>;
  impact?: Record<string, unknown>;
  honest_unknowns?: string[];
  inputs?: Record<string, unknown>;
}

interface TimelineResp {
  asset_id?: string;
  current_cbom_version?: number | null;
  risk?: { score?: number | null; level?: string | null } | null;
  events?: Array<{ event_type?: string; source?: string; observed_at?: string | null; cbom_version?: number; risk_score?: number | null }>;
  truncated_to?: number;
}

/* Sensible defaults per input key, so launching a scenario is one click —
   the engine validates everything and answers 400 (surfaced, not hidden). */
const INPUT_DEFAULTS: Record<string, string> = {
  from_algo: "RSA",
  to_algo: "ML-KEM-768",
  horizon_days: "90",
  algorithm: "RSA",
  vendor: "thales",
  protocol: "TLS",
  min_version: "1.2",
  min_key_bits: "3072",
  seed_asset: "",
  max_depth: "5",
  system_id: "",
  actions: "move_to_kms",
};

export default function DigitalTwin() {
  const overview = useApi<Record<string, unknown>>(apiDigitalTwinOverview);
  const scenarios = useApi<{ scenario_count: number; scenarios: TwinScenarioDescriptor[] }>(apiDigitalTwinScenarios);

  const [selected, setSelected] = useState<string>("");
  const [params, setParams] = useState<Record<string, string>>({});
  const [result, setResult] = useState<ApiResult<SimulateResp> | null>(null);
  const [busy, setBusy] = useState(false);

  const [timelineAsset, setTimelineAsset] = useState("");
  const [timeline, setTimeline] = useState<ApiResult<TimelineResp> | null>(null);

  const ov = overview.data as TwinOverview | null;
  const fid = (overview.data as TwinOverview | null)?.fidelity ?? ({} as TwinFidelity);
  const scen = scenarios.data?.scenarios ?? [];
  const active = scen.find((s) => s.id === selected);

  const choose = (id: string) => {
    setSelected(id);
    setResult(null);
    const inputs = scen.find((s) => s.id === id)?.inputs ?? {};
    const next: Record<string, string> = {};
    for (const k of Object.keys(inputs)) next[k] = INPUT_DEFAULTS[k] ?? "";
    setParams(next);
  };

  const simulate = async () => {
    if (!selected) return;
    setBusy(true);
    const payload: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(params)) {
      if (v === "") continue;
      if (k === "actions") payload[k] = v.split(",").map((x) => x.trim()).filter(Boolean);
      else if (/^\d+(\.\d+)?$/.test(v)) payload[k] = Number(v);
      else payload[k] = v;
    }
    setResult(await apiDigitalTwinSimulate(selected, payload) as ApiResult<SimulateResp>);
    setBusy(false);
  };

  const loadTimeline = async () => {
    if (!timelineAsset.trim()) return;
    setTimeline(await apiDigitalTwinTimeline(timelineAsset.trim()) as ApiResult<TimelineResp>);
  };

  const res = result?.data;
  const unknowns = res?.honest_unknowns ?? [];
  const fidelityUnknowns = fid.honest_unknowns ?? [];
  const quantum = ov?.quantum_mix ?? {};
  const timelineEvents = timeline?.data?.events ?? [];

  const overviewCards = useMemo(() => [
    { k: "twin assets", v: ov?.twin_assets ?? 0, sub: "live crypto replicas (crypto_live_states)" },
    { k: "systems", v: ov?.systems ?? 0, sub: "registered estate systems" },
    { k: "certificates", v: ov?.certificates ?? 0, sub: "inventory certificates" },
    { k: "evidence records", v: ov?.evidence_records ?? 0, sub: "source-scan findings feeding the twin" },
    { k: "dependency edges", v: ov?.dependency_edges ?? 0, sub: "system dependency graph" },
    { k: "network endpoints", v: ov?.network_endpoints ?? 0, sub: "registered scan targets" },
  ], [ov]);

  return (
    <>
      <PageHead
        crumb="plan / digital twin"
        title="Cryptographic Digital Twin"
        sub="The live replica of the crypto estate — what it holds, how faithfully it tracks reality, and what happens under stress"
        right={overview.data && <LiveBadge source={overview.source} label={overview.source === "live" ? "live replica" : "offline"} />}
      />

      {/* read-only banner — scenarios project, they never act */}
      <div className="sim-banner">
        <span className="sim-ico"><IconTarget size={ICON_LG} /></span>
        <div>
          <div className="sim-t">REPLICA VIEW — SCENARIOS PROJECT, NEVER ACT</div>
          <div className="sim-d">
            Every scenario runs deterministically over a read-only snapshot of the twin. Nothing is re-keyed,
            deployed or written. Gaps in the replica are reported as honest unknowns, never estimated away.
          </div>
        </div>
      </div>

      {overview.error && <Panel title="Twin unavailable" className="mt"><p className="dim" style={{ fontSize: 13 }}>{overview.error}</p></Panel>}

      {/* ── overview ─────────────────────────────────────────────── */}
      <Panel className="mt" title="Twin overview" sub="what the replica currently holds">
        {ov?.schema && (
          <div style={{ marginBottom: 10 }}>
            <Badge tone="slate">{ov.schema}</Badge>
          </div>
        )}
        <div className="check-grid">
          {overviewCards.map((c) => (
            <div key={c.k} className="check-card ok">
              <div className="chk-head"><span className="chk-name">{c.k}</span></div>
              <div className="chk-n" style={{ color: "var(--cyan)" }}>{c.v}</div>
              <div className="chk-sub">{c.sub}</div>
            </div>
          ))}
        </div>
        <div className="row" style={{ marginTop: 14, flexWrap: "wrap", gap: 8 }}>
          {Object.entries(quantum).map(([k, n]) => (
            <Badge key={k} tone={k === "vulnerable" ? "red" : k === "ready" ? "green" : "slate"}>
              {k}: {n}
            </Badge>
          ))}
        </div>
      </Panel>

      {/* ── fidelity ─────────────────────────────────────────────── */}
      <div className="grid cols-2 mt">
        <Panel title="Twin fidelity" sub="measured against the real estate — staleness, coverage, journal">
          <Table
            head={["measure", "value"]}
            rows={[
              ["assets fresh", String(fid.staleness?.assets_fresh ?? 0)],
              ["assets stale", String(fid.staleness?.assets_stale ?? 0)],
              ["staleness", fid.staleness?.staleness_pct == null ? "—" : `${fid.staleness.staleness_pct}%`],
              ["journal events", String(fid.twin?.journal_events ?? 0)],
              ["max CBOM version", String(fid.twin?.cbom_versions?.max ?? "—")],
              ["systems with twin state", `${fid.twin?.systems_with_twin_state ?? 0} / ${fid.twin?.systems_known ?? 0}`],
              ["coverage", fid.coverage?.systems_covered_pct == null ? "unknown" : `${fid.coverage.systems_covered_pct}%`],
            ]}
          />
          {fidelityUnknowns.length > 0 && (
            <div className="mono" style={{ marginTop: 12, fontSize: 12, color: "var(--amber)" }}>
              <IconWarn className="ico" size={ICON_MD} /> honest unknowns: {fidelityUnknowns.join(" · ")}
            </div>
          )}
        </Panel>

        <Panel title="Asset journal (time-travel)" sub="the immutable crypto_live_events history for one asset">
          <div className="row">
            <input
              className="inp"
              style={{ flex: 1 }}
              placeholder="asset id, e.g. hsm-core-01"
              value={timelineAsset}
              onChange={(e) => setTimelineAsset(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") void loadTimeline(); }}
            />
            <button className="btn primary" onClick={() => void loadTimeline()}>Load journal</button>
          </div>
          {timeline?.error && <p className="dim" style={{ fontSize: 13, marginTop: 10 }}>{timeline.error}</p>}
          {timeline?.data && (
            <>
              <div className="row" style={{ marginTop: 12, gap: 8 }}>
                <Badge tone="slate">CBOM v{timeline.data.current_cbom_version ?? "—"}</Badge>
                {timeline.data.risk?.level && (
                  <Badge tone={timeline.data.risk.level === "HIGH" || timeline.data.risk.level === "CRITICAL" ? "red" : "green"}>
                    risk {timeline.data.risk.level}
                  </Badge>
                )}
                <Badge tone="slate">{timelineEvents.length} events</Badge>
              </div>
              <div style={{ marginTop: 10 }}>
                <Table
                  head={["observed", "event", "source", "CBOM"]}
                  rows={timelineEvents.slice(0, 25).map((e) => [
                    e.observed_at ? new Date(e.observed_at).toLocaleString() : "—",
                    e.event_type ?? "—",
                    e.source ?? "—",
                    `v${e.cbom_version ?? "—"}`,
                  ])}
                />
              </div>
            </>
          )}
          {!timeline && (
            <p className="dim" style={{ fontSize: 13, marginTop: 10 }}>
              Enter an asset id to read its journal — the twin's memory of every observed change.
            </p>
          )}
        </Panel>
      </div>

      {/* ── scenario launcher ───────────────────────────────────── */}
      <Panel className="mt" title="Scenario launcher" sub={`${scenarios.data?.scenario_count ?? 0} deterministic scenario types from the engine — no hardcoded templates`}>
        {scen.length === 0 && !scenarios.running && (
          <p className="dim" style={{ fontSize: 13 }}>
            {scenarios.error ?? "No scenarios returned by the engine."}
          </p>
        )}
        <div className="row" style={{ flexWrap: "wrap" }}>
          {scen.map((s) => (
            <button
              key={s.id}
              className="btn sm"
              title={s.description}
              style={s.id === selected ? { borderColor: "var(--cyan)", color: "var(--accent)", background: "color-mix(in srgb, var(--accent) 10%, transparent)" } : {}}
              onClick={() => choose(s.id)}
            >
              {s.name}
            </button>
          ))}
        </div>

        {active && (
          <div style={{ marginTop: 14 }}>
            <div className="dim" style={{ fontSize: 13, marginBottom: 8 }}>{active.description}</div>
            <div className="row" style={{ flexWrap: "wrap", gap: 8 }}>
              {Object.keys(active.inputs).map((k) => (
                <label key={k} style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 12, color: "var(--dim)" }}>
                  {k}
                  <input
                    className="inp mono"
                    style={{ width: 170 }}
                    value={params[k] ?? ""}
                    placeholder={INPUT_DEFAULTS[k] ?? ""}
                    onChange={(e) => setParams({ ...params, [k]: e.target.value })}
                  />
                </label>
              ))}
            </div>
            <div className="row" style={{ marginTop: 12 }}>
              <button className="btn primary" onClick={() => void simulate()} disabled={busy}>
                {busy ? "Running scenario…" : "Run against the twin"}
              </button>
            </div>
          </div>
        )}
      </Panel>

      {result?.error && <Panel title="Scenario rejected" className="mt"><p className="dim" style={{ fontSize: 13 }}>{result.error}</p></Panel>}

      {res && (
        <Panel className="mt" title="Scenario result" sub={`${res.scenario} · deterministic · read-only`}>
          <div className="feas-verdict">
            <span className="feas-big" style={{ color: res.verdict === "AFFECTED" || res.verdict === "AT_RISK" ? "var(--red)" : res.verdict === "INSUFFICIENT_DATA" ? "var(--amber)" : "var(--green)" }}>
              {res.verdict ?? "—"}
            </span>
            <div className="row" style={{ gap: 8 }}>
              <Badge tone="green">deterministic</Badge>
              <Badge tone="green">mutates nothing</Badge>
            </div>
          </div>
          <div className="grid cols-2" style={{ marginTop: 14 }}>
            <div>
              <div className="dim" style={{ fontSize: 12, marginBottom: 6 }}>affected</div>
              <Table
                head={["what", "count / items"]}
                rows={Object.entries(res.affected ?? {}).map(([k, v]) => {
                  const items = Array.isArray(v) ? v : null;
                  return [
                    k,
                    items === null
                      ? String(v ?? "—")
                      : `${items.length}${items.length ? `: ${items.slice(0, 4).join(", ")}${items.length > 4 ? "…" : ""}` : ""}`,
                  ];
                })}
              />
            </div>
            <div>
              <div className="dim" style={{ fontSize: 12, marginBottom: 6 }}>impact</div>
              <Table
                head={["measure", "value"]}
                rows={Object.entries(res.impact ?? {}).map(([k, v]) => [
                  k,
                  typeof v === "object" && v !== null ? JSON.stringify(v) : String(v ?? "—"),
                ])}
              />
            </div>
          </div>
          {unknowns.length > 0 && (
            <div className="mono" style={{ marginTop: 14, fontSize: 12, color: "var(--amber)" }}>
              <IconWarn className="ico" size={ICON_MD} /> honest unknowns (the twin could not verify — never assumed true):
              <ul className="plan-steps" style={{ marginTop: 6 }}>
                {unknowns.map((u, i) => <li key={i}>{u}</li>)}
              </ul>
            </div>
          )}
        </Panel>
      )}
    </>
  );
}
