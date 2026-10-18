import { Link } from "react-router-dom";
import React from "react";
import { Badge, PageHead, Panel, Table } from "../components/ui.jsx";
import { useLive, LiveStatus } from "../lib/useLive.js";

/* Migration planning (spec §21) — the deterministic post-quantum migration
   plan from the live engine: replacement workstreams phased into 3 waves
   (HNDL-critical first), plus Mosca-model readiness. No fabricated board:
   columns are empty until a scan produces vulnerable sites. */

interface Wave { focus?: string; sites?: any[]; site_count?: number }
interface SystemWaveRow {
  system_id: string; name?: string; wave: number; position?: number; rationale?: string | null; unscored?: boolean;
  readiness_score?: number | null; source?: string; constrained_by?: string[]; cycle_group?: string;
  code_cascade?: { providers?: number; weak_parameters?: number; earliest_wave?: number | null; algorithms?: string[] } | null;
}
interface SystemWaves {
  waves?: Record<string, SystemWaveRow[]>; wave_order?: number[]; total_systems?: number; cycle_groups?: number;
  systems_bumped?: string[]; unscored_systems?: number; code_only_systems?: number; import_edges?: number; systems_delayed_by_imports?: string[];
}
interface Plan {
  inventory?: { total_sites?: number; vulnerable_sites?: number; pqc_ready_sites?: number; by_family?: Record<string, number> };
  workstreams?: any[];
  waves?: Record<string, Wave>;
  mosca?: { computable?: boolean; reason?: string; threat_year?: number; z_years_to_crqc?: number };
  summary?: string;
}

const WAVE_META: Record<string, { label: string; tone: string }> = {
  "1": { label: "WAVE 1 · HARVEST-NOW", tone: "red" },
  "2": { label: "WAVE 2 · SHOR-VULNERABLE", tone: "amber" },
  "3": { label: "WAVE 3 · GROVER SYMMETRIC", tone: "violet" },
};

export default function Migration() {
  const { data, loading, error } = useLive<Plan>("/api/v1/quantum/plan", {});
  const sysWaves = useLive<SystemWaves>("/api/v1/graph/migration-waves", {});
  const sysRows: SystemWaveRow[] = Object.values(sysWaves.data.waves ?? {}).flat();
  const inv = data.inventory ?? {};
  const waves = data.waves ?? {};
  const workstreams = data.workstreams ?? [];
  const total = inv.total_sites ?? 0;
  const vulnerable = inv.vulnerable_sites ?? 0;
  const ready = inv.pqc_ready_sites ?? 0;
  const progressPct = total ? Math.round((ready / total) * 100) : 0;

  return (
    <>
      <PageHead
        crumb="plan / migration planning"
        title="Migration planning"
        sub="Roadmap · waves · dependencies · workstreams · milestones — deterministic plan from the live quantum-risk engine"
        right={<Badge tone="cyan">PROGRESS {progressPct}% · {ready}/{total} READY</Badge>}
      />
      <div style={{ marginBottom: 12 }}><LiveStatus loading={loading} error={error} /></div>

      <div className="kanban">
        {["1", "2", "3"].map((w) => {
          const wave: Wave = waves[w] ?? { sites: [], site_count: 0 };
          const sites = wave.sites ?? [];
          return (
            <div className="col" key={w}>
              <h4>{WAVE_META[w].label} · {wave.site_count ?? sites.length}</h4>
              <div className="dim" style={{ fontSize: 11.5, marginBottom: 8 }}>{wave.focus ?? ""}</div>
              {sites.map((s, i) => (
                <div className="card" key={s.id ?? s.site ?? s.name ?? i}>
                  <div style={{ fontWeight: 600, fontSize: 12.5 }}>{s.name ?? s.site ?? s.asset_id ?? s.id}</div>
                  <div className="meta">
                    <span>{s.algorithm ?? s.family ?? s.system ?? "site"}</span>
                    <Badge tone={WAVE_META[w].tone}>{w === "1" ? "HIGH" : w === "2" ? "MEDIUM" : "LOW"}</Badge>
                  </div>
                  {(s.owner || s.workstream) && <div className="meta"><span>owner: {s.owner ?? s.workstream}</span></div>}
                </div>
              ))}
              {sites.length === 0 && <div className="dim" style={{ fontSize: 12 }}>no sites in this wave yet</div>}
            </div>
          );
        })}
      </div>

      <div className="grid cols-2 mt">
        <Panel title="Inventory" sub="live quantum-risk inventory">
          <Table
            head={["metric", "value"]}
            rows={[
              ["total sites", <span className="num" key="t">{total}</span>],
              ["quantum-vulnerable", <span className="num" key="v">{vulnerable}</span>],
              ["PQC-ready", <span className="num" key="r">{ready}</span>],
              ...Object.entries(inv.by_family ?? {}).map(([fam, n]) => [fam, <span className="num" key={fam}>{n}</span>]),
            ]}
          />
        </Panel>
        <Panel title="Mosca risk model" sub="shelf-life vs migration time vs crypto-agility">
          <div className="mono" style={{ fontSize: 13, display: "flex", flexDirection: "column", gap: 8 }}>
            <div><span className="faint">computable:</span> <Badge tone={data.mosca?.computable ? "green" : "amber"}>{data.mosca?.computable ? "yes" : "no"}</Badge></div>
            <div><span className="faint">threat year:</span> {data.mosca?.threat_year ?? "—"}</div>
            <div><span className="faint">years to CRQC:</span> {data.mosca?.z_years_to_crqc ?? "—"}</div>
            {data.mosca?.reason && <div className="dim" style={{ fontSize: 12.5 }}>{data.mosca.reason}</div>}
          </div>
        </Panel>
        <Panel title="Replacement workstreams" sub="ordered by the deterministic planner">
          <Table
            head={["workstream", "target", "sites"]}
            rows={workstreams.map((ws, i) => [
              <span className="mono" style={{ fontWeight: 600 }} key={i}>{ws.name ?? ws.id ?? ws.workstream ?? `workstream ${i + 1}`}</span>,
              ws.target_algorithm ?? ws.target ?? ws.family ?? "—",
              <span className="num" key={`n${i}`}>{ws.site_count ?? ws.sites ?? (Array.isArray(ws.sites) ? ws.sites.length : "—")}</span>,
            ])}
          />
          {workstreams.length === 0 && <p className="dim" style={{ fontSize: 13 }}>No workstreams yet — run a scan to inventory quantum-vulnerable crypto.</p>}
        </Panel>
        <Panel title="Plan summary" sub="engine output">
          <p className="dim" style={{ fontSize: 13, marginTop: 0 }}>{data.summary ?? "No migration plan yet."}</p>
          <p className="dim" style={{ fontSize: 12.5 }}>Run a <Link to="/what-if">what-if analysis</Link> on a target algorithm; waves populate as vulnerable sites are discovered.</p>
        </Panel>
      </div>

      <Panel title="System migration order" sub="Readiness waves reflect dependency cycles and code-level imports. A system that depends on cryptography in another system cannot migrate first." className="mt">
        {sysRows.length === 0 ? (
          <p className="dim" style={{ fontSize: 13 }}>{sysWaves.loading ? "Loading…" : "No systems in the graph yet — register systems (CMDB) or add cryptoscan-systems.yml to scanned repositories."}</p>
        ) : (
          <>
            <div className="dim" style={{ fontSize: 12, marginBottom: 8 }}>
              {sysWaves.data.total_systems} systems · {sysWaves.data.code_only_systems ?? 0} declared only in code · {sysWaves.data.import_edges ?? 0} code import edges ·{" "}
              {(sysWaves.data.systems_delayed_by_imports ?? []).length} delayed by imports · {sysWaves.data.cycle_groups ?? 0} dependency cycles · {sysWaves.data.unscored_systems ?? 0} unscored
            </div>
            <Table
              head={["Wave", "#", "System", "Code crypto", "Constraint", "Why"]}
              rows={sysRows.map((r) => [
                <Badge key={r.system_id} tone={r.wave === 1 ? "red" : r.wave === 2 ? "amber" : "violet"}>wave {r.wave}</Badge>,
                r.position ?? "",
                <span key={r.system_id + "n"}>{r.name || r.system_id}{r.source === "cryptoscan-systems.yml" && <span className="dim" style={{ fontSize: 10, marginLeft: 6 }}>code-declared</span>}</span>,
                r.code_cascade ? `${r.code_cascade.providers ?? 0} providers${r.code_cascade.weak_parameters ? ` · ${r.code_cascade.weak_parameters} weak` : ""}${r.code_cascade.earliest_wave ? ` · code wave ${r.code_cascade.earliest_wave}` : ""}` : "—",
                r.constrained_by?.length ? `after ${r.constrained_by.join(", ")}` : r.cycle_group ? r.cycle_group : "—",
                <span key={r.system_id + "w"} style={{ fontSize: 12 }}>{r.rationale || ""}</span>,
              ])}
            />
          </>
        )}
      </Panel>
    </>
  );
}
