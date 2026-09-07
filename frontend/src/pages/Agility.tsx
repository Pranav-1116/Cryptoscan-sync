import React from "react";
import { Panel, Badge, Bar, Ring, Table, PageHead } from "../components/ui.jsx";
import { useLive, LiveStatus } from "../lib/useLive.js";

interface AgilitySystem {
  system?: string;
  system_id?: string;
  agility_score?: number;
  category?: string;
  score_delta?: number;
}
interface AgilityResp {
  systems?: AgilitySystem[];
  average?: number;
}

export default function Agility() {
  const { data, loading, error } = useLive<AgilityResp>("/api/v1/agility", { systems: [], average: 0 });
  const systems = data.systems ?? [];
  const score = Math.round(data.average ?? 0);
  const pqcReady = systems.length ? Math.round((systems.filter((s) => (s.agility_score ?? 0) >= 70).length / systems.length) * 100) : 0;
  const hardCoded = systems.length ? Math.round((systems.filter((s) => (s.agility_score ?? 0) < 40).length / systems.length) * 100) : 0;
  const configurable = 100 - hardCoded;

  return (
    <>
      <PageHead
        crumb="post-quantum / crypto agility"
        title="Crypto agility"
        sub="How fast can the enterprise move off a broken or quantum-vulnerable algorithm?"
        right={<Badge tone={score >= 70 ? "green" : score >= 50 ? "amber" : "red"}>{score} / 100</Badge>}
      />
      <div style={{ marginBottom: 12 }}><LiveStatus loading={loading} error={error} /></div>
      <div className="grid cols-2" style={{ marginBottom: 16 }}>
        <Panel title="Enterprise score" sub="aggregate crypto agility (live)">
          <div style={{ display: "flex", alignItems: "center", gap: 26, flexWrap: "wrap" }}>
            <Ring pct={score / 100} label={score} sub="AGILITY" tone={score >= 70 ? "green" : "amber"} />
            <div style={{ display: "flex", flexDirection: "column", gap: 12, flex: 1, minWidth: 240 }}>
              {[
                { k: "Hard-coded crypto", v: hardCoded, tone: "red" },
                { k: "Configurable crypto", v: configurable, tone: "cyan" },
                { k: "PQC ready", v: pqcReady, tone: "green" },
                { k: "Systems scored", v: systems.length, tone: "violet", raw: true },
              ].map((r) => (
                <div key={r.k}>
                  <div className="spread" style={{ marginBottom: 4, fontSize: 13 }}>
                    <span>{r.k}</span><span className="mono">{r.raw ? r.v : r.v + "%"}</span>
                  </div>
                  {!r.raw && <Bar value={r.v / 100} tone={r.tone} />}
                </div>
              ))}
            </div>
          </div>
        </Panel>
        <Panel title="Hard-coded crypto" sub="the blocker — flagged after a scan">
          <div className="dim" style={{ fontSize: 13.5 }}>
            Hard-coded algorithms cannot be re-configured without code changes: they are found in
            binaries, source and firmware. ZELNX flags each with its location so teams can plan the
            code change — not just the config change. {systems.length === 0 && !loading &&
              "No systems scored yet — run a discovery/scan to populate."}
          </div>
        </Panel>
      </div>
      <Panel title="System-level drill-down" sub="agility score per discovered system">
        <Table
          head={["system", "score", "category", "trend"]}
          rows={systems.map((a) => [
            <span className="mono" style={{ fontWeight: 600 }}>{a.system || a.system_id}</span>,
            <Badge tone={(a.agility_score ?? 0) >= 70 ? "green" : (a.agility_score ?? 0) >= 50 ? "amber" : "red"}>{a.agility_score ?? 0}</Badge>,
            <Badge tone="violet">{a.category ?? "—"}</Badge>,
            <span className="mono" style={{ fontSize: 12 }}>
              {a.score_delta === undefined ? "—" : a.score_delta > 0 ? `▲ ${a.score_delta}` : a.score_delta < 0 ? `▼ ${Math.abs(a.score_delta)}` : "flat"}
            </span>,
          ])}
        />
      </Panel>
    </>
  );
}
