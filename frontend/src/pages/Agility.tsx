import React from "react";
import { Panel, Badge, Bar, Ring, Table, PageHead } from "../components/ui.jsx";
import { agility } from "../data/initial.js";

export default function Agility() {
  return (
    <>
      <PageHead
        crumb="post-quantum / crypto agility"
        title="Crypto agility"
        sub="How fast can the enterprise move off a broken or quantum-vulnerable algorithm?"
        right={<Badge tone={agility.score >= 70 ? "green" : agility.score >= 50 ? "amber" : "red"}>{agility.score} / 100</Badge>}
      />
      <div className="grid cols-2" style={{ marginBottom: 16 }}>
        <Panel title="Enterprise score" sub="aggregate crypto agility">
          <div style={{ display: "flex", alignItems: "center", gap: 26, flexWrap: "wrap" }}>
            <Ring pct={agility.score / 100} label={agility.score} sub="AGILITY" tone={agility.score >= 70 ? "green" : "amber"} />
            <div style={{ display: "flex", flexDirection: "column", gap: 12, flex: 1, minWidth: 240 }}>
              {[
                { k: "Hard-coded crypto", v: agility.hardCoded, tone: "red" },
                { k: "Configurable crypto", v: agility.configurable, tone: "cyan" },
                { k: "PQC ready", v: agility.pqcReady, tone: "green" },
                { k: "Hybrid ready", v: agility.hybridReady, tone: "violet" },
              ].map((r) => (
                <div key={r.k}>
                  <div className="spread" style={{ marginBottom: 4, fontSize: 13 }}>
                    <span>{r.k}</span><span className="mono">{r.v}%</span>
                  </div>
                  <Bar value={r.v / 100} tone={r.tone} />
                </div>
              ))}
            </div>
          </div>
        </Panel>
        <Panel title="Hard-coded crypto" sub="the blocker — 18% of the estate">
          <div className="dim" style={{ fontSize: 13.5 }}>
            Hard-coded algorithms cannot be re-configured without code changes: they are found in
            binaries, source and firmware. ZELNX flags each with its location so teams can plan the
            code change — not just the config change.
          </div>
        </Panel>
      </div>
      <Panel title="Application-level drill-down" sub="agility score per application">
        <Table
          head={["application", "score", "hard-coded", "configurable", "pqc ready"]}
          rows={agility.byApp.map((a) => [
            <span className="mono" style={{ fontWeight: 600 }}>{a.app}</span>,
            <Badge tone={a.score >= 70 ? "green" : a.score >= 50 ? "amber" : "red"}>{a.score}</Badge>,
            <div style={{ minWidth: 110 }}><span className="mono" style={{ fontSize: 11.5 }}>{a.hard}%</span><Bar value={a.hard / 100} tone="red" /></div>,
            <div style={{ minWidth: 110 }}><span className="mono" style={{ fontSize: 11.5 }}>{a.config}%</span><Bar value={a.config / 100} tone="cyan" /></div>,
            <div style={{ minWidth: 110 }}><span className="mono" style={{ fontSize: 11.5 }}>{a.pqc}%</span><Bar value={a.pqc / 100} tone="green" /></div>,
          ])}
        />
      </Panel>
    </>
  );
}
