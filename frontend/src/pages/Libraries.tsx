import React from "react";
import { Panel, Badge, Table, Bar, PageHead } from "../components/ui.jsx";
import { libraries } from "../data/initial.js";

export default function Libraries() {
  return (
    <>
      <PageHead
        crumb="inventory / crypto libraries"
        title="Crypto libraries"
        sub="Library · version · applications · algorithms · vulnerabilities · PQC support · crypto provider · upgrade status"
        right={<Badge tone="cyan"><span className="dot" /> 1,294 LIBRARIES</Badge>}
      />
      <Panel title="Library center" sub="upgrade status tracked per library">
        <Table
          head={["library", "version", "provider", "applications", "algorithms", "pqc support", "upgrade status"]}
          rows={libraries.map((l) => [
            <span className="mono" style={{ fontWeight: 600 }}>{l.name}</span>,
            <span className="num">{l.version}</span>,
            l.provider,
            <span className="num">{l.apps}</span>,
            <span className="num">{l.algorithms}</span>,
            l.pqc ? <Badge tone="green">SUPPORTED</Badge> : <Badge tone="amber">NOT YET</Badge>,
            <div style={{ minWidth: 130 }}>
              <span className="mono" style={{ fontSize: 11.5 }}>{l.upgrade}</span>
              <Bar value={l.pqc ? 1 : 0.4} tone={l.pqc ? "green" : "amber"} />
            </div>,
          ])}
        />
      </Panel>
    </>
  );
}
