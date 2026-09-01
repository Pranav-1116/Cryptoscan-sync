import React from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import { compliance } from "../data/demo.js";

export default function Compliance() {
  return (
    <>
      <PageHead
        crumb="govern / compliance"
        title="Compliance"
        sub="Framework → requirement → control → evidence → status · versioned, configurable mappings"
        right={<Badge tone="amber">2 PARTIAL · 1 NON-COMPLIANT</Badge>}
      />
      <Panel title="Policy-driven compliance" sub="regulatory mappings are versioned and configurable">
        <Table
          head={["framework", "requirement", "control", "status", "evidence"]}
          rows={compliance.map((c) => [
            <span className="mono" style={{ fontWeight: 600 }}>{c.framework}</span>,
            c.requirement,
            c.control,
            <Badge>{c.status}</Badge>,
            <a className="mono" href="#/evidence" style={{ fontSize: 12 }}>{c.evidence}</a>,
          ])}
        />
      </Panel>
    </>
  );
}
