import React from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import { governance } from "../data/initial.js";

export default function Governance() {
  return (
    <>
      <PageHead
        crumb="govern / governance"
        title="Governance"
        sub="Ownership · approvals · exceptions · risk acceptance · change approvals · migration approvals · policy · audit trail"
        right={<Badge tone="amber">2 ACTIVE EXCEPTIONS</Badge>}
      />
      <div className="grid cols-2">
        <Panel title="Ownership" sub="every crypto asset has an accountable owner">
          <Table
            head={["asset", "owner", "approved", "by"]}
            rows={governance.owners.map((o) => [
              <span className="mono">{o.asset}</span>, o.owner,
              <span className="mono">{o.approved}</span>, <span className="mono">{o.by}</span>,
            ])}
          />
        </Panel>
        <Panel title="Exceptions" sub="risk acceptances are time-boxed and reviewed">
          <Table
            head={["id", "asset", "reason", "expires", "approved by"]}
            rows={governance.exceptions.map((e) => [
              <span className="mono">{e.id}</span>,
              <span className="mono">{e.asset}</span>,
              <span style={{ fontSize: 12.5 }}>{e.reason}</span>,
              <span className="mono">{e.expires}</span>,
              <Badge tone="violet">{e.approvedBy}</Badge>,
            ])}
          />
        </Panel>
      </div>
      <Panel title="Audit trail" sub="append-only · evidence-linked" className="mt">
        <div className="timeline">
          {governance.audit.map((a) => (
            <div className="tl" key={a.t}>
              <span className="mono faint">{a.t}</span> <span className="mono" style={{ fontSize: 12.5 }}>{a.actor}</span>
              <span className="dim" style={{ fontSize: 13 }}> — {a.action} ({a.target})</span>
            </div>
          ))}
        </div>
      </Panel>
    </>
  );
}
