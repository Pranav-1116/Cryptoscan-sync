import React from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import { integrations } from "../data/demo.js";

export default function Integrations() {
  return (
    <>
      <PageHead
        crumb="operate / integrations"
        title="Integrations"
        sub="SIEM / SOC streaming · ticketing · migration tracking · webhooks · email"
        right={<Badge tone="green"><span className="dot" /> ALL CONNECTED</Badge>}
      />
      <Panel title="Connected systems" sub="events fan out to every channel">
        <Table
          head={["integration", "kind", "status", "detail"]}
          rows={integrations.map((i) => [
            <span style={{ fontWeight: 600 }}>{i.name}</span>,
            <Badge tone="cyan">{i.kind}</Badge>,
            <Badge tone="green">{i.status}</Badge>,
            <span style={{ fontSize: 12.5 }} className="dim">{i.detail}</span>,
          ])}
        />
      </Panel>
    </>
  );
}
