import React from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import { assets } from "../data/initial.js";

export default function Assets() {
  return (
    <>
      <PageHead
        crumb="inventory / assets"
        title="Assets"
        sub="Every asset with owner, environment, region, risk and evidence — server-side pagination ready for 100K+"
        right={<Badge tone="green"><span className="dot" /> 125,482 TOTAL</Badge>}
      />
      <Panel title="Asset inventory" sub="sample of the estate (server-side filters apply at scale)">
        <Table
          head={["asset id", "type", "name", "env", "region", "owner", "risk", "evidence"]}
          rows={assets.map((a) => [
            <span className="mono">{a.id}</span>,
            <Badge tone="cyan">{a.type}</Badge>,
            <span className="mono">{a.name}</span>,
            a.env,
            a.region,
            a.owner,
            <Badge>{a.risk}</Badge>,
            <span className="num">{a.evidence}</span>,
          ])}
        />
      </Panel>
    </>
  );
}
