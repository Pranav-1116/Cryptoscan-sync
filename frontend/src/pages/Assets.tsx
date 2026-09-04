import React from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import { assets } from "../data/initial.js";

export default function Assets() {
  return (
    <>
      <PageHead
        crumb="inventory / assets"
        title="Assets"
        sub="Every asset with owner, environment, region, risk and evidence — populated by discovery"
        right={<Badge tone={assets.length ? "green" : ""}><span className="dot" /> {assets.length.toLocaleString()} TOTAL</Badge>}
      />
      <Panel title="Asset inventory" sub={assets.length ? "live inventory from the control plane" : "no assets yet — run discovery to populate the estate"}>
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
