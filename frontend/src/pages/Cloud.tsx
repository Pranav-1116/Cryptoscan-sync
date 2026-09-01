import React, { useState } from "react";
import { Panel, Badge, Table, Tabs, PageHead } from "../components/ui.jsx";
import { cloudResources } from "../data/demo.js";

const PROVIDERS = ["All", "AWS", "Azure", "GCP"];

export default function Cloud() {
  const [tab, setTab] = useState(0);
  const rows = cloudResources.filter((c) => tab === 0 || c.provider === PROVIDERS[tab]);

  return (
    <>
      <PageHead
        crumb="discovery / cloud"
        title="Cloud"
        sub="Unified abstraction across AWS, Azure and GCP — accounts · regions · resources · certificates · KMS · load balancers · databases · Kubernetes"
        right={<Badge tone="green"><span className="dot" /> 318 RESOURCES · 3 PROVIDERS</Badge>}
      />
      <Tabs tabs={PROVIDERS} active={tab} onChange={setTab} />
      <Panel title="Cloud resources" sub="one dashboard for every provider">
        <Table
          head={["provider", "service", "name", "certificates", "kms", "status"]}
          rows={rows.map((c) => [
            <Badge tone="violet">{c.provider}</Badge>,
            c.service,
            <span className="mono">{c.name}</span>,
            c.certs.length ? c.certs.join(", ") : <span className="faint">—</span>,
            <span className="num">{c.kms}</span>,
            <Badge>{c.status}</Badge>,
          ])}
        />
      </Panel>
    </>
  );
}
