import React, { useState } from "react";
import { Panel, Badge, Table, Tabs, PageHead } from "../components/ui.jsx";
import { protocols } from "../data/initial.js";

const GROUPS = ["TLS", "SSH", "IPsec", "VPN", "QUIC"];

export default function Protocols() {
  const [tab, setTab] = useState(0);
  const rows = protocols.filter((p) => p.protocol === GROUPS[tab]);

  return (
    <>
      <PageHead
        crumb="inventory / protocols"
        title="Protocols"
        sub="TLS · SSH · IPsec · VPN · QUIC — version, cipher, key exchange, signature, certificate, endpoint, risk, PQC readiness"
        right={<Badge tone={protocols.length ? "cyan" : ""}><span className="dot" /> {protocols.length.toLocaleString()} PROTOCOL ENDPOINTS</Badge>}
      />
      <Tabs tabs={GROUPS} active={tab} onChange={setTab} />
      <Panel title={`${GROUPS[tab]} endpoints`} sub="risk and PQC readiness per endpoint">
        <Table
          head={["version", "cipher", "key exchange", "signature", "certificate", "endpoint", "risk", "pqc readiness"]}
          rows={rows.map((p) => [
            p.version,
            <span className="mono">{p.cipher}</span>,
            <span className="mono">{p.kex}</span>,
            <span className="mono">{p.signature}</span>,
            <span className="mono">{p.cert}</span>,
            <span className="mono">{p.endpoint}</span>,
            <Badge>{p.risk}</Badge>,
            <Badge>{p.pqc}</Badge>,
          ])}
        />
      </Panel>
    </>
  );
}
