import React from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import { hardware, bomComponents, globalState } from "../data/initial.js";

export default function Hbom() {
  return (
    <>
      <PageHead
        crumb="boms / hbom"
        title="HBOM"
        sub="Hardware Bill of Materials — hardware · components · firmware · TPM · HSM · crypto capability"
        right={<Badge tone="green"><span className="dot" /> v{globalState.hbomVersion} · LATEST</Badge>}
      />
      <Panel title="HBOM explorer" sub="every device with its crypto capability">
        <Table
          head={["type", "component"]}
          rows={bomComponents.filter((c) => ["device", "firmware"].includes(c.type)).map((c) => [
            <Badge tone="violet">{c.type}</Badge>, <span className="mono">{c.name}</span>,
          ])}
        />
      </Panel>
      <Panel title="Trusted hardware layer" sub="HSM · TPM · secure elements · accelerators" className="mt">
        <Table
          head={["id", "type", "vendor", "firmware", "capabilities", "status"]}
          rows={hardware.map((h) => [
            <span className="mono">{h.id}</span>,
            <Badge tone="violet">{h.type}</Badge>,
            h.vendor,
            <span className="num">{h.firmware}</span>,
            <span className="row">{h.caps.map((c) => <Badge key={c} tone={c.startsWith("ML-") ? "green" : ""}>{c}</Badge>)}</span>,
            <Badge>{h.status}</Badge>,
          ])}
        />
      </Panel>
    </>
  );
}
