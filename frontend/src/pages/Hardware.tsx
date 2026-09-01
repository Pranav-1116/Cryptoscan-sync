import React from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import { hardware, firmwareRows } from "../data/demo.js";

export default function Hardware() {
  return (
    <>
      <PageHead
        crumb="discovery / hardware"
        title="Hardware"
        sub="Servers · CPU · GPU · NIC · storage · TPM · HSM · BIOS · UEFI · BMC · firmware · crypto accelerators"
        right={<Badge tone="green"><span className="dot" /> 259 DEVICES · SCANNER NOMINAL</Badge>}
      />
      <Panel title="HSM · TPM · secure elements · accelerators" sub="capabilities, firmware, PQC support">
        <Table
          head={["id", "type", "vendor", "firmware", "capabilities", "host", "status"]}
          rows={hardware.map((h) => [
            <span className="mono">{h.id}</span>,
            <Badge tone="violet">{h.type}</Badge>,
            h.vendor,
            <span className="num">{h.firmware}</span>,
            <span className="row">{h.caps.map((c) => <Badge key={c} tone={c.startsWith("ML-") ? "green" : ""}>{c}</Badge>)}</span>,
            <span className="mono">{h.host}</span>,
            <Badge>{h.status}</Badge>,
          ])}
        />
      </Panel>
      <Panel title="Firmware vs baseline" sub="drift detection across the hardware layer" className="mt">
        <Table
          head={["device", "kind", "version", "status"]}
          rows={firmwareRows.map((f) => [
            <span className="mono">{f.device}</span>,
            f.kind,
            <span className="num">{f.version}</span>,
            f.status.startsWith("DRIFT") ? <Badge tone="red">{f.status}</Badge> : <Badge tone="green">{f.status}</Badge>,
          ])}
        />
      </Panel>
      <Panel title="Hardware timeline" sub="every change is evidence-linked" className="mt">
        <div className="timeline">
          {[
            { t: "08:30", e: "Device discovered — tpm-pay-09", hi: false },
            { t: "09:14", e: "Firmware changed — fw-edge-01 PAN-OS 11.1.2", hi: true },
            { t: "10:22", e: "TPM changed — tpm-pay-01 PCR policy updated", hi: false },
            { t: "11:05", e: "Crypto capability changed — hsm-pci-01 ML-KEM-768", hi: false },
          ].map((x) => (
            <div className={`tl ${x.hi ? "hi" : ""}`} key={x.t}>
              <span className="mono faint">{x.t}</span> <span className="dim" style={{ fontSize: 13 }}>{x.e}</span>
            </div>
          ))}
        </div>
      </Panel>
    </>
  );
}
