import React from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import { hardware, firmwareRows } from "../data/initial.js";

export default function Hardware() {
  return (
    <>
      <PageHead
        crumb="discovery / hardware"
        title="Hardware"
        sub="Servers · CPU · GPU · NIC · storage · TPM · HSM · BIOS · UEFI · BMC · firmware · crypto accelerators"
        right={<Badge tone={hardware.length ? "green" : ""}><span className="dot" /> {hardware.length.toLocaleString()} DEVICES</Badge>}
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
        {hardware.length || firmwareRows.length ? (
          <div className="timeline">
            {firmwareRows.slice(0, 8).map((f, i) => (
              <div className="tl" key={`${f.device}-${i}`}>
                <span className="dim" style={{ fontSize: 13 }}>{f.kind} {f.version} — {f.device} · {f.status}</span>
              </div>
            ))}
          </div>
        ) : (
          <div className="dim" style={{ fontSize: 13 }}>
            No hardware events yet — hardware/HSM/TPM/BMC discoveries and firmware changes appear here after a scan.
          </div>
        )}
      </Panel>
    </>
  );
}
