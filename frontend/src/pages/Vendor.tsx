import React, { useMemo } from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import { useApi, LiveBadge } from "../lib/apiUi.jsx";
import { apiHardwareCatalog, HardwareEntry } from "../lib/api.js";

/* Vendor view — crypto-hardware manufacturers derived from the canonical
   hardware registry (GET /api/v1/hardware/catalog): devices per vendor,
   attestation and PQC-ready counts. Live product/firmware telemetry appears
   after hardware scans. Zero demo data. */

export default function Vendor() {
  const res = useApi(() => apiHardwareCatalog(), []);
  const live = res.source === "live";
  const devices: HardwareEntry[] = useMemo(() => res.data?.devices ?? [], [res.data]);

  const vendors = useMemo(() => {
    const byVendor = new Map<string, HardwareEntry[]>();
    for (const d of devices) {
      const mfr = d.manufacturer || "Generic / standard";
      if (!byVendor.has(mfr)) byVendor.set(mfr, []);
      byVendor.get(mfr)!.push(d);
    }
    return [...byVendor.entries()]
      .map(([name, devs]) => ({
        name,
        devices: devs.length,
        attested: devs.filter((d) => d.attestation).length,
        pqc: devs.filter((d) => d.quantum_resistant).length,
        disallowed: devs.filter((d) => d.status === "DISALLOWED" || d.status === "DEPRECATED").length,
      }))
      .sort((a, b) => b.devices - a.devices);
  }, [devices]);

  const totalPqc = vendors.reduce((s, v) => s + v.pqc, 0);

  return (
    <>
      <PageHead
        crumb="discovery / vendor"
        title="Vendor"
        sub="Crypto-hardware manufacturers from the canonical registry — devices, attestation and PQC support per vendor"
        right={
          <>
            <LiveBadge source={res.source} />
            <Badge tone={live ? "green" : ""}><span className="dot" /> {vendors.length.toLocaleString()} VENDORS · {devices.length} DEVICES</Badge>
          </>
        }
      />
      <Panel title="Hardware vendors" sub="attestation and PQC-ready support across named products">
        <Table
          head={["vendor", "devices", "attestation-capable", "PQC-ready", "deprecated/disallowed"]}
          rows={vendors.map((v) => [
            <span style={{ fontWeight: 600 }}>{v.name}</span>,
            <span className="num">{v.devices}</span>,
            v.attested ? <Badge tone="cyan">{v.attested}</Badge> : <span className="dim">—</span>,
            v.pqc ? <Badge tone="green">{v.pqc}</Badge> : <span className="dim">—</span>,
            v.disallowed ? <Badge tone="red">{v.disallowed}</Badge> : <Badge tone="green">0</Badge>,
          ])}
        />
        {!vendors.length && (
          <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>
            {live ? "No vendor data." : "Backend offline — hardware catalog unavailable."}
          </div>
        )}
      </Panel>
      <Panel title="PQC roadmap watch" sub="hardware with native post-quantum support in the registry" className="mt">
        {devices.some((d) => d.quantum_resistant) ? (
          <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
            {devices.filter((d) => d.quantum_resistant).map((d) => (
              <Badge key={d.device} tone="green">{d.device} · {d.manufacturer || "std"}</Badge>
            ))}
          </div>
        ) : (
          <div className="dim" style={{ fontSize: 13 }}>
            {totalPqc === 0 && live
              ? "No PQC-capable hardware entries flagged."
              : "PQC roadmap telemetry appears after hardware scans; see the catalog for native-PQC devices (e.g. IBM Crypto Express, ARM CCA)."}
          </div>
        )}
      </Panel>
    </>
  );
}
