import React, { useMemo, useState } from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import { useApi, LiveBadge } from "../lib/apiUi.jsx";
import { apiHardwareCatalog, HardwareEntry } from "../lib/api.js";

/* Vendor view — crypto-hardware manufacturers derived from the canonical
   hardware registry (GET /api/v1/hardware/catalog). Vendors render as cards;
   click one to drill into its devices with a verdict distribution (required →
   allowed → restricted → deprecated → disallowed). Zero demo data: a fresh
   tenant sees an honest empty state. */

const HW_STATUS_TONE: Record<string, string> = {
  DISALLOWED: "red", DEPRECATED: "amber", RESTRICTED: "amber",
  UNKNOWN: "slate", ALLOWED: "green", REQUIRED: "green",
};
const VERDICT_ORDER = ["REQUIRED", "ALLOWED", "RESTRICTED", "DEPRECATED", "DISALLOWED", "UNKNOWN"];
const VERDICT_COLOR: Record<string, string> = {
  REQUIRED: "var(--green)", ALLOWED: "var(--green)", RESTRICTED: "var(--amber)",
  DEPRECATED: "var(--orange)", DISALLOWED: "var(--red)", UNKNOWN: "var(--slate)",
};

interface VendorAgg {
  name: string;
  devices: HardwareEntry[];
  count: number;
  attested: number;
  pqc: number;
  verdicts: Record<string, number>;
}

export default function Vendor() {
  const res = useApi(() => apiHardwareCatalog(), []);
  const live = res.source === "live";
  const devices: HardwareEntry[] = useMemo(() => res.data?.devices ?? [], [res.data]);
  const [selVendor, setSelVendor] = useState<string | null>(null);

  const vendors = useMemo<VendorAgg[]>(() => {
    const byVendor = new Map<string, HardwareEntry[]>();
    for (const d of devices) {
      const mfr = d.manufacturer || "Generic / standard";
      if (!byVendor.has(mfr)) byVendor.set(mfr, []);
      byVendor.get(mfr)!.push(d);
    }
    return [...byVendor.entries()]
      .map(([name, devs]) => {
        const verdicts: Record<string, number> = {};
        for (const s of VERDICT_ORDER) verdicts[s] = 0;
        for (const d of devs) verdicts[d.status] = (verdicts[d.status] ?? 0) + 1;
        return {
          name,
          devices: devs.sort((a, b) => String(a.device).localeCompare(String(b.device))),
          count: devs.length,
          attested: devs.filter((d) => d.attestation).length,
          pqc: devs.filter((d) => d.quantum_resistant).length,
          verdicts,
        };
      })
      .sort((a, b) => b.count - a.count);
  }, [devices]);

  const selected = selVendor ? vendors.find((v) => v.name === selVendor) ?? null : null;
  const totalPqc = vendors.reduce((s, v) => s + v.pqc, 0);

  return (
    <>
      <PageHead
        crumb="discovery / vendor"
        title="Vendor drill-down"
        sub="Crypto-hardware manufacturers from the canonical registry — click a vendor for its devices and verdict mix"
        right={
          <>
            <LiveBadge source={res.source} />
            <Badge tone={live ? "green" : ""}><span className="dot" /> {vendors.length} vendors · {devices.length} devices</Badge>
          </>
        }
      />

      {!vendors.length ? (
        <Panel title="Hardware vendors" sub="attestation and PQC-ready support across named products">
          <div className="dim" style={{ fontSize: 13 }}>
            {live ? "No vendor data — the hardware registry is empty." : "Backend offline — hardware catalog unavailable."}
          </div>
        </Panel>
      ) : (
        <>
          <Panel title="Vendors" sub="click a card to drill into that vendor's device inventory">
            <div className="vendor-grid">
              {vendors.map((v) => (
                <button
                  key={v.name}
                  className={`vendor-card ${selVendor === v.name ? "sel" : ""}`}
                  onClick={() => setSelVendor(selVendor === v.name ? null : v.name)}
                >
                  <div className="v-name">{v.name}</div>
                  <div className="v-stats">
                    <div className="v-stat"><span className="n">{v.count}</span><div className="l">devices</div></div>
                    <div className="v-stat"><span className="n" style={{ color: "var(--cyan)" }}>{v.attested}</span><div className="l">attested</div></div>
                    <div className="v-stat"><span className="n" style={{ color: "var(--green)" }}>{v.pqc}</span><div className="l">pqc</div></div>
                    <div className="v-stat"><span className="n" style={{ color: v.verdicts.DISALLOWED + v.verdicts.DEPRECATED ? "var(--red)" : undefined }}>
                      {v.verdicts.DISALLOWED + v.verdicts.DEPRECATED}
                    </span><div className="l">flagged</div></div>
                  </div>
                </button>
              ))}
            </div>
          </Panel>

          {selected && (
            <Panel
              title={`${selected.name} — device inventory`}
              sub={`${selected.count} device${selected.count === 1 ? "" : "s"} · ${selected.attested} attestation-capable · ${selected.pqc} PQC-ready`}
              className="mt"
            >
              <div className="verdict-bar">
                {VERDICT_ORDER.map((s) =>
                  selected.verdicts[s] > 0 ? (
                    <i key={s} style={{ width: `${(selected.verdicts[s] / selected.count) * 100}%`, background: VERDICT_COLOR[s] }} title={`${s}: ${selected.verdicts[s]}`} />
                  ) : null
                )}
              </div>
              <div className="verdict-legend" style={{ marginBottom: 14 }}>
                {VERDICT_ORDER.map((s) => (
                  <span key={s}><span className="sw" style={{ background: VERDICT_COLOR[s] }} />{s.toLowerCase()} {selected.verdicts[s]}</span>
                ))}
              </div>
              <Table
                head={["device", "category", "attestation", "PQC-ready", "status", "notes"]}
                rows={selected.devices.map((d) => [
                  <span className="mono" style={{ fontWeight: 600 }}>{d.device}</span>,
                  <Badge tone="violet">{d.category}</Badge>,
                  d.attestation ? <Badge tone="cyan">attested</Badge> : <span className="faint">—</span>,
                  d.quantum_resistant ? <Badge tone="green">yes</Badge> : <span className="faint">—</span>,
                  <Badge tone={HW_STATUS_TONE[d.status] ?? ""}>{d.status}</Badge>,
                  <span className="dim" style={{ fontSize: 12 }}>{d.risk_reason || d.notes || ""}</span>,
                ])}
              />
            </Panel>
          )}
        </>
      )}

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
