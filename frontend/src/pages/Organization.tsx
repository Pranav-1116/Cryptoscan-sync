import React, { useState } from "react";
import { Panel, Badge, Bar, Table, PageHead } from "../components/ui.jsx";
import { organization } from "../data/demo.js";
import { RegionUnit } from "../types.js";

/* Global organization view (spec §34): org → region → business unit →
   environment → assets → crypto. */

export default function Organization() {
  const [region, setRegion] = useState<RegionUnit>(organization[0]);
  const [bu, setBu] = useState(region.bu[0].id);

  const activeBu = region.bu.find((b) => b.id === bu) || region.bu[0];

  return (
    <>
      <PageHead
        crumb="command center / organization"
        title="Global organization view"
        sub="Organization → region → business unit → environment → assets → crypto"
        right={<Badge tone="green"><span className="dot" /> 4 REGIONS · 6 BUSINESS UNITS · 16 ENVIRONMENTS</Badge>}
      />

      <Panel title="Regions" sub="click a region to drill in">
        <div className="row">
          {organization.map((r) => (
            <button
              key={r.id}
              className={`btn sm ${region.id === r.id ? "" : ""}`}
              style={region.id === r.id ? { borderColor: "var(--cyan)", color: "#cfe4ff", background: "rgba(77,159,255,0.10)" } : {}}
              onClick={() => { setRegion(r); setBu(r.bu[0].id); }}
            >
              {r.flag} {r.name}
            </button>
          ))}
        </div>
      </Panel>

      <div className="grid cols-2 mt">
        <Panel title={`${region.name} — business units`} sub="account / business unit">
          <Table
            clickable
            selected={region.bu.findIndex((b) => b.id === bu)}
            onSelect={(i) => setBu(region.bu[i].id)}
            head={["business unit", "environments", "assets", "crypto"]}
            rows={region.bu.map((b) => [
              <span style={{ fontWeight: 600 }}>{b.name}</span>,
              <span className="num">{b.env.length}</span>,
              <span className="num">{b.env.reduce((n, e) => n + e.assets, 0).toLocaleString()}</span>,
              <span className="num">{b.env.reduce((n, e) => n + e.crypto, 0).toLocaleString()}</span>,
            ])}
          />
        </Panel>
        <Panel title={`${activeBu.name} — environments`} sub="environment → assets → crypto → risk">
          <Table
            head={["environment", "assets", "crypto assets", "risk"]}
            rows={activeBu.env.map((e) => [
              <span className="mono" style={{ fontWeight: 600 }}>{e.name}</span>,
              <span className="num">{e.assets.toLocaleString()}</span>,
              <span className="num">{e.crypto.toLocaleString()}</span>,
              <Badge>{e.risk}</Badge>,
            ])}
          />
          <div style={{ marginTop: 12, fontSize: 13, color: "var(--dim)" }}>
            Crypto share:{" "}
            <Bar value={activeBu.env.reduce((n, e) => n + e.crypto, 0) / Math.max(1, activeBu.env.reduce((n, e) => n + e.assets, 0))} tone="violet" />
          </div>
        </Panel>
      </div>

      <Panel title="Region comparison" sub="assets vs crypto assets per region" className="mt">
        <Table
          head={["region", "business units", "assets", "crypto assets", "crypto share"]}
          rows={organization.map((r) => {
            const assets = r.bu.reduce((n, b) => n + b.env.reduce((m, e) => m + e.assets, 0), 0);
            const crypto = r.bu.reduce((n, b) => n + b.env.reduce((m, e) => m + e.crypto, 0), 0);
            return [
              <span style={{ fontWeight: 600 }}>{r.flag} {r.name}</span>,
              <span className="num">{r.bu.length}</span>,
              <span className="num">{assets.toLocaleString()}</span>,
              <span className="num">{crypto.toLocaleString()}</span>,
              <div style={{ minWidth: 120 }}>
                <Bar value={crypto / Math.max(1, assets)} tone="violet" />
              </div>,
            ];
          })}
        />
      </Panel>
    </>
  );
}
