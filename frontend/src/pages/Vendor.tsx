import React from "react";
import { Panel, Badge, Table, Bar, PageHead } from "../components/ui.jsx";
import { vendors } from "../data/initial.js";

export default function Vendor() {
  return (
    <>
      <PageHead
        crumb="discovery / vendor"
        title="Vendor"
        sub="Vendor → model → device → firmware → configuration → crypto capabilities → protocols → certificates → risk → changes"
        right={<Badge tone="green"><span className="dot" /> 14 VENDORS · 96 PRODUCTS</Badge>}
      />
      <Panel title="Crypto vendors" sub="product risk scored continuously">
        <Table
          head={["vendor", "devices", "firmware", "configs", "high-risk findings", "pqc roadmap", "risk score"]}
          rows={vendors.map((v) => [
            <span style={{ fontWeight: 600 }}>{v.name}</span>,
            <span className="num">{v.devices}</span>,
            <span className="num">{v.firmware}</span>,
            <span className="num">{v.configs}</span>,
            <span className="num">{v.findings}</span>,
            <span className="dim" style={{ fontSize: 12.5 }}>{v.pqc}</span>,
            <div style={{ display: "flex", alignItems: "center", gap: 10, minWidth: 120 }}>
              <span className="num">{v.score}</span>
              <Bar value={v.score / 100} tone={v.risk === "LOW" ? "green" : v.risk === "MEDIUM" ? "amber" : "red"} />
            </div>,
          ])}
        />
      </Panel>
      <div className="grid cols-2 mt">
        <Panel title="Example — Cisco" sub="drill into one vendor">
          <div className="tree">
            Cisco<br />
            {" ├── 184 devices"}<br />
            {" ├── 13 firmware versions"}<br />
            {" ├── 4 crypto configurations"}<br />
            {" └── 8 high-risk findings"}<br />
          </div>
        </Panel>
        <Panel title="PQC roadmap watch" sub="vendor commitments">
          {vendors.map((v) => (
            <div className="spread" key={v.name} style={{ padding: "6px 0", borderBottom: "1px solid rgba(56,189,248,0.07)", fontSize: 13 }}>
              <span>{v.name}</span>
              <Badge tone={v.pqc.includes("no PQC") ? "red" : v.pqc.includes("2026") ? "amber" : "green"}>
                {v.pqc.includes("no PQC") ? "NO ROADMAP" : v.pqc.includes("2026") ? "2026" : "ON TRACK"}
              </Badge>
            </div>
          ))}
        </Panel>
      </div>
    </>
  );
}
