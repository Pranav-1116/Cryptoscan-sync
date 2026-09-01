import React, { useState } from "react";
import { Panel, Badge, Table, Bar, PageHead, Drawer } from "../components/ui.jsx";
import { certificates, certCenter } from "../data/demo.js";

export default function Certificates() {
  const [sel, setSel] = useState<number | null>(null);
  const detail = sel !== null ? certificates[sel] : null;

  return (
    <>
      <PageHead
        crumb="inventory / certificates"
        title="Certificates"
        sub="Inventory · expiration calendar · chains · CA relationships · algorithm · key size · trust store · usage · changes"
        right={<Badge tone="cyan"><span className="dot" /> 7,821 CERTIFICATES</Badge>}
      />
      <div className="grid cols-5" style={{ marginBottom: 16 }}>
        {[
          ["expired", certCenter.expired, "red"],
          ["expiring <30d", certCenter.expiring30, "amber"],
          ["weak algorithm", certCenter.weakAlgorithm, "red"],
          ["unknown owner", certCenter.unknownOwner, "amber"],
          ["pqc migration", certCenter.pqcMigration, "violet"],
        ].map(([k, v, tone]) => (
          <div className="kpi" key={k as string}>
            <span className="k">{k}</span>
            <span className="v" style={{ color: `var(--${tone})` }}>{v}</span>
          </div>
        ))}
      </div>
      <Panel title="Certificate inventory" sub="click a certificate to inspect its chain and usage">
        <Table
          clickable
          selected={sel ?? -1}
          onSelect={setSel}
          head={["common name", "signature", "key", "days left", "SAN", "EKU", "owner", "status"]}
          rows={certificates.map((c) => [
            <span className="mono" style={{ fontWeight: 600 }}>{c.cn}</span>,
            c.sig,
            <span className="num">{c.key}</span>,
            <span className="num">{c.days}</span>,
            c.san,
            <span style={{ fontSize: 12 }}>{c.eku}</span>,
            c.owner,
            <Badge>{c.status}</Badge>,
          ])}
        />
      </Panel>
      {detail && <CertDrawer cert={detail} onClose={() => setSel(null)} />}
      <Panel title="Expiration calendar" sub="next 90 days" className="mt">
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {[
            { cn: "api.payments.internal", days: 12, tone: "red" },
            { cn: "pos-gw.example", days: 4, tone: "red" },
            { cn: "db.internal", days: 88, tone: "amber" },
            { cn: "gw.vpn.internal", days: 210, tone: "green" },
            { cn: "payments.internal", days: 334, tone: "green" },
          ].map((c) => (
            <div key={c.cn} className="spread" style={{ fontSize: 13 }}>
              <span className="mono">{c.cn}</span>
              <div style={{ flex: 1, maxWidth: 320 }}>
                <Bar value={c.days / 365} tone={c.tone} />
              </div>
              <span className="mono">{c.days} days</span>
            </div>
          ))}
        </div>
      </Panel>
    </>
  );
}

function CertDrawer({ cert, onClose }: { cert: { cn: string; sig: string; key: string; days: number; san: number; eku: string; status: string; owner: string }; onClose: () => void }) {
  return (
    <Drawer title={cert.cn} sub={`${cert.key} · ${cert.sig} · owner ${cert.owner}`} onClose={onClose}>
      <div className="row" style={{ marginBottom: 16 }}>
        <Badge>{cert.status}</Badge>
        <Badge tone={cert.days < 30 ? "red" : cert.days < 90 ? "amber" : "green"}>{cert.days} DAYS LEFT</Badge>
      </div>
      <Panel title="Certificate chain" sub="CA relationships" frame>
        <div className="tree">
          ROOT CA — root-ca.internal (RSA-4096)<br />
          {"  └── INTERMEDIATE — org-ca.internal (RSA-3072)"}<br />
          {"      └── "}<span className="hl">{cert.cn}</span> <span className="faint">({cert.sig})</span><br />
          <br />
          trust store: system.jks · anchors verified ✓
        </div>
      </Panel>
      <Panel title="Usage" sub="where this certificate is deployed" frame className="mt">
        <div className="tree">
          {"├── 3 load balancers"}<br />
          {"├── 8 applications"}<br />
          {"├── 2 VPN gateways"}<br />
          {"└── 1 HSM"}
        </div>
      </Panel>
      <Panel title="Evidence" sub="linked artifacts" frame className="mt">
        <div className="mono dim" style={{ fontSize: 12 }}>
          ev-00921 · certificate parser · 99%<br />
          ev-00920 · artifact scan · 99%
        </div>
        <a href="#/evidence" className="mono" style={{ fontSize: 12 }}>open evidence chain →</a>
      </Panel>
      <Panel title="Actions" sub="deterministic operations" frame className="mt">
        <div className="row">
          <a href="#/whatif" className="btn sm">Re-key (what-if)</a>
          <a href="#/migration" className="btn sm">Migration plan</a>
        </div>
      </Panel>
    </Drawer>
  );
}
