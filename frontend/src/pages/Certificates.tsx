import React, { useState } from "react";
import { Panel, Badge, Table, Bar, PageHead, Drawer } from "../components/ui.jsx";
import { certificates, certCenter } from "../data/initial.js";

export default function Certificates() {
  const [sel, setSel] = useState<number | null>(null);
  const detail = sel !== null ? certificates[sel] : null;

  return (
    <>
      <PageHead
        crumb="inventory / certificates"
        title="Certificates"
        sub="Inventory · expiration calendar · chains · CA relationships · algorithm · key size · trust store · usage · changes"
        right={<Badge tone={certificates.length ? "cyan" : ""}><span className="dot" /> {certificates.length.toLocaleString()} CERTIFICATES</Badge>}
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
      <Panel title="Expiration calendar" sub="certificate lifetimes from the live inventory" className="mt">
        {certificates.length ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {certificates.slice(0, 8).map((c) => (
            <div key={c.cn} className="spread" style={{ fontSize: 13 }}>
              <span className="mono">{c.cn}</span>
              <div style={{ flex: 1, maxWidth: 320 }}>
                <Bar value={Math.max(0, Math.min(1, c.days / 365))} tone={c.days < 30 ? "red" : c.days < 90 ? "amber" : "green"} />
              </div>
              <span className="mono">{c.days} days</span>
            </div>
          ))}
        </div>
        ) : (
          <div className="dim" style={{ fontSize: 13 }}>No certificates discovered yet — run a scan to populate the expiration calendar.</div>
        )}
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
      <Panel title="Certificate" sub="parsed properties" frame>
        <div className="tree">
          CN: <span className="hl">{cert.cn}</span><br />
          signature: {cert.sig}<br />
          key: {cert.key} · SAN entries: {cert.san}<br />
          EKU: {cert.eku} · owner: {cert.owner}
        </div>
      </Panel>
      <Panel title="Usage" sub="where this certificate is deployed (from the dependency graph)" frame className="mt">
        <div className="dim" style={{ fontSize: 12.5 }}>
          Deployment edges are derived from the live CBOM dependency graph — link this certificate after a scan to see the assets that consume it.
        </div>
      </Panel>
      <Panel title="Evidence" sub="linked artifacts" frame className="mt">
        <div className="mono dim" style={{ fontSize: 12 }}>
          Evidence records are linked after a scan.
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
