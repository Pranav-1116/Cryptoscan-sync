import React, { useState } from "react";
import { Panel, Badge, Table, PageHead, Drawer } from "../components/ui.jsx";
import { networkAssets } from "../data/initial.js";

/* Interactive topology (spec §6) — click any asset for its detail panel. */

/* Network topology is built from discovered network assets. It starts
   empty and populates after network discovery runs. */
const TOPO: { id: string; label: string; x: number; y: number; kind: string }[] = [];

export default function Network() {
  const [sel, setSel] = useState<string | null>(null);
  const detail = networkAssets.find((n) => n.id === sel);
  const c = {
    subnets: networkAssets.filter((n) => n.kind === "subnet").length,
    hosts: networkAssets.length,
    routers: networkAssets.filter((n) => n.kind === "router").length,
    firewalls: networkAssets.filter((n) => n.kind === "firewall").length,
    vpn: networkAssets.filter((n) => n.kind === "vpn_gateway").length,
  };

  return (
    <>
      <PageHead
        crumb="discovery / network"
        title="Network"
        sub="Networks · subnets · hosts · routers · switches · firewalls · VPN · load balancers · endpoints · open services · changes"
        right={<Badge tone={networkAssets.length ? "green" : ""}><span className="dot" /> {networkAssets.length} ASSETS</Badge>}
      />
      <div className="grid cols-5" style={{ marginBottom: 16 }}>
        {[["subnets", c.subnets], ["hosts", c.hosts], ["routers", c.routers], ["firewalls", c.firewalls], ["vpn gateways", c.vpn]].map(([k, v]) => (
          <div className="kpi" key={k}><span className="k">{k}</span><span className="v">{v}</span></div>
        ))}
      </div>
      <Panel title="Network topology" sub={networkAssets.length ? "click any node for detail" : "no network assets yet — run network discovery"}>
        {networkAssets.length === 0 ? (
          <div style={{ minHeight: 180, display: "grid", placeItems: "center" }}>
            <div className="frame" style={{ border: "1px dashed var(--line-strong)", borderRadius: 12, padding: "30px 38px", textAlign: "center", color: "var(--faint)", fontSize: 13.5, maxWidth: 440 }}>
              Topology appears after discovery.<br />
              <span className="dim">Add network scope in <a href="#/onboarding">Onboarding</a> (CIDR / IP range / domain) and run discovery — routers, switches, firewalls, VPNs, load balancers and endpoints are mapped automatically.</span>
            </div>
          </div>
        ) : (
        <div className="graphwrap">
          <svg viewBox="0 0 800 500" width="100%" style={{ minWidth: 680 }}>
            {TOPO.slice(0, -1).map((node, i) => {
              const next = TOPO[i + 1];
              if (!next) return null;
              return <path key={`${node.id}-${next.id}`} className="edge" d={`M${node.x} ${node.y + 26} L${next.x} ${next.y - 26}`} />;
            })}
            {TOPO.map((t) => {
              const isSel = sel === t.id;
              const asset = networkAssets.find((n) => n.id === t.id);
              return (
                <g key={t.id} className={`gnode ${isSel ? "sel" : ""}`} onClick={() => setSel(isSel ? null : t.id)}>
                  <rect x={t.x - 80} y={t.y} width="160" height="52" opacity={asset && asset.status === "NEW" ? 1 : undefined} />
                  {asset && asset.status === "NEW" && <rect x={t.x - 80} y={t.y} width="160" height="52" fill="none" stroke="var(--amber)" strokeDasharray="5 4" rx="9" />}
                  <text x={t.x} y={t.y + 21} textAnchor="middle" style={{ fontWeight: 600 }}>{t.label}</text>
                  <text x={t.x} y={t.y + 36} textAnchor="middle" className="gsub">{asset ? asset.ip : "public"}</text>
                </g>
              );
            })}
          </svg>
        </div>
        )}
      </Panel>
      <Panel title="Endpoints" sub="TLS · SSH · IPsec posture per endpoint" className="mt">
        <Table
          head={["kind", "id", "ip", "tls / key exchange", "certificates", "os", "status"]}
          rows={networkAssets.map((n) => [
            <Badge tone="cyan">{n.kind}</Badge>,
            <span className="mono">{n.id}</span>,
            <span className="num">{n.ip}</span>,
            n.tls,
            n.certs.length ? n.certs.join(", ") : <span className="faint">—</span>,
            n.os,
            <Badge>{n.status}</Badge>,
          ])}
        />
      </Panel>
      {detail && (
        <Drawer title={detail.id} sub={`${detail.kind} · ${detail.ip} · ${detail.os}`} onClose={() => setSel(null)}>
          <div className="row" style={{ marginBottom: 16 }}>
            <Badge tone="cyan">{detail.kind}</Badge>
            <Badge>{detail.status}</Badge>
          </div>
          <div className="tree" style={{ marginBottom: 16 }}>
            Crypto posture:<br />
            {" └── "}{detail.tls}
          </div>
          <Panel title="Certificates" sub="served by this endpoint" frame>
            {detail.certs.length ? detail.certs.map((c) => <Badge key={c} tone="cyan">{c}</Badge>) : <span className="faint" style={{ fontSize: 13 }}>none observed</span>}
          </Panel>
          <Panel title="Evidence" sub="linked artifacts" frame className="mt">
            <div className="mono dim" style={{ fontSize: 12 }}>
              Evidence records are linked to this endpoint after a scan.
            </div>
            <a href="#/evidence" className="mono" style={{ fontSize: 12 }}>open evidence chain →</a>
          </Panel>
        </Drawer>
      )}
    </>
  );
}
