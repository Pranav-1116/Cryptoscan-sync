import React, { useState } from "react";
import { Panel, Badge, Table, PageHead, Drawer } from "../components/ui.jsx";
import { networkAssets } from "../data/initial.js";

/* Interactive topology (spec §6) — click any asset for its detail panel. */

const TOPO: { id: string; label: string; x: number; y: number; kind: string }[] = [
  { id: "internet", label: "INTERNET", x: 380, y: 30, kind: "external" },
  { id: "fw-edge-01", label: "FIREWALL", x: 380, y: 110, kind: "firewall" },
  { id: "rtr-core-1", label: "ROUTER", x: 380, y: 190, kind: "router" },
  { id: "sw-dc-01", label: "SWITCH", x: 380, y: 270, kind: "switch" },
  { id: "lb-pay-01", label: "LOAD BALANCER", x: 380, y: 350, kind: "load_balancer" },
  { id: "app-pay-01", label: "APP SERVER", x: 230, y: 430, kind: "endpoint" },
  { id: "db-pay-01", label: "DB SERVER", x: 530, y: 430, kind: "database" },
  { id: "vpn-01", label: "VPN GATEWAY", x: 610, y: 190, kind: "vpn_gateway" },
];

export default function Network() {
  const [sel, setSel] = useState<string | null>(null);
  const detail = networkAssets.find((n) => n.id === sel);

  return (
    <>
      <PageHead
        crumb="discovery / network"
        title="Network"
        sub="Networks · subnets · hosts · routers · switches · firewalls · VPN · load balancers · endpoints · open services · changes"
        right={<Badge tone="green"><span className="dot" /> SCANNER RUNNING · 611 ASSETS</Badge>}
      />
      <div className="grid cols-5" style={{ marginBottom: 16 }}>
        {[["subnets", "14"], ["hosts", "611"], ["routers", "8"], ["firewalls", "3"], ["vpn gateways", "6"]].map(([k, v]) => (
          <div className="kpi" key={k}><span className="k">{k}</span><span className="v">{v}</span></div>
        ))}
      </div>
      <Panel title="Network topology" sub="Internet → firewall → router → switch → servers — click any node">
        <div className="graphwrap">
          <svg viewBox="0 0 800 500" width="100%" style={{ minWidth: 680 }}>
            {[
              ["internet", "fw-edge-01"], ["fw-edge-01", "rtr-core-1"], ["rtr-core-1", "sw-dc-01"],
              ["rtr-core-1", "vpn-01"], ["sw-dc-01", "lb-pay-01"], ["lb-pay-01", "app-pay-01"],
              ["lb-pay-01", "db-pay-01"],
            ].map(([a, b]) => {
              const na = TOPO.find((t) => t.id === a)!;
              const nb = TOPO.find((t) => t.id === b)!;
              return <path key={`${a}-${b}`} className="edge" d={`M${na.x} ${na.y + 26} L${nb.x} ${nb.y - 26}`} />;
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
            Open services:<br />
            {" ├── TLS 1.3 · AES-256-GCM · X25519"}<br />
            {" ├── SSH-2 · Ed25519"}<br />
            {" └── IPsec IKEv2 (VPN)"}
          </div>
          <Panel title="Certificates" sub="served by this endpoint" frame>
            {detail.certs.length ? detail.certs.map((c) => <Badge key={c} tone="cyan">{c}</Badge>) : <span className="faint" style={{ fontSize: 13 }}>none</span>}
          </Panel>
          <Panel title="Evidence" sub="linked artifacts" frame className="mt">
            <div className="mono dim" style={{ fontSize: 12 }}>
              ev-00919 · network agent · 100%<br />
              ev-00918 · port scan · 99%
            </div>
            <a href="#/evidence" className="mono" style={{ fontSize: 12 }}>open evidence chain →</a>
          </Panel>
        </Drawer>
      )}
    </>
  );
}
