import React from "react";
import { Panel, Badge, PageHead } from "../components/ui.jsx";

/* Unified live environment visualization (spec §5) — the five discovery
   domains feeding cryptography → applications → CBOM. */

export default function LiveEnvironment() {
  return (
    <>
      <PageHead
        crumb="command center / live environment"
        title="Live environment"
        sub="One graph across network, cloud, vendor, hardware, cryptography and applications"
        right={<Badge tone="green"><span className="dot" /> RECONCILED 2,403 RELATIONSHIPS</Badge>}
      />

      <Panel title="Unified map" sub="every domain feeds the cryptography layer — zoom global → region → org → environment → asset → crypto dependency">
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 14, padding: "18px 0 8px", overflowX: "auto" }}>
          <div className="row" style={{ justifyContent: "center", gap: 18 }}>
            <EnvNode name="Network" icon="◈" count="611 assets" />
            <EnvNode name="Cloud" icon="☁" count="318 resources" />
            <EnvNode name="Vendor" icon="▤" count="14 vendors" />
          </div>
          <svg width="420" height="26"><path d="M210 0 v14 H80 v-14" stroke="rgba(56,189,248,.5)" fill="none" /><path d="M210 0 v14 H210 v-14" stroke="rgba(56,189,248,.5)" fill="none" /><path d="M210 0 v14 H340 v-14" stroke="rgba(56,189,248,.5)" fill="none" /></svg>
          <div className="row" style={{ justifyContent: "center", gap: 18 }}>
            <EnvNode name="Hardware" icon="⌬" count="259 devices" />
            <EnvNode name="Cryptography" icon="⚿" count="42,391 assets" highlight />
          </div>
          <svg width="300" height="26"><path d="M150 0 v14 H150 v-14" stroke="rgba(56,189,248,.5)" fill="none" /></svg>
          <div className="row" style={{ justifyContent: "center", gap: 18 }}>
            <EnvNode name="Applications" icon="▣" count="87 apps" />
            <EnvNode name="CBOM" icon="⬡" count="v1,843" />
            <EnvNode name="HBOM" icon="⬢" count="v512" />
          </div>
        </div>
      </Panel>

      <div className="grid cols-2 mt">
        <Panel title="Zoom levels" sub="drill from planet to crypto dependency">
          <ol style={{ fontFamily: "var(--mono)", fontSize: 13, color: "var(--dim)", margin: 0, paddingLeft: 18, display: "flex", flexDirection: "column", gap: 6 }}>
            <li>Global <span className="faint">— 4 regions</span></li>
            <li>Region <span className="faint">— IN · UAE · EU · US</span></li>
            <li>Organization <span className="faint">— Global Bank Ltd</span></li>
            <li>Environment <span className="faint">— prod / staging / dev</span></li>
            <li>Asset <span className="faint">— payments-svc · lb-pay-01</span></li>
            <li>Crypto dependency <span className="faint">— RSA-2048 → ML-KEM-768</span></li>
          </ol>
        </Panel>
        <Panel title="Topology (sample)" sub="interactive graph — click any asset for full detail">
          <div className="graphwrap">
            <svg viewBox="0 0 760 260" width="100%" style={{ minWidth: 560 }}>
              <path className="edge" d="M380 30 L380 70" />
              <path className="edge" d="M380 100 L380 130" />
              <path className="edge" d="M380 160 L230 200" />
              <path className="edge" d="M380 160 L530 200" />
              <path className="edge" d="M230 230 L170 260" />
              <path className="edge" d="M230 230 L290 260" />
              <path className="edge" d="M530 230 L470 260" />
              <path className="edge" d="M530 230 L590 260" />
              <g className="gnode"><rect x="330" y="10" width="100" height="40" /><text x="380" y="34" textAnchor="middle">ROOT CA</text></g>
              <g className="gnode"><rect x="305" y="70" width="150" height="40" /><text x="380" y="94" textAnchor="middle">Certificate</text><text x="380" y="106" textAnchor="middle" className="gsub">payments.internal</text></g>
              <g className="gnode"><rect x="315" y="130" width="130" height="40" /><text x="380" y="154" textAnchor="middle">Load balancer</text><text x="380" y="166" textAnchor="middle" className="gsub">lb-pay-01</text></g>
              <g className="gnode"><rect x="145" y="200" width="170" height="40" /><text x="230" y="224" textAnchor="middle">App A · payments-svc</text></g>
              <g className="gnode"><rect x="445" y="200" width="170" height="40" /><text x="530" y="224" textAnchor="middle">App B · auth-svc</text></g>
              <g className="gnode"><rect x="100" y="260" width="140" height="34" /><text x="170" y="281" textAnchor="middle">OpenSSL</text></g>
              <g className="gnode"><rect x="220" y="260" width="140" height="34" /><text x="290" y="281" textAnchor="middle">BouncyCastle</text></g>
              <g className="gnode"><rect x="400" y="260" width="140" height="34" /><text x="470" y="281" textAnchor="middle">RSA-2048</text></g>
              <g className="gnode"><rect x="520" y="260" width="140" height="34" /><text x="590" y="281" textAnchor="middle">ECDSA-P-256</text></g>
            </svg>
          </div>
          <a className="mono" href="#/graph" style={{ fontSize: 12 }}>open full dependency graph →</a>
        </Panel>
      </div>
    </>
  );
}

function EnvNode({ name, icon, count, highlight }: { name: string; icon: string; count: string; highlight?: boolean }) {
  return (
    <div className="frame" style={{ border: "1px solid var(--line-strong)", borderRadius: 12, padding: "14px 26px", background: highlight ? "rgba(139,92,246,0.12)" : "rgba(8,12,24,0.6)", textAlign: "center", minWidth: 150 }}>
      <div style={{ fontSize: 22 }}>{icon}</div>
      <div style={{ fontWeight: 700, fontSize: 15, marginTop: 4 }}>{name}</div>
      <div className="mono faint" style={{ fontSize: 11 }}>{count}</div>
    </div>
  );
}
