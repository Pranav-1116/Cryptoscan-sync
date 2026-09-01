import React from "react";
import { Panel, Badge, Bar, Ring, Table, PageHead } from "../components/ui.jsx";
import { pqc } from "../data/demo.js";

export default function Pqc() {
  return (
    <>
      <PageHead
        crumb="post-quantum / pqc readiness"
        title="PQC readiness"
        sub="Executive-level view of the quantum transition"
        right={<Badge tone="violet">OVERALL {pqc.overall}%</Badge>}
      />
      <div className="grid cols-2" style={{ marginBottom: 16 }}>
        <Panel title="Overall readiness" sub="one number for the board">
          <div style={{ display: "flex", alignItems: "center", gap: 26, flexWrap: "wrap" }}>
            <Ring pct={pqc.overall / 100} label={`${pqc.overall}%`} sub="READINESS" tone="violet" />
            <div style={{ display: "flex", flexDirection: "column", gap: 12, flex: 1, minWidth: 240 }}>
              {[
                { k: "PQC ready", v: pqc.ready, tone: "green" },
                { k: "Hybrid ready", v: pqc.hybrid, tone: "violet" },
                { k: "Migration required", v: pqc.migrationRequired, tone: "red" },
              ].map((r) => (
                <div key={r.k}>
                  <div className="spread" style={{ marginBottom: 4, fontSize: 13 }}>
                    <span>{r.k}</span><span className="mono">{r.v}%</span>
                  </div>
                  <Bar value={r.v / 100} tone={r.tone} />
                </div>
              ))}
            </div>
          </div>
        </Panel>
        <Panel title="Quantum-vulnerable inventory" sub="by cryptographic family">
          <Table
            head={["family", "usages"]}
            rows={[
              ["RSA", <span className="num">{pqc.vulnerable.rsa.toLocaleString()}</span>],
              ["ECC", <span className="num">{pqc.vulnerable.ecc.toLocaleString()}</span>],
              ["DH", <span className="num">{pqc.vulnerable.dh.toLocaleString()}</span>],
              ["Legacy (MD5 · 3DES · SHA-1)", <span className="num">{pqc.vulnerable.legacy.toLocaleString()}</span>],
            ].map(([k, v]) => [k, v])}
          />
        </Panel>
      </div>
      <Panel title="By cryptographic function" sub="safe / vulnerable / unknown per function class">
        <Table
          head={["function", "quantum-safe", "quantum-vulnerable", "unknown"]}
          rows={pqc.byFunction.map((p) => [
            <Badge tone="cyan">{p.group}</Badge>,
            <span className="row">{p.safe.map((s) => <Badge key={s} tone="green">{s}</Badge>)}</span>,
            <span className="row">{p.vulnerable.map((v) => <Badge key={v} tone="red">{v}</Badge>)}</span>,
            <span className="num">{p.unknown}</span>,
          ])}
        />
      </Panel>
      <Panel title="Migration map" sub="current → affected → dependencies → candidate PQC → compatibility → complexity" className="mt">
        <div className="tree">
          Current: RSA-2048<br />
          {"  ↓ affected applications: 184"}<br />
          {"  ↓ dependencies: 6 libraries · 2 HSMs · 3 cloud KMS"}<br />
          {"  ↓ candidate PQC: ML-KEM-768 (key exchange) · ML-DSA-65 (signature)"}<br />
          {"  ↓ compatibility: 82%"}<br />
          {"  ↓ migration complexity: MEDIUM"}<br />
          <a href="#/whatif" className="mono" style={{ fontSize: 12 }}>run the what-if simulator →</a>
        </div>
      </Panel>
    </>
  );
}
