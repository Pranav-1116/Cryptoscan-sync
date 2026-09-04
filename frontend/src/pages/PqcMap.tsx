import React from "react";
import { Panel, Badge, Bar, Table, PageHead } from "../components/ui.jsx";
import { pqc, whatif } from "../data/initial.js";

/* PQC migration map (spec §21): current → affected applications →
   dependencies → candidate PQC → compatibility → migration complexity. */

export default function PqcMap() {
  return (
    <>
      <PageHead
        crumb="post-quantum / pqc migration map"
        title="PQC migration map"
        sub="Current state → affected applications → dependencies → candidate PQC → compatibility → migration complexity"
        right={<Badge tone="violet">OVERALL READINESS {pqc.overall}%</Badge>}
      />
      <Panel title="Migration path" sub="one deterministic pipeline from current state to PQC">
        <div className="tree" style={{ fontSize: 13.5, lineHeight: 2.2 }}>
          <span className="hl">Current</span>: RSA-2048 · ECDSA-P-256 · X25519 · DH-2048 (quantum vulnerable)<br />
          {"  ↓ affected applications: 184"}<br />
          {"  ↓ dependencies: 6 libraries · 2 HSMs · 3 cloud KMS · 4 vendors"}<br />
          {"  ↓ candidate PQC: ML-KEM-768 (key exchange) · ML-DSA-65 (signature)"}<br />
          {"  ↓ compatibility: "}<Badge tone="green">{whatif.compatibility}%</Badge><br />
          {"  ↓ migration complexity: "}<Badge tone="amber">{whatif.complexity}</Badge><br />
          {"  ↓ target: "}<Badge tone="green">PQC_READY · 100% of TLS/SSH/IPsec</Badge>
        </div>
      </Panel>

      <div className="grid cols-3 mt">
        <Panel title="Vulnerable by family" sub="what must migrate">
          <Table
            head={["family", "usages"]}
            rows={[
              ["RSA", <span className="num">{pqc.vulnerable.rsa.toLocaleString()}</span>],
              ["ECC", <span className="num">{pqc.vulnerable.ecc.toLocaleString()}</span>],
              ["DH", <span className="num">{pqc.vulnerable.dh.toLocaleString()}</span>],
              ["Legacy", <span className="num">{pqc.vulnerable.legacy.toLocaleString()}</span>],
            ]}
          />
        </Panel>
        <Panel title="Candidate algorithms" sub="NIST FIPS 203 / 204">
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {[
              { alg: "ML-KEM-768", use: "key exchange", status: "ACTIVE · 81 usages" },
              { alg: "ML-DSA-65", use: "signature", status: "ACTIVE · 41 usages" },
              { alg: "SLH-DSA", use: "signature (stateless)", status: "CANDIDATE" },
            ].map((c) => (
              <div key={c.alg}>
                <div className="spread" style={{ fontSize: 13.5 }}>
                  <span className="mono" style={{ fontWeight: 600 }}>{c.alg}</span>
                  <Badge tone={c.status.startsWith("ACTIVE") ? "green" : "amber"}>{c.status.split(" · ")[0]}</Badge>
                </div>
                <div className="dim" style={{ fontSize: 12 }}>{c.use} · {c.status.split(" · ")[1]}</div>
              </div>
            ))}
          </div>
        </Panel>
        <Panel title="Migration complexity" sub="per stage">
          <Table
            head={["stage", "complexity"]}
            rows={[
              ["library upgrades", <Badge tone="green">LOW</Badge>],
              ["certificate re-key", <Badge tone="green">LOW</Badge>],
              ["protocol config", <Badge tone="amber">MEDIUM</Badge>],
              ["application code", <Badge tone="amber">MEDIUM</Badge>],
              ["HSM firmware", <Badge tone="red">HIGH</Badge>],
            ]}
          />
        </Panel>
      </div>

      <Panel title="Readiness by stage" sub="how close each layer is" className="mt">
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {[
            { k: "Libraries", v: 0.8, tone: "green" },
            { k: "Certificates", v: 0.65, tone: "amber" },
            { k: "Protocols", v: 0.55, tone: "amber" },
            { k: "Applications", v: 0.31, tone: "red" },
            { k: "Hardware", v: 0.22, tone: "red" },
          ].map((r) => (
            <div key={r.k}>
              <div className="spread" style={{ marginBottom: 4, fontSize: 13 }}>
                <span>{r.k}</span><span className="mono">{(r.v * 100).toFixed(0)}%</span>
              </div>
              <Bar value={r.v} tone={r.tone} />
            </div>
          ))}
        </div>
        <div className="row mt" style={{ marginTop: 16 }}>
          <a href="#/whatif" className="btn sm">Run what-if</a>
          <a href="#/migration" className="btn sm">Open migration planner</a>
        </div>
      </Panel>
    </>
  );
}
