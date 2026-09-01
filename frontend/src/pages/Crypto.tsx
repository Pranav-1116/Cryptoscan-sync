import React from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import { algorithms, protocols, libraries } from "../data/demo.js";

export default function Crypto() {
  const crypto = {
    algorithms: 18492,
    certificates: 7821,
    libraries: 1294,
    protocols: 5821,
    endpoints: 8491,
    unknown: 184,
  };
  return (
    <>
      <PageHead
        crumb="discovery / cryptography"
        title="Cryptography"
        sub="The cryptographic state of the entire estate"
        right={<Badge tone="red"><span className="dot" /> 184 UNKNOWN CRYPTO</Badge>}
      />
      <div className="grid cols-5" style={{ marginBottom: 16 }}>
        {[
          ["algorithms", crypto.algorithms], ["certificates", crypto.certificates],
          ["crypto libraries", crypto.libraries], ["protocols", crypto.protocols],
          ["crypto endpoints", crypto.endpoints],
        ].map(([k, v]) => (
          <div className="kpi" key={k}><span className="k">{k}</span><span className="v">{v.toLocaleString()}</span></div>
        ))}
      </div>
      <Panel title="Algorithm usage" sub="deterministic classification per NIST transition rules">
        <Table
          head={["algorithm", "operation", "library", "usages", "quantum status", "priority"]}
          rows={algorithms.slice(0, 10).map((a) => [
            <span className="mono" style={{ fontWeight: 600 }}>{a.name}</span>,
            a.op,
            a.library,
            <span className="num">{a.usageCount.toLocaleString()}</span>,
            <Badge>{a.quantum}</Badge>,
            <Badge>{a.priority}</Badge>,
          ])}
        />
      </Panel>
      <div className="grid cols-2 mt">
        <Panel title="Protocols" sub="TLS · SSH · IPsec · QUIC posture">
          <Table
            head={["protocol", "version", "risk", "pqc"]}
            rows={protocols.slice(0, 6).map((p) => [
              <Badge tone="cyan">{p.protocol}</Badge>,
              p.version,
              <Badge>{p.risk}</Badge>,
              <Badge>{p.pqc}</Badge>,
            ])}
          />
        </Panel>
        <Panel title="Libraries" sub="PQC support per library">
          <Table
            head={["library", "version", "pqc"]}
            rows={libraries.slice(0, 7).map((l) => [
              <span className="mono">{l.name}</span>,
              l.version,
              l.pqc ? <Badge tone="green">SUPPORTED</Badge> : <Badge tone="amber">NOT YET</Badge>,
            ])}
          />
        </Panel>
      </div>
    </>
  );
}
