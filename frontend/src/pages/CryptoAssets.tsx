import React, { useState } from "react";
import { Panel, Badge, Bar, Table, Drawer, PageHead } from "../components/ui.jsx";
import { algorithms } from "../data/initial.js";

/* Algorithm explorer (spec §11) + crypto asset detail drawer (spec §12). */

const FILTERS = ["all", "vulnerable", "safe", "critical"];

export default function CryptoAssets() {
  const [f, setF] = useState(0);
  const [sel, setSel] = useState(-1);

  const filtered = algorithms.filter((a) => {
    if (f === 1) return a.quantum === "QUANTUM_VULNERABLE";
    if (f === 2) return a.quantum === "QUANTUM_SAFE";
    if (f === 3) return a.priority === "CRITICAL" || a.priority === "HIGH";
    return true;
  });

  return (
    <>
      <PageHead
        crumb="inventory / crypto assets"
        title="Crypto assets"
        sub="Algorithm explorer — usage, assets, quantum status, confidence. Click a row for the full asset detail."
        right={<Badge tone={algorithms.length ? "cyan" : ""}><span className="dot" /> {algorithms.length.toLocaleString()} CRYPTO ASSETS</Badge>}
      />
      <div className="tabs">
        {["all", "quantum vulnerable", "quantum safe", "critical / high"].map((t, i) => (
          <button key={t} className={i === f ? "active" : ""} onClick={() => setF(i)}>{t}</button>
        ))}
      </div>
      <Panel title="Algorithm explorer" sub="deterministic classification — confidence comes from the evidence chain">
        <Table
          clickable
          selected={sel}
          onSelect={setSel}
          head={["algorithm", "usage", "assets", "quantum status", "confidence", "priority"]}
          rows={filtered.map((a) => [
            <span className="mono" style={{ fontWeight: 600 }}>{a.name}</span>,
            <span className="num">{a.usageCount.toLocaleString()}</span>,
            <span className="num">{a.assets.toLocaleString()}</span>,
            <Badge>{a.quantum}</Badge>,
            <div style={{ minWidth: 120 }}>
              <span className="mono" style={{ fontSize: 11.5 }}>{(a.confidence * 100).toFixed(1)}%</span>
              <Bar value={a.confidence} tone={a.quantum === "QUANTUM_SAFE" ? "green" : "amber"} />
            </div>,
            <Badge>{a.priority}</Badge>,
          ])}
        />
      </Panel>
      {sel >= 0 && <DetailDrawer name={filtered[sel].name} onClose={() => setSel(-1)} />}
    </>
  );
}

function DetailDrawer({ name, onClose }: { name: string; onClose: () => void }) {
  const alg = algorithms.find((a) => a.name === name)!;
  return (
    <Drawer
      title={alg.name}
      sub={`${alg.op} · library ${alg.library} · confidence ${(alg.confidence * 100).toFixed(1)}%`}
      onClose={onClose}
    >
      <div className="row" style={{ marginBottom: 16 }}>
        <Badge>{alg.quantum}</Badge>
        <Badge>{alg.priority} PRIORITY</Badge>
      </div>
      <div className="kpi" style={{ marginBottom: 8 }}><span className="k">usages</span><span className="v">{alg.usageCount.toLocaleString()}</span></div>
      <div className="kpi" style={{ marginBottom: 8 }}><span className="k">assets</span><span className="v">{alg.assets.toLocaleString()}</span></div>
      <div className="kpi" style={{ marginBottom: 16 }}><span className="k">in use</span><span className="v">{alg.usage ? "yes" : "no"}</span></div>
      <Panel title="Dependencies" sub="graph edges from the CBOM">
        <span className="dim" style={{ fontSize: 12.5 }}>Dependency edges are derived from the live CBOM — none linked to a dependency graph yet.</span>
      </Panel>
      <Panel title="Evidence" sub="linked artifacts" frame className="mt">
        <div className="mono dim" style={{ fontSize: 12 }}>
          Detected via {alg.library} · confidence {(alg.confidence * 100).toFixed(1)}%
        </div>
        <a href="#/evidence" className="mono" style={{ fontSize: 12 }}>open evidence chain →</a>
      </Panel>
      <Panel title="Migration options" sub="deterministic what-if" frame className="mt">
        <div className="row">
          <a href="#/whatif" className="btn sm">What-if → ML-KEM-768</a>
          <a href="#/migration" className="btn sm">Migration plan</a>
        </div>
      </Panel>
    </Drawer>
  );
}
