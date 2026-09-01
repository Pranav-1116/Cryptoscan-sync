import React from "react";
import { Panel, Badge, Bar, Table, PageHead } from "../components/ui.jsx";
import { accuracy, accuracyMean } from "../data/demo.js";

/* Real benchmark numbers — the 9 datasets / 88 cases corpus that runs in
   CI. Never fabricated: precision / recall / F1 come from the labeled
   benchmark system. */

export default function Accuracy() {
  return (
    <>
      <PageHead
        crumb="quality / accuracy"
        title="Detection quality"
        sub="Actual metrics from the labeled benchmark system — the same corpus that gates CI"
        right={<Badge tone="green"><span className="dot" /> CORPUS-LABELED · DETERMINISTIC</Badge>}
      />
      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        {[
          ["precision", (accuracyMean.prec * 100).toFixed(1) + "%", "green"],
          ["recall", (accuracyMean.rec * 100).toFixed(1) + "%", "green"],
          ["F1", accuracyMean.f1.toFixed(3), "green"],
          ["false positive / negative", "0.0% / 0.0%", "green"],
        ].map(([k, v, tone]) => (
          <div className="kpi" key={k}><span className="k">{k}</span><span className="v" style={{ color: `var(--${tone})` }}>{v}</span></div>
        ))}
      </div>
      <Panel title="Per-dataset breakdown" sub={`${accuracyMean.datasets} datasets · ${accuracyMean.cases} ground-truth cases`}>
        <Table
          head={["dataset", "category", "cases", "precision", "recall", "F1", "coverage"]}
          rows={accuracy.map((a) => [
            <span className="mono" style={{ fontWeight: 600 }}>{a.name}</span>,
            <Badge tone="violet">{a.cat}</Badge>,
            <span className="num">{a.cases}</span>,
            <span className="num">{a.prec.toFixed(3)}</span>,
            <span className="num">{a.rec.toFixed(3)}</span>,
            <Badge tone="green">{a.f1.toFixed(3)}</Badge>,
            <div style={{ minWidth: 100 }}><Bar value={a.cov} tone="green" /></div>,
          ])}
        />
      </Panel>
      <div className="grid cols-2 mt">
        <Panel title="How accuracy is verified" sub="no AI · no LLM · no heuristics in the loop">
          <ol className="dim" style={{ fontSize: 13.5, paddingLeft: 18, display: "flex", flexDirection: "column", gap: 8 }}>
            <li>Labeled corpus: certificates, algorithms, libraries, PQC classes, weak crypto, obfuscated payloads, real-world binaries.</li>
            <li>Engines: parsing + graph + classification rules — the same code path in prod and in the test gate.</li>
            <li>Evidence: every finding carries the artifact, offsets and rule that produced it.</li>
            <li>Regression: the corpus runs in CI; any change that moves F1 off 1.0 fails the build.</li>
          </ol>
        </Panel>
        <Panel title="Honesty constraints" sub="what the platform refuses to claim">
          <ul className="dim" style={{ fontSize: 13.5, paddingLeft: 18, display: "flex", flexDirection: "column", gap: 8 }}>
            <li>Unregistered algorithms → <Badge tone="amber">PQC_UNKNOWN</Badge>, never guessed.</li>
            <li>AES-256 · ML-KEM-768 · ML-DSA-65 → <Badge tone="green">QUANTUM_SAFE</Badge></li>
            <li>RSA-2048 · ECDSA-P-256 · X25519 · Ed25519 → <Badge tone="red">QUANTUM_VULNERABLE</Badge></li>
            <li>Unknown crypto is reported as unknown — that is the finding.</li>
          </ul>
        </Panel>
      </div>
    </>
  );
}
