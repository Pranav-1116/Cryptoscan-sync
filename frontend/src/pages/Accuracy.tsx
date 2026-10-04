import React from "react";
import { Panel, Badge, Bar, Table, PageHead } from "../components/ui.jsx";
import { useLive, LiveStatus } from "../lib/useLive.js";

interface MetricSet {
  precision: number; recall: number; f1: number;
  false_positive_rate: number; false_negative_rate: number; coverage: number; unknown_rate?: number;
}

export default function Accuracy() {
  const { data, loading, error } = useLive<Record<string, MetricSet>>("/api/v1/crypto/accuracy", {});
  const rows = Object.entries(data).map(([name, m]) => ({ name, ...m }));
  const mean = rows.length
    ? rows.reduce((a, r) => ({ prec: a.prec + (r.precision || 0), rec: a.rec + (r.recall || 0), f1: a.f1 + (r.f1 || 0) }), { prec: 0, rec: 0, f1: 0 })
    : { prec: 0, rec: 0, f1: 0 };
  const n = rows.length || 1;
  const meanPrec = (mean.prec / n) * 100;
  const meanRec = (mean.rec / n) * 100;
  const meanF1 = mean.f1 / n;

  return (
    <>
      <PageHead
        crumb="quality / accuracy"
        title="Detection quality"
        sub="Actual metrics from the labeled benchmark system — the same corpus that gates CI"
        right={<Badge tone="green"><span className="dot" /> CORPUS-LABELED · DETERMINISTIC</Badge>}
      />
      <div style={{ marginBottom: 12 }}><LiveStatus loading={loading} error={error} /></div>
      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        {[
          ["precision", meanPrec.toFixed(1) + "%", "green"],
          ["recall", meanRec.toFixed(1) + "%", "green"],
          ["F1", meanF1.toFixed(3), "green"],
          ["datasets", String(rows.length), "cyan"],
        ].map(([k, v, tone]) => (
          <div className="kpi" key={k}><span className="k">{k}</span><span className="v" style={{ color: `var(--${tone})` }}>{v}</span></div>
        ))}
      </div>
      <Panel title="Per-dataset breakdown" sub={`${rows.length} datasets · metrics computed live by the deterministic benchmark engine`}>
        <Table
          head={["dataset", "precision", "recall", "F1", "false-pos", "false-neg", "coverage"]}
          rows={rows.map((a) => [
            <span className="mono" style={{ fontWeight: 600 }}>{a.name.replace(/_/g, " ")}</span>,
            <span className="num">{(a.precision ?? 0).toFixed(3)}</span>,
            <span className="num">{(a.recall ?? 0).toFixed(3)}</span>,
            <Badge tone="green">{(a.f1 ?? 0).toFixed(3)}</Badge>,
            <span className="num">{((a.false_positive_rate ?? 0) * 100).toFixed(1)}%</span>,
            <span className="num">{((a.false_negative_rate ?? 0) * 100).toFixed(1)}%</span>,
            <div style={{ minWidth: 100 }}><Bar value={a.coverage ?? 0} tone="green" /></div>,
          ])}
        />
        {rows.length === 0 && !loading && <p className="dim" style={{ fontSize: 13 }}>Benchmark metrics unavailable — run the benchmark to populate.</p>}
      </Panel>
      <div className="grid cols-2 mt">
        <Panel title="How accuracy is verified" sub="labeled corpus · deterministic rules · replayable evidence">
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
