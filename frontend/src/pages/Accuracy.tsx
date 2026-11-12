import React from "react";
import { Panel, Badge, Bar, Table, PageHead } from "../components/ui.jsx";
import { useLive, LiveStatus } from "../lib/useLive.js";

interface MetricSet {
  precision?: number | null; recall?: number | null; f1?: number | null;
  false_positive_rate?: number | null; false_negative_rate?: number | null; coverage?: number | null; unknown_rate?: number | null;
}

export default function Accuracy() {
  const { data, loading, error } = useLive<Record<string, MetricSet>>("/api/v1/crypto/accuracy", {});
  const rows = Object.entries(data).map(([name, m]) => ({ name, ...m }));
  const valid = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1;
  const mean = (field: keyof MetricSet): number | null => {
    const values = rows.map(row => row[field]).filter(valid);
    return values.length ? values.reduce((a, b) => a + b, 0) / values.length : null;
  };
  const fmt = (value: number | null | undefined, percent = false) => valid(value)
    ? percent ? `${(value * 100).toFixed(1)}%` : value.toFixed(3)
    : "Not measured";

  return (
    <>
      <PageHead
        crumb="quality / accuracy"
        title="Detection quality"
        sub="Returned corpus benchmarks — not bank field accuracy or discovery completeness"
        right={<Badge tone="green"><span className="dot" /> CORPUS RESULTS · REVIEW REQUIRED</Badge>}
      />
      <div style={{ marginBottom: 12 }}><LiveStatus loading={loading} error={error} /></div>
      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        {[
          ["precision", fmt(mean("precision"), true), "green"],
          ["recall", fmt(mean("recall"), true), "green"],
          ["F1", fmt(mean("f1")), "green"],
          ["datasets", String(rows.length), "cyan"],
        ].map(([k, v, tone]) => (
          <div className="kpi" key={k}><span className="k">{k}</span><span className="v" style={{ color: `var(--${tone})` }}>{v}</span></div>
        ))}
      </div>
      <Panel title="Per-dataset breakdown" sub={`${rows.length} datasets · macro averages use only defined returned metrics; missing denominators are not zero`}>
        <Table
          head={["dataset", "precision", "recall", "F1", "false-pos", "false-neg", "coverage"]}
          rows={rows.map((a) => [
            <span className="mono" style={{ fontWeight: 600 }}>{a.name.replace(/_/g, " ")}</span>,
            <span className="num">{fmt(a.precision)}</span>,
            <span className="num">{fmt(a.recall)}</span>,
            <Badge tone="green">{fmt(a.f1)}</Badge>,
            <span className="num">{fmt(a.false_positive_rate, true)}</span>,
            <span className="num">{fmt(a.false_negative_rate, true)}</span>,
            <div style={{ minWidth: 100 }}>{valid(a.coverage) ? <Bar value={a.coverage} tone="green" /> : "Not measured"}</div>,
          ])}
        />
        {rows.length === 0 && !loading && <p className="dim" style={{ fontSize: 13 }}>Benchmark metrics unavailable — run the benchmark to populate.</p>}
      </Panel>
    </>
  );
}
