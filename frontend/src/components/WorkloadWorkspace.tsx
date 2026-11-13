/**
 * Workload & Transaction Intelligence (docs/performance/03_UI_SPEC.md §8):
 * business workloads attributed from delivered labels only; peak/off-peak
 * derived from real request samples and labelled derived; crypto overhead
 * per transaction and queue backlogs stay named gaps. The engine reports
 * correlation candidates only — timestamps and traces must correlate
 * before causation is suggested.
 */
import React from "react";
import { Panel } from "./ui.jsx";
import { SummaryTable } from "./InfraWorkspace";

const CATEGORY_LABELS: Record<string, string> = {
  payments: "Payment transactions",
  authentication: "Authentication requests",
  card: "Card authorizations",
  batch: "Batch processing",
};

const MEASUREMENT_LABELS: Record<string, string> = {
  payment_throughput: "Payment transaction throughput",
  authentication_performance: "Authentication request performance",
  card_authorization_latency: "Card authorization latency",
  batch_duration: "Batch processing duration",
  database_transaction_time: "Database transaction time",
  crypto_overhead_per_transaction: "Cryptographic overhead per transaction",
  queue_backlogs: "Queue backlogs",
};

interface WorkloadBlock {
  state: string;
  metrics?: Record<string, unknown>;
  basis?: string;
}

interface WorkloadData {
  workload_metrics?: Record<string, unknown>;
  categories?: Record<string, WorkloadBlock>;
  measurements?: Record<string, WorkloadBlock>;
  peak_offpeak?: Record<string, unknown>;
  correlation_candidates?: Array<Record<string, unknown>>;
  note?: string;
}

export default function WorkloadWorkspace({ data }: { data: WorkloadData | null | undefined }) {
  const categories = data?.categories ?? {};
  const measurements = data?.measurements ?? {};
  const peak = data?.peak_offpeak ?? {};
  const peakDerived = peak.state === "derived";
  return (
    <div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(230px, 1fr))", gap: 10, marginBottom: 14 }}>
        {Object.keys(CATEGORY_LABELS).map((key) => {
          const cat = categories[key];
          const measured = cat?.state === "measured";
          return (
            <div key={key} style={{ border: "1px solid var(--rule)", borderRadius: 8, padding: "8px 10px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}>
                <span style={{ fontSize: 12, fontWeight: 600 }}>{CATEGORY_LABELS[key]}</span>
                <span style={{
                  fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 999, whiteSpace: "nowrap",
                  border: `1px solid ${measured ? "var(--green, #3ecf8e)" : "var(--slate, #64748b)"}`,
                  color: measured ? "var(--green, #3ecf8e)" : "var(--slate, #64748b)",
                }}>{measured ? "measured" : "not collected"}</span>
              </div>
              {cat?.basis ? <div style={{ fontSize: 10.5, opacity: 0.65, marginTop: 4 }}>{cat.basis}</div> : null}
            </div>
          );
        })}
      </div>

      <Panel title="Measurements" sub="the brief's workload measurements as delivered or as named gaps">
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 10 }}>
          {Object.keys(MEASUREMENT_LABELS).map((key) => {
            const m = measurements[key];
            const measured = m?.state === "measured";
            return (
              <div key={key} style={{ border: "1px solid var(--rule)", borderRadius: 8, padding: "8px 10px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}>
                  <span style={{ fontSize: 12, fontWeight: 600 }}>{MEASUREMENT_LABELS[key]}</span>
                  <span style={{
                    fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 999, whiteSpace: "nowrap",
                    border: `1px solid ${measured ? "var(--green, #3ecf8e)" : "var(--slate, #64748b)"}`,
                    color: measured ? "var(--green, #3ecf8e)" : "var(--slate, #64748b)",
                  }}>{measured ? "measured" : "not collected"}</span>
                </div>
                {m?.basis ? <div style={{ fontSize: 10.5, opacity: 0.65, marginTop: 4 }}>{m.basis}</div> : null}
              </div>
            );
          })}
        </div>
      </Panel>

      <div style={{ marginTop: 14 }}>
        <Panel title="Peak and off-peak performance" sub={peakDerived ? "derived from the window's delivered request samples" : "a named gap where no delivered series exists"}>
          {peakDerived ? (
            <div style={{ fontSize: 12 }}>
              <div>
                peak {String(peak.peak_bucket)} · {String(peak.peak_value)} requests/sec —
                off-peak mean {String(peak.offpeak_mean)} requests/sec
              </div>
              <div style={{ opacity: 0.7, marginTop: 4 }}>{String(peak.basis ?? "")}</div>
            </div>
          ) : (
            <div style={{ fontSize: 12, opacity: 0.75 }}>{String(peak.basis ?? "")}</div>
          )}
        </Panel>
      </div>

      {(data?.correlation_candidates ?? []).map((c, i) => (
        <div key={i} style={{ marginTop: 10, fontSize: 12, border: "1px solid var(--rule)", borderRadius: 8, padding: "8px 10px" }}>
          <div style={{ fontWeight: 600 }}>{String(c.question ?? "")}</div>
          <div style={{ opacity: 0.8, marginTop: 4 }}>
            TLS handshake {String(c.tls_handshake_ms ?? "—")} · application p95 {String(c.app_p95_latency_ms ?? "—")}
          </div>
          <div style={{ marginTop: 4, color: "var(--amber, #f59e0b)" }}>Causation: {String(c.causation ?? "unproven")}</div>
          <div style={{ opacity: 0.7 }}>{String(c.basis ?? "")}</div>
        </div>
      ))}

      {Object.keys(data?.workload_metrics ?? {}).length > 0 && (
        <div style={{ marginTop: 12 }}>
          <SummaryTable metrics={data?.workload_metrics as Record<string, never>} />
        </div>
      )}

      <div style={{ fontSize: 11, opacity: 0.75, marginTop: 10 }}>{data?.note ?? ""}</div>
    </div>
  );
}
