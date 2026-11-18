/**
 * HSM & KMS Performance (docs/performance/03_UI_SPEC.md §7): per-device
 * detail with an operation latency trend drawn from delivered samples
 * only — a missing bucket is null, never a fabricated flat point.
 * Collection is vendor-supported and read-only: key material is never
 * collected and HSM operations are never interfered with.
 */
import React from "react";
import { Panel } from "./ui.jsx";

const MEASUREMENT_LABELS: Record<string, string> = {
  availability: "Availability & health",
  throughput: "Request throughput",
  sign_latency: "Sign latency",
  verify_latency: "Verify latency",
  encrypt_latency: "Encrypt latency",
  decrypt_latency: "Decrypt latency",
  keygen_latency: "Key generation latency",
  queue_saturation: "Queue depth & saturation",
  session_utilization: "Session utilization",
  provider_errors: "Provider errors",
  failover: "Failover status",
  firmware_changes: "Firmware & configuration changes",
  kms_latency: "KMS API latency",
  kms_throttling: "KMS throttling",
};

interface HsmMeasurement {
  state: string;
  metrics: Record<string, unknown>;
  basis: string;
}

interface HsmDeviceRow {
  device: string;
  operation_latency_ms?: number | null;
  p95_latency_ms?: number | null;
  queue_depth?: number | null;
  utilization_pct?: number | null;
  provider_errors?: number | null;
  availability_pct?: number | null;
  operations_per_sec?: number | null;
  samples: number;
  last_observed?: string | null;
  trend?: Array<{ bucket: string; value: number | null; samples: number }>;
}

/** Hour-bucketed trend: delivered points only; null buckets draw a
 *  dashed placeholder so a gap is visibly a gap. */
export function TrendBars({ trend }: { trend: Array<{ bucket: string; value: number | null; samples: number }> }) {
  const max = Math.max(1, ...trend.map((p) => p.value ?? 0));
  return (
    <div style={{ display: "flex", gap: 3, alignItems: "flex-end", height: 44 }}>
      {trend.map((point) => (
        <div key={point.bucket} title={`${point.bucket} — ${point.value === null ? "no samples" : `${point.value} ms (${point.samples} samples)`}`}
          style={{ width: 14, display: "flex", flexDirection: "column", justifyContent: "flex-end", height: "100%" }}>
          {point.value === null ? (
            <div style={{ height: 10, border: "1px dashed var(--slate, #64748b)", borderRadius: 2 }} />
          ) : (
            <div style={{ height: Math.max(3, Math.round((point.value / max) * 40)), background: "var(--accent)", borderRadius: 2 }} />
          )}
        </div>
      ))}
    </div>
  );
}

export default function HsmWorkspace({ data }: {
  data: { devices?: HsmDeviceRow[]; measurements?: Record<string, HsmMeasurement>; note?: string } | null | undefined;
}) {
  const devices = data?.devices ?? [];
  const measurements = data?.measurements ?? {};
  return (
    <div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))", gap: 10, marginBottom: 14 }}>
        {Object.keys(MEASUREMENT_LABELS).map((key) => {
          const m = measurements[key];
          const measured = m?.state === "measured";
          const count = Object.keys(m?.metrics ?? {}).length;
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
              <div style={{ fontSize: 11, opacity: 0.7, marginTop: 4 }}>
                {count ? `${count} series delivered` : "no series in window"}
              </div>
              {m?.basis ? <div style={{ fontSize: 10.5, opacity: 0.65, marginTop: 3 }}>{m.basis}</div> : null}
            </div>
          );
        })}
      </div>

      {!devices.length ? (
        <Panel title="Per-device detail">
          <div style={{ fontSize: 12, opacity: 0.75 }}>
            <span title={"No HSM or KMS performance telemetry is stored in this window — absence of telemetry is not a healthy device."}>{"No HSM or KMS performance telemetry is stored in this window"}</span>
          </div>
        </Panel>
      ) : devices.map((device) => (
        <Panel key={device.device} title={`Device — ${device.device}`} sub="per-device record as delivered">
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 10, marginBottom: 12 }}>
            {[
              { label: "Operations/sec", value: device.operations_per_sec },
              { label: "p95 latency", value: device.p95_latency_ms },
              { label: "Queue utilization", value: device.utilization_pct },
              { label: "Availability", value: device.availability_pct },
            ].map((cell) => (
              <div key={cell.label} style={{ border: "1px solid var(--rule)", borderRadius: 8, padding: "8px 10px" }}>
                <div style={{ fontSize: 11, opacity: 0.75 }}>{cell.label}</div>
                <div style={{ fontSize: 18, fontWeight: 700 }}>{cell.value ?? "—"}</div>
              </div>
            ))}
          </div>
          <div style={{ fontSize: 11, opacity: 0.75, marginBottom: 6 }}>Operation latency trend</div>
          {(device.trend ?? []).length ? (
            <TrendBars trend={device.trend ?? []} />
          ) : (
            <div style={{ fontSize: 12, opacity: 0.75 }}>
              <span title={"No operation-latency samples in this window — a missing trend is a collection gap, not a flat line."}>{"No operation-latency samples in this window"}</span>
            </div>
          )}
        </Panel>
      ))}

      {devices.length > 0 && (
        <Panel title="Device comparison" sub="latest delivered figures">
          <table style={{ width: "100%", fontSize: 12 }}>
            <thead>
              <tr>
                <th style={{ textAlign: "left", padding: 6 }}>Device</th>
                <th style={{ textAlign: "left", padding: 6 }}>Operation latency</th>
                <th style={{ textAlign: "left", padding: 6 }}>Queue depth</th>
                <th style={{ textAlign: "left", padding: 6 }}>Utilization</th>
                <th style={{ textAlign: "left", padding: 6 }}>Provider errors</th>
                <th style={{ textAlign: "left", padding: 6 }}>Last observed</th>
              </tr>
            </thead>
            <tbody>
              {devices.map((d) => (
                <tr key={d.device}>
                  <td style={{ padding: 6 }}>{d.device}</td>
                  <td style={{ padding: 6 }}>{d.operation_latency_ms ?? "—"}</td>
                  <td style={{ padding: 6 }}>{d.queue_depth ?? "—"}</td>
                  <td style={{ padding: 6 }}>{d.utilization_pct ?? "—"}</td>
                  <td style={{ padding: 6 }}>{d.provider_errors ?? "—"}</td>
                  <td style={{ padding: 6 }}>{d.last_observed ? String(d.last_observed).slice(0, 10) : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}

      <div style={{ fontSize: 11, opacity: 0.75, marginTop: 10 }}>{data?.note ?? ""}</div>
    </div>
  );
}
