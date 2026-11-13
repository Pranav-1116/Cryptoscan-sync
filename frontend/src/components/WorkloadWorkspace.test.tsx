/* Workload & Transaction Intelligence (docs/performance/03_UI_SPEC.md
   §8): business workloads attributed from delivered labels only; peak vs
   off-peak derived and labelled derived; crypto overhead per transaction
   stays a named gap; correlation candidates never upgrade to causation. */

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import WorkloadWorkspace from "./WorkloadWorkspace";

const summary = {
  sample_count: 8, value_count: 6, unknown_count: 2,
  coverage: "partial — 6/8 delivered",
  average: 42, minimum: 30, maximum: 60, p50: 40, p95: 58, p99: 60,
};

const data = {
  workload_metrics: { "api.requests_per_sec": summary },
  categories: {
    payments: { state: "measured", metrics: { "api.requests_per_sec": summary }, basis: "" },
    authentication: { state: "not_collected", metrics: {}, basis: "no authentication workload telemetry is labelled in the window — workload performance is not inferred from infrastructure metrics" },
    card: { state: "not_collected", metrics: {}, basis: "no card workload telemetry is labelled in the window — workload performance is not inferred from infrastructure metrics" },
    batch: { state: "not_collected", metrics: {}, basis: "no batch workload telemetry is labelled in the window — workload performance is not inferred from infrastructure metrics" },
  },
  measurements: {
    payment_throughput: { state: "measured", metrics: {}, basis: "" },
    authentication_performance: { state: "not_collected", metrics: {}, basis: "" },
    card_authorization_latency: { state: "not_collected", metrics: {}, basis: "" },
    batch_duration: { state: "not_collected", metrics: {}, basis: "" },
    database_transaction_time: { state: "measured", metrics: {}, basis: "" },
    crypto_overhead_per_transaction: { state: "not_collected", metrics: {}, basis: "cryptographic overhead per transaction has no collector family — it is never inferred from crypto latency alone, a named gap" },
    queue_backlogs: { state: "not_collected", metrics: {}, basis: "queue depth has no collector family — a named gap" },
  },
  peak_offpeak: {
    state: "derived", peak_bucket: "2026-10-16T10", peak_value: 520, offpeak_mean: 310,
    buckets: [{ bucket: "2026-10-16T09", value: 310 }, { bucket: "2026-10-16T10", value: 520 }],
    basis: "derived from the window's delivered request samples — derived figures are labelled derived",
  },
  correlation_candidates: [{
    question: "does TLS handshake time contribute to application latency?",
    tls_handshake_ms: 41, app_p95_latency_ms: 210, causation: "unproven",
    basis: "a time correlation alone never proves causation — timestamps and traces must correlate before causation is suggested",
  }],
  causation: "unproven",
  note: "the engine reports correlation candidates only — it must correlate timestamps and traces before suggesting causation",
};

describe("Workload & Transaction Intelligence (§8)", () => {
  it("draws the business workloads with unlabelled traffic never claimed", () => {
    render(<WorkloadWorkspace data={data} />);
    for (const label of ["Payment transactions", "Authentication requests", "Card authorizations", "Batch processing"]) {
      expect(screen.getAllByText(label).length).toBeGreaterThanOrEqual(1);
    }
    expect(screen.getAllByText(/not inferred from infrastructure metrics/).length).toBeGreaterThanOrEqual(3);
    expect(screen.queryByText("0")).not.toBeInTheDocument();
  });

  it("keeps crypto overhead per transaction a named gap", () => {
    render(<WorkloadWorkspace data={data} />);
    expect(screen.getAllByText(/Cryptographic overhead per transaction/).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/never inferred from crypto latency alone/).length).toBeGreaterThanOrEqual(1);
  });

  it("labels peak vs off-peak as derived from real samples", () => {
    render(<WorkloadWorkspace data={data} />);
    expect(screen.getAllByText(/peak 2026-10-16T10/).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/derived figures are labelled derived/).length).toBeGreaterThanOrEqual(1);
  });

  it("never upgrades a workload correlation to causation", () => {
    render(<WorkloadWorkspace data={data} />);
    expect(screen.getAllByText(/Causation: unproven/).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/timestamps and traces must correlate before causation/).length).toBeGreaterThanOrEqual(1);
    expect(screen.queryByText(/caused/i)).not.toBeInTheDocument();
  });
});
