/* HSM & KMS Performance (docs/performance/03_UI_SPEC.md §7): the eleven
   measurements with named gaps; per-device detail with an operation
   latency trend drawn from delivered samples only — a missing bucket is
   a gap, never a fabricated flat point; collection stays vendor-supported
   and read-only. */

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import HsmWorkspace, { TrendBars } from "./HsmWorkspace";

const data = {
  devices: [
    {
      device: "hsm-payments-1",
      operation_latency_ms: 2.7, p95_latency_ms: 4.1,
      queue_depth: 3, utilization_pct: null, provider_errors: null,
      availability_pct: 99.98, operations_per_sec: null,
      samples: 12, last_observed: "2026-10-16T10:00:00+00:00",
      trend: [
        { bucket: "2026-10-16T08", value: 2.4, samples: 4 },
        { bucket: "2026-10-16T09", value: null, samples: 0 },
        { bucket: "2026-10-16T10", value: 3.1, samples: 3 },
      ],
    },
  ],
  measurements: {
    availability: { state: "measured", metrics: { "availability.uptime_pct": {} }, basis: "" },
    throughput: { state: "not_collected", metrics: {}, basis: "request throughput has no counter family — unknown, never zero" },
    sign_latency: { state: "measured", metrics: { "crypto.sign_latency_ms": {} }, basis: "" },
    verify_latency: { state: "measured", metrics: { "crypto.verify_latency_ms": {} }, basis: "" },
    encrypt_latency: { state: "not_collected", metrics: {}, basis: "encrypt latency has no dedicated collector family — a named gap" },
    decrypt_latency: { state: "not_collected", metrics: {}, basis: "decrypt latency has no dedicated collector family — a named gap" },
    keygen_latency: { state: "not_collected", metrics: {}, basis: "no key-generation telemetry is stored in the window" },
    queue_saturation: { state: "measured", metrics: { "crypto.hsm_queue_depth": {} }, basis: "" },
    session_utilization: { state: "not_collected", metrics: {}, basis: "session utilization has no collector family — a named gap" },
    provider_errors: { state: "not_collected", metrics: {}, basis: "no provider-error telemetry is stored in the window" },
    failover: { state: "not_collected", metrics: {}, basis: "failover status has no collector family — a named gap" },
    firmware_changes: { state: "not_collected", metrics: {}, basis: "firmware and configuration changes are not performance telemetry here — a named gap" },
    kms_latency: { state: "not_collected", metrics: {}, basis: "no KMS latency telemetry is stored in the window" },
    kms_throttling: { state: "not_collected", metrics: {}, basis: "KMS throttling has no collector family — a named gap" },
  },
  measurement_kind: "observed-production",
  note: "vendor-supported read-only management and performance interfaces only — key material is never collected and HSM operations are never interfered with",
};

describe("HSM & KMS Performance workspace (§7)", () => {
  it("draws the eleven measurements with gaps named, never zeroed", () => {
    render(<HsmWorkspace data={data} />);
    for (const label of ["Availability & health", "Request throughput", "Sign latency",
      "Verify latency", "Encrypt latency", "Decrypt latency", "Key generation latency",
      "Queue depth & saturation", "Session utilization", "Provider errors",
      "Failover status", "Firmware & configuration changes", "KMS API latency",
      "KMS throttling"]) {
      expect(screen.getAllByText(label).length).toBeGreaterThanOrEqual(1);
    }
    expect(screen.getAllByText(/no counter family/).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/session utilization has no collector family/).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/failover status has no collector family/).length).toBeGreaterThanOrEqual(1);
    expect(screen.queryByText("0")).not.toBeInTheDocument();
  });

  it("draws the per-device record and trend from delivered points only", () => {
    render(<HsmWorkspace data={data} />);
    expect(screen.getAllByText("hsm-payments-1").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("4.1")).toBeInTheDocument();   // p95
    expect(screen.getByText("99.98")).toBeInTheDocument(); // availability
    // operations/sec was never delivered — unknown, not zero
    expect(screen.getAllByText("—").length).toBeGreaterThanOrEqual(2);
    // the read-only collection rule stays pinned
    expect(screen.getByText(/key material is never collected/)).toBeInTheDocument();
    expect(screen.getByText(/HSM operations are never interfered/)).toBeInTheDocument();
  });

  it("keeps a missing trend bucket visibly a gap", () => {
    render(<TrendBars trend={data.devices[0].trend!} />);
    expect(screen.getByTitle(/2026-10-16T08 — 2.4 ms \(4 samples\)/)).toBeInTheDocument();
    expect(screen.getByTitle(/2026-10-16T09 — no samples/)).toBeInTheDocument();
  });

  it("keeps an empty read honest", () => {
    render(<HsmWorkspace data={{ devices: [], measurements: {}, note: "" }} />);
    expect(screen.getByTitle(/absence of telemetry is not a healthy device/)).toBeInTheDocument();
    render(<HsmWorkspace data={{ devices: [{ device: "hsm-x", samples: 0, trend: [] }], measurements: {}, note: "" }} />);
    expect(screen.getByTitle(/a missing trend is a collection gap, not a flat line/)).toBeInTheDocument();
  });
});
