/* Cryptographic Performance (docs/performance/03_UI_SPEC.md §6): the ten
   categories — production telemetry only, benchmark results never mixed
   in; gaps are named (encryption/decryption have no collector family;
   PQC is benchmark-only), never zero-filled. */

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import CryptoWorkspace from "./CryptoWorkspace";

const summary = {
  sample_count: 8, value_count: 6, unknown_count: 2,
  coverage: "partial — 6/8 delivered",
  average: 42, minimum: 30, maximum: 60, p50: 40, p95: 58, p99: 60,
};

const data = {
  categories: {
    tls: { state: "measured", metrics: { "crypto.tls_handshake_ms": summary }, basis: "" },
    encryption: { state: "not_collected", metrics: {}, basis: "encryption throughput and operation latency have no dedicated collector family — a named gap, never zeros" },
    decryption: { state: "not_collected", metrics: {}, basis: "decryption throughput and operation latency have no dedicated collector family — a named gap, never zeros" },
    signatures: { state: "measured", metrics: { "crypto.sign_latency_ms": summary, "crypto.verify_latency_ms": summary }, basis: "" },
    keygen: { state: "measured", metrics: { "crypto.keygen_duration_ms": summary }, basis: "" },
    algorithms: { state: "measured", metrics: { "Ed25519": summary }, basis: "" },
    libraries: { state: "not_collected", metrics: {}, basis: "no provider-attributed telemetry is stored in the window" },
    pqc: { state: "benchmark-only", metrics: {}, basis: "ML-KEM and ML-DSA performance is benchmark-only here — no production PQC telemetry is collected" },
    errors: { state: "not_collected", metrics: {}, basis: "no provider-error telemetry is stored in the window" },
    resources: { state: "not_collected", metrics: {}, basis: "CPU consumption and memory overhead of cryptographic operations have no collector family — a named gap" },
  },
  measurement_kind: "observed-production",
  note: "observed production performance only — a controlled benchmark result is never presented as production traffic performance",
};

describe("Cryptographic Performance workspace (§6)", () => {
  it("draws the ten categories with gaps named, never zeroed", () => {
    render(<CryptoWorkspace data={data} />);
    for (const label of ["TLS", "Encryption", "Decryption", "Digital signatures",
      "Key generation", "Algorithms", "Crypto libraries", "PQC (ML-KEM & ML-DSA)",
      "Errors", "Resources"]) {
      expect(screen.getAllByText(label).length).toBeGreaterThanOrEqual(1);
    }
    expect(screen.getAllByText(/a named gap, never zeros/).length).toBeGreaterThanOrEqual(2);
    expect(screen.getAllByText(/collector family/).length).toBeGreaterThanOrEqual(3);
    expect(screen.queryByText("0")).not.toBeInTheDocument();
  });

  it("keeps PQC benchmark-only and production telemetry separate", () => {
    render(<CryptoWorkspace data={data} />);
    expect(screen.getAllByText("benchmark-only").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/no production PQC telemetry is collected/).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/never presented as production traffic performance/).length).toBeGreaterThanOrEqual(1);
  });

  it("keeps an empty read honest", () => {
    render(<CryptoWorkspace data={{ categories: {}, measurement_kind: "observed-production", note: "" }} />);
    expect(screen.getByText(/absence of telemetry is not healthy cryptography/)).toBeInTheDocument();
  });
});
