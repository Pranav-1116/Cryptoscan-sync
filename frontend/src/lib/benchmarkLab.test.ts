/* Benchmark Laboratory rules (docs/performance/03_UI_SPEC.md §6): the
   metadata checklist records every condition or says "not recorded"; and
   two algorithms are NEVER compared unless every run records hardware,
   implementation, key parameters, payload size and benchmark conditions.
   The rule governs the product; it is enforced here. */

import { describe, expect, it } from "vitest";
import { comparabilityGate, comparisonRows, metadataChecklist, type BenchmarkRunLike } from "./benchmarkLab";

const completeRun: BenchmarkRunLike = {
  run_id: "bench-complete",
  measurement_kind: "controlled_benchmark",
  approved: true,
  method: {
    hardware: "x86_64 (AMD EPYC)",
    software: "python 3.11.9, cryptography 42.0.0",
    provider: "cryptography-library",
    algorithm: "Ed25519",
    algorithm_parameters: { key_size: 256 },
    methodology: "sequential sign/verify timing",
    payload_size: 64,
    warmup: 100,
    concurrency: 1,
    sample_count: 50,
    os_kernel: "Linux 6.8",
  },
  results: [
    { operation: "sign", mean_ms: 0.06, min_ms: 0.05, max_ms: 0.09, samples: 50, median_ms: 0.06, p95_ms: 0.08, p99_ms: 0.09 },
    { operation: "verify", mean_ms: 0.12, min_ms: 0.1, max_ms: 0.2, samples: 50, median_ms: 0.12, p95_ms: 0.18, p99_ms: 0.2 },
  ],
  executed_at: "2026-10-16T10:00:00Z",
};

const sparseRun: BenchmarkRunLike = {
  run_id: "bench-sparse",
  measurement_kind: "controlled_benchmark",
  approved: true,
  method: {
    hardware: "aarch64 (unknown)",
    software: "python 3.11.9, cryptography 42.0.0",
    provider: "cryptography-library",
    algorithm: "RSA-2048",
    algorithm_parameters: {},
    methodology: "sequential sign/verify timing",
    concurrency: 1,
    sample_count: 50,
  },
  results: [{ operation: "sign", mean_ms: 1.9, min_ms: 1.5, max_ms: 3.1, samples: 50 }],
  executed_at: "2026-10-16T11:00:00Z",
};

describe("Benchmark Laboratory rules (§6)", () => {
  it("records every checklist item or says not recorded", () => {
    const rows = metadataChecklist(sparseRun);
    const byKey = Object.fromEntries(rows.map((r) => [r.key, r.value]));
    expect(byKey.cpu_arch).toBe("aarch64 (unknown)");
    expect(byKey.iterations).toBe("50");
    expect(byKey.concurrency).toBe("1");
    // OS/kernel, key size, payload size and warm-up were never recorded
    expect(byKey.os_kernel).toBeNull();
    expect(byKey.key_size).toBeNull();
    expect(byKey.payload).toBeNull();
    expect(byKey.warmup).toBeNull();
    expect(byKey.percentiles).toContain("median not recorded");
    expect(byKey.percentiles).toContain("p95 not recorded");
  });

  it("refuses a cross-algorithm comparison without payload size and conditions", () => {
    const gate = comparabilityGate([completeRun, sparseRun]);
    expect(gate.comparable).toBe(false);
    expect(gate.missing).toContain("payload size");
    expect(gate.basis).toContain("comparison withheld");
    expect(gate.basis).toContain("payload size and benchmark conditions");
    expect(gate.basis).toContain("not recorded here: payload size");
  });

  it("allows the comparison when every run records the conditions", () => {
    const gate = comparabilityGate([completeRun, { ...completeRun, run_id: "bench-complete-2", method: { ...completeRun.method, algorithm: "ECDSA-P256" } }]);
    expect(gate.comparable).toBe(true);
    expect(gate.basis).toBe("");
  });

  it("groups rows per algorithm and operation without inventing results", () => {
    const rows = comparisonRows([completeRun, sparseRun]);
    expect(rows.map((r) => `${r.algorithm}:${r.operation}`)).toEqual([
      "Ed25519:sign", "RSA-2048:sign", "Ed25519:verify",
    ]);
    expect(rows.every((r) => r.mean_ms > 0)).toBe(true);
  });
});
