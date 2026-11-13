/**
 * Cryptographic Benchmark Laboratory (docs/performance/03_UI_SPEC.md §6):
 * the metadata checklist and the comparability gate are RULES that govern
 * the product — a comparison is withheld unless every run records its
 * hardware, implementation, key parameters, payload size and benchmark
 * conditions. The rule is enforced here, not narrated on screen.
 */

export interface BenchmarkResultRow {
  operation: string;
  mean_ms: number;
  min_ms: number;
  max_ms: number;
  samples: number;
  median_ms?: number | null;
  p95_ms?: number | null;
  p99_ms?: number | null;
}

export interface BenchmarkRunLike {
  run_id: string;
  measurement_kind: string;
  approved?: boolean;
  method: Record<string, unknown>;
  results: BenchmarkResultRow[];
  executed_at?: string | null;
}

export interface MetadataField {
  key: string;
  label: string;
  value: string | null;
}

const str = (v: unknown): string | null =>
  v === undefined || v === null || v === "" ? null : String(v);

/** One checklist row per brief-required metadata item. Recorded values
 *  render as-is; anything absent renders null ("not recorded"). */
export function metadataChecklist(run: BenchmarkRunLike): MetadataField[] {
  const m = run.method ?? {};
  const params = (m.algorithm_parameters ?? {}) as Record<string, unknown>;
  const results = run.results ?? [];
  const means = results.map((r) => r.mean_ms);
  const medians = results.map((r) => r.median_ms ?? null);
  const p95s = results.map((r) => r.p95_ms ?? null);
  const p99s = results.map((r) => r.p99_ms ?? null);
  return [
    { key: "cpu_arch", label: "CPU and architecture", value: str(m.hardware) },
    { key: "os_kernel", label: "Operating system and kernel", value: str(m.os_kernel) ?? str(m.operating_system) },
    { key: "library_version", label: "Library/provider version", value: [str(m.provider), str(m.software)].filter(Boolean).join(" — ") || null },
    { key: "algorithm", label: "Algorithm and parameter set", value: [str(m.algorithm), params && Object.keys(params).length ? JSON.stringify(params) : null].filter(Boolean).join(" ") },
    { key: "key_size", label: "Key size", value: str(params.key_size) ?? str(params.key_bits) },
    { key: "payload", label: "Message/payload size", value: str(m.payload_size) ?? str(m.message_size) },
    { key: "iterations", label: "Number of iterations", value: str(m.sample_count) },
    { key: "warmup", label: "Warm-up period", value: str(m.warmup) ?? str(m.warm_up) },
    { key: "concurrency", label: "Concurrency", value: str(m.concurrency) },
    {
      key: "percentiles", label: "Mean, median, p95 and p99",
      value: means.length
        ? `mean ${Math.min(...means)}–${Math.max(...means)} ms` +
          (medians.every((v) => v !== null) ? ` · median ${medians.join("/")}` : " · median not recorded") +
          (p95s.every((v) => v !== null) ? ` · p95 ${p95s.join("/")}` : " · p95 not recorded") +
          (p99s.every((v) => v !== null) ? ` · p99 ${p99s.join("/")}` : " · p99 not recorded")
        : null,
    },
    { key: "date_env", label: "Test date and environment", value: run.executed_at ? String(run.executed_at) : null },
  ];
}

const GATE_KEYS: Array<{ key: string; label: string; probe: (m: Record<string, unknown>, r: BenchmarkRunLike) => unknown }> = [
  { key: "hardware", label: "hardware", probe: (m) => m.hardware },
  { key: "implementation", label: "implementation", probe: (m) => m.software ?? m.provider },
  { key: "key_parameters", label: "key parameters", probe: (m) => m.algorithm_parameters },
  { key: "payload_size", label: "payload size", probe: (m) => m.payload_size ?? m.message_size },
  { key: "conditions", label: "benchmark conditions", probe: (m) => m.methodology ?? m.warmup ?? m.warm_up },
];

export interface Comparability {
  comparable: boolean;
  missing: string[];
  basis: string;
}

/** The comparison rule as a function: two algorithms are never compared
 *  unless every run records hardware, implementation, key parameters,
 *  payload size and benchmark conditions. */
export function comparabilityGate(runs: BenchmarkRunLike[]): Comparability {
  const missing = new Set<string>();
  for (const run of runs) {
    const m = run.method ?? {};
    for (const gate of GATE_KEYS) {
      if (gate.probe(m, run) === undefined || gate.probe(m, run) === null || gate.probe(m, run) === "") {
        missing.add(gate.label);
      }
    }
  }
  const missingList = [...missing].sort();
  return {
    comparable: missingList.length === 0 && runs.length > 0,
    missing: missingList,
    basis: missingList.length === 0
      ? ""
      : `comparison withheld — every run must record hardware, implementation, key parameters, payload size and benchmark conditions; not recorded here: ${missingList.join(", ")}`,
  };
}

export interface ComparisonRow {
  algorithm: string;
  operation: string;
  mean_ms: number;
  samples: number;
  run_id: string;
}

/** Algorithm → mean-latency rows per operation. Bars are drawn only when
 *  the gate passes; otherwise the caller shows the withheld basis. */
export function comparisonRows(runs: BenchmarkRunLike[]): ComparisonRow[] {
  const rows: ComparisonRow[] = [];
  for (const run of runs) {
    const algorithm = String((run.method ?? {}).algorithm ?? "not recorded");
    for (const result of run.results ?? []) {
      rows.push({
        algorithm, operation: result.operation,
        mean_ms: result.mean_ms, samples: result.samples, run_id: run.run_id,
      });
    }
  }
  return rows.sort((a, b) =>
    a.operation.localeCompare(b.operation) || a.algorithm.localeCompare(b.algorithm));
}
