/**
 * Capacity & Forecasting (docs/performance/03_UI_SPEC.md §9): the brief's
 * questions are answered from real forecast rows only — an unanswered
 * question is a named gap, never a guess. Every forecast carries its
 * observation period, coverage, assumptions and uncertainty: a forecast
 * is not a guaranteed future result.
 */

export interface CapacityForecastRow {
  metric_name: string;
  status: string;
  method: string;
  sample_count: number;
  growth_per_second?: number | null;
  estimated_seconds_to_exhaustion?: number | null;
  disclaimer: string;
  note: string;
  observation_period?: string | null;
  coverage?: string | null;
  assumptions?: string | null;
  uncertainty?: string | null;
}

export interface CapacityAnswer {
  question: string;
  answer: string;
  answered: boolean;
  basis: string;
}

/** The eight planning features — each is named with its honest state. */
export const CAPACITY_FEATURES: Array<{ key: string; label: string; probes: string[] }> = [
  { key: "cpu_memory", label: "CPU and memory capacity planning", probes: ["cpu.", "ram.", "system.load"] },
  { key: "storage", label: "Storage growth forecasting", probes: ["storage."] },
  { key: "network", label: "Network bandwidth planning", probes: ["network."] },
  { key: "database", label: "Database growth projections", probes: ["db."] },
  { key: "hsm", label: "HSM capacity and throughput forecasting", probes: ["crypto.hsm", "crypto.kms", "cloud.kms"] },
  { key: "transactions", label: "Transaction peak modelling", probes: ["api.requests", "db.transactions"] },
  { key: "pqc", label: "PQC migration resource estimates", probes: ["pqc", "ml-kem", "ml-dsa"] },
  { key: "alerts", label: "Capacity threshold alerts", probes: ["capacity", "saturation"] },
];

export function featureState(rows: CapacityForecastRow[], feature: { probes: string[] }): {
  state: string; metrics: string[];
} {
  const metrics = rows.filter((r) =>
    feature.probes.some((probe) => r.metric_name.startsWith(probe))).map((r) => r.metric_name);
  return { state: metrics.length ? "forecast present" : "not derivable", metrics };
}

/** The brief's five questions, answered from the forecast rows only. */
export function capacityQuestions(rows: CapacityForecastRow[]): CapacityAnswer[] {
  const find = (probe: string) => rows.find((r) => r.metric_name.startsWith(probe)
    && r.status === "forecast" && r.estimated_seconds_to_exhaustion != null);
  const storage = find("storage.");
  const saturated = rows.filter((r) => r.metric_name.startsWith("cpu."))
    .flatMap((r) => r.metric_name);
  return [
    {
      question: "Will the current infrastructure handle the future workload?",
      answer: "a workload forecast needs transaction and resource series modelled together — not derivable in this window",
      answered: false,
      basis: "named gap — the engine never guesses a future workload",
    },
    {
      question: "When will storage capacity become insufficient?",
      answer: storage
        ? `estimated exhaustion in ${Math.round(storage.estimated_seconds_to_exhaustion ?? 0)} s (${storage.method}) — the forecast row below carries its disclaimer`
        : "no storage forecast is computable in this window",
      answered: Boolean(storage),
      basis: storage
        ? `observation ${storage.observation_period ?? "not recorded"} · coverage ${storage.coverage ?? "not recorded"} · ${storage.assumptions ?? "assumptions not recorded"} · ${storage.uncertainty ?? ""}`
        : "named gap — absence of a forecast is not an absence of saturation",
    },
    {
      question: "Which servers regularly experience CPU saturation?",
      answer: saturated.length
        ? `CPU series exist for ${saturated.join(", ")} — regularity cannot be claimed without a recorded saturation threshold`
        : "no CPU series is stored in this window",
      answered: false,
      basis: "a saturation claim needs a recorded threshold policy — data is shown, the claim is withheld",
    },
    {
      question: "What happens to HSM performance at peak transaction volume?",
      answer: "peak-impact modelling needs correlated HSM and transaction series — not derivable in this window",
      answered: false,
      basis: "named gap — a correlation alone would not prove the peak's effect",
    },
    {
      question: "How much capacity will a PQC migration require?",
      answer: "PQC migration resource estimates need benchmark baselines and workload models — not derivable from telemetry alone",
      answered: false,
      basis: "named gap — benchmark results are never presented as production requirements",
    },
  ];
}
