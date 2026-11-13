/* Capacity & Forecasting rules (docs/performance/03_UI_SPEC.md §9):
   every forecast carries its observation period, coverage, assumptions
   and uncertainty; the brief's questions are answered from real forecast
   rows only — an unanswered question is a named gap, never a guess. */

import { describe, expect, it } from "vitest";
import { CAPACITY_FEATURES, capacityQuestions, featureState, type CapacityForecastRow } from "./capacityBrief";

const forecast: CapacityForecastRow = {
  metric_name: "storage.used_bytes", status: "forecast", method: "linear-extrapolation",
  sample_count: 5, growth_per_second: 0.1, estimated_seconds_to_exhaustion: 51600,
  disclaimer: "forecast, not fact — a linear extrapolation of the window's growth rate, not a promise about the future",
  note: "",
  observation_period: "2026-10-16T00:00:00+00:00 to 2026-10-16T12:00:00+00:00",
  coverage: "5 delivered, 1 unknown of 6 samples in window",
  assumptions: "linear-extrapolation over the observation period at 0.1 units/sec",
  uncertainty: "a forecast is not a guaranteed future result — it is an extrapolation of the observation period's delivered samples and its assumptions hold only while the observed trend holds",
};

describe("Capacity & Forecasting rules (§9)", () => {
  it("answers the storage question only when a forecast row exists", () => {
    const answered = capacityQuestions([forecast]);
    const storage = answered.find((q) => q.question.startsWith("When will storage"))!;
    expect(storage.answered).toBe(true);
    expect(storage.answer).toContain("51600 s");
    // the metadata discipline is part of the answer
    expect(storage.basis).toContain("observation 2026-10-16");
    expect(storage.basis).toContain("5 delivered, 1 unknown of 6 samples");
    expect(storage.basis).toContain("linear-extrapolation over the observation period");
    expect(storage.basis).toContain("a forecast is not a guaranteed future result");
  });

  it("keeps unanswered questions as named gaps, never guesses", () => {
    const answers = capacityQuestions([forecast]);
    const workload = answers.find((q) => q.question.startsWith("Will the current"))!;
    expect(workload.answered).toBe(false);
    expect(workload.answer).toContain("not derivable");
    const hsm = answers.find((q) => q.question.startsWith("What happens to HSM"))!;
    expect(hsm.answered).toBe(false);
    const pqc = answers.find((q) => q.question.startsWith("How much capacity"))!;
    expect(pqc.basis).toContain("benchmark results are never presented as production requirements");
    // CPU saturation: data shown, claim withheld without a threshold
    const cpu = answers.find((q) => q.question.startsWith("Which servers"))!;
    expect(cpu.answered).toBe(false);
    expect(cpu.basis).toContain("the claim is withheld");
  });

  it("marks features honestly against the forecast rows", () => {
    expect(featureState([forecast], CAPACITY_FEATURES[1]).state).toBe("forecast present");
    expect(featureState([forecast], CAPACITY_FEATURES[1]).metrics).toEqual(["storage.used_bytes"]);
    expect(featureState([], CAPACITY_FEATURES[6]).state).toBe("not derivable");
    expect(featureState([], CAPACITY_FEATURES[6]).metrics).toEqual([]);
  });

  it("does not call no-capacity or insufficient-data rows forecasts", () => {
    const noCapacity: CapacityForecastRow = {
      ...forecast, status: "no-capacity", estimated_seconds_to_exhaustion: null,
      note: "a capacity ceiling was not supplied",
    };
    const sparse: CapacityForecastRow = {
      ...forecast, metric_name: "network.throughput_mbps", status: "insufficient-data",
      estimated_seconds_to_exhaustion: null, sample_count: 1,
    };
    const storage = featureState([noCapacity], CAPACITY_FEATURES[1]);
    expect(storage.state).toBe("not derivable");
    expect(storage.metrics).toContain("storage.used_bytes (no-capacity)");
    expect(featureState([sparse], CAPACITY_FEATURES[2]).state).toBe("not derivable");
    expect(capacityQuestions([noCapacity]).find((q) => q.question.startsWith("When will storage"))?.answered).toBe(false);
  });

  it("without rows, even storage is a named gap", () => {
    const storage = capacityQuestions([]).find((q) => q.question.startsWith("When will storage"))!;
    expect(storage.answered).toBe(false);
    expect(storage.answer).toContain("no storage forecast is computable");
    expect(storage.basis).toContain("absence of a forecast is not an absence of saturation");
  });
});
