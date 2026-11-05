import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { expect, it } from "vitest";
import GroundTruthPanel from "./GroundTruthPanel";
import { mockFetch } from "../test/setup";

/* A coverage number is only as good as its denominator, and the platform cannot compute
   one. These tests pin the three ways a panel like this could lie: print a percentage for
   a class nobody declared, print >100% as coverage, or call the bank wrong for an asset
   the estate does not hold. */

const MEASURE = "/api/v1/estate/evidence/twin/ground-truth";

function doc(overrides: Record<string, unknown> = {}) {
  return {
    schema: "cryptoscan.estate-ground-truth-measurement/1",
    status: "MEASURED",
    declared_by: "bank/inventory",
    live_state_modified: false,
    population: {
      rows: [
        { asset_type: "HOST", declared: 120, collected: 118, evidenced: 110, unevidenced: 8,
          status: "PARTIAL", note: "120 declared, 118 collected", collected_percent: 98.3 },
        { asset_type: "HSM", declared: 8, collected: 9, evidenced: 9, unevidenced: 0,
          status: "OVER_DECLARED", note: "9 found against 8 declared — not 112.5% coverage",
          collected_percent: null },
        { asset_type: "LIBRARY", declared: null, collected: 42, evidenced: 40, unevidenced: 2,
          status: "NOT_DECLARED", note: "no denominator", collected_percent: null },
      ],
      declared_classes: 2, classes_with_a_denominator: 2, classes_not_declared: 1,
      disagreements: [{ asset_type: "HSM" }],
      meaning: "declared counts are a bank's own denominator.",
    },
    claims: {
      results: [
        { claim_id: "c1", type: "ASSET_PRESENCE", verdict: "MATCHED",
          reason: "present as APPLICATION 'Payment API' with 2 evidence record(s)" },
        { claim_id: "c2", type: "OWNERSHIP", verdict: "CONTRADICTED",
          reason: "the estate states owner 'Payments Platform', not 'Payments Team'" },
        { claim_id: "c3", type: "ASSET_PRESENCE", verdict: "MISSING_FROM_ESTATE",
          reason: "the estate holds no asset by this id — either a collection gap or a stale declaration" },
      ],
      by_type: {
        ASSET_PRESENCE: { declared: 2, MATCHED: 1, CONTRADICTED: 0, MISSING_FROM_ESTATE: 1, NOT_CHECKABLE: 0, agreement_rate: 0.5, basis: "DECLARED_SAMPLE_ONLY" },
        OWNERSHIP: { declared: 1, MATCHED: 0, CONTRADICTED: 1, MISSING_FROM_ESTATE: 0, NOT_CHECKABLE: 0, agreement_rate: 0, basis: "DECLARED_SAMPLE_ONLY" },
      },
      meaning: "agreement rate is recall over the declared sample only. Precision is not reported.",
    },
    ...overrides,
  };
}

it("measures a declaration and shows the disagreement rather than a percentage above 100", async () => {
  mockFetch({ [MEASURE]: doc() });
  render(<GroundTruthPanel />);

  fireEvent.click(screen.getByRole("button", { name: "measure" }));
  await waitFor(() => expect(screen.getByText("DECLARED BY bank/inventory")).toBeInTheDocument());

  expect(screen.getAllByText("PARTIAL").length).toBeGreaterThanOrEqual(1);
  expect(screen.getByText("98.3%")).toBeInTheDocument();
  // the HSM row found more than declared: a disagreement badge, and no ratio at all
  expect(screen.getByText("OVER_DECLARED")).toBeInTheDocument();
  expect(screen.queryByText("112.5%")).toBeNull();
  expect(screen.getByText("1 disagreement(s)")).toBeInTheDocument();
});

it("prints no percentage for a class the bank never counted", async () => {
  mockFetch({ [MEASURE]: doc() });
  render(<GroundTruthPanel />);
  fireEvent.click(screen.getByRole("button", { name: "measure" }));

  await waitFor(() => expect(screen.getByText("LIBRARY")).toBeInTheDocument());
  expect(screen.getByText("— not declared")).toBeInTheDocument();
  expect(screen.getByText("NOT_DECLARED")).toBeInTheDocument();
  // 42 collected of nothing declared has no ratio, and the row prints none
  expect(screen.queryByText("0%")).toBeNull();
});

it("separates a contradiction from a claim the estate simply cannot see", async () => {
  mockFetch({ [MEASURE]: doc() });
  render(<GroundTruthPanel />);
  fireEvent.click(screen.getByRole("button", { name: "measure" }));

  await waitFor(() => expect(screen.getByText("CONTRADICTED")).toBeInTheDocument());
  expect(screen.getByText(/the estate states owner/)).toBeInTheDocument();
  expect(screen.getByText("MISSING_FROM_ESTATE")).toBeInTheDocument();
  expect(screen.getByText(/collection gap or a stale declaration/)).toBeInTheDocument();
  expect(screen.getByText(/Precision is not reported/)).toBeInTheDocument();
});

it("reports which claim types agree, and does not average them", async () => {
  mockFetch({ [MEASURE]: doc() });
  render(<GroundTruthPanel />);
  fireEvent.click(screen.getByRole("button", { name: "measure" }));

  await waitFor(() => expect(screen.getByText("ASSET_PRESENCE: 1/2 agreed")).toBeInTheDocument());
  expect(screen.getByText("OWNERSHIP: 0/1 agreed")).toBeInTheDocument();
  // no single score anywhere: two types disagree for different reasons
  expect(screen.queryByText(/overall accuracy/i)).toBeNull();
});

it("refuses malformed claims instead of measuring an empty declaration", async () => {
  mockFetch({ [MEASURE]: doc() });
  render(<GroundTruthPanel />);

  fireEvent.change(screen.getByLabelText("claims"), { target: { value: "{not json" } });
  fireEvent.click(screen.getByRole("button", { name: "measure" }));

  await waitFor(() => expect(screen.getByText(/not valid JSON — nothing was measured/)).toBeInTheDocument());
  expect(screen.queryByText("DECLARED BY bank/inventory")).toBeNull();
});

it("says an unreadable measurement is not an estate that agrees", async () => {
  mockFetch({});
  render(<GroundTruthPanel />);
  fireEvent.click(screen.getByRole("button", { name: "measure" }));

  await waitFor(() => expect(screen.getByText(/that is not 'the estate agrees'/)).toBeInTheDocument());
  expect(screen.queryByText(/COMPLETE/)).toBeNull();
});
