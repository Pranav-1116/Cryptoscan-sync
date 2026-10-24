import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { mockFetch, offlineFetch } from "../test/setup";
import Accuracy from "./Accuracy";

describe("Original bank M4 — returned benchmark metrics are not field qualification", () => {
  it("does not turn unavailable metrics into zero measured error rates", async () => {
    offlineFetch();
    render(<Accuracy />);
    await waitFor(() => expect(screen.getByText(/Benchmark metrics unavailable/)).toBeTruthy());
    expect(screen.queryByText("0.0%")).toBeNull();
    expect(screen.getAllByText("Not measured").length).toBeGreaterThan(0);
  });
  it("keeps each undefined metric unknown instead of averaging it as zero", async () => {
    mockFetch({ "/api/v1/crypto/accuracy": {
      measured: { precision: 0.8, recall: 0.5, f1: 0.615, coverage: 1 },
      undefined: { precision: null, recall: null, f1: null, coverage: null },
    }});
    render(<Accuracy />);
    await waitFor(() => expect(screen.getByText("measured")).toBeTruthy());
    expect(screen.getByText("80.0%")).toBeTruthy();
    expect(screen.getByText("50.0%")).toBeTruthy();
    expect(screen.queryByText("0.0%")).toBeNull();
    expect(screen.getAllByText("Not measured").length).toBeGreaterThan(0);
  });
  it("does not equate a benchmark or algorithm name with bank or deployed PQC qualification", async () => {
    mockFetch({ "/api/v1/crypto/accuracy": {} });
    render(<Accuracy />);
    await waitFor(() => expect(screen.getByText(/Benchmark metrics unavailable/)).toBeTruthy());
    expect(screen.queryByText(/same corpus that gates CI/)).toBeNull();
    expect(screen.queryByText("QUANTUM_SAFE")).toBeNull();
    expect(screen.getByText(/not bank field accuracy or discovery completeness/i)).toBeTruthy();
  });
});
