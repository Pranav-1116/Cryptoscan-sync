/* Workspace 5 — Event Correlation: patterns in the recorded store. Shared
   evidence and recorded asset identity are evidence-backed; a shared
   algorithm name is a hypothesis of possible dependency, never an edge. */
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { mockFetch } from "../test/setup";
import CryptoLogCorrelation from "./CryptoLogCorrelation";

const renderCorrelation = () =>
  render(
    <MemoryRouter>
      <CryptoLogCorrelation />
    </MemoryRouter>,
  );

describe("Event correlation", () => {
  it("evidence-backed and hypothesis groups are drawn apart", async () => {
    mockFetch({
      "/api/v1/cryptolog/correlation": {
        groups: [
          { basis: "shared_evidence", key: "ev-shared", event_ids: ["EV-A", "EV-B"],
            asset_ids: ["asset_a", "asset_b"], event_count: 2, evidence_backed: true,
            note: "Events carrying the same recorded evidence reference — the relation rests on shared evidence." },
          { basis: "shared_algorithm", key: "RSA", event_ids: ["EV-1", "EV-2"],
            asset_ids: ["asset_a", "asset_b"], event_count: 2, evidence_backed: false,
            note: "The same algorithm name appears across these assets — a possible dependency and a hypothesis only, never an established edge." },
        ],
        event_count: 4, groups_truncated: false,
        note: "Correlation groups are computed from recorded CryptoLog events only.",
      },
    });
    renderCorrelation();
    await screen.findByText("ev-shared");
    expect(screen.getByText("evidence-backed")).toBeInTheDocument();
    expect(screen.getByText("hypothesis")).toBeInTheDocument();
    expect(screen.getByText(/never an established edge/)).toBeInTheDocument();
  });

  it("absence of recorded correlation is never proof that nothing relates", async () => {
    mockFetch({
      "/api/v1/cryptolog/correlation": {
        groups: [], event_count: 0, groups_truncated: false,
        note: "Absence of groups is absence of recorded correlation, never proof that nothing relates.",
      },
    });
    renderCorrelation();
    const empty = await screen.findByTestId("correlation-empty");
    expect(empty).toHaveTextContent(/never proof that nothing relates/);
  });

  it("a failed correlation read is a failure, never an uncorrelated estate", async () => {
    mockFetch({
      "/api/v1/cryptolog/correlation": () =>
        new Response(JSON.stringify({ detail: "boom" }), { status: 500 }),
    });
    renderCorrelation();
    const failure = await screen.findByTestId("correlation-failure");
    expect(failure).toHaveTextContent(/never an uncorrelated estate/);
  });
});
