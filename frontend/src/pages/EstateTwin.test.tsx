/* The twin chain screen: draw how far the evidence reaches, never past it. */
import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import { renderWithProviders } from "../test/render";
import { mockFetch, offlineFetch } from "../test/setup";
import EstateTwin from "./EstateTwin";

const CHAIN = "/api/v1/estate/evidence/twin/chain";

const stage = (overrides: Record<string, unknown>) => ({
  index: 0,
  stage: "ESTATE",
  label: "Estate",
  question: "which snapshot is the twin a projection of?",
  status: "POPULATED",
  status_meaning: "the twin holds records on this link, measured now",
  detail: {},
  reason: null,
  endpoint: "/api/v1/estate/evidence/twin",
  ...overrides,
});

const chainDoc = (overrides: Record<string, unknown> = {}) => ({
  run_id: "run-1",
  schema: "cryptoscan.estate-twin-chain/1",
  estate: "payments-bank",
  projection_id: "abcdef0123456789",
  stages: [
    stage({ index: 0, stage: "ESTATE", label: "Estate", detail: { estate: "payments-bank" } }),
    stage({ index: 1, stage: "ASSETS", label: "Assets", detail: { assets: 12 }, question: "what does the twin hold as an asset?" }),
    stage({
      index: 2,
      stage: "RELATIONSHIPS",
      label: "Relationships",
      status: "EMPTY",
      detail: { relationships: 0, unresolved: 3 },
      reason: "no relationship has been established between this snapshot's assets; the twin holds the assets but cannot yet say how they reach each other",
      question: "how are those assets connected, and on what evidence?",
    }),
    stage({
      index: 5,
      stage: "HISTORY",
      label: "History",
      status: "NOT_EVALUATED",
      detail: {},
      reason: "observation store unreadable: disk I/O error",
      question: "does the twin remember earlier values, and does it dispute any?",
    }),
    stage({
      index: 6,
      stage: "IMPACT",
      label: "Impact analysis",
      status: "AWAITING_INPUT",
      detail: { reachable_assets: 12 },
      reason: "impact is computed for a selector you supply; no selector has been asked for yet",
      question: "what would a selector's failure reach?",
    }),
  ],
  order: ["ESTATE", "ASSETS", "RELATIONSHIPS", "CRYPTO_GRAPH", "EVIDENCE_GRAPH", "HISTORY", "IMPACT", "SIMULATION"],
  status_meaning: {
    POPULATED: "the twin holds records on this link, measured now",
    EMPTY: "the twin was read for this link and holds nothing — a real, measured emptiness",
    NOT_EVALUATED: "the underlying store was not read in this call; nothing is claimed about it",
    AWAITING_INPUT: "computable on request, but nothing has been asked yet",
  },
  first_incomplete_stage: "RELATIONSHIPS",
  claim: "this describes how far the twin's own chain is populated for this estate. It is not a crypto posture score, a coverage percentage or a statement that the estate is fully described",
  note: "links are ordered by dependency",
  ...overrides,
});

describe("twin chain", () => {
  it("prints the stage status the server sent and where the chain stops", async () => {
    mockFetch({ [CHAIN]: chainDoc() });
    renderWithProviders(<EstateTwin />);

    expect(await screen.findByTestId("chain-stage-ESTATE")).toBeTruthy();
    // the stop is named from first_incomplete_stage, not recomputed here
    expect(screen.getByText("stops at RELATIONSHIPS")).toBeTruthy();
    expect(screen.getByTestId("chain-stage-RELATIONSHIPS").textContent).toContain("first incomplete");
    // a measured count is echoed
    expect(screen.getByTestId("chain-stage-ASSETS").textContent).toContain("12");
    // the server's reason for an empty link is printed verbatim
    expect(screen.getByTestId("chain-stage-RELATIONSHIPS").textContent).toContain("cannot yet say how they reach each other");
  });

  it("keeps an unread store separate from an empty one", async () => {
    mockFetch({ [CHAIN]: chainDoc() });
    renderWithProviders(<EstateTwin />);

    const history = await screen.findByTestId("chain-stage-HISTORY");
    expect(history.textContent).toContain("NOT_EVALUATED");
    expect(history.textContent).toContain("not read — observation store unreadable: disk I/O error");
    // an unread link never renders a zero measurement
    expect(history.textContent).not.toContain("OBSERVATIONS");
  });

  it("never re-computes an awaiting-input link as a result", async () => {
    mockFetch({ [CHAIN]: chainDoc() });
    renderWithProviders(<EstateTwin />);

    const impact = await screen.findByTestId("chain-stage-IMPACT");
    expect(impact.textContent).toContain("AWAITING_INPUT");
    expect(impact.textContent).toContain("no selector has been asked for yet");
  });

  it("states that the chain was not read rather than showing an empty estate", async () => {
    mockFetch({ [CHAIN]: new Response(JSON.stringify({ detail: { error: "no_estate_discovery", reason: "no discovery run is stored" } }), { status: 404, headers: { "Content-Type": "application/json" } }) });
    renderWithProviders(<EstateTwin />);

    expect(await screen.findByText(/An unread chain is not an empty estate/)).toBeTruthy();
    expect(screen.getAllByText(/no discovery run is stored|not be read/i).length).toBeGreaterThan(0);
    expect(screen.queryByTestId("chain-stage-ESTATE")).toBeNull();
  });

  it("says the backend is offline instead of guessing the chain", async () => {
    offlineFetch();
    renderWithProviders(<EstateTwin />);

    expect(await screen.findByText(/The control plane did not answer/)).toBeTruthy();
    expect(screen.queryByTestId("chain-stage-ESTATE")).toBeNull();
  });

  it("does not read a 404 without a reason as an empty chain", async () => {
    mockFetch({});
    renderWithProviders(<EstateTwin />);

    expect(await screen.findByText(/An unread chain is not an empty estate/)).toBeTruthy();
    expect(screen.queryByTestId("chain-stage-ESTATE")).toBeNull();
  });

  it("prints the server's claim rather than a client-side summary", async () => {
    mockFetch({ [CHAIN]: chainDoc() });
    renderWithProviders(<EstateTwin />);

    expect(await screen.findByText(/not a crypto posture score/)).toBeTruthy();
  });
});
