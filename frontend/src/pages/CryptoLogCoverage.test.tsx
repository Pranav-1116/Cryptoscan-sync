/* Workspace 8 — Collector & Coverage Health. A collection gap is not a
   healthy zero: the empty state is drawn as a gap, missing sources are
   named unmeasured, and a failed read is a failure, never zero collectors. */
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { mockFetch } from "../test/setup";
import CryptoLogCoverage from "./CryptoLogCoverage";
import { withTitles } from "../test/withTitles";

const renderCoverage = () =>
  render(
    <MemoryRouter>
      <CryptoLogCoverage />
    </MemoryRouter>,
  );

describe("Collector & coverage health", () => {
  it("names its collectors — a collection gap is not a healthy zero", async () => {
    mockFetch({
      "/api/v1/cryptolog/overview": {
        event_total: 3,
        collectors: [{
          collector_id: "collector_nbom_01", event_count: 3,
          telemetry_modes: { EVENT: 3 },
          first_seen: "2026-11-12T10:00:00Z", last_seen: "2026-11-12T11:30:00Z",
          asset_count: 2, assets: ["asset_gateway_001", "hsm-04"],
        }],
        note: "Every figure counts recorded CryptoLog events and alerts.",
      },
    });
    renderCoverage();
    await screen.findByText("collector_nbom_01");
    expect(screen.getByText("asset_gateway_001")).toBeInTheDocument();
    expect(screen.getByText("hsm-04")).toBeInTheDocument();
    expect(screen.getByText(/last seen 2026-11-12T11:30:00Z/)).toBeInTheDocument();
  });

  it("states an empty estate as a collection gap, never health", async () => {
    mockFetch({ "/api/v1/cryptolog/overview": { event_total: 0, collectors: [] } });
    renderCoverage();
    const empty = await screen.findByTestId("coverage-collectors-empty");
    expect(withTitles(empty)).toMatch(/collection gap, not a\s+healthy estate/);
  });

  it("missing sources are unmeasured — never zero, never healthy", async () => {
    mockFetch({ "/api/v1/cryptolog/overview": { event_total: 0, collectors: [] } });
    renderCoverage();
    const unmeasured = await screen.findByTestId("coverage-unmeasured");
    expect(unmeasured).toHaveTextContent(/unmeasured/);
    expect(unmeasured).toHaveTextContent(/never zero and\s+never healthy/);
    expect(unmeasured).toHaveTextContent(/not a source with no\s+events/);
  });

  it("a failed health read is a failure, never zero collectors", async () => {
    mockFetch({
      "/api/v1/cryptolog/overview": () =>
        new Response(JSON.stringify({ detail: "boom" }), { status: 500 }),
    });
    renderCoverage();
    const failure = await screen.findByTestId("coverage-failure");
    expect(failure).toHaveTextContent(/never zero collectors, never a clean map/);
  });
});
