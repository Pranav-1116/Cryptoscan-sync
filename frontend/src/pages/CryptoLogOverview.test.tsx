/* Overview tests (docs/cryptolog/01_PRODUCT_SPEC.md §9): server-computed
   counts that name what they count, integrity that reads UNVERIFIED
   honestly before any checkpoint, collection health that names a gap as a
   gap — and a failed read that is a failure, never zeros. */

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { mockFetch, offlineFetch } from "../test/setup";
import CryptoLogOverview from "./CryptoLogOverview";

const overview = (over: Record<string, unknown> = {}) => ({
  event_total: 42,
  by_severity: { INFO: 30, HIGH: 10, CRITICAL: 2 },
  by_category: { TLS: 25, HSM_KMS: 17 },
  by_logging_kind: { ACTIVITY: 38, CHANGE: 4 },
  critical_changes: 3,
  alerts_total: 5,
  alerts_open: 4,
  collectors: [
    { collector_id: "collector_nbom_01", event_count: 30, telemetry_modes: { EVENT: 30 } },
    { collector_id: "collector_cfg_02", event_count: 12, telemetry_modes: { EVENT: 10, AGGREGATE: 2 } },
  ],
  integrity: {
    state: "UNVERIFIED",
    checkpoint_count: 0,
    latest_checkpoint_ref: null,
    latest_created_at: null,
    note: "an event store without a signed checkpoint is UNVERIFIED: this is not a failed chain, it is a chain not yet anchored",
  },
  note: "Every figure counts recorded CryptoLog events and alerts. A recorded count is not an estate guarantee: a missing collector is named in collection health, never a clean zero.",
  ...over,
});

const renderOverview = () => render(<CryptoLogOverview />);

describe("CryptoLog overview (§9)", () => {
  it("renders server-computed volume, critical changes and alert counts", async () => {
    mockFetch({ "/api/v1/cryptolog/overview": overview() });
    renderOverview();
    expect(await screen.findByTestId("overview-volume")).toHaveTextContent(/42/);
    expect(screen.getByTestId("overview-critical")).toHaveTextContent("3");
    expect(screen.getByTestId("overview-alerts")).toHaveTextContent("4 / 5");
    expect(screen.getByTestId("overview-by-severity")).toHaveTextContent(/CRITICAL 2/);
    expect(screen.getByTestId("overview-by-kind")).toHaveTextContent(/CHANGE 4/);
    expect(screen.getByTestId("overview-note")).toHaveTextContent(/not an estate guarantee/);
  });

  it("reads integrity honestly: UNVERIFIED before any checkpoint, never a pass", async () => {
    mockFetch({ "/api/v1/cryptolog/overview": overview() });
    renderOverview();
    expect(await screen.findByText("UNVERIFIED")).toBeInTheDocument();
    expect(screen.getByText(/not yet anchored/)).toBeInTheDocument();
  });

  it("names its collectors — a collection gap is not a healthy zero", async () => {
    mockFetch({ "/api/v1/cryptolog/overview": overview() });
    renderOverview();
    const health = await screen.findByTestId("overview-collectors");
    expect(health).toHaveTextContent(/collector_nbom_01/);
    expect(health).toHaveTextContent(/collector_cfg_02/);
  });

  it("states an empty estate as a collection gap, never health", async () => {
    mockFetch({ "/api/v1/cryptolog/overview": overview({
      event_total: 0, by_severity: {}, by_category: {}, by_logging_kind: {},
      critical_changes: 0, alerts_total: 0, alerts_open: 0, collectors: [],
    }) });
    renderOverview();
    expect(await screen.findByTestId("overview-collectors-empty")).toHaveTextContent(/collection gap, not a healthy estate/);
  });

  it("names a failed read instead of drawing zeros", async () => {
    offlineFetch();
    renderOverview();
    expect(await screen.findByTestId("overview-failure")).toHaveTextContent(/not an estate with no events/);
    expect(screen.queryByTestId("overview-volume")).not.toBeInTheDocument();
  });
});
