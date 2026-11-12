/* Threat investigation tests (docs/cryptolog/01_PRODUCT_SPEC.md §9):
   honest totals, server-side filters, the proven / NOT-proven boundary on
   every alert, append-only lifecycle history, and a failed read that is a
   named failure — never an empty list drawn as a truth. */

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { mockFetch, offlineFetch } from "../test/setup";
import CryptoLogAlerts from "./CryptoLogAlerts";

const AS_OF = "2026-11-07T04:00:00Z";

const alertRow = (over: Record<string, unknown> = {}) => ({
  alert_id: "alrt_01ABC",
  rule_id: "CL-002",
  event_id: "clog_01ABC",
  asset_id: "asset_gateway_001",
  severity: "HIGH",
  state: "OPEN",
  title: "CL-002: Weak cipher suite observed",
  basis: {
    severity_basis: "asset criticality HIGH, exposure network-facing, evidence quality OBSERVED",
    severity_drivers: ["asset criticality HIGH", "evidence quality OBSERVED"],
  },
  what_is_proven: ["TLS_RSA_WITH_3DES_EDE_CBC_SHA negotiated at 2026-11-07T04:00:00Z"],
  what_is_not_proven: ["that this negotiation exposed customer data"],
  evidence_ids: ["evidence_001"],
  occurred_at: AS_OF,
  transitions: [{ action: "ACKNOWLEDGE", actor: "analyst_lin", at: AS_OF, state: "ACKNOWLEDGED", note: "reviewing" }],
  ...over,
});

const renderAlerts = () => render(<CryptoLogAlerts />);

describe("CryptoLog threat investigation (§9)", () => {
  it("shows the deterministic rule catalogue: a detection, never a verdict", async () => {
    mockFetch({
      "/api/v1/cryptolog/rules": {
        rules: [{
          rule_id: "CL-002", detection: "Weak cipher suite observed",
          suggested_severity: "High",
          investigation: "identify the endpoint offering the weak suite and whether policy permits it",
        }],
        note: "Deterministic rules over recorded CryptoLog events only. A rule is a detection, never a verdict.",
      },
      "/api/v1/cryptolog/alerts": { rows: [], total_count: 0, next_cursor: null, has_more: false },
    });
    render(<CryptoLogAlerts />);
    await screen.findByText("Weak cipher suite observed");
    expect(screen.getByTestId("rules-note")).toHaveTextContent(/a detection, never a verdict/);
    expect(screen.getByText(/identify the endpoint offering the weak suite/)).toBeInTheDocument();
  });

  it("renders alerts with the server's totals, never a page count as a total", async () => {
    mockFetch({
      "/api/v1/cryptolog/alerts": {
        rows: [alertRow(), alertRow({ alert_id: "alrt_02DEF", rule_id: "CL-005", title: "CL-005: HSM key metadata change", severity: "CRITICAL", state: "ACKNOWLEDGED" })],
        total_count: 7,
        next_cursor: "alrt_02DEF",
        has_more: true,
      },
    });
    renderAlerts();
    expect(await screen.findByText("CL-002: Weak cipher suite observed")).toBeInTheDocument();
    expect(screen.getByText("CL-005: HSM key metadata change")).toBeInTheDocument();
    expect(screen.getByTestId("alerts-loaded-line")).toHaveTextContent(/2 loaded of 7 recorded/);
    expect(screen.getByTestId("alerts-loaded-line")).toHaveTextContent(/more available/);
  });

  it("sends filters to the alert store, never a page-local filter", async () => {
    const fetchSpy = mockFetch({
      "/api/v1/cryptolog/alerts": { rows: [alertRow()], total_count: 1, next_cursor: null, has_more: false },
    });
    renderAlerts();
    await screen.findByText("CL-002: Weak cipher suite observed");
    fireEvent.change(screen.getByLabelText("alert state"), { target: { value: "OPEN" } });
    fireEvent.change(screen.getByLabelText("rule id"), { target: { value: "CL-002" } });
    fireEvent.click(screen.getByTestId("apply-alert-filters"));
    await waitFor(() => {
      const urls = fetchSpy.mock.calls.map(([u]) => String(u));
      expect(urls.some((u) => u.includes("/api/v1/cryptolog/alerts") && u.includes("state=OPEN") && u.includes("rule_id=CL-002"))).toBe(true);
    });
  });

  it("names a failed read instead of drawing an empty list", async () => {
    offlineFetch();
    renderAlerts();
    expect(await screen.findByTestId("alerts-failure")).toBeInTheDocument();
    expect(screen.getByTestId("alerts-failure")).toHaveTextContent(/not a source with no alerts/);
    expect(screen.queryByTestId("alerts-rows")).not.toBeInTheDocument();
  });

  it("states an empty result as an empty result, never invented alerts", async () => {
    mockFetch({ "/api/v1/cryptolog/alerts": { rows: [], total_count: 0, next_cursor: null, has_more: false } });
    renderAlerts();
    expect(await screen.findByTestId("alerts-empty")).toHaveTextContent(/never invents alerts/);
  });

  it("shows what is proven AND what is NOT proven, with severity drivers and append-only history", async () => {
    mockFetch({
      "/api/v1/cryptolog/alerts": { rows: [alertRow()], total_count: 1, next_cursor: null, has_more: false },
      "/api/v1/cryptolog/alerts/*": alertRow(),
    });
    renderAlerts();
    fireEvent.click(await screen.findByTestId("alert-row"));
    expect(await screen.findByTestId("alert-proven")).toHaveTextContent(/TLS_RSA_WITH_3DES_EDE_CBC_SHA negotiated/);
    expect(screen.getByTestId("alert-not-proven")).toHaveTextContent(/not.*exposed customer data|that this negotiation exposed customer data/);
    expect(screen.getByTestId("alert-basis")).toHaveTextContent(/asset criticality HIGH/);
    expect(screen.getByTestId("alert-transitions")).toHaveTextContent(/ACKNOWLEDGE by analyst_lin/);
  });

  it("names a failed detail read instead of a blank panel", async () => {
    mockFetch({ "/api/v1/cryptolog/alerts": { rows: [alertRow()], total_count: 1, next_cursor: null, has_more: false } });
    renderAlerts();
    fireEvent.click(await screen.findByTestId("alert-row"));
    expect(await screen.findByTestId("alert-detail-failure")).toBeInTheDocument();
  });
});
