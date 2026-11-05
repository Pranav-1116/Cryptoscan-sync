import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { expect, it } from "vitest";
import ProtocolFloorPanel from "./ProtocolFloorPanel";
import { mockFetch } from "../test/setup";

/* A floor check answers the half the twin holds evidence for — what endpoints
   negotiated — and must not imply anything about the half it cannot see. The tests
   pin the three buckets apart and pin the failure case, because "the call failed" and
   "nothing is below the floor" are the two answers an operator must never confuse. */

const FLOOR = "/api/v1/estate/evidence/twin/protocol-floor";

function doc(overrides: Record<string, unknown> = {}) {
  return {
    schema: "cryptoscan.estate-twin-protocol-floor/1",
    status: "BELOW_FLOOR_PRESENT",
    floor: "TLSv1.2",
    floor_rank: 4,
    projection_id: "p".repeat(32),
    counts: {
      below_floor: 1, at_floor: 0, above_floor: 1, unrecognised: 1, protocol_records: 3,
      assets_below_floor: 1, assets_with_negotiated_evidence: 2,
      assets_without_negotiated_evidence: 5, assets_in_scope: 7,
    },
    below_floor: [{
      asset_id: "lb:bbb", asset_name: "LB-07", asset_type: "LOAD_BALANCER",
      evidence_id: "ev-3", collector: "probe", observed_at: "2026-11-01T09:00:00Z",
      negotiated: "TLSv1.0", position: "BELOW_FLOOR",
    }],
    at_floor: [], above_floor: [],
    unrecognised: [{
      asset_id: "hsm:ccc", asset_name: "HSM-03", evidence_id: "ev-9",
      negotiated: "TLS_FUTURE", position: "UNRECOGNISED",
    }],
    without_negotiated_evidence: ["application:aaa"],
    note: "1 of 3 observed handshake record(s) negotiated a protocol below TLSv1.2",
    blind_spots: [
      "client acceptance: a client that only offers an older protocol is not an asset, so which "
        + "clients would fail after the floor moves is not in this answer",
    ],
    limits: ["the ranking is a version ladder only"],
    declared: {
      basis: "DECLARED",
      meaning: "a declaration is what a TLS configuration allows or requires, read from "
        + "configuration evidence. It is not a negotiation.",
      counts: {
        assets_with_declaration: 2, declares_below_floor: 1, declared_ceiling_below_floor: 1,
        declared_without_a_rankable_floor: 0, partially_parsed: 0,
      },
      declares_below_floor: [{
        asset_id: "lb:bbb", asset_name: "LB-07", evidence_id: "ev-cfg", basis: "DECLARED",
        declared: ["TLSV1.0", "TLSV1.2"], declared_floor: null, field: "protocols",
        position: "DECLARES_BELOW_FLOOR",
      }],
      declared_ceiling_below_floor: [{
        asset_id: "host:ddd", asset_name: "payment-prod-01", evidence_id: "ev-old",
        basis: "DECLARED", declared_ceiling: "TLSV1.1", edges: [],
        position_ceiling: "CEILING_BELOW_FLOOR",
      }],
      declared_without_a_rankable_floor: [], partially_parsed: [],
    },
    ...overrides,
  };
}

it("names the endpoints below the floor, and keeps unrecognised out of the finding", async () => {
  mockFetch({ [FLOOR]: doc() });
  render(<ProtocolFloorPanel />);

  await waitFor(() => expect(screen.getByText("BELOW_FLOOR_PRESENT")).toBeInTheDocument());
  expect(screen.getAllByText("LB-07").length).toBeGreaterThanOrEqual(1);
  // the row's value, not the floor chip that happens to share the string
  expect(screen.getAllByText("TLSv1.0").length).toBeGreaterThanOrEqual(1);
  // the buckets are separate badges, not one "issues" number
  expect(screen.getByText("3 handshake records")).toBeInTheDocument();
  expect(screen.getByText("2 assets measured")).toBeInTheDocument();
  expect(screen.getByText("5 with no handshake evidence")).toBeInTheDocument();
  expect(screen.getByText("1 unrecognised")).toBeInTheDocument();
  // an unrankable value is printed as unrankable, never as compliance
  expect(screen.getByText(/which this build cannot rank/)).toBeInTheDocument();
  expect(screen.getByText(/Unrecognised is not compliant/)).toBeInTheDocument();
});

it("asks about the floor that was chosen, not the one it started with", async () => {
  const fetchSpy = mockFetch({ [FLOOR]: doc() });
  render(<ProtocolFloorPanel />);
  await waitFor(() => expect(screen.getByText("BELOW_FLOOR_PRESENT")).toBeInTheDocument());

  fireEvent.click(screen.getByRole("button", { name: "TLSv1.3" }));

  await waitFor(() => {
    const asked = fetchSpy.mock.calls.filter(([url]) => String(url).includes("protocol-floor"));
    expect(String(asked[asked.length - 1][0])).toContain("floor=TLSv1.3");
  });
  expect(screen.getByRole("button", { name: "TLSv1.3" })).toHaveAttribute("aria-pressed", "true");
});

it("says an unreadable check is a failed read, not a clean estate", async () => {
  mockFetch({});
  render(<ProtocolFloorPanel />);

  expect(await screen.findByText(/that is not 'nothing is below the floor'/)).toBeInTheDocument();
  expect(screen.queryByText("AT_OR_ABOVE_FLOOR")).toBeNull();
});

it("prints no-evidence as a collection gap, and says what the check cannot see", async () => {
  mockFetch({ [FLOOR]: doc({ status: "INSUFFICIENT_EVIDENCE", below_floor: [], unrecognised: [] }) });
  render(<ProtocolFloorPanel />);

  await waitFor(() => expect(screen.getByText("INSUFFICIENT_EVIDENCE")).toBeInTheDocument());
  expect(screen.getByText(/That is a collection gap, not a clean result/)).toBeInTheDocument();

  fireEvent.click(screen.getByText(/what this check cannot see/));
  expect(screen.getByText(/client acceptance/)).toBeInTheDocument();
});

it("draws a declared configuration beside the handshake, and says which is which", async () => {
  mockFetch({ [FLOOR]: doc() });
  render(<ProtocolFloorPanel />);
  await waitFor(() => expect(screen.getByText("BELOW_FLOOR_PRESENT")).toBeInTheDocument());

  // the basis is on the label: a config that permits TLSv1.0 is not a handshake that used it
  expect(screen.getByText("DECLARED")).toBeInTheDocument();
  expect(screen.getByText(/what configurations allow — not what a handshake produced/)).toBeInTheDocument();
  expect(screen.getByText(/still permits/)).toBeInTheDocument();
  expect(screen.getByText("TLSV1.0, TLSV1.2")).toBeInTheDocument();
  expect(screen.getByText(/It is not a negotiation/)).toBeInTheDocument();
});

it("will not read an asset with no recorded edge as an asset that strands nothing", async () => {
  mockFetch({ [FLOOR]: doc() });
  render(<ProtocolFloorPanel />);
  await waitFor(() => expect(screen.getByText("BELOW_FLOOR_PRESENT")).toBeInTheDocument());

  expect(screen.getByText(/cannot reach TLSv1.2 at all/)).toBeInTheDocument();
  expect(screen.getByText("TLSV1.1")).toBeInTheDocument();
  expect(screen.getByText(/nothing recorded on either side of it/)).toBeInTheDocument();
  // not the other reading: an empty edge list is an absence of records, not an absence of risk
  expect(screen.queryByText(/nothing would break/)).toBeNull();
});

it("gives a declaration that permits an older protocol its own verdict", async () => {
  mockFetch({ [FLOOR]: doc({ status: "BELOW_FLOOR_DECLARED", below_floor: [] }) });
  render(<ProtocolFloorPanel />);

  await waitFor(() => expect(screen.getByText("BELOW_FLOOR_DECLARED")).toBeInTheDocument());
  // and it is still not an empty result
  expect(screen.getAllByText("LB-07").length).toBeGreaterThanOrEqual(1);
});
