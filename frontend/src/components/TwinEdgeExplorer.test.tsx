import React from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { expect, it } from "vitest";
import TwinEdgeExplorer from "./TwinEdgeExplorer";
import { mockFetch } from "../test/setup";

/* The edge-first explorer, and the three rules that make it honest:

* an edge is read from the twin's own export, so the ids it asks about are the ids
  the twin knows — not a second, legacy id space that would answer UNKNOWN_ASSET
  for every edge a reader clicked;
* the answer is the evidence or the refusal, never a blend: "nothing came back" is
  printed as "that is not 'no evidence exists'";
* a refused candidate is counted where it is not drawn, because an unproven
  relationship drawn as a line is an assumption with a border. */

const GRAPH = "/api/v1/estate/evidence/twin/graph";
const WHY = "/api/v1/estate/evidence/twin/why";

function exportDoc() {
  return {
    schema: "cryptoscan.estate-graph-export/1",
    projection_id: "d".repeat(32),
    generated_at: "2026-11-05T00:00:00Z",
    counts: { nodes: 4, asset_nodes: 3, evidence_nodes: 1, relationships: 2, unresolved: 1 },
    nodes: [
      { id: "application:aaa", labels: ["ASSET", "APPLICATION"], properties: { name: "Payment API" } },
      { id: "hsm:bbb", labels: ["ASSET", "HSM"], properties: { name: "HSM-03" } },
      { id: "certificate:ccc", labels: ["ASSET", "CERTIFICATE"], properties: { name: "payments.bank:443" } },
    ],
    relationships: [
      { type: "USES_HSM", from: "application:aaa", to: "hsm:bbb", properties: { evidence_ids: ["ev-1"] } },
      { type: "USES_CERTIFICATE", from: "application:aaa", to: "certificate:ccc",
        properties: { evidence_ids: ["ev-1", "ev-2"] } },
    ],
    unresolved: [{ type: "UNRESOLVED", from: "application:aaa", to: "hsm:bbb", properties: {} }],
    load_notes: {},
  };
}

it("lists the twin's own relationships, with the evidence count on each", async () => {
  mockFetch({ [GRAPH]: exportDoc() });
  render(<TwinEdgeExplorer />);

  // "Payment API" appears on both of its edges — one row per relationship, not per asset
  await waitFor(() => expect(screen.getAllByText("Payment API").length).toBe(2));
  expect(screen.getByText("HSM-03")).toBeInTheDocument();
  expect(screen.getByText("uses_hsm")).toBeInTheDocument();
  expect(screen.getByText("2 edges")).toBeInTheDocument();
  // the refused candidate is counted where it is not drawn
  expect(screen.getByText(/1 refused candidates/)).toBeInTheDocument();
});

it("asks the why route about the edge that was selected, and shows its evidence", async () => {
  const why = {
    schema: "cryptoscan.estate-twin-why/1",
    status: "ESTABLISHED",
    answer: "established by a PKCS11 reference",
    matches: [{
      edge: { subject: "application:aaa", predicate: "uses_hsm", object: "hsm:bbb", basis: "PKCS11_REFERENCE" },
      answer: "established by a PKCS11 reference",
      evidence: [{
        evidence_id: "ev-1", evidence_type: "CONFIGURED", collector: "linux-static",
        source: "/etc/payment/pkcs11.conf", observed_at: "2026-11-01T09:00:00Z", hash: "f".repeat(64),
      }],
    }],
  };
  const fetchSpy = mockFetch({ [GRAPH]: exportDoc(), [WHY]: why });
  render(<TwinEdgeExplorer />);

  fireEvent.click(await screen.findByText("uses_hsm"));

  await waitFor(() => expect(screen.getByText("ESTABLISHED")).toBeInTheDocument());
  expect(screen.getByText(/linux-static/)).toHaveTextContent("CONFIGURED");
  expect(screen.getByText(/linux-static/)).toHaveTextContent("/etc/payment/pkcs11.conf");

  const asked = fetchSpy.mock.calls.find(([url]) => String(url).includes("/twin/why"));
  const query = new URLSearchParams(String(asked?.[0]).split("?")[1]);
  expect(query.get("subject")).toBe("application:aaa");
  expect(query.get("predicate")).toBe("uses_hsm");
  expect(query.get("object")).toBe("hsm:bbb");
});

it("prints a refusal as a refusal, and never as 'no evidence'", async () => {
  mockFetch({
    [GRAPH]: exportDoc(),
    [WHY]: { schema: "cryptoscan.estate-twin-why/1", status: "NOT_ESTABLISHED",
      detail: "no relationship of that shape was established from this evidence", matches: [] },
  });
  render(<TwinEdgeExplorer />);

  fireEvent.click(await screen.findByText("uses_certificate"));

  await waitFor(() => expect(screen.getByText("NOT_ESTABLISHED")).toBeInTheDocument());
  expect(screen.getByText(/no relationship of that shape was established/)).toBeInTheDocument();
});

it("says an unreadable export is unavailable rather than showing an empty graph", async () => {
  mockFetch({});
  render(<TwinEdgeExplorer />);

  expect(await screen.findByText(/this is not 'no relationships'/)).toBeInTheDocument();
});
