import React from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { expect, it } from "vitest";
import TwinGraphCanvas from "./TwinGraphCanvas";
import { mockFetch } from "../test/setup";

/* The drawn canvas, and the four rules that make a picture honest:

* it is drawn from the twin's own export, so a line on it is a relationship the
  twin holds — asking "why" about that line is the same question the edge panel
  asks, with the twin's ids;
* the layout is layered and deterministic: placement above assets, evidence below,
  so the same projection draws the same picture;
* a refused candidate is counted and never drawn — an unproven relationship with a
  border reads as a fact;
* the cap is stated. A graph that silently drops nodes is a picture that reads as
  a complete estate. */

const GRAPH = "/api/v1/estate/evidence/twin/graph";
const WHY = "/api/v1/estate/evidence/twin/why";

function doc(overrides: Record<string, unknown> = {}) {
  return {
    schema: "cryptoscan.estate-graph-export/1",
    projection_id: "d".repeat(32),
    generated_at: "2026-11-05T00:00:00Z",
    counts: { nodes: 4, asset_nodes: 2, evidence_nodes: 1, relationships: 2, unresolved: 2 },
    nodes: [
      { id: "application:aaa", labels: ["Asset", "APPLICATION"], properties: { name: "Payment API", evidence_count: 1 } },
      { id: "hsm:bbb", labels: ["Asset", "HSM"], properties: { name: "HSM-03" } },
      { id: "ev-1", labels: ["Evidence", "RUNTIME_OBSERVED"], properties: { target: "application:aaa" } },
      { id: "placement:environment:eee", labels: ["PLACEMENT", "ENVIRONMENT"], properties: { name: "production" } },
    ],
    relationships: [
      { type: "USES_HSM", from: "application:aaa", to: "hsm:bbb", properties: { evidence_ids: ["ev-1"] } },
      { type: "SUPPORTS", from: "ev-1", to: "application:aaa", properties: { evidence_ids: ["ev-1"] } },
    ],
    unresolved: [
      { type: "UNRESOLVED", from: "application:aaa", to: "hsm:bbb", properties: {} },
      { type: "UNRESOLVED", from: "hsm:bbb", to: "application:aaa", properties: {} },
    ],
    load_notes: {},
    ...overrides,
  };
}

it("draws the twin's nodes and counts refused candidates without drawing them", async () => {
  mockFetch({ [GRAPH]: doc() });
  render(<TwinGraphCanvas />);

  await waitFor(() => expect(screen.getByText("4 nodes drawn")).toBeInTheDocument());
  expect(screen.getByText("Payment API")).toBeInTheDocument();
  expect(screen.getByText("HSM-03")).toBeInTheDocument();
  expect(screen.getByText("production")).toBeInTheDocument();
  expect(screen.getByText("2 relationships")).toBeInTheDocument();
  // refused candidates are counted where they are not drawn
  expect(screen.getByText(/2 refused candidates, not drawn/)).toBeInTheDocument();
  expect(screen.queryByLabelText(/^unresolved:/)).toBeNull();
});

it("asks the why route about the line that was selected, and shows its evidence", async () => {
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
  const fetchSpy = mockFetch({ [GRAPH]: doc(), [WHY]: why });
  render(<TwinGraphCanvas />);

  fireEvent.click(await screen.findByRole("button", { name: "uses_hsm: Payment API → HSM-03" }));

  await waitFor(() => expect(screen.getByText("ESTABLISHED")).toBeInTheDocument());
  expect(screen.getByText("CONFIGURED")).toBeInTheDocument();
  expect(screen.getByText("linux-static")).toBeInTheDocument();
  expect(screen.getByText("/etc/payment/pkcs11.conf")).toBeInTheDocument();

  const asked = fetchSpy.mock.calls.find(([url]) => String(url).includes("/twin/why"));
  const query = new URLSearchParams(String(asked?.[0]).split("?")[1]);
  // the twin's own ids, not a legacy id space
  expect(query.get("subject")).toBe("application:aaa");
  expect(query.get("predicate")).toBe("uses_hsm");
  expect(query.get("object")).toBe("hsm:bbb");
});

it("prints a refusal as a refusal, and never as 'no evidence'", async () => {
  mockFetch({
    [GRAPH]: doc(),
    [WHY]: { schema: "cryptoscan.estate-twin-why/1", status: "NOT_ESTABLISHED",
      detail: "no evidence asserts this relationship", matches: [] },
  });
  render(<TwinGraphCanvas />);

  fireEvent.click(await screen.findByRole("button", { name: "supports: ev-1 → Payment API" }));

  await waitFor(() => expect(screen.getByText("NOT_ESTABLISHED")).toBeInTheDocument());
  expect(screen.getByText(/no evidence asserts this relationship/)).toBeInTheDocument();
  expect(screen.getByText(/not the same as .*no evidence exists/)).toBeInTheDocument();
});

it("says the drawing is truncated rather than implying it is the whole estate", async () => {
  const nodes = Array.from({ length: 130 }, (_, index) => ({
    id: `application:n${String(index).padStart(3, "0")}`,
    labels: ["Asset", "APPLICATION"],
    properties: { name: `App ${index}` },
  }));
  const relationships = Array.from({ length: 5 }, (_, index) => ({
    type: "USES_HSM", from: `application:n${String(index).padStart(3, "0")}`,
    to: `application:n${String(129 - index).padStart(3, "0")}`, properties: {},
  }));
  mockFetch({ [GRAPH]: doc({ nodes, relationships, counts: { nodes: 130, relationships: 5, unresolved: 0 } }) });
  render(<TwinGraphCanvas />);

  await waitFor(() => expect(screen.getByText("120 nodes drawn")).toBeInTheDocument());
  expect(screen.getByText(/10 further node\(s\) are not drawn/)).toBeInTheDocument();
  expect(screen.getByText(/This is a drawing limit, not the edge of the estate/)).toBeInTheDocument();
});

it("says an unreadable export is unavailable rather than showing an empty picture", async () => {
  mockFetch({});
  render(<TwinGraphCanvas />);

  expect(await screen.findByText(/this is not 'no relationships'/)).toBeInTheDocument();
  expect(screen.queryByText("0 nodes drawn")).toBeNull();
});

it("draws the same picture twice for the same projection", async () => {
  mockFetch({ [GRAPH]: doc() });
  const first = render(<TwinGraphCanvas />);
  await waitFor(() => expect(screen.getByText("4 nodes drawn")).toBeInTheDocument());
  const firstLabel = screen.getByRole("img", { name: "The twin's relationship graph" }).innerHTML;
  first.unmount();

  mockFetch({ [GRAPH]: doc() });
  render(<TwinGraphCanvas />);
  await waitFor(() => expect(screen.getByText("4 nodes drawn")).toBeInTheDocument());
  const secondLabel = screen.getByRole("img", { name: "The twin's relationship graph" }).innerHTML;

  expect(secondLabel).toBe(firstLabel);
});
