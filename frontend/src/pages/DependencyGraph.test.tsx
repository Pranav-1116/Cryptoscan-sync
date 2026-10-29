/* DependencyGraph page truth (§5 P1): the blast-radius card must read the
 * API's real `systems` array (not `affected_systems`, which is always
 * absent — a hidden impact false-negative), must not default an unknown
 * backend to "Neo4j Cluster", and must not claim "no dependencies" when
 * the traversal simply failed. */
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { mockFetch, offlineFetch } from "../test/setup";
import DependencyGraph from "./DependencyGraph";

afterEach(() => {
  localStorage.clear();
});

const renderPage = () =>
  render(
    <MemoryRouter>
      <DependencyGraph />
    </MemoryRouter>,
  );

const graph = (over: Record<string, unknown> = {}) => ({
  nodes: [
    { id: "system:payments", label: "payments", kind: "system" },
    { id: "system:billing", label: "billing", kind: "system" },
  ],
  edges: [{ from: "system:payments", to: "system:billing", label: "CALLS" }],
  backend: "memory",
  ...over,
});

const clickNode = async (label: string) => {
  fireEvent.click(await screen.findByText(label, { selector: "span" }));
};

describe("DependencyGraph — honest blast radius and backend", () => {
  it("counts impacted systems from the real `systems` field with per-system hops", async () => {
    mockFetch({
      "/api/v1/graph": graph(),
      "/api/v1/graph/stats": { nodes: 2, edges: 1 },
      "/api/v1/graph/blast-radius": {
        start: "system:payments",
        systems: [
          { id: "billing", name: "billing", hops: 1 },
          { id: "checkout", name: "checkout", hops: 2 },
        ],
        hops: 2,
        nodes_visited: 3,
        backend: "memory",
      },
    });
    renderPage();
    await clickNode("payments");
    await waitFor(() => expect(screen.getByText("Downstream Dependents:")).toBeTruthy());
    expect(screen.getByText("↳ billing").parentElement).toHaveTextContent("1 hop");
    expect(screen.getByText("↳ checkout").parentElement).toHaveTextContent("2 hops");
  });

  it("never defaults an unreported backend to Neo4j Cluster", async () => {
    mockFetch({
      "/api/v1/graph": graph({ backend: undefined }),
      "/api/v1/graph/stats": { nodes: 2, edges: 1 },
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("Not reported")).toBeTruthy());
    expect(screen.queryByText("Neo4j Cluster")).toBeNull();
    expect(screen.getByText("Backend not reported")).toBeTruthy();
  });

  it("labels the real neo4j backend from the API response", async () => {
    mockFetch({
      "/api/v1/graph": graph({ backend: "bolt://neo4j:7687" }),
      "/api/v1/graph/stats": { nodes: 2, edges: 1 },
    });
    renderPage();
    await waitFor(() => expect(screen.getByText(/Neo4j \(bolt:\/\/neo4j:7687\)/)).toBeTruthy());
    expect(screen.queryByText("Deterministic Memory Engine")).toBeNull();
  });

  it("an empty traversal shows zero honestly instead of claiming none exist globally", async () => {
    mockFetch({
      "/api/v1/graph": graph(),
      "/api/v1/graph/stats": { nodes: 2, edges: 1 },
      "/api/v1/graph/blast-radius": { start: "system:payments", systems: [], hops: 2, nodes_visited: 1, backend: "memory" },
    });
    renderPage();
    await clickNode("payments");
    await waitFor(() => expect(screen.getAllByText("0").length).toBeGreaterThan(0));
    expect(screen.getByText("0 hops")).toBeTruthy();
  });

  it("breaks the edge count down by provenance instead of implying all edges are observed", async () => {
    mockFetch({
      "/api/v1/graph": {
        nodes: [
          { id: "system:payments", label: "payments", kind: "system" },
          { id: "system:billing", label: "billing", kind: "system" },
          { id: "asset:ca-1", label: "RSA-2048", kind: "asset" },
        ],
        edges: [
          { from: "system:payments", to: "system:billing", label: "CALLS", provenance: "DECLARED" },
          { from: "system:payments", to: "asset:ca-1", label: "USES", provenance: "SCANNER_DERIVED" },
        ],
        backend: "memory",
      },
      "/api/v1/graph/stats": { nodes: 3, edges: 2 },
    });
    renderPage();
    await waitFor(() =>
      expect(document.body.textContent).toContain("1 declared · 1 scanner-derived"));
    expect(
      screen.getByText(/declared = operator statement · scanner-derived = from scan evidence · unattributed = origin unknown/),
    ).toBeTruthy();
  });

  it("labels edges with no provenance as unattributed, never as observed", async () => {
    mockFetch({
      "/api/v1/graph": graph(), // legacy fixture: edges without provenance
      "/api/v1/graph/stats": { nodes: 2, edges: 1 },
    });
    renderPage();
    await waitFor(() => expect(screen.getAllByText("1 unattributed").length).toBeGreaterThan(0));
    expect(screen.getByText(/unattributed = origin unknown/)).toBeTruthy();
    expect(screen.queryByText(/\bobserved edges\b/i)).toBeNull();
  });

  it("discloses the provenance of the edges the blast radius traversed", async () => {
    mockFetch({
      "/api/v1/graph": graph(),
      "/api/v1/graph/stats": { nodes: 2, edges: 1 },
      "/api/v1/graph/blast-radius": {
        start: "system:payments",
        systems: [{ id: "billing", name: "billing", hops: 1 }],
        hops: 1,
        nodes_visited: 2,
        backend: "memory",
        provenance_counts: {
          OBSERVED: 0, DECLARED: 2, SCANNER_DERIVED: 1, INFERRED: 0, UNATTRIBUTED: 0,
        },
      },
    });
    renderPage();
    await clickNode("payments");
    await waitFor(() =>
      expect(document.body.textContent).toContain("Path edges: 2 declared · 1 scanner-derived"));
    expect(document.body.textContent).toContain(
      "declared edges are operator statements, not observed traffic");
  });

  it("a failed traversal says unavailable rather than 'no dependencies detected'", async () => {
    mockFetch({
      "/api/v1/graph": graph(),
      "/api/v1/graph/stats": { nodes: 2, edges: 1 },
    });
    renderPage();
    await clickNode("payments");
    await waitFor(() => expect(screen.getByText(/No traversal result — not linked to any system, or graph offline/)).toBeTruthy());
    expect(screen.getByText("Traversal unavailable — impact unknown")).toBeTruthy();
    expect(screen.queryByText(/No downstream dependencies detected/)).toBeNull();
  });
});

describe("DependencyGraph — asset-inventory deep link (round 64)", () => {
  it("?asset= runs the asset-start blast radius with owning systems and honest linkage labels", async () => {
    mockFetch({
      "/api/v1/graph": graph(),
      "/api/v1/graph/stats": { nodes: 2, edges: 1 },
      "/api/v1/graph/blast-radius": {
        start: "asset-77",
        start_kind: "asset",
        owning_systems: ["sys-payments", "sys-billing"],
        systems: [{ id: "checkout", name: "checkout", hops: 2 }],
        hops: 5,
        nodes_visited: 3,
        backend: "memory",
      },
    });
    render(
      <MemoryRouter initialEntries={["/dependency-graph?asset=asset-77"]}>
        <DependencyGraph />
      </MemoryRouter>,
    );
    expect(await screen.findByText(/Asset start — walk fans out from every system using this asset/)).toBeTruthy();
    expect(screen.getByText(/2 owners/)).toBeTruthy();
    expect(screen.getByText("Downstream Dependents:")).toBeTruthy();
    expect(screen.getByText("↳ checkout").parentElement).toHaveTextContent("2 hops");
    // the system-start walk stays available: the topology list still works
    await clickNode("payments");
    await waitFor(() => expect(screen.getByText("payments", { selector: "span" })).toBeTruthy());
    expect(screen.queryByText(/2 owners/)).toBeNull();
  });

  it("?asset= with no system links says unknown, never zero impact", async () => {
    mockFetch(
      {
        "/api/v1/graph": graph(),
        "/api/v1/graph/stats": { nodes: 2, edges: 1 },
      },
      404,
    );
    render(
      <MemoryRouter initialEntries={["/dependency-graph?asset=asset-lonely"]}>
        <DependencyGraph />
      </MemoryRouter>,
    );
    expect(await screen.findByText(/No traversal result — not linked to any system, or graph offline/)).toBeTruthy();
    expect(screen.getByText(/Blast is unknown, not zero/)).toBeTruthy();
  });
});
