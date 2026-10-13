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
  edges: [{ src: "system:payments", dst: "system:billing", rel: "CALLS" }],
  backend: "memory",
  ...over,
});

const clickNode = async (label: string) => {
  fireEvent.click(await screen.findByText(label));
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
    await waitFor(() => expect(screen.getByText("Impacted Systems")).toBeTruthy());
    expect(screen.getByText(/· 1 hop/)).toBeTruthy();
    expect(screen.getByText(/· 2 hops/)).toBeTruthy();
  });

  it("never defaults an unreported backend to Neo4j Cluster", async () => {
    mockFetch({
      "/api/v1/graph": graph({ backend: undefined }),
      "/api/v1/graph/stats": { nodes: 2, edges: 1 },
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("Not reported")).toBeTruthy());
    expect(screen.queryByText("Neo4j Cluster")).toBeNull();
    expect(screen.getByText(/Backend not reported by the API/)).toBeTruthy();
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

  it("a failed traversal says unavailable rather than 'no dependencies detected'", async () => {
    mockFetch({
      "/api/v1/graph": graph(),
      "/api/v1/graph/stats": { nodes: 2, edges: 1 },
    });
    renderPage();
    await clickNode("payments");
    await waitFor(() => expect(screen.getByText(/Blast radius unavailable/)).toBeTruthy());
    expect(screen.queryByText(/No downstream dependencies detected/)).toBeNull();
  });
});
