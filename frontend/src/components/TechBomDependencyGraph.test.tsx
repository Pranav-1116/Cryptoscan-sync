import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import TechBomDependencyGraph, { buildDependencyGraph, orderColumns } from "./TechBomDependencyGraph";
import type { TechBomState } from "../lib/api";

const state = (over: Partial<TechBomState> = {}): TechBomState => ({
  snapshot_id: "s1", environment: "prod", state_version: 1, total_components: 6,
  components_by_layer: {}, fingerprint: "f",
  layers: {
    sbom: { count: 3, components: [
      { "bom-ref": "app:sys-core", name: "Core Banking", type: "application" },
      { "bom-ref": "library:pypi/cryptography", name: "cryptography", version: "42.0.5", type: "library" },
      { "bom-ref": "app:sys-crm", name: "Customer CRM", type: "application" },
    ] },
    cbom: { count: 1, components: [{ "bom-ref": "crypto:c-1:core-db", name: "RSA-2048", type: "cryptographic-asset" }] },
    hbom: { count: 1, components: [{ "bom-ref": "hw:hsm-01", name: "Thales Luna", type: "device" }] },
    vendor: { count: 1, components: [{ "bom-ref": "vendor:Thales", name: "Thales", type: "vendor" }] },
  },
  dependencies: [
    ["sys-core", "sys-crm", ""],                               // system ids → app: refs
    ["app:sys-core", "library:pypi/cryptography", "contains"], // exact bom-refs
    ["c-1", "hsm-01", "uses"],                                  // crypto id / hw id
    ["sys-core", "mrdn-sbx-dc1-coredb01::host", "runs_on"],     // not a BOM component
    ["sys-core", "sys-core", ""],                               // self loop
  ],
  ...over,
});

describe("Technology BOM dependency graph", () => {
  it("draws only recorded edges and resolves every id form to its component", () => {
    const g = buildDependencyGraph(state());
    expect(g.recorded).toBe(5);
    expect(g.edges).toHaveLength(4);
    expect(g.selfLoops).toBe(1);
    const ids = g.edges.map((e) => `${e.source} > ${e.target} (${e.type})`);
    expect(ids).toContain("sbom|app:sys-core > sbom|app:sys-crm (depends on)");
    expect(ids).toContain("sbom|app:sys-core > sbom|library:pypi/cryptography (contains)");
    expect(ids).toContain("cbom|crypto:c-1:core-db > hbom|hw:hsm-01 (uses)");
    // an end that is not a BOM component is kept, in its own column — never guessed
    expect(ids).toContain("sbom|app:sys-core > external|mrdn-sbx-dc1-coredb01::host (runs on)");
    expect(g.external).toBe(1);
  });

  it("never invents edges from a dependency count", () => {
    const g = buildDependencyGraph(state({ dependencies: [], dependency_count: 643 }));
    expect(g.edges).toHaveLength(0);
  });

  it("orders each column so connected components sit together", () => {
    const g = buildDependencyGraph(state());
    const cols = orderColumns(g.nodes, g.edges);
    expect(cols.get("sbom")!.map((n) => n.label)).toHaveLength(3);
    expect(cols.get("external")!.map((n) => n.label)).toEqual(["mrdn-sbx-dc1-coredb01::host"]);
  });

  it("hides components with no recorded dependency until asked, and says so", () => {
    render(<TechBomDependencyGraph state={state()} />);
    // Thales (vendor) has no edge
    expect(screen.queryByTestId("depnode-vendor|vendor:Thales")).not.toBeInTheDocument();
    expect(screen.getByText(/1 with no recorded dependency hidden/)).toBeInTheDocument();
    expect(screen.getByText(/1 edge ends are not BOM components/)).toBeInTheDocument();
    fireEvent.click(screen.getByLabelText(/connected only/));
    expect(screen.getByTestId("depnode-vendor|vendor:Thales")).toBeInTheDocument();
  });

  it("lists what a selected component depends on and what uses it", () => {
    render(<TechBomDependencyGraph state={state()} />);
    fireEvent.click(screen.getByTestId("depnode-sbom|app:sys-core"));
    const detail = screen.getByLabelText("Selected component");
    expect(detail).toHaveTextContent("Depends on · 3");
    expect(detail).toHaveTextContent("cryptography 42.0.5");
    expect(detail).toHaveTextContent("Used by · 0");
  });

  it("filters layers with the chips", () => {
    render(<TechBomDependencyGraph state={state()} />);
    expect(screen.getByTestId("depnode-hbom|hw:hsm-01")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Hardware/ }));
    expect(screen.queryByTestId("depnode-hbom|hw:hsm-01")).not.toBeInTheDocument();
  });

  it("shows components only, with a note, when the BOM records no edges", () => {
    render(<TechBomDependencyGraph state={state({ dependencies: [] })} />);
    expect(screen.getByText(/No dependency edges recorded in this BOM/)).toBeInTheDocument();
    expect(screen.getByTestId("depnode-vendor|vendor:Thales")).toBeInTheDocument();
  });
});
