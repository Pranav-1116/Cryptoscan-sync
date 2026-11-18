import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import CryptoDependencyMap from "./CryptoDependencyMap";
import SystemCascadeSimulator from "./SystemCascadeSimulator";
import { apiDependencyCascade, apiDependencyMap, type CascadeResult, type DependencyMap } from "../../lib/api";

vi.mock("../../lib/api", () => ({ apiDependencyMap: vi.fn(), apiDependencyCascade: vi.fn() }));

const edge = (id: string, from: string, to: string, relation = "CALLS", propagates = true) => ({
  id, from: `system:${from}`, to: `system:${to}`, relation, lifecycle_state: propagates ? "ACTIVE" : "RETIRED",
  propagates, provenance: "DECLARED", source: "imported", evidence_ref: `${from} uses ${to}`,
});

function depMap(): DependencyMap {
  const sys = (id: string, label: string, algos: string[], risk: any, criticality = "HIGH") => ({
    id: `system:${id}`, system_id: id, label, kind: "system" as const, criticality, business_unit: null, owner: null,
    environment: null, algorithm_ids: algos, risk, component_count: algos.length ? 1 : 0,
  });
  return {
    policy: { version: "p/2", direction: "consumer_to_provider", meaning: "A → B means A depends on B" },
    generated_at: "2026-11-16T00:00:00Z",
    systems: [
      sys("atm", "ATM Switch", ["algorithm:rsa-1024"], "disallowed"),
      sys("core", "Core Ledger", [], null, "CRITICAL"),
      sys("hsm", "Payment HSM", [], null, "CRITICAL"),
      sys("ibank", "Internet Banking", ["algorithm:rsa-2048"], "quantum_vulnerable"),
    ],
    components: [
      { id: "component:a", label: "bdk_loader.cpp", kind: "source", location: "atm-switch/src/dukpt/bdk_loader.cpp", system_ids: ["atm"], algorithm_ids: ["algorithm:rsa-1024"], asset_count: 1, languages: ["cpp"], risk: "disallowed" },
      { id: "component:b", label: "TlsContextFactory.java", kind: "source", location: "portal/src/TlsContextFactory.java", system_ids: ["ibank"], algorithm_ids: ["algorithm:rsa-2048"], asset_count: 1, languages: ["java"], risk: "quantum_vulnerable" },
    ],
    libraries: [{ id: "library:bouncycastle@1.78", label: "BouncyCastle 1.78", name: "BouncyCastle", version: "1.78", component_ids: ["component:b"], algorithm_ids: ["algorithm:rsa-2048"], system_ids: ["ibank"] }],
    algorithms: [
      { id: "algorithm:rsa-1024", label: "RSA-1024", canonical: "RSA", family: "pke", status: "DISALLOWED", quantum_impact: "shor", key_size: 1024, risk: "disallowed", risk_label: "Disallowed", asset_count: 1, component_ids: ["component:a"], system_ids: ["atm"], library_ids: [], purposes: ["SIGNING"], modes: [] },
      { id: "algorithm:rsa-2048", label: "RSA-2048", canonical: "RSA", family: "pke", status: "ALLOWED", quantum_impact: "shor", key_size: 2048, risk: "quantum_vulnerable", risk_label: "Quantum-vulnerable", asset_count: 1, component_ids: ["component:b"], system_ids: ["ibank"], library_ids: ["library:bouncycastle@1.78"], purposes: ["SIGNING"], modes: [] },
    ],
    edges: {
      contains: [
        { from: "system:atm", to: "component:a", relation: "CONTAINS", basis: "system_assets link", asset_ids: ["x1"] },
        { from: "system:ibank", to: "component:b", relation: "CONTAINS", basis: "system_assets link", asset_ids: ["x2"] },
      ],
      uses: [
        { from: "component:a", to: "algorithm:rsa-1024", relation: "USES", basis: "row", library_ids: [], locations: [{ asset_id: "x1", file_path: "atm-switch/src/dukpt/bdk_loader.cpp", line_number: 12, purpose: "SIGNING", mode: null, key_size: 1024, confidence: "HIGH", is_hardcoded_key: false, scanner_ids: [] }] },
        { from: "component:b", to: "algorithm:rsa-2048", relation: "USES", basis: "row", library_ids: ["library:bouncycastle@1.78"], locations: [{ asset_id: "x2", file_path: "portal/src/TlsContextFactory.java", line_number: 41, purpose: "SIGNING", mode: null, key_size: 2048, confidence: "HIGH", is_hardcoded_key: false, scanner_ids: [] }] },
      ],
      links: [{ from: "component:b", to: "library:bouncycastle@1.78", relation: "LINKS", basis: "lib", asset_ids: ["x2"] }],
      provides: [{ from: "library:bouncycastle@1.78", to: "algorithm:rsa-2048", relation: "PROVIDES", basis: "lib", asset_ids: ["x2"] }],
      depends_on: [edge("e1", "ibank", "core"), edge("e2", "core", "hsm", "DEPENDS_ON"), edge("e3", "atm", "hsm", "DEPENDS_ON"), edge("e4", "atm", "core", "CALLS", false)],
    },
    coverage: { assets: 2, attributed_assets: 2, unattributed_assets: 0, systems: 4, systems_with_crypto: 2, dependency_edges: 4, propagating_edges: 3 },
  };
}

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(apiDependencyMap).mockResolvedValue({ source: "live", data: depMap() });
});

describe("CryptoDependencyMap", () => {
  it("lists which software uses each algorithm with file:line evidence", async () => {
    render(<CryptoDependencyMap />);
    await screen.findByText("Which software uses each algorithm");
    expect(screen.getByRole("button", { name: "algorithm RSA-1024" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "algorithm RSA-1024" }));
    expect(await screen.findByText(/bdk_loader\.cpp:12/)).toBeTruthy();
    expect(screen.getByText(/Used by/)).toBeTruthy();
  });

  it("filters to weak algorithms only", async () => {
    render(<CryptoDependencyMap />);
    await screen.findByText("Which software uses each algorithm");
    fireEvent.click(screen.getByRole("button", { name: "Weak only" }));
    await waitFor(() => expect(screen.queryByRole("button", { name: "algorithm RSA-2048" })).toBeNull());
    expect(screen.getByRole("button", { name: "algorithm RSA-1024" })).toBeTruthy();
  });

  it("shows system dependencies in the system inspector", async () => {
    render(<CryptoDependencyMap />);
    await screen.findByText("Which software uses each algorithm");
    fireEvent.click(screen.getByRole("button", { name: "system Internet Banking" }));
    expect(await screen.findByText(/Depends on:/)).toBeTruthy();
    expect(screen.getByRole("button", { name: /Core Ledger · CALLS/ })).toBeTruthy();
  });
});

describe("SystemCascadeSimulator", () => {
  it("renders who depends on whom and runs a selected-system cascade", async () => {
    const result: CascadeResult = {
      direction: "dependents", hops: 6,
      seeds: [{ id: "system:hsm", system_id: "hsm", name: "Payment HSM", criticality: "CRITICAL", risk: null, algorithms: [], weak_algorithms: [], reasons: ["selected"] }],
      impacted: [{ id: "system:core", system_id: "core", name: "Core Ledger", criticality: "CRITICAL", risk: null, algorithms: [], weak_algorithms: [], hops: 1, direction: "dependents",
        path: ["system:hsm", "system:core"], chain: ["system:core", "system:hsm"], path_names: ["Payment HSM", "Core Ledger"], chain_names: ["Core Ledger", "Payment HSM"],
        path_edges: [edge("e2", "core", "hsm", "DEPENDS_ON") as any] }],
      algorithm_seeds: [], unknown_selections: [],
      summary: { seed_systems: 1, impacted_systems: 1, max_depth: 1, by_criticality: { CRITICAL: 1 }, edges_considered: 3, edges_not_propagating: 1 },
      not_propagating: [], semantics: "dependents = consumers",
    };
    vi.mocked(apiDependencyCascade).mockResolvedValue({ source: "live", data: result });
    render(<SystemCascadeSimulator />);
    await screen.findByText("Who depends on whom");
    fireEvent.click(screen.getByRole("checkbox", { name: "analyse Payment HSM" }));
    fireEvent.click(screen.getByRole("button", { name: "Simulate cascade" }));
    await screen.findByTestId("cascade-result");
    expect(apiDependencyCascade).toHaveBeenCalledWith({ system_ids: ["hsm"], algorithm_ids: [], direction: "dependents", hops: 6 });
    expect(screen.getByText("1 impacted")).toBeTruthy();
    expect(screen.getByText(/depends on the seed/)).toBeTruthy();
  });

  it("refuses to run with nothing selected", async () => {
    render(<SystemCascadeSimulator />);
    await screen.findByText("Who depends on whom");
    fireEvent.click(screen.getByRole("button", { name: "Simulate cascade" }));
    expect(await screen.findByText("Select at least one system or algorithm.")).toBeTruthy();
    expect(apiDependencyCascade).not.toHaveBeenCalled();
  });
});
