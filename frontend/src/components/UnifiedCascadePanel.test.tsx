import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import UnifiedCascadePanel from "./UnifiedCascadePanel";
import { apiCascadeRunDiff, apiCascadeRuns, apiUnifiedCascade, UnifiedCascadeResult } from "../lib/api";

vi.mock("../lib/api", () => ({
  apiCascadeRunDiff: vi.fn(), apiCascadeRuns: vi.fn(), apiUnifiedCascade: vi.fn(),
}));

function answer(): UnifiedCascadeResult {
  return {
    schema: "cryptoscan.unified-cascade/1", verdict: "AFFECTED", run_id: "run-1",
    target: { input: "payments", kind: "system" }, as_of: "2026-10-18T00:00:00Z",
    layers: {}, honest_unknowns: ["Registered links only"],
    impact: {
      affected_systems: ["ledger", "mobile", "payments"], affected_system_count: 3,
      system_classification: {
        schema: "cryptoscan.cascade-system-scope/1",
        direct_exposure: { systems: ["payments"], count: 1 },
        dependent_consumers: { systems: ["mobile"], count: 1 },
        supporting_context: { systems: ["ledger"], count: 1 },
        exposure_systems: ["mobile", "payments"], exposure_system_count: 2,
        review_systems: ["ledger", "mobile", "payments"], review_system_count: 3,
      },
    },
  };
}

async function runCascade() {
  fireEvent.change(screen.getByRole("textbox", { name: "cascade target" }), { target: { value: "payments" } });
  fireEvent.click(screen.getByRole("button", { name: "Run cascade" }));
  await screen.findByText("Modeled exposure: 2");
}

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(apiCascadeRuns).mockResolvedValue({ source: "live", data: { runs: [], count: 0 } });
  vi.mocked(apiUnifiedCascade).mockResolvedValue({ source: "live", data: answer() });
});

describe("cascade disjoint system classification", () => {
  it("renders direct, consumer and context lists separately and labels both totals", async () => {
    render(<UnifiedCascadePanel />);
    await runCascade();
    const direct = within(screen.getByRole("region", { name: "Direct exposure" }));
    const consumers = within(screen.getByRole("region", { name: "Dependent consumers" }));
    const context = within(screen.getByRole("region", { name: "Supporting context" }));
    expect(direct.getByText("payments")).toBeInTheDocument();
    expect(consumers.getByText("mobile")).toBeInTheDocument();
    expect(consumers.queryByText("ledger")).not.toBeInTheDocument();
    expect(context.getByText("ledger")).toBeInTheDocument();
    expect(screen.getByText("Review scope: 3")).toBeInTheDocument();
    expect(screen.queryByText("Affected systems")).not.toBeInTheDocument();
    expect(screen.getByText(/not confirmed failures\. Zero linked systems/)).toBeInTheDocument();
  });

  it("does not invent a classification for an older answer", async () => {
    const legacy = answer();
    delete legacy.impact.system_classification;
    vi.mocked(apiUnifiedCascade).mockResolvedValue({ source: "live", data: legacy });
    render(<UnifiedCascadePanel />);
    fireEvent.change(screen.getByRole("textbox", { name: "cascade target" }), { target: { value: "payments" } });
    fireEvent.click(screen.getByRole("button", { name: "Run cascade" }));
    expect(await screen.findByText("Legacy review scope: 3")).toBeInTheDocument();
    expect(screen.getByText(/Classification unavailable for this answer/)).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Direct exposure" })).not.toBeInTheDocument();
    expect(screen.queryByText(/Modeled exposure:/)).not.toBeInTheDocument();
  });

  it("keeps inventory-only zero counts explicitly unknown rather than safe", async () => {
    const inventory = answer();
    inventory.layers = { hardware: { inventory_only: true } };
    inventory.impact.affected_systems = [];
    inventory.impact.affected_system_count = 0;
    inventory.impact.system_classification = {
      schema: "cryptoscan.cascade-system-scope/1",
      direct_exposure: { systems: [], count: 0 }, dependent_consumers: { systems: [], count: 0 },
      supporting_context: { systems: [], count: 0 }, exposure_systems: [], exposure_system_count: 0,
      review_systems: [], review_system_count: 0,
    };
    vi.mocked(apiUnifiedCascade).mockResolvedValue({ source: "live", data: inventory });
    render(<UnifiedCascadePanel />);
    fireEvent.change(screen.getByRole("textbox", { name: "cascade target" }), { target: { value: "hsm" } });
    fireEvent.click(screen.getByRole("button", { name: "Run cascade" }));
    expect(await screen.findByText("Modeled exposure: 0")).toBeInTheDocument();
    expect(screen.getByText(/Hardware linkage is inventory-only/)).toBeInTheDocument();
    expect(screen.getByText("AFFECTED")).toBeInTheDocument();
  });

  it("labels legacy history and unavailable mixed-version comparisons honestly", async () => {
    vi.mocked(apiCascadeRuns).mockResolvedValue({ source: "live", data: { count: 1, runs: [{
      id: "old", target: "payments", target_kind: "system", max_depth: 6, verdict: "AFFECTED",
      affected_system_count: 3, created_by: "auditor", created_at: null,
    }] } });
    vi.mocked(apiCascadeRunDiff).mockResolvedValue({ source: "live", data: {
      target: "payments", verdict_changed: false,
      run: { id: "old", created_at: null, verdict: "AFFECTED" },
      against: { id: "older", created_at: null, verdict: "AFFECTED" },
      affected_systems: { before: 3, after: 3, added: [], removed: [], unchanged_count: 3 },
      affected_processes: { before: 0, after: 0, added: [], removed: [] },
      system_classification: { available: false },
    } });
    render(<UnifiedCascadePanel />);
    expect(await screen.findByText(/legacy review scope: 3 · breakdown unavailable/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "diff vs previous" }));
    expect(await screen.findByText("Classification comparison unavailable for these stored runs.")).toBeInTheDocument();
  });
  it("shows per-category moves even when the review total stays unchanged", async () => {
    vi.mocked(apiCascadeRuns).mockResolvedValue({ source: "live", data: { count: 1, runs: [{
      id: "new", target: "payments", target_kind: "system", max_depth: 6, verdict: "AFFECTED",
      affected_system_count: 3, created_by: "auditor", created_at: null,
      system_classification: answer().impact.system_classification,
    }] } });
    const unchanged = { before: 1, after: 1, added: [], removed: [], unchanged_count: 1 };
    vi.mocked(apiCascadeRunDiff).mockResolvedValue({ source: "live", data: {
      target: "payments", verdict_changed: false,
      run: { id: "new", created_at: null, verdict: "AFFECTED" },
      against: { id: "old", created_at: null, verdict: "AFFECTED" },
      affected_systems: { before: 3, after: 3, added: [], removed: [], unchanged_count: 3 },
      affected_processes: { before: 0, after: 0, added: [], removed: [] },
      system_classification: { available: true, direct_exposure: unchanged,
        dependent_consumers: { before: 1, after: 2, added: ["ledger"], removed: [], unchanged_count: 1 },
        supporting_context: { before: 1, after: 0, added: [], removed: ["ledger"], unchanged_count: 0 } },
    } });
    render(<UnifiedCascadePanel />);
    expect(await screen.findByText(/1 direct \/ 1 consumers \/ 1 context · 3 review/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "diff vs previous" }));
    expect(await screen.findByText(/Dependent consumers: 1 → 2 · added: ledger/)).toBeInTheDocument();
    expect(screen.getByText(/Supporting context: 1 → 0 · removed: ledger/)).toBeInTheDocument();
  });

  it("shows the versioned policy on new results and warns for mixed-policy comparisons", async () => {
    const result = answer();
    result.relationship_policy = {
      version: "cryptoscan.system-dependency-policy/1", direction: "consumer_to_provider",
      propagating_relations: ["CALLS", "IMPORTS", "IMPORTS_CRYPTO", "DEPENDS_ON"],
      context_relations: ["CONTAINS"], unknown_relations: "non_propagating",
      unspecified_relation: "CALLS", max_system_hops: 12,
    };
    vi.mocked(apiUnifiedCascade).mockResolvedValue({ source: "live", data: result });
    vi.mocked(apiCascadeRuns).mockResolvedValue({ source: "live", data: { count: 1, runs: [{
      id: "new", target: "payments", target_kind: "system", max_depth: 6, verdict: "AFFECTED",
      affected_system_count: 3, created_by: "auditor", created_at: null,
    }] } });
    vi.mocked(apiCascadeRunDiff).mockResolvedValue({ source: "live", data: {
      target: "payments", verdict_changed: false,
      run: { id: "new", created_at: null, verdict: "AFFECTED" },
      against: { id: "old", created_at: null, verdict: "AFFECTED" },
      affected_systems: { before: 3, after: 3, added: [], removed: [], unchanged_count: 3 },
      affected_processes: { before: 0, after: 0, added: [], removed: [] },
      system_classification: { available: false, reason: "relationship policy is unknown" },
      policy_comparison: { comparable: false, run_version: result.relationship_policy.version, against_version: null },
    } });
    render(<UnifiedCascadePanel />);
    await runCascade();
    expect(screen.getByText(/Relationship policy: cryptoscan.system-dependency-policy\/1/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "diff vs previous" }));
    expect(await screen.findByText(/Count changes are not evidence of remediation/)).toBeInTheDocument();
  });

  it("discloses release digests, SBOM document hashes and declared deployment evidence separately", async () => {
    const result = answer();
    result.layers.software = {
      schema: "cryptoscan.software-supply-chain/1",
      artifacts: [{ id: "release", digest: `sha256:${"a".repeat(64)}`, identity_source: "CONTENT_HASHED", evidence_ref: "build/17" }],
      sbom_bindings: [{ id: "link", artifact_id: "release", sbom_artifact_id: "sbom-doc", sbom_sha256: "b".repeat(64), assertion_source: "SUPPLIER_DECLARED", evidence_ref: "supplier/17", unresolved_component_count: 1 }],
      packages: [{ purl: "pkg:pypi/crypto@1.0", package_identity: "pkg:pypi/crypto@1.0", name: "crypto", sbom_binding_id: "link", artifact_id: "release" }],
      deployments: [{ id: "deployment", artifact_id: "release", system_id: "payments", deployment_key: "cluster/pay/revision-17", environment: "prod", assertion_source: "OPERATOR_DECLARED", evidence_ref: "change/17" }],
      systems: ["payments"], unlinked_deployment_ids: [], unbound_artifact_ids: [],
      deployment_evidence: "explicit declarations; not independently observed running deployments",
    };
    vi.mocked(apiUnifiedCascade).mockResolvedValue({ source: "live", data: result });
    render(<UnifiedCascadePanel />);
    await runCascade();
    const software = within(screen.getByRole("region", { name: "Software release and deployment evidence" }));
    expect(software.getByText(/Release: sha256:/)).toHaveTextContent("CONTENT_HASHED");
    expect(software.getByText(/document SHA-256:/)).toHaveTextContent("SUPPLIER_DECLARED");
    expect(software.getByText(/Application: payments/)).toHaveTextContent("OPERATOR_DECLARED");
    expect(software.getByText(/not independently observed/)).toBeInTheDocument();
    expect(software.getByText(/Package: pkg:pypi\/crypto@1.0/)).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "package" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "artifact" })).toBeInTheDocument();
  });

  it("keeps stale/expired uncertainty separate and never labels fewer links safe", async () => {
    const result = answer();
    result.relationship_lifecycle = {
      schema: "cryptoscan.relationship-lifecycle/1", as_of: result.as_of,
      counts: { ACTIVE: 1, STALE: 1, EXPIRED: 1, DELETED: 1 },
      excluded_count: 3, excluded_records: [
        { id: "old-edge", kind: "system_dependency", state: "STALE" },
        { id: "old-deployment", kind: "deployment", state: "EXPIRED", valid_until: "2026-10-17T00:00:00Z" },
        { id: "retired", kind: "sbom_binding", state: "DELETED" },
      ], excluded_records_truncated: false, unbounded_active_count: 1, note: "not safety",
    };
    result.impact.lifecycle_uncertainty = { count: 1, possible_additional_systems: ["possible-consumer"], possible_direct_systems: [], note: "not confirmed" };
    vi.mocked(apiUnifiedCascade).mockResolvedValue({ source: "live", data: result });
    render(<UnifiedCascadePanel />);
    await runCascade();
    const panel = within(screen.getByRole("status", { name: "Relationship lifecycle" }));
    expect(panel.getByText(/Fewer active links are not proof of remediation or safety/)).toBeInTheDocument();
    expect(panel.getByText(/Legacy\/unbounded eligibility is not verified freshness/)).toBeInTheDocument();
    expect(panel.getByText("possible-consumer")).toBeInTheDocument();
    expect(panel.getByText(/old-deployment: EXPIRED/)).toBeInTheDocument();
    expect(panel.getByText(/retired: DELETED/)).toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Dependent consumers" })).queryByText("possible-consumer")).not.toBeInTheDocument();
  });

  it("warns about unbound release identity and bounded software input", async () => {
    const result = answer();
    result.layers.software = {
      schema: "cryptoscan.software-supply-chain/1", artifacts: [], sbom_bindings: [], packages: [], deployments: [],
      systems: [], unbound_artifact_ids: ["unbound"], unlinked_deployment_ids: ["missing-system"],
      deployment_evidence: "explicit declarations",
      coverage: { truncated: true, collections: {} },
    };
    vi.mocked(apiUnifiedCascade).mockResolvedValue({ source: "live", data: result });
    render(<UnifiedCascadePanel />);
    await runCascade();
    expect(screen.getByText(/Consumers remain unknown, not safe/)).toBeInTheDocument();
    expect(screen.getByText(/Software supply-chain input was truncated/)).toBeInTheDocument();
    expect(screen.getByText(/missing systems or conflicting environments/)).toBeInTheDocument();
  });

});
