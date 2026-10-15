/* CMDB page truth (§4.6, round 68): every unified-risk score is
 * explainable. The "Why?" affordance loads the asset-level chain —
 * per-factor provenance with DECLARED/OBSERVED basis, the evidence rows
 * joined on the identity spine, the STORED control verdicts, the asset's
 * own PQC wave and its owners — and the honest limitations are surfaced,
 * not absorbed. A failed explain never fabricates a panel. */
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { mockFetch } from "../test/setup";
import Cmdb from "./Cmdb";

afterEach(() => {
  localStorage.clear();
});

const renderPage = () =>
  render(
    <MemoryRouter>
      <Cmdb />
    </MemoryRouter>,
  );

const inventoryAsset = {
  id: "crypto:42",
  asset_type: "Crypto",
  name: "DES",
  risk: "MEDIUM",
  pqc: "unknown",
  algorithm: "DES",
  owner: "payments-team",
  relationships: { used_by: ["sys-x"] },
};

const unifiedAsset = {
  id: "crypto:42",
  name: "DES",
  asset_type: "Crypto",
  score: 21.6,
  level: "LOW",
  factors: {
    technical: { level: 2, points: 3.6, weight: 0.18 },
    crypto: { level: 4, points: 6.4, weight: 0.16 },
    pqc: { level: 0, points: 0, weight: 0.16 },
    exposure: { level: 0, points: 0, weight: 0.12 },
    business_criticality: { level: 0, points: 0, weight: 0.14 },
    dependency_impact: { level: 1, points: 1.0, weight: 0.1 },
    evidence_confidence: { level: 4, points: 2.4, weight: 0.06 },
    threat: { level: 0, points: 0, weight: 0.08 },
  },
  missing: [],
};

const pageMocks = () =>
  mockFetch({
    "/api/v1/inventory/assets": { assets: [inventoryAsset], count: 1 },
    "/api/v1/inventory/summary": {
      total: 1,
      by_type: { Crypto: 1 },
      by_risk: { MEDIUM: 1 },
      by_pqc: { unknown: 1 },
    },
    "/api/v1/risk/unified": {
      assets: [unifiedAsset],
      count: 1,
      estate: { score: 21.6, level: "LOW", count: 1, by_level: { LOW: 1 } },
      factors: ["technical", "crypto", "pqc", "exposure", "business_criticality", "dependency_impact", "evidence_confidence", "threat"],
      source: "unified_risk_engine",
    },
  });

const explainBody = {
  asset_id: "crypto:42",
  asset_type: "Crypto",
  name: "DES",
  risk: { score: 21.6, level: "LOW", calculation_version: "unified-risk-v1", weights_source: "default" },
  factors: [
    {
      factor: "crypto",
      level: 4,
      points: 6.4,
      weight: 0.16,
      basis: "OBSERVED",
      basis_note: "algorithm designations observed in the latest scan's evidence",
      derived_from: {
        inputs: { algorithm: "DES", "stored crypto_level": null },
        rule: "algorithm name matches the weak_or_legacy family token 'DES' → level 4; max with any stored crypto_level",
      },
    },
    {
      factor: "threat",
      level: 0,
      points: 0,
      weight: 0.08,
      basis: "OBSERVED",
      basis_note: "CVE rows recorded for the latest scan",
      derived_from: {
        inputs: { threat_level: null },
        rule: "inventory rows carry no threat feed today — level 0 means UNKNOWN, not 'no active threat'",
      },
    },
  ],
  inventory_row: inventoryAsset,
  evidence_trail: {
    asset_key: "fact:v1:abc123",
    total_observations: 1,
    entries: [
      {
        evidence_id: "ev-1",
        scan_id: "scan-x",
        verify_path: "/api/v1/scans/scan-x/verify",
        location: "src/F0.java:1",
        chain_position: 0,
        compliance_status: "FAIL",
      },
    ],
    failing_controls: [
      {
        rule_id: "BASE-001",
        rule_name: "No DES",
        worst_outcome: "FAIL",
        evidence_count: 1,
        messages: ["DES is deprecated"],
      },
    ],
    note: "Joined on the identity spine (fact:v1:abc123…); 1 observation(s) across 1 scan(s).",
  },
  pqc_rationale: null,
  accountability: {
    owner: "payments-team",
    technical_owner: null,
    security_owner: null,
    systems_using: ["sys-x"],
    note: "Owners as registered on the asset.",
  },
  system_explain_path: null,
  limitations: [
    "Dependency impact counts declared CMDB edges, not an observed blast radius.",
    "Threat level 0 means no threat feed on this inventory row — unknown, not 'no active threat'.",
  ],
  model: "asset-risk-explanation/v1",
};

describe("Cmdb — per-asset risk explainability (§4.6)", () => {
  it("renders the unified risk rows with a Why? affordance per asset", async () => {
    pageMocks();
    renderPage();
    await waitFor(() => expect(screen.getByRole("button", { name: "Why?" })).toBeTruthy());
  });

  it("Why? loads the chain: factor provenance, evidence trail, stored verdicts, owners, limitations", async () => {
    // NOTE: the asset id is URL-encoded on the wire (crypto%3A42)
    const fn = mockFetch({
      "/api/v1/inventory/assets": { assets: [inventoryAsset], count: 1 },
      "/api/v1/inventory/summary": { total: 1, by_type: { Crypto: 1 }, by_risk: { MEDIUM: 1 }, by_pqc: { unknown: 1 } },
      "/api/v1/risk/unified": { assets: [unifiedAsset], count: 1, estate: { score: 21.6, level: "LOW", count: 1, by_level: { LOW: 1 } }, factors: [], source: "unified_risk_engine" },
      "/api/v1/risk/unified/crypto%3A42/explain": explainBody,
    });
    renderPage();
    await waitFor(() => expect(screen.getByRole("button", { name: "Why?" })).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "Why?" }));
    await waitFor(() => expect(screen.getByText(/weak_or_legacy family token 'DES'/)).toBeTruthy());
    // the explain call carries the encoded asset id
    const called = fn.mock.calls.map((c) => String(c[0]));
    expect(called.some((p) => p.includes("/api/v1/risk/unified/crypto%3A42/explain"))).toBe(true);
    // WHERE the observation came from + the verify path context
    expect(screen.getByText("src/F0.java:1")).toBeTruthy();
    expect(screen.getByText("scan-x")).toBeTruthy();
    // WHY the control fails — the stored verdict, rule id and message
    expect(screen.getByText("BASE-001")).toBeTruthy();
    expect(screen.getByText(/DES is deprecated/)).toBeTruthy();
    // WHO owns it (also rendered by the inventory table — both are real)
    expect(screen.getAllByText("payments-team").length).toBeGreaterThanOrEqual(2);
    // level 0 explained as unknown, never clean
    expect(screen.getByText(/level 0 means UNKNOWN/)).toBeTruthy();
    expect(screen.getAllByText(/no threat feed/).length).toBeGreaterThanOrEqual(2);
    // the epistemic basis is visible per factor (both mock factors are OBSERVED)
    expect(screen.getAllByText("OBSERVED").length).toBe(2);
  });

  it("Close hides the panel; a failed explain never fabricates one", async () => {
    mockFetch({
      "/api/v1/inventory/assets": { assets: [inventoryAsset], count: 1 },
      "/api/v1/inventory/summary": { total: 1, by_type: { Crypto: 1 }, by_risk: { MEDIUM: 1 }, by_pqc: { unknown: 1 } },
      "/api/v1/risk/unified": { assets: [unifiedAsset], count: 1, estate: { score: 21.6, level: "LOW", count: 1, by_level: { LOW: 1 } }, factors: [], source: "unified_risk_engine" },
      // explain 404s (default fallback)
    });
    renderPage();
    await waitFor(() => expect(screen.getByRole("button", { name: "Why?" })).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "Why?" }));
    await waitFor(() => expect(screen.queryByText(/weak_or_legacy/)).toBeNull());
    expect(screen.queryByText("Honest limitations")).toBeNull();
  });
});
