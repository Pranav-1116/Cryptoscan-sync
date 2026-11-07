import React from "react";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { mockFetch } from "../test/setup";
import IntelligenceWorkbench from "./IntelligenceWorkbench";
import {
  apiIntelligencePqcClaims,
  apiIntelligenceRisk,
  apiIntelligenceSimulation,
} from "../lib/api";
import type { PqcReport, RiskProfile, SimulationResult, ThreatReport } from "./types";

const FINDINGS: ThreatReport = {
  findings: [
    {
      class: "CERTIFICATE_RISK",
      asset: "cn=payments",
      what_changed: "the certificate expires in 5 day(s)",
      why_it_matters: "an expired certificate breaks the trust path",
      evidence_ids: ["E1"],
      not_proven: "this does not prove an outage will happen",
      investigate: "who owns renewal",
      compromise_declared: false,
    },
  ],
  counts: { CERTIFICATE_RISK: 1 },
  compromise_declared: false,
  note: "a detection is a question",
  detectors_fired: ["CERTIFICATE_RISK"],
  detectors_not_fired: {
    PQC_REGRESSION: "no recorded claim contradictions in this database: this detector did not run here",
  },
};

const CLAIMS: PqcReport = {
  subjects: {
    "payments-api": {
      stages: {
        SUPPORT_AVAILABLE: { state: "CLAIMED" },
        CONFIGURED: { state: "NOT_CLAIMED" },
        RUNTIME_OBSERVED: { state: "NOT_CLAIMED" },
        NETWORK_NEGOTIATED: { state: "NOT_CLAIMED" },
        MIGRATION_VALIDATED: { state: "NOT_CLAIMED" },
      },
      readiness: "SUPPORT_ONLY",
      readiness_reason: "a library supporting ML-KEM is not PQC readiness",
      contradictions: [],
    },
  },
  counts: { SUPPORT_ONLY: 1 },
  note: "five stages",
  derived_from: "claims derived from recorded live-state evidence only",
};

const RISK: RiskProfile = {
  dimensions: {
    CRYPTO_RISK: {
      dimension: "CRYPTO_RISK",
      score: 40,
      band: "MEDIUM",
      sense: "risk",
      factors: [{ rule: "CR-2", input: "Shor-broken", contribution: 30, evidence_ids: [] }],
      evidence_ids: [],
      reason: null,
      known: true,
    },
  },
  blended_requested: false,
  blended_score: null,
  blended_arithmetic: [],
  excluded_dimensions: [],
  note: "five dimensions",
  asset_id: "payments-api",
};

const SIM: SimulationResult & { evidence_note?: string } = {
  scenario: "CA_COMPROMISE",
  description: "a certificate authority is compromised",
  hypothetical: true,
  snapshot: { snapshot_id: "7", version: 3, captured_at: "2026-11-07" },
  proven_dependencies: [],
  assumed_dependencies: [
    {
      asset: "lb-1",
      chain: [{ from: "lb-1", predicate: "uses", to: "cert-1", provenance: "UNKNOWN", evidence_ids: [] }],
      why_assumed: "UNKNOWN",
    },
  ],
  approvals_required: ["PKI owner approval"],
  rollback_plan: ["re-pin the previous trust path"],
  evidence_note: "an edge without evidence references classifies as UNKNOWN",
};

describe("IntelligenceWorkbench — live data", () => {
  it("renders findings, detector explanations and claim stages from the API", async () => {
    mockFetch({
      "/api/v1/intelligence/findings": FINDINGS,
      "/api/v1/intelligence/pqc/claims": CLAIMS,
    });
    render(<IntelligenceWorkbench />);
    expect(await screen.findByText("the certificate expires in 5 day(s)")).toBeInTheDocument();
    const notFired = screen.getByLabelText("Detectors that did not run");
    expect(within(notFired).getByText(/PQC_REGRESSION/)).toBeInTheDocument();
    expect(within(notFired).getByText(/did not run here/)).toBeInTheDocument();
    expect(screen.getByText("SUPPORT_ONLY")).toBeInTheDocument();
    expect(screen.getByText(/derived from recorded live-state evidence only/)).toBeInTheDocument();
  });

  it("an offline backend is announced, never fabricated as zeros", async () => {
    render(<IntelligenceWorkbench />); // default stub: every fetch rejects
    expect(await screen.findByText(/BACKEND OFFLINE/)).toBeInTheDocument();
    expect(screen.getByText(/Absence of rows is not absence of risk/)).toBeInTheDocument();
    // the empty ladder keeps its honest wording instead of a clean bill
    expect(screen.getByText(/neither\s+ready nor fine/)).toBeInTheDocument();
  });
});

describe("IntelligenceWorkbench — risk form", () => {
  it("loads five dimensions and sends the horizon as a policy input", async () => {
    const seen: string[] = [];
    mockFetch({
      "/api/v1/intelligence/findings": FINDINGS,
      "/api/v1/intelligence/pqc/claims": CLAIMS,
      "/api/v1/intelligence/risk/payments-api": (url: string) => {
        seen.push(url);
        return RISK;
      },
    });
    render(<IntelligenceWorkbench />);
    await userEvent.type(await screen.findByLabelText("Asset id"), "payments-api");
    await userEvent.clear(screen.getByLabelText(/Quantum threat horizon/));
    await userEvent.type(screen.getByLabelText(/Quantum threat horizon/), "5");
    await userEvent.click(screen.getByRole("button", { name: "load risk" }));
    expect(await screen.findByText("CRYPTO_RISK")).toBeInTheDocument();
    expect(seen.some((u) =>
      u.includes("/api/v1/intelligence/risk/payments-api")
      && u.includes("quantum_threat_horizon_years=5"))).toBe(true);
  });
});

describe("IntelligenceWorkbench — simulation form", () => {
  it("runs against a named snapshot version and labels the result hypothetical", async () => {
    const bodies: Array<Record<string, unknown>> = [];
    mockFetch({
      "/api/v1/intelligence/findings": FINDINGS,
      "/api/v1/intelligence/pqc/claims": CLAIMS,
      "/api/v1/intelligence/simulation": (_url: string, init?: RequestInit) => {
        bodies.push(JSON.parse(String(init?.body)));
        return SIM;
      },
    });
    render(<IntelligenceWorkbench />);
    await userEvent.selectOptions(await screen.findByLabelText("Scenario"), "CA_COMPROMISE");
    await userEvent.type(screen.getByLabelText("Focal asset"), "cert-1");
    await userEvent.type(screen.getByLabelText("Snapshot version"), "3");
    await userEvent.click(screen.getByRole("button", { name: "run simulation" }));
    expect(await screen.findByText(/HYPOTHETICAL/)).toBeInTheDocument();
    expect(bodies).toEqual([{
      scenario: "CA_COMPROMISE", focal_asset: "cert-1", snapshot_version: 3,
    }]);
    expect(screen.getByText(/classifies as UNKNOWN/)).toBeInTheDocument();
    expect(screen.getByText(/assumed dependencies \(not proven\)/)).toBeInTheDocument();
  });
});

describe("intelligence API client contracts", () => {
  it("pqc claims accept a subject filter and risk encodes the asset id", async () => {
    const seen: string[] = [];
    mockFetch({
      "/api/v1/intelligence/pqc/claims*": (url: string) => {
        seen.push(url);
        return CLAIMS;
      },
      "/api/v1/intelligence/risk/*": (url: string) => {
        seen.push(url);
        return RISK;
      },
      "/api/v1/intelligence/findings": FINDINGS,
      "/api/v1/intelligence/simulation": () => SIM,
    });
    await apiIntelligencePqcClaims("payments-api");
    await apiIntelligenceRisk("asset with space", 5);
    expect(seen.some((u) => u.includes("subject=payments-api"))).toBe(true);
    expect(seen.some((u) =>
      u.includes("/intelligence/risk/asset%20with%20space")
      && u.includes("quantum_threat_horizon_years=5"))).toBe(true);
  });

  it("a simulation post names the snapshot explicitly", async () => {
    let body: Record<string, unknown> | null = null;
    mockFetch({
      "/api/v1/intelligence/simulation": (_url: string, init?: RequestInit) => {
        body = JSON.parse(String(init?.body));
        return SIM;
      },
    });
    const result = await apiIntelligenceSimulation({
      scenario: "HSM_FAILURE", focal_asset: "hsm-1", snapshot_version: 12,
    });
    expect(result.source).toBe("live");
    expect(body).toEqual({
      scenario: "HSM_FAILURE", focal_asset: "hsm-1", snapshot_version: 12,
    });
  });
});
