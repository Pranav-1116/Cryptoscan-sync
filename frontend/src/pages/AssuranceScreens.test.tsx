import React from "react";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { mockFetch } from "../test/setup";
import AssuranceCoverage from "./AssuranceCoverage";
import AssuranceQualification from "./AssuranceQualification";
import AssuranceRecords from "./AssuranceRecords";
import AssuranceSampling from "./AssuranceSampling";
import AssuranceTrace from "./AssuranceTrace";

/* The five assurance read screens.
 *
 * What is asserted here is deliberately narrow, because it is the whole contract:
 * a screen reads only after an exact identifier is supplied, renders the server's
 * payload rather than a derived percentage, and shows the error instead of a
 * previous success when the read fails.
 */

const record = (revision: number, subject: string) => ({
  id: `rec-${revision}`, kind: "estate_register", subject_id: subject, revision,
  payload: { declared: subject }, payload_sha256: "a".repeat(64), previous_sha256: revision > 1 ? "b".repeat(64) : null,
  created_by: "11111111-1111-1111-1111-111111111111", created_at: "2026-10-01T00:00:00Z",
});

const coverage = {
  register_id: "reg-1", revision: 3, registered_targets: 2,
  register_completeness: "OWNER_ATTESTED", scope_description: "Synthetic payments scope",
  completeness_evidence_ref: "EV-77", whole_bank_verified: false,
  denominator_basis: "REGISTERED_TARGETS_ONLY_NOT_DISCOVERED_ASSETS",
  completeness_basis: "OWNER_ATTESTATION_NOT_INDEPENDENT_VERIFICATION",
  counts: { OBSERVED: 1, STALE: 1, BLOCKED: 0, UNSUPPORTED: 0, NOT_ATTEMPTED: 0 },
  by_kind: { HOST: { registered: 2, OBSERVED: 1, STALE: 1, BLOCKED: 0, UNSUPPORTED: 0, NOT_ATTEMPTED: 0 } },
  targets: [
    { target_id: "t-1", target_ref: "hsm-prod-03", kind: "HOST", method: "SSH_READONLY", state: "OBSERVED",
      freshness_seconds: 3600, expires_at: "2026-10-01T01:00:00Z", last_attempted_at: "2026-10-01T00:10:00Z",
      last_successful_at: "2026-10-01T00:10:00Z" },
    { target_id: "t-2", target_ref: "legacy-api-02", kind: "HOST", method: "SSH_READONLY", state: "STALE",
      freshness_seconds: 60, expires_at: "2026-10-01T00:11:00Z", last_attempted_at: "2026-09-30T23:00:00Z",
      last_successful_at: "2026-09-30T23:00:00Z" },
  ],
  as_of: "2026-10-01T00:30:00Z",
};

const trace = {
  application_id: "app-1", complete: false, runtime_verified: false,
  note: "Explicit evidence-traceable reviewed assertions; package presence is not deployment.",
  paths: [{ application_id: "app-1", deployment_id: "d-1", deployment_basis: "ATTESTED", deployment_evidence_ref: "EV-1",
    artifact_id: "art-1", artifact_digest: "c".repeat(64), artifact_identity_source: "SBOM",
    sbom_binding_id: "bind-1", sbom_sha256: "d".repeat(64), package_identity: "pkg:generic/openssl@3.0.1",
    crypto_evidence_id: "EV-9", algorithm: "RSA", purpose: "TLS", location: { file: "src/tls.c", line: 42 },
    relationship_id: "rel-1", relationship_sha256: "e".repeat(64), evidence_ids: ["EV-9"], trust: { trust: "REVIEWED" },
    deployed_verified: false, invocation_verified: false }],
  unresolved: [{ reason: "NO_CURRENT_REVIEWED_CRYPTO_EDGE", artifact_id: "art-2", package_identity: "pkg:generic/zlib@1.3" }],
};

const workbook = {
  sample_id: "smp-1", sample_sha256: "f".repeat(64), phase: "FIRST_PASS" as const,
  domain_owner: "payments-platform", scope: "release 2026.10",
  units: [{ unit_id: "u-1", split: "FIRST_PASS", prediction: { algorithm: "AES" }, truth_label: "UNREVIEWED" }],
  truth_labels: ["PRESENT", "ABSENT", "UNREVIEWED"],
  note: "Return truth labels and explanations; TP/FP/misses are calculated from frozen predictions.",
};

const adapter = {
  manifest: { ...record(1, "adp-1"), kind: "adapter_manifest" },
  qualification: null,
  offline_profile_exercised: false, live_vendor_supported: false as const,
  support_status: "NOT_QUALIFIED" as const,
};

const redis = {
  objectives: { ...record(2, "obj-1"), kind: "redis_objectives" },
  matrix: [{ role: "session_store", scenario: "failover", measurement_id: null, accepted: false, state: "NOT_MEASURED" }],
  unqualified_roles: ["cache"],
  deployment_evidence_meets_objectives: false,
  whole_infrastructure_qualified: false,
  qualification_basis: "DEPLOYMENT_SPECIFIC_OPERATOR_MEASUREMENTS_AND_SEPARATE_HUMAN_REVIEW",
  local_sentinel_promotion_is_deployment_qualification: false as const,
};

describe("assurance read screens", () => {
  it("records screen reads nothing until a kind page is requested and then quotes the chain", async () => {
    const fetch = mockFetch({
      "/api/v1/assurance/records": { records: [record(2, "reg-1")], has_more: true, next_offset: 100, includes_all_revisions: true },
      "/api/v1/assurance/records/estate_register/reg-1": { revisions: [record(1, "reg-1"), record(2, "reg-1")], has_more: false },
    });
    render(<MemoryRouter><AssuranceRecords /></MemoryRouter>);
    expect(fetch).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Read up to 100 revisions" }));
    await screen.findByText(/1 revision\(s\)/);
    expect(screen.getByText(/more available at offset 100/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "history" }));
    await screen.findByText(/2 revision\(s\) returned/);
    expect(fetch.mock.calls.some(([url]) => String(url).includes("/records/estate_register/reg-1"))).toBe(true);
  });

  it("coverage screen prints the register basis and refuses to imply whole-bank coverage", async () => {
    mockFetch({ "/api/v1/assurance/registers/reg-1/coverage": coverage });
    render(<MemoryRouter><AssuranceCoverage /></MemoryRouter>);
    fireEvent.change(screen.getByLabelText("Register ID"), { target: { value: "reg-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Read coverage" }));

    await screen.findByText(/2 registered target\(s\)/);
    expect(screen.getByText(/DENOMINATOR IS THE REGISTER/)).toBeInTheDocument();
    expect(screen.getAllByText(/REGISTERED_TARGETS_ONLY_NOT_DISCOVERED_ASSETS/).length).toBeGreaterThan(0);
    expect(screen.getByText("whole_bank_verified: false")).toBeInTheDocument();
    expect(screen.getByText(/no whole-bank percentage/)).toBeInTheDocument();
  });

  it("trace screen shows the unresolved component instead of dropping it", async () => {
    mockFetch({ "/api/v1/assurance/applications/app-1/trace": trace });
    render(<MemoryRouter><AssuranceTrace /></MemoryRouter>);
    fireEvent.change(screen.getByLabelText("Application ID"), { target: { value: "app-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Read trace" }));

    await screen.findByText(/1 resolved path\(s\)/);
    expect(screen.getByText("pkg:generic/openssl@3.0.1")).toBeInTheDocument();
    expect(screen.getByText("NO_CURRENT_REVIEWED_CRYPTO_EDGE")).toBeInTheDocument();
    expect(screen.getByText(/CALL PATH NOT PROVEN/)).toBeInTheDocument();
  });

  it("sampling screen renders UNREVIEWED as unreviewed and computes no metric", async () => {
    mockFetch({ "/api/v1/assurance/samples/smp-1/workbook": workbook });
    render(<MemoryRouter><AssuranceSampling /></MemoryRouter>);
    fireEvent.change(screen.getByLabelText("Sample ID"), { target: { value: "smp-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Read workbook" }));

    await screen.findByText(/1 unit\(s\) in this phase/);
    expect(screen.getAllByText("UNREVIEWED").length).toBeGreaterThan(0);
    expect(screen.getByText(/NO METRIC COMPUTED HERE/)).toBeInTheDocument();
  });

  it("qualification screen says a declared manifest is not a supported adapter", async () => {
    mockFetch({
      "/api/v1/assurance/adapters/adp-1": adapter,
      "/api/v1/assurance/redis-objectives/obj-1/qualification": redis,
    });
    render(<MemoryRouter><AssuranceQualification /></MemoryRouter>);
    fireEvent.change(screen.getByLabelText("Adapter ID"), { target: { value: "adp-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Read adapter status" }));

    await screen.findByText(/support status/);
    expect(screen.getByText(/No qualification exists for this manifest/)).toBeInTheDocument();
    expect(screen.getByText(/live vendor supported/)).toHaveTextContent("false");

    fireEvent.change(screen.getByLabelText("Objectives ID"), { target: { value: "obj-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Read qualification matrix" }));
    await screen.findByText(/deployment meets objectives/);
    expect(screen.getByText("NOT_MEASURED")).toBeInTheDocument();
    expect(screen.getByText(/local_sentinel_promotion_is_deployment_qualification:\s*false/)).toBeInTheDocument();
  });

  it("shows the failure instead of the previous payload when a read fails", async () => {
    mockFetch({ "/api/v1/assurance/registers/reg-1/coverage": coverage });
    render(<MemoryRouter><AssuranceCoverage /></MemoryRouter>);
    fireEvent.change(screen.getByLabelText("Register ID"), { target: { value: "reg-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Read coverage" }));
    await screen.findByText(/2 registered target\(s\)/);

    // The next read has no route: the mock answers 404.
    fireEvent.change(screen.getByLabelText("Register ID"), { target: { value: "reg-missing" } });
    fireEvent.click(screen.getByRole("button", { name: "Read coverage" }));
    await screen.findByRole("alert");
    expect(screen.getByRole("alert")).toHaveTextContent("no cached success substituted");
    expect(screen.queryByText(/2 registered target\(s\)/)).toBeNull();
  });

  it("clears a rendered payload when the estate context changes", async () => {
    mockFetch({ "/api/v1/assurance/applications/app-1/trace": trace });
    render(<MemoryRouter><AssuranceTrace /></MemoryRouter>);
    fireEvent.change(screen.getByLabelText("Application ID"), { target: { value: "app-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Read trace" }));
    await screen.findByText(/1 resolved path\(s\)/);

    await act(async () => {
      localStorage.setItem("cryptoscan_tenant", "another-estate");
      window.dispatchEvent(new StorageEvent("storage", { key: "cryptoscan_tenant", storageArea: localStorage }));
    });
    expect(screen.queryByText(/1 resolved path\(s\)/)).toBeNull();
  });
});
