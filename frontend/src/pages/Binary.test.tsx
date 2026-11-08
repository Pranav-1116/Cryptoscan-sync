/* Binary Intelligence (docs/binary-intelligence/01_PRODUCT_SPEC.md §16):
   the honesty rules are display rules: an unknown key size says
   "unknown — never guessed"; a function reference is not proof of
   runtime use; 'not detected' is never 'absent'; every comparison delta
   carries its caveat; relationships carry provenance; a failed read
   says "Read failed" and never prints zeros. */

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { mockFetch } from "../test/setup";
import Binary from "./Binary";

const renderPage = () =>
  render(
    <MemoryRouter initialEntries={["/binary-intelligence"]}>
      <Binary />
    </MemoryRouter>,
  );

const setTenant = () => {
  fireEvent.change(screen.getByLabelText("Tenant"), { target: { value: "tenant_001" } });
};

const setArtifact = (id: string) => {
  fireEvent.change(screen.getByLabelText("Artifact"), { target: { value: id } });
};

const finding = (over: Record<string, unknown> = {}) => ({
  finding_id: "bfind-001",
  subject: "payments-engine",
  finding_type: "cryptographic_algorithm",
  algorithm: "RSA",
  variant: "",
  operation: "key_generation",
  mode_or_padding: "",
  key_size_bits: null,
  library: "OpenSSL",
  detection_method: "function_import_analysis",
  evidence: [{
    type: "function_reference",
    location: "dynamic import table: RSA_generate_key_ex",
    description: "Recognized cryptographic function reference",
    excerpt: "RSA_generate_key_ex",
  }],
  confidence: "indicated",
  usage_status: "statically_referenced",
  runtime_confirmed: false,
  quantum_vulnerable: true,
  pqc_family: false,
  limitations: [
    "a function reference is an indicator of capability or reference — it is not proof that the algorithm runs at runtime (§5)",
  ],
  scanner_version: "cryptoscan-binary-intelligence",
  signature_database_version: "cryptoscan-crypto-fingerprints/1.0.0",
  ...over,
});

describe("Binary Intelligence (§16)", () => {
  it("gates every action behind the tenant", () => {
    renderPage();
    expect(screen.getByRole("button", { name: "Artifact Inventory & Scan" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Crypto Findings" })).toBeDisabled();
    const notes = screen.getAllByText(/never executed/);
    expect(notes.length).toBeGreaterThanOrEqual(1);
  });

  it("renders findings with unknown key sizes named, never guessed", async () => {
    mockFetch({
      "/api/v1/binary/artifacts/bin-1/findings": {
        artifact_id: "bin-1",
        findings: [finding()],
        note: "every finding carries its evidence class and usage status; a function reference is not proof of runtime use (§5), and no finding is never proof of absence (§7)",
      },
    });
    renderPage();
    setTenant();
    setArtifact("bin-1");
    fireEvent.click(screen.getByText("Crypto Findings"));
    fireEvent.click(screen.getByText("load findings"));
    expect(await screen.findByText("unknown")).toBeInTheDocument();
    expect(screen.getByText("(never guessed)")).toBeInTheDocument();
    expect(screen.getByText("statically_referenced")).toBeInTheDocument();
    expect(screen.getByText("indicated")).toBeInTheDocument();
    const claims = await screen.findAllByText(/not proof of runtime use/i);
    expect(claims.length).toBeGreaterThanOrEqual(1);
  });

  it("a not-detected finding is never rendered as absence", async () => {
    mockFetch({
      "/api/v1/binary/artifacts/bin-1/findings": {
        artifact_id: "bin-1",
        findings: [finding({
          finding_id: "bfind-000",
          finding_type: "analysis_result",
          algorithm: "",
          operation: "",
          quantum_vulnerable: false,
          confidence: "not_detected",
          usage_status: "unresolved",
          limitations: [
            "no cryptography was detected within the declared static analysis scope — this is 'not detected', never 'absent': symbols may be stripped, code may be packed, and coverage is partial (§7)",
          ],
        })],
        note: "no finding is never proof of absence",
      },
    });
    renderPage();
    setTenant();
    setArtifact("bin-1");
    fireEvent.click(screen.getByText("Crypto Findings"));
    fireEvent.click(screen.getByText("load findings"));
    expect(await screen.findByText("not_detected")).toBeInTheDocument();
    expect(screen.getByText(/never 'absent'/)).toBeInTheDocument();
  });

  it("every comparison delta carries its caveat", async () => {
    mockFetch({
      "/api/v1/binary/artifacts/bin-old/comparison": {
        base_artifact_id: "bin-old",
        against_artifact_id: "bin-new",
        deltas: [
          {
            change: "added", algorithm: "SHA-2", variant: "SHA-256",
            detail: "absent in base, present in compared artifact (indicated, statically_referenced)",
            caveat: "a new static indicator is not proof of new runtime behavior (§5)",
          },
          {
            change: "removed", algorithm: "RSA", variant: "",
            detail: "present in base (indicated, statically_referenced), absent in the compared artifact",
            caveat: "an indicator can disappear because symbols were stripped or code was packed — removal of the capability is not proven",
          },
        ],
        summary: { added: 1, removed: 1, changed: 0, unchanged: 2 },
        note: "comparison reports drift of static INDICATORS, never drift of runtime behavior (§6) — a missing indicator may mean stripping or packing, not removal",
      },
    });
    renderPage();
    setTenant();
    setArtifact("bin-old");
    fireEvent.click(screen.getByText("Version Comparison"));
    fireEvent.change(screen.getByLabelText("Against"), { target: { value: "bin-new" } });
    fireEvent.click(screen.getByText("compare"));
    const added = await screen.findAllByText("added");
    expect(added.length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("removed").length).toBeGreaterThanOrEqual(1);
    expect(
      screen.getByText(/not proof of new runtime behavior/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/removal of the capability is not proven/),
    ).toBeInTheDocument();
    expect(screen.getByText(/never drift of runtime behavior/)).toBeInTheDocument();
  });

  it("coverage is not confidence and stripped symbols are named", async () => {
    mockFetch({
      "/api/v1/binary/artifacts/bin-1/coverage": {
        total_bytes: 720,
        bytes_inspected: 720,
        coverage_fraction: 1.0,
        sections_total: 6,
        sections_inspected: 6,
        executable_sections: 0,
        symbols_found: 3,
        symbols_stripped: true,
        unresolved_dependencies: ["libvendorx.so"],
        unsupported_regions: [],
        extraction_failures: [],
        deep_analysis_completed: false,
        packed_or_encrypted_suspected: false,
        analysis_timeouts: 0,
        note: "analysis coverage is not finding confidence: a fully covered artifact can still hold undetected cryptography, and no finding is never proof of absence",
      },
    });
    renderPage();
    setTenant();
    setArtifact("bin-1");
    fireEvent.click(screen.getByText("Coverage"));
    fireEvent.click(screen.getByText("load coverage"));
    expect(await screen.findByText("symbols stripped")).toBeInTheDocument();
    expect(screen.getByText(/not finding confidence/)).toBeInTheDocument();
  });

  it("relationships carry provenance and a uses edge needs evidence", async () => {
    mockFetch({
      "/api/v1/binary/artifacts/bin-1/bom": {
        artifact_id: "bin-1",
        bom: {
          schema: "cryptoscan.binary-bom/1",
          artifact_id: "bin-1",
          artifact_sha256: "a".repeat(64),
          subject: "payments-engine",
          components: [],
          relationships: [
            {
              source: "OpenSSL", relationship_type: "provides",
              target: "AES-256-GCM", provenance: "inferred",
              evidence_class: "strongly_supported",
              limitations: ["a library provides cryptographic capability; it does not follow that the application uses the algorithm (§5)"],
            },
            {
              source: "payments-engine", relationship_type: "indicates",
              target: "RSA", provenance: "unresolved",
              evidence_class: "indicated",
              limitations: ["an indicator only — no `uses` edge is created from co-occurrence or a single reference (§5)"],
            },
          ],
          sbom_components: [],
          cbom_assets: [],
          limitations: [],
        },
        note: "relationships carry provenance; a library PROVIDES an algorithm and the application USES it only when evidence supports the claim (docs/binary-intelligence/01_PRODUCT_SPEC.md §5)",
      },
    });
    renderPage();
    setTenant();
    setArtifact("bin-1");
    fireEvent.click(screen.getByText("Digital Twin"));
    fireEvent.click(screen.getByText("load relationships"));
    expect(await screen.findByText("provides")).toBeInTheDocument();
    expect(screen.getByText("indicates")).toBeInTheDocument();
    expect(screen.getByText("inferred")).toBeInTheDocument();
    expect(screen.getByText("unresolved")).toBeInTheDocument();
    expect(
      screen.getByText(/only when evidence supports the claim/),
    ).toBeInTheDocument();
  });

  it("a failed read says Read failed and never prints zeros", async () => {
    mockFetch({
      "/api/v1/binary/artifacts/bin-x/findings": () =>
        new Response(JSON.stringify({ detail: "store unavailable" }), {
          status: 500, headers: { "Content-Type": "application/json" },
        }),
    });
    renderPage();
    setTenant();
    setArtifact("bin-x");
    fireEvent.click(screen.getByText("Crypto Findings"));
    fireEvent.click(screen.getByText("load findings"));
    expect(await screen.findByText("Read failed")).toBeInTheDocument();
    expect(screen.getByText(/never prints zeros/)).toBeInTheDocument();
    expect(screen.queryByText("0 findings")).not.toBeInTheDocument();
  });
});
