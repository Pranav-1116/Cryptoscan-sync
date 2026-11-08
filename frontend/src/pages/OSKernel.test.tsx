/* OS & Kernel Intelligence (docs/os-kernel-intelligence/01_PRODUCT_SPEC.md):
   the honesty rules are display rules: an unavailable source renders its
   reason, never zeros; 'not detected' is never 'absent'; a registered
   kernel capability is never proof of runtime use; one host is never
   enterprise qualification; a detection is never a verdict; a failed
   read says "Read failed" and never prints zeros. */

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { mockFetch } from "../test/setup";
import OSKernel from "./OSKernel";

const renderPage = () =>
  render(
    <MemoryRouter initialEntries={["/os-kernel-intelligence"]}>
      <OSKernel />
    </MemoryRouter>,
  );

const asset = (over: Record<string, unknown> = {}) => ({
  asset_id: "host-under-test",
  collection_id: "oscol-1",
  kernel_name: "Linux",
  kernel_release: "6.1.158+",
  kernel_version: "#1 SMP",
  machine: "x86_64",
  os_pretty_name: "Debian GNU/Linux 12 (bookworm)",
  os_id: "debian",
  os_version_id: "12",
  arch: "x86_64",
  cmdline: "BOOT_IMAGE=/vmlinuz",
  tainted_flags: "0",
  tainted_meanings: [],
  environment_development_only: true,
  qualification_note:
    "this inventory is evidence for THIS host only — it is not an enterprise qualification result (§12)",
  collector_version: "os-intelligence/1.0.0",
  notes: [],
  collected_at: "2026-11-08T12:00:00+00:00",
  ...over,
});

const capability = (over: Record<string, unknown> = {}) => ({
  algorithm: "cbc(aes)",
  driver: "cbc(aes-fixed-time)",
  type: "skcipher",
  module: "kernel",
  priority: 101,
  blocksize: 16,
  digestsize: null,
  key_size_range: null,
  selftest: "passed",
  hardware_accelerated: false,
  runtime_usage_confirmed: false,
  parse_notes: [],
  ...over,
});

const finding = (over: Record<string, unknown> = {}) => ({
  finding_type: "OS-CRYPTO-001",
  host_id: "host-under-test",
  algorithm: "md5",
  implementation: "md5-generic",
  evidence_source: "Linux Kernel Crypto API (/proc/crypto)",
  observation_type: "registered_capability",
  runtime_usage_confirmed: false,
  evidence_class: "observed",
  severity_label: "low",
  severity_factors: {
    factors: {
      S_security_significance: "medium",
      E_evidence_confidence: "high (from evidence class 'observed')",
      X_actual_exposure: "configuration_only",
      B_business_impact: "requires_registered_mapping",
      C_compensating_controls: "unknown",
    },
    derivation: ["base = medium from S='medium'"],
  },
  risk_model_version: "os-risk/1.0",
  details: { risk: "Legacy cryptographic risk" },
  limitations: [
    "a registered implementation is inventory, never proof of runtime use (§2.2)",
  ],
  ...over,
});

const setAsset = (id = "host-under-test") => {
  fireEvent.change(screen.getByLabelText("Asset"), { target: { value: id } });
};

describe("OS & Kernel Intelligence", () => {
  it("never shows a missing asset as clean", async () => {
    mockFetch({});
    renderPage();
    setAsset("ghost");
    fireEvent.click(screen.getByText("read"));
    await waitFor(() =>
      expect(screen.getByText(/Read failed/)).toBeInTheDocument(),
    );
    expect(screen.getByText(/never prints zeros/)).toBeInTheDocument();
  });

  it("states the qualification caveat on every host", async () => {
    mockFetch({
      "/api/v1/os-intelligence/assets": { assets: [asset()], note: "n" },
    });
    renderPage();
    await waitFor(() =>
      expect(screen.getByText("host-under-test")).toBeInTheDocument(),
    );
    expect(
      screen.getByText(/not an enterprise qualification result/),
    ).toBeInTheDocument();
    expect(screen.getByText(/development-only/)).toBeInTheDocument();
  });

  it("renders an unknown kernel release as unknown — never guessed", async () => {
    mockFetch({
      "/api/v1/os-intelligence/assets": {
        assets: [asset({ kernel_release: "unknown" })],
        note: "n",
      },
    });
    renderPage();
    await waitFor(() =>
      expect(screen.getAllByText("unknown").length).toBeGreaterThan(0),
    );
    expect(screen.getAllByText("(never guessed)").length).toBeGreaterThan(0);
  });

  it("keeps the algorithm name distinct from the implementation driver", async () => {
    mockFetch({
      "/api/v1/os-intelligence/assets/host-under-test/crypto-capabilities": {
        capabilities: [capability()],
        note: "inventory of REGISTERED kernel crypto implementations — not proof of runtime use (§2.2)",
      },
    });
    renderPage();
    setAsset();
    fireEvent.click(screen.getByText("Kernel Crypto API"));
    await waitFor(() =>
      expect(screen.getByText("cbc(aes)")).toBeInTheDocument(),
    );
    expect(
      screen.getByText(/distinct from the generic algorithm name/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/not proof of runtime use/),
    ).toBeInTheDocument();
  });

  it("shows unknown key size as unknown — never guessed", async () => {
    mockFetch({
      "/api/v1/os-intelligence/assets/host-under-test/crypto-capabilities": {
        capabilities: [capability()],
        note: "n",
      },
    });
    renderPage();
    setAsset();
    fireEvent.click(screen.getByText("Kernel Crypto API"));
    await waitFor(() =>
      expect(screen.getAllByText("(never guessed)").length).toBeGreaterThan(0),
    );
  });

  it("renders runtime usage as never confirmed for registrations", async () => {
    mockFetch({
      "/api/v1/os-intelligence/assets/host-under-test/crypto-capabilities": {
        capabilities: [capability()],
        note: "n",
      },
    });
    renderPage();
    setAsset();
    fireEvent.click(screen.getByText("Kernel Crypto API"));
    await waitFor(() =>
      expect(
        screen.getAllByText("runtime usage not confirmed").length,
      ).toBeGreaterThan(0),
    );
  });

  it("an empty module list is never 'no modules exist'", async () => {
    mockFetch({
      "/api/v1/os-intelligence/assets/host-under-test/modules": {
        modules: [],
        note: "loaded-module inventory — a missing module row is never evidence that a feature is unavailable; it may be built into the kernel (§2.1)",
      },
    });
    renderPage();
    setAsset();
    fireEvent.click(screen.getByText("Kernel Modules"));
    await waitFor(() =>
      expect(
        screen.getAllByText(/may be built into/).length,
      ).toBeGreaterThan(0),
    );
    expect(
      screen.getAllByText(/never/).length,
    ).toBeGreaterThan(0);
  });

  it("unavailable sources render reasons, never zeros", async () => {
    mockFetch({
      "/api/v1/os-intelligence/assets/host-under-test/coverage": {
        sources_attempted: ["uname", "proc_crypto"],
        sources_collected: ["proc_crypto"],
        sources_unavailable: [
          { source: "uname", reason: "permission_denied" },
        ],
        source_digests: { proc_crypto: "abc" },
        note: "coverage is collection completeness — an unavailable source is recorded as unavailable and NEVER treated as 'disabled' or 'absent' (§2.1); coverage is not finding confidence",
      },
    });
    renderPage();
    setAsset();
    fireEvent.click(screen.getByText("Coverage"));
    await waitFor(() =>
      expect(screen.getByText(/permission_denied/)).toBeInTheDocument(),
    );
    expect(screen.getByText(/NEVER treated as/)).toBeInTheDocument();
  });

  it("not_detected is never absent in findings", async () => {
    mockFetch({
      "/api/v1/os-intelligence/assets/host-under-test/findings": {
        findings: [
          finding({
            finding_type: "OS-CRYPTO-015",
            evidence_class: "not_detected",
            severity_label: "informational",
          }),
        ],
        note: "detections, not verdicts (§1)",
      },
    });
    renderPage();
    setAsset();
    fireEvent.click(screen.getByText("Findings"));
    await waitFor(() =>
      expect(screen.getByText("OS-CRYPTO-015")).toBeInTheDocument(),
    );
    expect(screen.getByText("not_detected")).toBeInTheDocument();
    expect(
      screen.getByText(/never "absent"/),
    ).toBeInTheDocument();
  });

  it("shows computed severity factors, never a multiplied score", async () => {
    mockFetch({
      "/api/v1/os-intelligence/assets/host-under-test/findings": {
        findings: [finding()],
        note: "detections, not verdicts (§1)",
      },
    });
    renderPage();
    setAsset();
    fireEvent.click(screen.getByText("Findings"));
    await waitFor(() =>
      expect(
        screen.getByText(/severity: low \(computed · os-risk\/1\.0\)/),
      ).toBeInTheDocument(),
    );
    expect(
      screen.getByText(/preserved, never a multiplied score/),
    ).toBeInTheDocument();
  });

  it("a collection with no findings is never 'no issues'", async () => {
    mockFetch({
      "/api/v1/os-intelligence/assets/host-under-test/findings": {
        findings: [],
        note: "n",
      },
    });
    renderPage();
    setAsset();
    fireEvent.click(screen.getByText("Findings"));
    await waitFor(() =>
      expect(screen.getByText(/never\s+\"no issues\"/)).toBeInTheDocument(),
    );
  });

  it("rules view separates evaluated from not_evaluable honestly", async () => {
    mockFetch({
      "/api/v1/os-intelligence/rules": {
        rules: [
          { rule_id: "OS-CRYPTO-001", detection: "Weak cryptographic implementation exposed", potential_impact: "Legacy cryptographic risk" },
        ],
        note: "OS-CRYPTO detections, not automatic vulnerability verdicts (§9)",
      },
      "/api/v1/os-intelligence/assets/host-under-test/rule-evaluation": {
        rule_model_version: "os-crypto-rules/1.0",
        results: [
          {
            rule_id: "OS-CRYPTO-001",
            detection: "Weak cryptographic implementation exposed",
            potential_impact: "Legacy cryptographic risk",
            status: "evaluated",
            evaluation_note: "1 weak/legacy implementation registered",
            findings: [finding()],
          },
          {
            rule_id: "OS-CRYPTO-006",
            detection: "TLS configuration allows weak protocols",
            potential_impact: "Network cryptographic exposure",
            status: "not_evaluable",
            evaluation_note: "evidence source TLS configuration was not collected — this is NEVER treated as clean (§2.1)",
            findings: [],
          },
        ],
        note: "rule results are detections, not verdicts (§9)",
      },
    });
    renderPage();
    setAsset();
    fireEvent.click(screen.getByText("OS-CRYPTO Rules"));
    await waitFor(() =>
      expect(screen.getByText("OS-CRYPTO-006")).toBeInTheDocument(),
    );
    expect(screen.getAllByText("not_evaluable").length).toBeGreaterThan(0);
    expect(screen.getByText(/never treated as clean/i)).toBeInTheDocument();
    expect(screen.getByText(/detections, not verdicts/)).toBeInTheDocument();
  });

  it("hardware trust absence is never 'no TPM'", async () => {
    mockFetch({
      "/api/v1/os-intelligence/assets/host-under-test/hardware-trust": {
        hardware_trust: [
          {
            subject: "tpm",
            state: "unavailable",
            evidence_class: "unknown",
            metadata: {},
            notes: [
              "no TPM device node observed in /dev — recorded as unavailable; absence of a device node is not proof of absence of a TPM (§2.1)",
            ],
          },
        ],
        note: "device presence is metadata, never a trust verdict (§12)",
      },
    });
    renderPage();
    setAsset();
    fireEvent.click(screen.getByText("Hardware Trust"));
    await waitFor(() =>
      expect(screen.getByText("unavailable")).toBeInTheDocument(),
    );
    expect(
      screen.getByText(/not proof of absence of a TPM/),
    ).toBeInTheDocument();
    expect(screen.getByText(/never a trust verdict/)).toBeInTheDocument();
  });
});

  it("BOM view: versions never guessed, no uses edge ever drawn", async () => {
    mockFetch({
      "/api/v1/os-intelligence/assets/host-under-test/bom": {
        schema: "cryptoscan.os-bom/1",
        kind: "cbom",
        subject: "host-under-test",
        components: [
          {
            type: "crypto_implementation",
            name: "sha384 (sha384-avx2)",
            version: "",
            properties: {
              runtime_usage_confirmed: false,
              key_size_bits: null,
              limitations: ["key size unknown — never guessed"],
            },
          },
        ],
        relationships: [
          {
            source: "kernel",
            relationship: "provides",
            target: "sha384 (sha384-avx2)",
            provenance: "directly_observed",
            limitations: [
              "'provides' means the implementation is registered — it is NOT a 'uses' claim about any application (§2.2)",
            ],
          },
        ],
        coverage: { sources_collected: ["proc_crypto"] },
        note: "a projection of ONE read-only OS collection into the shared BOM ecosystem — components are registrations and metadata, never proof of runtime use (§2.2); this engine emits NO 'uses' edge (§8)",
      },
    });
    renderPage();
    setAsset();
    fireEvent.click(screen.getByText("BOM Projection"));
    await waitFor(() =>
      expect(
        screen.getAllByText("sha384 (sha384-avx2)").length,
      ).toBeGreaterThan(0),
    );
    expect(screen.getAllByText("(never guessed)").length).toBeGreaterThan(0);
    expect(screen.getAllByText(/never proof of runtime use/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/provides/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/NOT a 'uses' claim/).length).toBeGreaterThan(0);
    expect(screen.queryAllByText(/— uses →/)).toHaveLength(0);
  });
