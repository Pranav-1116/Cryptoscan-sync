/* Discovery coverage matrix: the panel may not print a claim the registry did not make. */
import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "../test/render";
import { mockFetch, offlineFetch } from "../test/setup";
import SurfaceCoverage from "./SurfaceCoverage";

const PATH = "/api/v1/estate/evidence/discovery/surfaces";

const surface = (overrides: Record<string, unknown> = {}) => ({
  id: "linux_host",
  label: "Linux hosts",
  planes: ["STATIC"],
  kind: "STATIC_ANALYSIS",
  kind_meaning: "parses artefacts collected elsewhere",
  maturity: "MEASURED",
  maturity_ceiling: "MEASURED",
  maturity_meaning: "a collector reads it and the read is measured",
  declared_maturity: "MEASURED",
  reads: "crypto libraries, config cipher suites and key files under a scanned root",
  cannot_claim: "it does not see in-memory keys or anything outside the passed root",
  gaps: ["no memory inspection"],
  detectors: [{ ref: "shell_parser:parse_shell_file", present: true, reason: null }],
  configuration: { state: "NOT_CONFIGURED", reason: "no scan root configured" },
  observed: { state: "NOT_OBSERVED", planes: [], collected: 0, reason: "no discovery run stored" },
  notes: [],
  ...overrides,
});

const doc = (overrides: Record<string, unknown> = {}) => ({
  schema: "cryptoscan.discovery-surfaces/1",
  run_id: null,
  surfaces: [
    surface(),
    surface({
      id: "hsm",
      label: "HSM",
      kind: "LIVE_CONTROL_PLANE",
      maturity: "PARTIAL",
      reads: "PKCS#11 key usage and KMIP object attributes",
      cannot_claim: "it cannot see keys that never leave the HSM",
      detectors: [
        { ref: "cbom.kmip:assess_kmip_object", present: true, reason: null },
        { ref: "definitely_absent:thing", present: false, reason: "not found in this build" },
      ],
      configuration: { state: "CONFIGURED", reason: null },
    }),
  ],
  rollup: {
    surfaces: 2,
    by_maturity: { MEASURED: 1, PARTIAL: 1 },
    by_kind: { STATIC_ANALYSIS: 1, LIVE_CONTROL_PLANE: 1 },
    credentials_resolved: 1,
    no_credentials_needed: 1,
    observed_in_last_run: 0,
  },
  kinds: {},
  maturities: {},
  claim:
    "an evidence-driven framework for discovering cryptographic assets across multiple infrastructure surfaces, with coverage expanding by collector",
  note: "measured per surface, never a blanket assertion",
  ...overrides,
});

describe("discovery coverage matrix", () => {
  it("prints the server's claim and the measured rollup, not a client-side summary", async () => {
    mockFetch({ [PATH]: doc() });
    renderWithProviders(<SurfaceCoverage />);

    expect(await screen.findByText(/coverage expanding by collector/)).toBeTruthy();
    expect(screen.getByText("2 surfaces")).toBeTruthy();
    expect(screen.getByText("1 measured")).toBeTruthy();
    expect(screen.getByText("1 partial")).toBeTruthy();
    expect(screen.getByText("0 observed in last run")).toBeTruthy();
  });

  it("names each surface's own maturity and where it is not configured", async () => {
    mockFetch({ [PATH]: doc() });
    renderWithProviders(<SurfaceCoverage />);

    expect(await screen.findByText("Linux hosts")).toBeTruthy();
    expect(screen.getByText("HSM")).toBeTruthy();
    // the per-surface ceiling, not the product's
    expect(screen.getAllByText("MEASURED").length).toBeGreaterThan(0);
    expect(screen.getByText("PARTIAL")).toBeTruthy();
    expect(screen.getByText("not configured here")).toBeTruthy();
    expect(screen.getByText("1 detector(s) absent")).toBeTruthy();
  });

  it("expands to the limitation the registry declares for that surface", async () => {
    mockFetch({ [PATH]: doc() });
    renderWithProviders(<SurfaceCoverage />);

    await userEvent.click(await screen.findByRole("button", { name: /HSM/ }));

    expect(screen.getByText(/cannot see keys that never leave the HSM/)).toBeTruthy();
    expect(screen.getByText(/no memory inspection/)).toBeTruthy();
    expect(screen.getByText(/not found in this build/)).toBeTruthy();
  });

  it("says the matrix was not read instead of showing zero coverage", async () => {
    mockFetch({});
    renderWithProviders(<SurfaceCoverage />);

    expect(await screen.findByText(/Coverage matrix not read/)).toBeTruthy();
    expect(screen.queryByText(/coverage expanding by collector/)).toBeNull();
  });

  it("distinguishes an offline backend from an empty registry", async () => {
    offlineFetch();
    renderWithProviders(<SurfaceCoverage />);

    expect(await screen.findByText(/Coverage matrix not read/)).toBeTruthy();
    expect(screen.queryByText("0 surfaces")).toBeNull();
  });
});
