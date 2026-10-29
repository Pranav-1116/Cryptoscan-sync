/* Discovery / Intelligence honesty invariants.
 *
 * These five pages shared one defect class: a read that did not return (or a
 * value the server never sent) was rendered as a measured zero — "0/100
 * RIGID", "100% configurable", "no hardware", a supplier count capped at the
 * five rows on screen — and one of them, NBOM, never rendered at all because
 * it gated a `call()` result on `ok`, which `call()` never sets.
 *
 * What is locked here:
 *   - NBOM renders when the read returned, and says why when it did not.
 *   - Agility draws no score, no band share and no tone it was not given.
 *   - SBOM counts every supplier, not the visible five.
 *   - VBOM draws only shares of two measured counts.
 *   - Hardware distinguishes "not measured" from "measured absent".
 */
import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { mockFetch, offlineFetch } from "../test/setup";
import Nbom from "./Nbom";
import Sbom from "./Sbom";
import Vbom from "./Vbom";
import Hardware from "./Hardware";
import Agility from "./Agility";

afterEach(() => {
  localStorage.clear();
  vi.restoreAllMocks();
});

const inRouter = (ui: React.ReactElement) => render(<MemoryRouter>{ui}</MemoryRouter>);

const techBom = (sbom: Array<Record<string, unknown>>, extra: Record<string, unknown> = {}) => ({
  source: "technology_bom",
  live: true,
  total_components: 12,
  components_by_layer: { sbom: sbom.length, cbom: 0, hbom: 0, vendor: 2 },
  layers: {
    sbom: { components: sbom, count: sbom.length },
    cbom: { components: [], count: 0 },
    hbom: { components: [], count: 0 },
    vendor: { components: [], count: 2 },
    certificates: { components: [], count: 0 },
  },
  snapshot_id: "TECHBOM-1",
  state_version: 1,
  ...extra,
});

describe("NBOM", () => {
  it("renders the network inventory the read returned", async () => {
    mockFetch({
      "/api/v1/cbom/nbom": {
        nbom: {
          components: [
            // deliberately no "cryptoscan:findings" key: a component the
            // scanner returned without findings must not blank the page
            { "bom-ref": "nbom-1", name: "payments-gw",
              properties: [
                { name: "cryptoscan:kind", value: "listener" },
                { name: "cryptoscan:tls_version", value: "TLSv1.2" },
                { name: "cryptoscan:observed", value: "True" },
              ] },
          ],
        },
        summary: { components: 1, by_severity: { critical: 0, high: 0 } },
        source: "live",
        notes: [],
      },
    });
    inRouter(<Nbom />);

    // The bug: gating a call() result on `ok` (never set) left this page
    // permanently on its empty branch.
    expect(await screen.findByText("payments-gw")).toBeTruthy();
    expect(screen.queryByText(/NBOM not read/)).toBeNull();
  });

  it("says the read failed instead of claiming an empty inventory", async () => {
    mockFetch({});
    inRouter(<Nbom />);
    await waitFor(() => expect(screen.getByText(/NBOM not read:/)).toBeTruthy());
    // it names the reason the server gave, not a bare status code
    expect(screen.getAllByText(/not found/).length).toBeGreaterThan(0);
  });
});

describe("SBOM", () => {
  it("counts every supplier, not only the five it lists", async () => {
    const components = ["a", "b", "c", "d", "e", "f", "g"].map((id, idx) => ({
      name: `pkg-${id}`, supplier: `vendor-${id}`, version: "1.0", component_type: "library",
      layer: "sbom", evidence_ids: [`ev-${idx}`],
    }));
    mockFetch({ "/api/v1/technology-bom": techBom(components) });
    inRouter(<Sbom />);

    await waitFor(() => expect(screen.getByText(/UNIQUE SUPPLIERS/i)).toBeTruthy());
    // seven distinct suppliers exist; the list below shows five of them
    await waitFor(() => expect(screen.getByText("UNIQUE SUPPLIERS").parentElement)
      .toHaveTextContent("7"));
    expect(screen.getByText(/100% of components name a supplier/)).toBeTruthy();
  });

  it("renders an unread BOM as not-read, never as zero components", async () => {
    mockFetch({});
    inRouter(<Sbom />);
    await waitFor(() => expect(screen.getAllByText(/not read/i).length).toBeGreaterThan(0));
    expect(screen.queryByText(/^0$/)).toBeNull();
  });
});

describe("VBOM", () => {
  it("reports the vendor layer as a share of the estate it was counted against", async () => {
    mockFetch({
      "/api/v1/technology-bom": techBom([]),
      "/api/v1/technology-bom/vendor": {
        vendor_count: 2,
        vendors: [
          { id: "v1", name: "Thales", vendor_type: "HSM", criticality: "CRITICAL" },
          { id: "v2", name: "Utimaco", vendor_type: "HSM", criticality: "LOW" },
        ],
        linkage: [{ vendor_id: "v1", system_id: "sys-1" }],
        notes: [],
      },
    });
    inRouter(<Vbom />);
    await waitFor(() => expect(screen.getByText("Thales")).toBeTruthy());
    // 2 vendor-layer components of 12 total = 17%, and 1 of 2 vendors linked
    expect(screen.getAllByText(/17% of the estate/).length).toBeGreaterThan(0);
    expect(screen.getByText(/50% of registered vendors are linked/)).toBeTruthy();
  });
});

describe("Agility", () => {
  it("draws no score when the read did not return", async () => {
    offlineFetch();
    inRouter(<Agility />);
    await waitFor(() => expect(screen.getAllByText("—").length).toBeGreaterThan(0));
    // the old page painted a 0/100 "rigid" estate and 100% "configurable" out
    // of the empty fallback shape
    expect(screen.queryByText(/^0$/)).toBeNull();
    expect(screen.queryByText(/100%/)).toBeNull();
  });

  it("does not print the server's zero average as a real score on an empty estate", async () => {
    mockFetch({
      "/api/v1/agility": {
        systems: [], average: 0,
        distribution: { EXCELLENT: 0, GOOD: 0, MODERATE: 0, POOR: 0, CRITICAL: 0 },
        trend: { improving: 0, declining: 0, flat: 0, no_history: 0, deltas: {} },
      },
    });
    inRouter(<Agility />);
    await waitFor(() => expect(screen.getByText(/0 systems scored/)).toBeTruthy());
    // average over zero systems is not a score
    expect(screen.queryByText(/^0 \/ 100$/)).toBeNull();
    expect(screen.getAllByText("—").length).toBeGreaterThan(0);
  });

  it("derives every band share from the systems it was given", async () => {
    mockFetch({
      "/api/v1/agility": {
        systems: [
          { system_id: "s1", agility_score: 90 },
          { system_id: "s2", agility_score: 55 },
          { system_id: "s3", agility_score: 20 },
          { system_id: "s4", agility_score: 10 },
        ],
        average: 43.75,
        distribution: {},
        trend: {},
      },
    });
    inRouter(<Agility />);
    // 1 of 4 agile = 25%, 1 of 4 transitional = 25%, 2 of 4 rigid = 50%
    expect((await screen.findAllByText(/2 rigid/)).length).toBeGreaterThan(0);
    expect(screen.getAllByText("25%").length).toBeGreaterThan(0);
    // the hero figure is the server's own average, rounded for display
    expect(screen.getAllByText(/43|44/).length).toBeGreaterThan(0);
  });
});

describe("Hardware", () => {
  it("reports the four root-of-trust primitives as not measured, not absent", async () => {
    // No scan cycle has run, so the hardware scanner has no summary. The page
    // used to render "absent" (a claim about hardware nobody looked at) and a
    // green 0/4 ring; it now says "not measured" and draws no ring fill.
    mockFetch({});
    inRouter(<Hardware />);
    await waitFor(() => expect(screen.getAllByText(/not measured/i).length).toBeGreaterThanOrEqual(4));
    expect(screen.queryByText(/^absent$/)).toBeNull();
  });
});
