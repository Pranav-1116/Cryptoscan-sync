/* CBOM page truth (§5 P0): rows come from the unified /cbom/query
 * endpoint. The page must not invent asset IDs, owners, locations,
 * risk or PQC status from catalog counts, and an empty/offline result
 * must never produce fabricated green rows. */
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { mockFetch, offlineFetch } from "../test/setup";
import Cbom from "./Cbom";

afterEach(() => {
  localStorage.clear();
});

const renderPage = () =>
  render(
    <MemoryRouter>
      <Cbom />
    </MemoryRouter>,
  );

const queryResponse = (matches: unknown[]) => ({
  model: "cross-bom/query-v1",
  boms: ["cbom"],
  identities_matching: matches.length,
  matches,
  conflict_count: 0,
  note: "Canonical keys associate matching algorithms/names, not confirmed physical assets.",
});

const coverage = { coverage_pct: 100, systems: 1, with_cbom: 1 };

const match = (over: Record<string, unknown> = {}) => ({
  identity: "crypto:RSA-2048",
  kind: "crypto",
  label: "RSA-2048",
  boms: ["cbom", "techbom"],
  bom_count: 2,
  linked: true,
  relationship: "algorithm_association",
  conflicts: [],
  variations: [],
  present_in: [
    { bom: "cbom", ref: "cbom-ref-1", values: { key_length: 2048 } },
    { bom: "techbom", ref: "tech-ref-9", values: {} },
  ],
  ...over,
});

describe("Cbom — no fabricated components", () => {
  it("renders real identities from /cbom/query with their BOM badges", async () => {
    mockFetch({
      "/api/v1/cbom/query": queryResponse([match()]),
      "/api/v1/cbom/coverage": coverage,
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("crypto:RSA-2048")).toBeTruthy());
    expect(screen.getByText("Linked · 2 BOMs")).toBeTruthy();
    expect(screen.getByText("cbom")).toBeTruthy();
    expect(screen.getByText("techbom")).toBeTruthy();
    // association disclaimer from the backend is surfaced, not hidden
    expect(screen.getByText(/not confirmed physical assets/i)).toBeTruthy();
  });

  it("never shows invented risk, owner, location or PQC columns", async () => {
    mockFetch({
      "/api/v1/cbom/query": queryResponse([match()]),
      "/api/v1/cbom/coverage": coverage,
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("crypto:RSA-2048")).toBeTruthy());
    for (const fabricated of ["PQC Status", "Owner", "Risk", "Quantum Ready", "PQC Migration Target", "Production host", "Engineering"]) {
      expect(screen.queryByText(fabricated)).toBeNull();
    }
  });

  it("an empty query result shows the honest empty state, not default rows", async () => {
    mockFetch({
      "/api/v1/cbom/query": queryResponse([]),
      "/api/v1/cbom/coverage": { coverage_pct: 0, systems: 0, with_cbom: 0 },
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("No CBOM identities found")).toBeTruthy());
    expect(screen.getByText(/Distinct canonical identities/)).toBeTruthy();
  });

  it("flags cross-BOM conflicts instead of a blanket green", async () => {
    mockFetch({
      "/api/v1/cbom/query": queryResponse([
        match({
          identity: "crypto:AES-128",
          label: "AES-128",
          boms: ["cbom", "techbom"],
          linked: true,
          conflicts: [{ field: "key_length", values: { cbom: 128, techbom: 256 } }],
        }),
      ]),
      "/api/v1/cbom/coverage": coverage,
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("1 conflict")).toBeTruthy());
    expect(screen.getByText(/Cross-BOM Conflicts/)).toBeTruthy();
  });

  it("linkage filters only affect real fields", async () => {
    mockFetch({
      "/api/v1/cbom/query": queryResponse([
        match(),
        match({ identity: "vendor:OpenSSL", kind: "vendor", label: "OpenSSL", boms: ["hbom"], bom_count: 1, linked: false, present_in: [{ bom: "hbom", ref: "h-1", values: {} }] }),
      ]),
      "/api/v1/cbom/coverage": coverage,
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("vendor:OpenSSL")).toBeTruthy());

    fireEvent.click(screen.getByRole("button", { name: "UNLINKED" }));
    expect(screen.queryByText("crypto:RSA-2048")).toBeNull();
    expect(screen.getByText("vendor:OpenSSL")).toBeTruthy();
    expect(screen.getByText("Single source")).toBeTruthy();
  });

  it("unreachable BOM sources leave the table empty with a warning, never fake rows", async () => {
    offlineFetch();
    renderPage();
    await waitFor(() => expect(screen.getByText(/BOM sources are unreachable/i)).toBeTruthy());
    await waitFor(() => expect(screen.getByText("No CBOM identities found")).toBeTruthy());
    expect(screen.queryByText("Quantum Ready")).toBeNull();
  });
});

/* ── Pinned snapshots (§4.4): one content-addressed rendering per pin,
 * served verbatim with an integrity self-check — the live query above
 * regenerates, a snapshot never does. ── */

const snapshotRow = (over: Record<string, unknown> = {}) => ({
  snapshot_id: "snap-1",
  content_hash: "a".repeat(64),
  signed: "jws",
  generator: "api",
  component_count: 2,
  snapshotted_at: "2026-10-13T00:00:00Z",
  created_by: "auditor",
  verify_path: "/api/v1/cbom/snapshots/snap-1",
  ...over,
});

describe("Cbom — pinned snapshots", () => {
  it("pins a scan's CBOM and lists the pinned rendering", async () => {
    let pinned = false;
    const fetchSpy = mockFetch({
      "/api/v1/cbom/query": queryResponse([]),
      "/api/v1/cbom/coverage": coverage,
      "/api/v1/scans": { scans: [{ scan_id: "scan-snap-9", status: "COMPLETED", target_location: "https://github.com/acme/payments.git" }], total_count: 1 },
      "/api/v1/cbom/scan/scan-snap-9/snapshots": () =>
        pinned ? { scan_id: "scan-snap-9", snapshots: [snapshotRow()], count: 1, note: "Each snapshot is a pinned rendering; the live route regenerates from current evidence and may differ." }
               : { scan_id: "scan-snap-9", snapshots: [], count: 0, note: "" },
      "/api/v1/cbom/scan/scan-snap-9/snapshot": () => {
        pinned = true;
        return { snapshot_id: "snap-1", created: true, content_hash: "a".repeat(64), component_count: 2, note: "Snapshot pinned." };
      },
    });
    renderPage();
    fireEvent.change(await screen.findByLabelText("Scan"), { target: { value: "scan-snap-9" } });
    await waitFor(() => expect(screen.getByText(/No snapshots pinned for this scan yet/)).toBeTruthy());

    fireEvent.click(screen.getByRole("button", { name: "Pin Snapshot" }));
    const post = fetchSpy.mock.calls.find(([p, init]) => String(p).includes("/cbom/scan/scan-snap-9/snapshot") && init?.method === "POST");
    expect(post).toBeTruthy();
    await waitFor(() => expect(screen.getByText("aaaaaaaaaaaaaaaa…")).toBeTruthy());
    expect(screen.getByText("JWS")).toBeTruthy(); // signature form is shown, not implied
    expect(screen.getByText("api")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Verify & View" })).toBeTruthy();
  });

  it("serves the pinned document verbatim with its integrity self-check", async () => {
    mockFetch({
      "/api/v1/cbom/query": queryResponse([]),
      "/api/v1/cbom/coverage": coverage,
      "/api/v1/scans": { scans: [{ scan_id: "scan-snap-9", status: "COMPLETED", target_location: "x" }], total_count: 1 },
      "/api/v1/cbom/scan/scan-snap-9/snapshots": { scan_id: "scan-snap-9", snapshots: [snapshotRow()], count: 1 },
      "/api/v1/cbom/snapshots/snap-1": {
        snapshot_id: "snap-1", content_hash: "a".repeat(64), integrity: "OK",
        integrity_note: "SHA-256 over the stored payload matches the pinned content hash.",
        scan_verify_path: "/api/v1/scans/scan-snap-9/verify",
        payload: { components: [{ name: "RSA-2048" }, { name: "AES-256-GCM" }] },
      },
    });
    renderPage();
    fireEvent.change(await screen.findByLabelText("Scan"), { target: { value: "scan-snap-9" } });
    fireEvent.click(await screen.findByRole("button", { name: "Verify & View" }));
    expect(await screen.findByText("INTEGRITY OK")).toBeTruthy();
    expect(screen.getByText(/SHA-256 over the stored payload matches the pinned content hash/)).toBeTruthy();
    expect(screen.getByText(/\/api\/v1\/scans\/scan-snap-9\/verify/)).toBeTruthy();
    // the exact pinned document is inspectable, never regenerated
    expect(screen.getByText(/Pinned document \(2 components\)/)).toBeTruthy();
  });

  it("shows a tampered snapshot as MISMATCH — detected, never trusted", async () => {
    mockFetch({
      "/api/v1/cbom/query": queryResponse([]),
      "/api/v1/cbom/coverage": coverage,
      "/api/v1/scans": { scans: [{ scan_id: "scan-snap-9", status: "COMPLETED", target_location: "x" }], total_count: 1 },
      "/api/v1/cbom/scan/scan-snap-9/snapshots": { scan_id: "scan-snap-9", snapshots: [snapshotRow()], count: 1 },
      "/api/v1/cbom/snapshots/snap-1": {
        snapshot_id: "snap-1", integrity: "MISMATCH",
        integrity_note: "Stored payload does NOT match its pinned content hash — the document was mutated after pinning. Do not trust it.",
        payload: {},
      },
    });
    renderPage();
    fireEvent.change(await screen.findByLabelText("Scan"), { target: { value: "scan-snap-9" } });
    fireEvent.click(await screen.findByRole("button", { name: "Verify & View" }));
    expect(await screen.findByText("INTEGRITY MISMATCH")).toBeTruthy();
    expect(screen.getByText(/Do not trust it/)).toBeTruthy();
  });
});
