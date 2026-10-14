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

/* ── Two-pin comparison (§5, round 62): repeated-scan snapshot
 * comparability as a product workflow — diff a newer pin against the
 * previous pin of the same scan, spine-keyed by default (estate drift,
 * not evidence churn). ── */

const diffResponse = (over: Record<string, unknown> = {}) => ({
  target: { snapshot_id: "snap-2", scan_id: "scan-snap-9", content_hash: "b".repeat(64) },
  baseline: { snapshot_id: "snap-1", scan_id: "scan-snap-9", content_hash: "a".repeat(64) },
  diff: {
    identical: false,
    components: {
      key_by: "asset_key",
      added: [{ key: "spine:k2", "bom-ref": "ev-9", name: "ML-KEM-768", type: "cryptographic-asset" }],
      removed: [{ key: "spine:k1", "bom-ref": "ev-3", name: "3DES", type: "cryptographic-asset" }],
      changed: [{
        key: "spine:k3", "bom-ref": "ev-1",
        changes: [{ path: "evidence.compliance_status", before: "PASS", after: "FAIL" }],
      }],
      unchanged: 4,
    },
    metadata_changes: [],
    summary: { baseline_components: 6, target_components: 6, added: 1, removed: 1, changed: 1, unchanged: 4 },
  },
  note: "Computed from the two pinned payloads (never stored). 'added' = present in the target snapshot only.",
  ...over,
});

describe("Cbom — two-pin comparison", () => {
  const twoPins = [
    snapshotRow({ snapshot_id: "snap-2", content_hash: "b".repeat(64), snapshotted_at: "2026-10-14T00:00:00Z" }),
    snapshotRow({ snapshot_id: "snap-1" }),
  ];

  function setupDiff(handler: (url: string) => unknown) {
    return mockFetch({
      "/api/v1/cbom/query": queryResponse([]),
      "/api/v1/cbom/coverage": coverage,
      "/api/v1/scans": { scans: [{ scan_id: "scan-snap-9", status: "COMPLETED", target_location: "payments" }], total_count: 1 },
      "/api/v1/cbom/scan/scan-snap-9/snapshots": { scan_id: "scan-snap-9", snapshots: twoPins, count: 2, note: "" },
      "/api/v1/cbom/snapshots/snap-2/diff": (url: string) => handler(url),
    });
  }

  it("diffs a newer pin against the previous pin, spine-keyed by default", async () => {
    let calledWith = "";
    setupDiff((url) => {
      calledWith = url;
      return diffResponse();
    });
    renderPage();
    fireEvent.change(await screen.findByLabelText("Scan"), { target: { value: "scan-snap-9" } });
    await waitFor(() => expect(screen.getByText("Diff vs Prev Pin")).toBeTruthy());

    fireEvent.click(screen.getByRole("button", { name: "Diff vs Prev Pin" }));
    await waitFor(() => expect(screen.getByText("PIN COMPARISON")).toBeTruthy());
    // the request: target snap-2 against the previous pin snap-1, spine keying
    expect(calledWith).toContain("/api/v1/cbom/snapshots/snap-2/diff");
    expect(calledWith).toContain("against=snap-1");
    expect(calledWith).toContain("key_by=asset_key");
    // estate drift rendered honestly: added, removed, changed, unchanged
    expect(screen.getByText("+1 added")).toBeTruthy();
    expect(screen.getByText("−1 removed")).toBeTruthy();
    expect(screen.getByText("1 changed")).toBeTruthy();
    expect(screen.getByText("4 unchanged")).toBeTruthy();
    expect(screen.getByText("ML-KEM-768")).toBeTruthy(); // the added fact
    expect(screen.getByText("3DES")).toBeTruthy(); // the removed fact
    expect(screen.getByText(/Added \(in the newer pin only\)/)).toBeTruthy();
    expect(screen.getByText(/Removed \(in the baseline only\)/)).toBeTruthy();
    expect(screen.getByText("evidence.compliance_status")).toBeTruthy();
    expect(screen.getByText(/identity spine — same crypto fact across scans/)).toBeTruthy();
  });

  it("switches to exact per-scan evidence keying on request", async () => {
    let calls: string[] = [];
    setupDiff((url) => {
      calls.push(url);
      return diffResponse({ diff: { ...diffResponse().diff, components: { ...diffResponse().diff.components, key_by: "bom_ref" } } });
    });
    renderPage();
    fireEvent.change(await screen.findByLabelText("Scan"), { target: { value: "scan-snap-9" } });
    await waitFor(() => expect(screen.getByText("Diff vs Prev Pin")).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "Diff vs Prev Pin" }));
    await waitFor(() => expect(screen.getByText("PIN COMPARISON")).toBeTruthy());

    fireEvent.click(screen.getByRole("button", { name: "bom_ref" }));
    await waitFor(() => expect(calls.some((c) => c.includes("key_by=bom_ref"))).toBeTruthy());
    expect(screen.getByText(/per-scan evidence ids — every re-scan mints new rows/)).toBeTruthy();
  });

  it("renders the identical state without inventing drift", async () => {
    const identical = diffResponse({
      diff: { identical: true, components: { key_by: "asset_key", added: [], removed: [], changed: [], unchanged: 6 }, metadata_changes: [], summary: { baseline_components: 6, target_components: 6, added: 0, removed: 0, changed: 0, unchanged: 6 } },
    });
    setupDiff(() => identical);
    renderPage();
    fireEvent.change(await screen.findByLabelText("Scan"), { target: { value: "scan-snap-9" } });
    await waitFor(() => expect(screen.getByText("Diff vs Prev Pin")).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "Diff vs Prev Pin" }));
    await waitFor(() => expect(screen.getByText("IDENTICAL")).toBeTruthy());
    expect(screen.queryByText("+1 added")).toBeNull(); // no invented drift
    expect(screen.getByText("6 unchanged")).toBeTruthy();
  });

  it("offers no comparison with a single pin — honestly", async () => {
    mockFetch({
      "/api/v1/cbom/query": queryResponse([]),
      "/api/v1/cbom/coverage": coverage,
      "/api/v1/scans": { scans: [{ scan_id: "scan-snap-9", status: "COMPLETED", target_location: "payments" }], total_count: 1 },
      "/api/v1/cbom/scan/scan-snap-9/snapshots": { scan_id: "scan-snap-9", snapshots: [snapshotRow()], count: 1, note: "" },
    });
    renderPage();
    fireEvent.change(await screen.findByLabelText("Scan"), { target: { value: "scan-snap-9" } });
    await waitFor(() => expect(screen.getByText("aaaaaaaaaaaaaaaa…")).toBeTruthy());
    expect(screen.queryByText("Diff vs Prev Pin")).toBeNull();
  });
});
