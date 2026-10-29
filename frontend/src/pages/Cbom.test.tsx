/* CBOM page truth (§5 P0): rows come from the unified /cbom/query
 * endpoint. The page must not invent asset IDs, owners, locations,
 * risk or PQC status from catalog counts, and an empty/offline result
 * must never produce fabricated green rows. */
import { render, screen, fireEvent, waitFor, act } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
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

/* The backend computes the estate-wide summary (services/cbom/bom_query.py);
 * this fixture mirrors that arithmetic so the page's headline cards are
 * always echoing server numbers rather than counting rows in the browser. */
const summary = (matches: any[]) => ({
  identities: matches.length,
  linked: matches.filter((m) => m.linked).length,
  single_source: matches.filter((m) => !m.linked).length,
  conflict_count: matches.reduce((n, m) => n + (m.conflicts?.length || 0), 0),
  variation_count: matches.reduce((n, m) => n + (m.variations?.length || 0), 0),
  by_kind: [],
  by_bom: [],
  scope: "estate-wide — counts every canonical identity, not the filtered result",
  asset_identity_confirmed: false,
});

const queryResponse = (matches: any[]) => ({
  model: "cross-bom/query-v1",
  boms: ["cbom"],
  identities_matching: matches.length,
  matches,
  summary: summary(matches),
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
    expect(screen.getByText("Canonical spine")).toBeTruthy();
    expect(screen.getByText("Register systems, then initiate network, host, or container discovery scans.")).toBeTruthy();
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
    expect(screen.getByText("Value disagreements")).toBeTruthy();
    expect(screen.queryByText("no conflicts")).toBeNull();
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
    await waitFor(() => expect(screen.getByText("Offline").parentElement).toHaveTextContent("no live query · table empty · no cache fallback"));
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

it("downloads the native1.6 portfolio CBOM, never the catalog JSON", async () => {
  const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  const fetch = mockFetch({
    "/api/v1/cbom/query": queryResponse([]),
    "/api/v1/cbom/coverage": coverage,
    "/api/v1/cbom/portfolio": { bomFormat: "CycloneDX", specVersion: "1.6", components: [] },
  });
  renderPage();
  fireEvent.click(screen.getByRole("button", { name: "Export CycloneDX 1.6 JSON" }));
  await waitFor(() => expect(fetch.mock.calls.some(([url]) => String(url).includes("/api/v1/cbom/portfolio?fmt=cyclonedx16"))).toBe(true));
  await waitFor(() => expect(click).toHaveBeenCalledTimes(1));
  await waitFor(() => expect(screen.getByRole("button", { name: "Export CycloneDX 1.6 JSON" })).not.toBeDisabled());
  click.mockRestore();
  expect(fetch.mock.calls.some(([url]) => String(url).endsWith("/api/v1/cbom"))).toBe(false);
});

const chooseImport = (text = '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}') => {
  fireEvent.change(screen.getByLabelText("Import system name"), { target: { value: "Payments" } });
  const file = new File([text], "bank.json", { type: "application/json" });
  // jsdom's File lacks text(); real Chromium exercises the native File API.
  Object.defineProperty(file, "text", { value: async () => text });
  fireEvent.change(screen.getByLabelText("CBOM JSON file"), { target: { files: [file] } });
  return file;
};
const importReceipt = { system: { id: "system-persisted", name: "Payments" }, imported: 1,
  document_sha256: "c".repeat(64), source_basis: "IMPORTED_DECLARATIONS_NOT_SCANNER_OBSERVATIONS" };
const emptyRoutes = { "/api/v1/cbom/query": queryResponse([]), "/api/v1/cbom/coverage": coverage };

describe("Cbom — durable import and private context fences", () => {
  it("submits authenticated metadata once, refreshes readback and offers persisted export", async () => {
    const spy = mockFetch({ ...emptyRoutes, "/api/v1/cbom/ingest": importReceipt });
    renderPage(); chooseImport();
    fireEvent.click(screen.getByRole("button", { name: "Import metadata" }));
    expect(await screen.findByText(/Saved metadata: 1 assets for Payments/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Export persisted metadata" })).toBeTruthy();
    const posts = spy.mock.calls.filter(([url, init]) => String(url).endsWith("/cbom/ingest") && init?.method === "POST");
    expect(posts).toHaveLength(1);
    expect(JSON.parse(posts[0][1]?.body as string).system_name).toBe("Payments");
    await waitFor(() => expect(spy.mock.calls.filter(([url]) => String(url).includes("/cbom/query"))).toHaveLength(2));
  });

  it("rejects invalid JSON locally without a write", async () => {
    const spy = mockFetch(emptyRoutes);
    renderPage(); chooseImport("{invalid");
    fireEvent.click(screen.getByRole("button", { name: "Import metadata" }));
    expect(await screen.findByText(/Invalid JSON document/)).toBeTruthy();
    expect(spy.mock.calls.some(([, init]) => init?.method === "POST")).toBe(false);
  });

  it("rejects oversized files before reading or uploading them", async () => {
    const spy = mockFetch(emptyRoutes);
    renderPage(); const file = chooseImport();
    Object.defineProperty(file, "size", { value: 1024 * 1024 + 1 });
    fireEvent.click(screen.getByRole("button", { name: "Import metadata" }));
    expect(await screen.findByText(/File exceeds the 1 MiB/)).toBeTruthy();
    expect(spy.mock.calls.some(([, init]) => init?.method === "POST")).toBe(false);
  });

  it("does not claim success or automatically retry an ambiguous write failure", async () => {
    const spy = mockFetch({ ...emptyRoutes, "/api/v1/cbom/ingest": () => { throw new TypeError("network interrupted"); } });
    renderPage(); chooseImport();
    fireEvent.click(screen.getByRole("button", { name: "Import metadata" }));
    expect(await screen.findByText(/Import not confirmed/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Export persisted metadata" })).toBeNull();
    expect(spy.mock.calls.filter(([url]) => String(url).includes("/cbom/ingest"))).toHaveLength(1);
  });

  it("clears private drafts on an estate switch", async () => {
    mockFetch(emptyRoutes); renderPage(); chooseImport();
    fireEvent(window, new Event("zelinx:tenant"));
    expect(screen.getByLabelText("Import system name")).toHaveValue("");
    expect(screen.getByLabelText("CBOM JSON file")).toHaveValue("");
    expect(screen.getByText(/unsubmitted drafts were cleared/)).toBeTruthy();
    await screen.findByText("No CBOM identities found");
  });

  it("never submits a file whose asynchronous parsing finishes in an old estate", async () => {
    let finish!: (text: string) => void;
    const spy = mockFetch(emptyRoutes);
    renderPage(); chooseImport();
    const file = new File(["{}"], "pending.json");
    Object.defineProperty(file, "text", { value: () => new Promise<string>((resolve) => { finish = resolve; }) });
    fireEvent.change(screen.getByLabelText("CBOM JSON file"), { target: { files: [file] } });
    fireEvent.click(screen.getByRole("button", { name: "Import metadata" }));
    fireEvent(window, new Event("zelinx:tenant"));
    await act(async () => { finish("{}"); });
    await waitFor(() => expect(screen.getByLabelText("Import system name")).toHaveValue(""));
    expect(spy.mock.calls.some(([, init]) => init?.method === "POST")).toBe(false);
  });

  it("discards a late import receipt after an estate switch without replaying it", async () => {
    let finish!: (result: unknown) => void;
    const spy = mockFetch({ ...emptyRoutes, "/api/v1/cbom/ingest": () => new Promise((resolve) => { finish = resolve; }) });
    renderPage(); chooseImport();
    fireEvent.click(screen.getByRole("button", { name: "Import metadata" }));
    await waitFor(() => expect(finish).toBeTypeOf("function"));
    fireEvent(window, new Event("zelinx:tenant"));
    await act(async () => { finish(importReceipt); });
    await waitFor(() => expect(screen.getByLabelText("Import system name")).toHaveValue(""));
    expect(screen.queryByText(/Saved metadata:/)).toBeNull();
    expect(screen.queryByText(/cccccccc/)).toBeNull();
    expect(spy.mock.calls.filter(([url]) => String(url).includes("/cbom/ingest"))).toHaveLength(1);
  });

  it("discards snapshot responses from a previous selection", async () => {
    let finish!: (result: unknown) => void;
    mockFetch({ ...emptyRoutes,
      "/api/v1/scans": { scans: [{ scan_id:"old-scan", status:"COMPLETED", target_location:"old" }] },
      "/api/v1/cbom/scan/old-scan/snapshots": () => new Promise((resolve) => { finish = resolve; }),
    });
    renderPage();
    await waitFor(() => expect(screen.getByRole("option", { name: /old-scan/ })).toBeTruthy());
    fireEvent.change(screen.getByLabelText("Scan"), { target:{ value:"old-scan" } });
    await waitFor(() => expect(finish).toBeTypeOf("function"));
    fireEvent.change(screen.getByLabelText("Scan"), { target:{ value:"" } });
    await act(async () => { finish({ snapshots:[snapshotRow()], note:"old private note" }); });
    await waitFor(() => expect(screen.getByLabelText("Scan")).toHaveValue(""));
    expect(screen.queryByText("old private note")).toBeNull();
    expect(screen.queryByRole("button", { name:"Verify & View" })).toBeNull();
  });
});

it("does not turn unavailable scan coverage into a fabricated zero", async () => {
  mockFetch({ "/api/v1/cbom/query": queryResponse([match()]) });
  renderPage();
  expect(await screen.findByText("crypto:RSA-2048")).toBeTruthy();
  expect(screen.getByText("Unknown")).toBeTruthy();
  expect(screen.queryByText("0%")).toBeNull();
  expect(screen.getByText(/Imports are excluded; this is not discovery completeness/)).toBeTruthy();
});

/* ── Same shell as SBOM / NBOM / VBOM (request: "same UI, different
 * content"). The CBOM page reads the shared Technology BOM's materialized
 * crypto layer and the query's estate-wide summary; nothing here counts
 * rows in the browser to produce a headline number. ── */

const techBom = {
  snapshot_id: "TECHBOM-20261029-120000",
  environment: "production",
  state_version: 7,
  total_components: 10,
  components_by_layer: { cbom: 3, sbom: 7 },
  layers: {
    cbom: {
      count: 3,
      components: [
        { type: "crypto", algorithm: "ECDSA-P256", "bom-ref": "crypto:1:" },
        { type: "crypto", algorithm: "ECDSA-P256", "bom-ref": "crypto:2:" },
        { type: "crypto", algorithm: "SHA-1", "bom-ref": "crypto:3:" },
      ],
    },
  },
  fingerprint: "abcdef0123456789",
};

describe("Cbom — shared Technology BOM shell", () => {
  it("renders the CBOM layer's algorithms, share of estate and fingerprint", async () => {
    mockFetch({
      "/api/v1/technology-bom": techBom,
      "/api/v1/cbom/query": queryResponse([match()]),
      "/api/v1/cbom/coverage": coverage,
    });
    renderPage();
    expect(await screen.findByText("ECDSA-P256")).toBeTruthy();
    expect(screen.getByText("SHA-1")).toBeTruthy();
    // the headline card quotes the layer count and its share of the estate
    expect(screen.getByText("CBOM COMPONENTS")).toBeTruthy();
    expect(screen.getByText("30% of 10 total assets")).toBeTruthy();
    expect(screen.getByText(/algorithm field/)).toBeTruthy();
    expect(screen.getByText("SHA abcdef01…")).toBeTruthy();
    expect(screen.getByText("v7")).toBeTruthy();
    expect(screen.getByText("production")).toBeTruthy();
  });

  it("headline cards echo the query's estate-wide summary, not the visible rows", async () => {
    const base = queryResponse([
      match(),
      match({ identity: "vendor:OpenSSL", kind: "vendor", label: "OpenSSL", boms: ["hbom"], bom_count: 1, linked: false, conflicts: [], present_in: [{ bom: "hbom", ref: "h-1", values: {} }] }),
    ]);
    mockFetch({
      "/api/v1/cbom/query": {
        ...base,
        summary: { ...base.summary, identities: 40, linked: 12, single_source: 28 },
      },
      "/api/v1/cbom/coverage": coverage,
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("crypto:RSA-2048")).toBeTruthy());
    // server numbers, not the two rows on screen
    const identitiesCard = screen.getByText("IDENTITIES").parentElement as HTMLElement;
    expect(identitiesCard).toHaveTextContent("40");
    expect(identitiesCard).not.toHaveTextContent("2 ");
    expect(screen.getByText("12")).toBeTruthy();
    expect(screen.getByText("12 / 40 in 2+ BOMs")).toBeTruthy();
    expect(screen.getByText("30% of 40 identities")).toBeTruthy();

    // filtering the table to one row leaves the estate cards alone
    fireEvent.click(screen.getByRole("button", { name: "UNLINKED" }));
    expect(screen.queryByText("crypto:RSA-2048")).toBeNull();
    expect(screen.getByText("IDENTITIES").parentElement).toHaveTextContent("40");
    expect(screen.getByText("12")).toBeTruthy();
  });

  it("an unreachable query leaves the cards without numbers rather than zeros", async () => {
    offlineFetch();
    renderPage();
    await waitFor(() => expect(screen.getByText("Offline")).toBeTruthy());
    const identitiesCard = screen.getByText("IDENTITIES").parentElement;
    expect(identitiesCard).toHaveTextContent("—");
    expect(identitiesCard).not.toHaveTextContent("0");
    expect(screen.getAllByText("no live query").length).toBeGreaterThan(0);
  });
});
