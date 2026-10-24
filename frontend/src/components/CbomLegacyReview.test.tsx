import React from "react";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import PrivateScope from "./PrivateScope";
import CbomLegacyReview from "./CbomLegacyReview";
import { mockFetch, offlineFetch } from "../test/setup";

const list = { systems: [{ id: "legacy-system", name: "Payments" }], total: 1, page: 1, page_size: 50, unassigned_review_required: 0 };
const review = { system_id: "legacy-system", system_name: "Payments", snapshot_sha256: "a".repeat(64),
  replacement_document_sha256: "b".repeat(64), pending_assets: 1, mixed_evidence_assets: 0,
  assets: [{ id: "old", algorithm: "RSA", reported_confidence: "HIGH", linked_evidence_count: 0 }], limit: 2000,
  message: "Reimport is declaration metadata, not a scan or bank approval." };
const routes = (over = {}) => ({ "/api/v1/cbom/legacy-imports": list,
  "/api/v1/cbom/system/legacy-system/legacy-imports": review, ...over });
const renderReview = (onCommitted = vi.fn()) => render(<PrivateScope><CbomLegacyReview refresh={0} onCommitted={onCommitted} /></PrivateScope>);
async function openReview() {
  fireEvent.click(screen.getByRole("button", { name: "Review historical imports" }));
  fireEvent.click(await screen.findByRole("button", { name: "Review Payments" }));
  await screen.findByText(/Payments: 1 historical records/);
}
function confirm() {
  fireEvent.change(screen.getByLabelText("Review rationale (no secrets)"), { target: { value: "Reviewed synthetic original document and replacement metadata." } });
  fireEvent.click(screen.getByRole("checkbox"));
}
afterEach(() => { localStorage.clear(); });

describe("Historical import reconciliation", () => {
  it("loads only on demand, requires human review and sends the source snapshot", async () => {
    const changed = vi.fn();
    const fetcher = mockFetch(routes({ "/api/v1/cbom/system/legacy-system/reconcile-legacy": { audit_id: "durable-audit", detached_assets: 1, archived_declarations: 1 } }));
    renderReview(changed);
    expect(fetcher).not.toHaveBeenCalled();
    await openReview();
    const submit = screen.getByRole("button", { name: "Reconcile historical declarations" });
    expect(submit).toBeDisabled(); confirm(); expect(submit).not.toBeDisabled(); fireEvent.click(submit);
    expect(await screen.findByText(/Reconciliation committed. Audit receipt: durable-audit/)).toBeTruthy();
    expect(changed).toHaveBeenCalledOnce();
    const mutation = fetcher.mock.calls.find(([path]) => String(path).endsWith("/reconcile-legacy"));
    expect(JSON.parse(mutation![1]!.body as string)).toMatchObject({ expected_snapshot_sha256: "a".repeat(64), replacement_document_sha256: "b".repeat(64) });
  });
  it("blocks mixed scanner evidence on the UI as well as the server", async () => {
    mockFetch(routes({ "/api/v1/cbom/system/legacy-system/legacy-imports": { ...review, mixed_evidence_assets: 1 } }));
    renderReview(); await openReview(); confirm();
    expect(screen.getByText(/Automatic reconciliation is blocked/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Reconcile historical declarations" })).toBeDisabled();
  });
  it("requires a reimported fingerprint", async () => {
    mockFetch(routes({ "/api/v1/cbom/system/legacy-system/legacy-imports": { ...review, replacement_document_sha256: null } }));
    renderReview(); await openReview(); confirm();
    expect(screen.getByText(/first reimport the original CBOM/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Reconcile historical declarations" })).toBeDisabled();
  });
  it("does not invent clearance when reads are offline", async () => {
    offlineFetch(); renderReview(); fireEvent.click(screen.getByRole("button", { name: "Review historical imports" }));
    expect(await screen.findByText(/No clearance assumed/)).toBeTruthy();
    expect(screen.queryByRole("checkbox")).toBeNull();
  });
  it("treats a failed write as unconfirmed and never replays it", async () => {
    const fetcher = mockFetch(routes({ "/api/v1/cbom/system/legacy-system/reconcile-legacy": () => new Response("{}", { status: 503 }) }));
    renderReview(); await openReview(); confirm(); fireEvent.click(screen.getByRole("button", { name: "Reconcile historical declarations" }));
    expect(await screen.findByText(/Reconciliation is not confirmed/)).toBeTruthy();
    expect(fetcher.mock.calls.filter(([path]) => String(path).endsWith("/reconcile-legacy"))).toHaveLength(1);
    expect(screen.queryByRole("checkbox")).toBeNull();
  });
  it("clears private review drafts on scope changes", async () => {
    mockFetch(routes()); renderReview(); await openReview(); confirm();
    await act(async () => { window.dispatchEvent(new StorageEvent("storage", { key: "cryptoscan_tenant", newValue: "other" })); });
    await waitFor(() => expect(screen.queryByRole("checkbox")).toBeNull());
    expect(screen.queryByText("Payments: 1 historical records")).toBeNull();
  });
});

it("suppresses a late review read after a private-context change", async () => {
  let resolve!: (value: unknown) => void;
  mockFetch(routes({ "/api/v1/cbom/system/legacy-system/legacy-imports": () => new Promise(r => { resolve = r; }) }));
  renderReview(); fireEvent.click(screen.getByRole("button", { name: "Review historical imports" }));
  fireEvent.click(await screen.findByRole("button", { name: "Review Payments" }));
  await act(async () => { window.dispatchEvent(new Event("zelinx:auth")); });
  await act(async () => { resolve(review); });
  expect(screen.queryByRole("checkbox")).toBeNull();
  expect(screen.queryByText("Payments: 1 historical records")).toBeNull();
});
