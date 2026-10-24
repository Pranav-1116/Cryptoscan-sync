import React from "react";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import PrivateScope from "./PrivateScope";
import { MixedHistoryDecision, UnassignedHistory } from "./CbomControlledHistory";
import { LegacyImportReview } from "../lib/api";
import { mockFetch } from "../test/setup";
const snapshot = "a".repeat(64), digest = "b".repeat(64);
const review = { system_id: "synthetic", snapshot_sha256: snapshot, replacement_document_sha256: digest } as LegacyImportReview;
const proposal = { payload_sha256: digest, payload: { state: "PENDING_SECOND_HUMAN", expected_snapshot_sha256: snapshot, submitted_by: "human-one", reason: "Original proposal rationale", evidence_ref: "change/42" } };
function wrap(ui: React.ReactNode) { return render(<PrivateScope>{ui}</PrivateScope>); }
function confirmMixed() {
  fireEvent.change(screen.getByLabelText("Mixed-source rationale (no secrets)"), { target: { value: "Reviewed synthetic retained evidence and partial export consequences." } });
  fireEvent.change(screen.getByLabelText("Mixed-source evidence reference"), { target: { value: "review/42" } });
  fireEvent.click(screen.getByRole("checkbox"));
}
describe("Controlled historical decisions", () => {
  it("makes ownership an intentional snapshot-bound declaration, never clearance", async () => {
    const changed = vi.fn();
    const fetcher = mockFetch({
      "/api/v1/cbom/legacy-imports/unassigned": { total: 1, page: 1, page_size: 50, assets: [{ id: "orphan", algorithm: "AES" }] },
      "/api/v1/cbom/legacy-assets/orphan/review": { asset_id: "orphan", algorithm: "AES", snapshot_sha256: snapshot, linked_evidence_count: 1, unassigned: true },
      "/api/v1/cbom/legacy-assets/orphan/assign": { audit_id: "synthetic-receipt" },
    });
    wrap(<UnassignedHistory onCommitted={changed} />); expect(fetcher).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Review unassigned records" }));
    fireEvent.click(await screen.findByRole("button", { name: "Inspect AES (orphan)" }));
    const button = await screen.findByRole("button", { name: "Assign declared responsibility" }); expect(button).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Destination system ID (same estate)"), { target: { value: "system-a" } });
    fireEvent.change(screen.getByLabelText("Ownership rationale (no secrets)"), { target: { value: "Reviewed synthetic owner records without any scan claim." } });
    fireEvent.change(screen.getByLabelText("Ownership evidence reference"), { target: { value: "cmdb/42" } });
    fireEvent.click(button); await waitFor(() => expect(changed).toHaveBeenCalledOnce());
    expect(changed.mock.calls[0][0]).toMatch(/historical review\/export blocks remain/);
    const request = fetcher.mock.calls.find(([path]) => String(path).endsWith("/assign"));
    expect(JSON.parse(request![1]!.body as string)).toMatchObject({ expected_snapshot_sha256: snapshot, system_id: "system-a" });
  });
  it("shows the immutable proposal and sends only the selected case digest for second review", async () => {
    const changed = vi.fn(), fetcher = mockFetch({ "/api/v1/cbom/system/synthetic/mixed-review": { case: proposal }, "/api/v1/cbom/system/synthetic/mixed-review/approve": { audit_id: "audit-42" } });
    wrap(<MixedHistoryDecision review={review} onCommitted={changed} />);
    fireEvent.click(screen.getByRole("button", { name: "Load controlled mixed review" }));
    expect(await screen.findByText("Original proposal rationale")).toBeTruthy();
    expect(screen.getByText("human-one")).toBeTruthy();
    const approve = screen.getByRole("button", { name: "Approve as second human" }); expect(approve).toBeDisabled();
    confirmMixed(); fireEvent.click(approve); await waitFor(() => expect(changed).toHaveBeenCalledOnce());
    const request = fetcher.mock.calls.find(([path]) => String(path).endsWith("/approve"));
    expect(JSON.parse(request![1]!.body as string)).toMatchObject({ expected_case_sha256: digest });
    expect(changed.mock.calls[0][0]).toMatch(/No clean posture grade or bank approval/);
  });
  it("disables approval when the proposal snapshot differs from current reviewed inventory", async () => {
    mockFetch({ "/api/v1/cbom/system/synthetic/mixed-review": { case: { ...proposal, payload: { ...proposal.payload, expected_snapshot_sha256: "c".repeat(64) } } } });
    wrap(<MixedHistoryDecision review={review} onCommitted={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: "Load controlled mixed review" }));
    await screen.findByText(/Changed — refresh source/); confirmMixed();
    expect(screen.getByRole("button", { name: "Approve as second human" })).toBeDisabled();
  });
  it("does not retry or retain a reusable case after an unconfirmed write", async () => {
    const changed = vi.fn(), fetcher = mockFetch({ "/api/v1/cbom/system/synthetic/mixed-review": { case: proposal }, "/api/v1/cbom/system/synthetic/mixed-review/approve": () => new Response("{}", { status: 503 }) });
    wrap(<MixedHistoryDecision review={review} onCommitted={changed} />);
    fireEvent.click(screen.getByRole("button", { name: "Load controlled mixed review" }));
    await screen.findByText("Original proposal rationale"); confirmMixed(); fireEvent.click(screen.getByRole("button", { name: "Approve as second human" }));
    await screen.findByText(/Decision not confirmed/);
    expect(screen.queryByRole("button", { name: "Approve as second human" })).toBeNull(); expect(changed).not.toHaveBeenCalled();
    expect(fetcher.mock.calls.filter(([path]) => String(path).endsWith("/approve"))).toHaveLength(1);
  });
  it("discards a late proposal read after an estate change", async () => {
    let finish!: (value: unknown) => void;
    mockFetch({ "/api/v1/cbom/system/synthetic/mixed-review": () => new Promise(resolve => { finish = resolve; }) });
    wrap(<MixedHistoryDecision review={review} onCommitted={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: "Load controlled mixed review" }));
    await waitFor(() => expect(finish).toBeTypeOf("function"));
    act(() => { window.dispatchEvent(new StorageEvent("storage", { key: "cryptoscan_tenant", newValue: "other" })); });
    await screen.findByText(/Private evidence and unsubmitted drafts were cleared/);
    await act(async () => { finish({ case: proposal }); });
    expect(screen.queryByText("Original proposal rationale")).toBeNull();
    expect(screen.queryByRole("button", { name: "Approve as second human" })).toBeNull();
  });
});
