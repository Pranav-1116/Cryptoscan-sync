import React from "react";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import PrivateScope from "./PrivateScope";
import HostEvidencePanel from "./HostEvidencePanel";
import { mockFetch, offlineFetch } from "../test/setup";
const id = "a".repeat(36), P = "/api/v1/host-evidence/approvals";
const receipt = { approval_id: id, scan_id: "scan-a", system_id: "system-a", snapshot_sha256: "b".repeat(64), evidence_count: 2, source_basis: "IMPORTED", runtime_use: "UNKNOWN", pqc_assessment: "UNKNOWN", policy_result: "NOT_EVALUATED", whole_host_coverage_verified: false, host_identity_attested: false };
const detail = { ...receipt, integrity: { result: "PASS", content_intact: true, chain_intact: true, manifest_intact: true, hash_format_valid: true },
  snapshot: { manifest: { host_id: "payments-1", environment: "prod" }, finished_at: "2026-10-24T00:00:00Z", receipts: [
    { input_id: "certificate", status: "PARSED", reason: "METADATA_ONLY", facts: [{ kind: "CERTIFICATE", algorithm: "RSA", key_size: 2048, local_basis: "OBSERVED", runtime_use: "UNKNOWN", software_name: null, software_version: null }] },
    { input_id: "unavailable", status: "UNAVAILABLE", reason: "NOT_FOUND", facts: [] }] } };
function mount() { return render(<PrivateScope><HostEvidencePanel /></PrivateScope>); }
function chooseApproval() { fireEvent.change(screen.getByLabelText("Host approval ID"), { target: { value: id } }); }
function inspect() { chooseApproval(); fireEvent.click(screen.getByRole("button", { name: "Inspect host evidence" })); }
async function load(label: string, data: unknown, size = 100) {
  const file = new File(["{}"], "metadata.json", { type: "application/json" });
  Object.defineProperty(file, "text", { value: () => Promise.resolve(JSON.stringify(data)) });
  Object.defineProperty(file, "size", { value: size });
  fireEvent.change(screen.getByLabelText(label), { target: { files: [file] } });
  await screen.findByText(/loaded locally|Invalid or oversized JSON/);
}

describe("Approved offline host workflow", () => {
  it("makes no request on mount and never offers broad remote execution", () => {
    const fetcher = mockFetch({}); mount(); expect(fetcher).not.toHaveBeenCalled();
    expect(screen.getByText(/Windows execution and production host admission are not qualified/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Approve host scope" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Import approved metadata" })).toBeDisabled();
  });
  it("approves only an explicit locally loaded manifest and system", async () => {
    const fetcher = mockFetch({ [P]: { subject_id: id, payload_sha256: "d".repeat(64) } }); mount();
    fireEvent.change(screen.getByLabelText("Host system ID"), { target: { value: "system-a" } });
    await load("Approved host manifest JSON", { inputs: ["explicit-fixture"] }); expect(fetcher).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Approve host scope" }));
    await screen.findByText(/Scope approved for one offline snapshot/);
    expect(JSON.parse(String(fetcher.mock.calls[0][1]?.body))).toEqual({ system_id: "system-a", manifest: { inputs: ["explicit-fixture"] } });
    expect(screen.getByLabelText("Host approval ID")).toHaveValue(id);
  });
  it("imports explicitly and never marks imported metadata as host attestation", async () => {
    const fetcher = mockFetch({ [`${P}/${id}/intake`]: receipt }); mount(); chooseApproval();
    await load("Offline host snapshot JSON", { schema_version: "fixture" }); expect(fetcher).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Import approved metadata" }));
    await screen.findByText(/Metadata committed as IMPORTED/);
    expect(screen.getByRole("button", { name: "Import approved metadata" })).toBeDisabled();
    expect(screen.queryByRole("button", { name: /Download CycloneDX/ })).toBeNull();
  });
  it("inspects a stored receipt without interpreting denied inputs as security results", async () => {
    const fetcher = mockFetch({ [`${P}/${id}/snapshot`]: detail }); mount(); inspect();
    await screen.findByText("payments-1 · prod"); expect(screen.getByText("UNAVAILABLE · NOT_FOUND")).toBeTruthy();
    expect(screen.getByText(/Runtime use: UNKNOWN · PQC assessment: UNKNOWN/)).toBeTruthy();
    expect(fetcher.mock.calls).toHaveLength(1);
    fireEvent.change(screen.getByLabelText("Host approval ID"), { target: { value: "b".repeat(36) } });
    expect(screen.queryByText("payments-1 · prod")).toBeNull();
  });
  it.each([
    { ...detail, source_basis: "OBSERVED" }, { ...detail, host_identity_attested: true }, { ...detail, whole_host_coverage_verified: true },
    { ...detail, approval_id: "other" }, { ...detail, integrity: { ...detail.integrity, manifest_intact: false } },
    { ...detail, snapshot: { ...detail.snapshot, receipts: [{ input_id: "broken", status: "DENIED", reason: "LIMIT", facts: null }] } },
  ])("rejects malformed or promoted live-shaped proof", async broken => {
    mockFetch({ [`${P}/${id}/snapshot`]: broken }); mount(); inspect(); await screen.findByText(/No verified receipt or security verdict assumed/);
    expect(screen.queryByRole("button", { name: /Download CycloneDX/ })).toBeNull();
  });
  it("discards a pending private read on tenant switch without replay", async () => {
    let finish!: (value: unknown) => void;
    const fetcher = mockFetch({ [`${P}/${id}/snapshot`]: () => new Promise(resolve => { finish = resolve; }) }); mount(); inspect();
    await waitFor(() => expect(finish).toBeTypeOf("function"));
    act(() => window.dispatchEvent(new StorageEvent("storage", { key: "cryptoscan_tenant", newValue: "other" })));
    await screen.findByText(/Private evidence and unsubmitted drafts were cleared/);
    await act(async () => { finish(detail); });
    expect(screen.queryByText("payments-1 · prod")).toBeNull(); expect(fetcher.mock.calls).toHaveLength(1);
    expect(screen.getByLabelText("Host approval ID")).toHaveValue("");
  });
  it("discards a pending import response on logout", async () => {
    let finish!: (value: unknown) => void;
    mockFetch({ [`${P}/${id}/intake`]: () => new Promise(resolve => { finish = resolve; }) }); mount(); chooseApproval();
    await load("Offline host snapshot JSON", {}); fireEvent.click(screen.getByRole("button", { name: "Import approved metadata" }));
    await waitFor(() => expect(finish).toBeTypeOf("function"));
    act(() => window.dispatchEvent(new StorageEvent("storage", { key: "zelinx_token", newValue: null })));
    await act(async () => { finish(receipt); });
    expect(screen.queryByText(/Metadata committed as IMPORTED/)).toBeNull();
  });
  it("refuses oversized local JSON without a request", async () => {
    const fetcher = mockFetch({}); mount(); chooseApproval(); await load("Offline host snapshot JSON", {}, 1500001);
    expect(fetcher).not.toHaveBeenCalled(); expect(screen.getByRole("button", { name: "Import approved metadata" })).toBeDisabled();
  });
  it("shows production admission refusal without retrying or substituting samples", async () => {
    const fetcher = mockFetch({ [`${P}/${id}/snapshot`]: () => new Response('{"detail":"Unqualified host adapter"}', { status: 409 }) });
    mount(); inspect(); await screen.findByText(/No verified receipt or security verdict assumed/); expect(fetcher.mock.calls).toHaveLength(1);
  });
  it("retains Linux OS-release as imported declared metadata, not crypto use", async () => {
    const os = { ...detail, snapshot: { ...detail.snapshot, receipts: [{ input_id: "os", status: "PARSED", reason: "METADATA_ONLY", facts: [{ kind: "OS_RELEASE", algorithm: "UNKNOWN", key_size: null, local_basis: "DECLARED", runtime_use: "UNKNOWN", software_name: "ubuntu", software_version: "24.04" }] }] } };
    mockFetch({ [`${P}/${id}/snapshot`]: os }); mount(); inspect();
    await screen.findByText(/OS_RELEASE · ubuntu · 24.04 · local claim DECLARED/);
    expect(screen.getByText(/Runtime use: UNKNOWN · PQC assessment: UNKNOWN/)).toBeTruthy();
  });
  it("does not invent evidence when offline", async () => {
    offlineFetch(); mount(); inspect(); await screen.findByText(/No verified receipt or security verdict assumed/);
    expect(screen.queryByText("payments-1 · prod")).toBeNull();
  });
});
