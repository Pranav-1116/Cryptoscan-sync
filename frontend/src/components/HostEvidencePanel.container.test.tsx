import React from "react";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import PrivateScope from "./PrivateScope";
import HostEvidencePanel from "./HostEvidencePanel";
import { mockFetch } from "../test/setup";
import facts from "../test/fixtures/verifiedContainerFacts.json";

const id = "a".repeat(36), P = "/api/v1/host-evidence/approvals", sha = "b".repeat(64);
function detail(content: unknown = facts.content, runtime: unknown = facts.runtime) {
  return { approval_id: id, scan_id: "scan-a", system_id: "system-a", snapshot_sha256: sha,
    evidence_count: 2, source_basis: "IMPORTED", runtime_use: "UNKNOWN", pqc_assessment: "UNKNOWN", policy_result: "NOT_EVALUATED",
    whole_host_coverage_verified: false, host_identity_attested: false,
    integrity: { result: "PASS", content_intact: true, chain_intact: true, manifest_intact: true, hash_format_valid: true },
    snapshot: { manifest: { host_id: "fixture-image", environment: "test" }, finished_at: "2026-10-25T00:00:00Z",
      receipts: [{ input_id: "content", status: "PARSED", reason: "METADATA_ONLY", facts: [content] },
        { input_id: "runtime", status: "PARSED", reason: "METADATA_ONLY", facts: [runtime] }] } };
}
function mount() {
  render(<PrivateScope><HostEvidencePanel /></PrivateScope>);
  fireEvent.change(screen.getByLabelText("Host approval ID"), { target: { value: id } });
  fireEvent.click(screen.getByRole("button", { name: "Inspect host evidence" }));
}
describe("Verified container content and runtime metadata", () => {
  it("shows layer/package records and exact cgroup observation without admission/image-use claims", async () => {
    const fetcher = mockFetch({ [`${P}/${id}/snapshot`]: detail() }); mount();
    await screen.findByText(/verified layer bytes and virtual overlay/);
    expect(screen.getByText(/1 package DB records/)).toBeTruthy();
    expect(screen.getByText(/kernel cgroup membership only; image operator DECLARED/)).toBeTruthy();
    expect(screen.getByText(/Container production admission: BLOCKED/)).toBeTruthy();
    expect(fetcher.mock.calls).toHaveLength(1);
  });
  it.each([
    { layer_contents_verified: false }, { package_inventory_verified: true }, { deployment_verified: true },
    { vendor_identity_verified: true }, { final_filesystem_view_verified: false }, { image: { ...facts.content.image, runtime_use: "OBSERVED" } },
    { packages: [{ ...facts.content.packages[0], layer_index: 99 }] },
    { packages: [{ ...facts.content.packages[0], source_sha256: "f".repeat(64) }] },
    { databases: [] }, { rootfs_view_sha256: "bad" }, { arbitrary: "promoted" },
  ])("refuses malformed/promoted content", async patch => {
    mockFetch({ [`${P}/${id}/snapshot`]: detail({ ...facts.content, ...patch }) }); mount();
    await screen.findByText(/No verified receipt or security verdict assumed/);
    expect(screen.queryByRole("button", { name: /verified layer and package-record/ })).toBeNull();
  });
  it.each([{ runtime_image_verified: true }, { deployment_verified: true }, { process_observed: false },
    { image_binding_basis: "VERIFIED" }, { identity_key: "wrong" }, { source_sha256: "bad" },
    { process: { ...facts.runtime.process, runtime_use: "OBSERVED" } },
  ])("refuses promoted runtime evidence", async patch => {
    mockFetch({ [`${P}/${id}/snapshot`]: detail(facts.content, { ...facts.runtime, ...patch }) }); mount();
    await screen.findByText(/No verified receipt or security verdict assumed/);
  });
  it("downloads only the matching verified-content export on explicit action", async () => {
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    const url = vi.spyOn(URL, "createObjectURL");
    const fetcher = mockFetch({ [`${P}/${id}/snapshot`]: detail(), [`${P}/${id}/container/cyclonedx-1.6`]: {
      bomFormat: "CycloneDX", specVersion: "1.6", metadata: { properties: [
        { name: "cryptoscan:profile", value: "VERIFIED_OCI_LAYERS_AND_SCOPED_PACKAGE_DATABASES" },
        { name: "cryptoscan:snapshot_sha256", value: sha }] } } });
    mount(); await screen.findByText(/verified layer bytes/);
    expect(fetcher.mock.calls).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "Download verified layer and package-record SBOM" }));
    await screen.findByText(/CycloneDX 1.6 metadata downloaded/);
    expect(click).toHaveBeenCalledOnce();expect(url).toHaveBeenCalledOnce();
    click.mockRestore();url.mockRestore();
  });
  it("does not download an old-context container export after logout", async () => {
    let finish!: (value: unknown) => void;
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    mockFetch({ [`${P}/${id}/snapshot`]: detail(), [`${P}/${id}/container/cyclonedx-1.6`]: () => new Promise(resolve => { finish = resolve; }) });
    mount();await screen.findByText(/verified layer bytes/);
    fireEvent.click(screen.getByRole("button", { name: "Download verified layer and package-record SBOM" }));
    act(() => window.dispatchEvent(new StorageEvent("storage", { key: "zelinx_token", newValue: null })));
    await act(async () => { finish({ bomFormat: "CycloneDX", specVersion: "1.6" }); });
    expect(click).not.toHaveBeenCalled();click.mockRestore();
  });
});
