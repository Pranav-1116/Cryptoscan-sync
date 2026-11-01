import React from "react";
import { setToken } from "../lib/api";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import LinuxSoftwarePanel from "./LinuxSoftwarePanel";
import { mockFetch } from "../test/setup";
const job = "a".repeat(36), envelope = "b".repeat(64), path = `/api/v1/collection/jobs/${job}/software/linux`;
function inventory() {
  return { schema_version: "cryptoscan.linux-software-inventory/v1", coverage: { job_id: job, envelope_sha256: envelope, bom_observation_counts: { SBOM: 0 } }, packages: [], binary_presence: [], mapped_library_paths: [], package_inputs: [{ input_id: "packages", status: "INVALID", reason: "INVALID_FORMAT" }], provenance: "IMPORTED", standard_document: false, dependencies_complete: false, installed_package_inventory_complete: false, host_identity_attested: false, production_execution_qualified: false, materialized_without_collection: true };
}
function click() { fireEvent.click(screen.getByText("Read Linux software evidence")); }
it("reads explicitly with tenant/session, preserves input failure and never starts collection", async () => {
  localStorage.setItem("cryptoscan_tenant", "synthetic-bank"); setToken("synthetic-token");
  const fetch = mockFetch({ [path]: inventory() }); render(<LinuxSoftwarePanel job={job} envelope={envelope} />);
  expect(fetch).not.toHaveBeenCalled(); click();
  expect(await screen.findByText(/packages: INVALID/)).toBeInTheDocument();
  expect(screen.getByText(/not a standard CycloneDX SBOM/)).toBeInTheDocument();
  expect(fetch.mock.calls[0][1]?.method).toBeUndefined();
  expect(fetch.mock.calls[0][1]?.headers).toMatchObject({ "X-Tenant-ID": "synthetic-bank", Authorization: "Bearer synthetic-token" });
});
it.each(["standard_document", "dependencies_complete", "installed_package_inventory_complete", "host_identity_attested", "production_execution_qualified", "wrong-envelope", "wrong-job", "wrong-count"])("rejects promoted or mismatched %s", async change => {
  const value = inventory();
  if (change === "wrong-envelope") value.coverage.envelope_sha256 = "c".repeat(64);
  else if (change === "wrong-job") value.coverage.job_id = "other";
  else if (change === "wrong-count") value.coverage.bom_observation_counts.SBOM = 1;
  else Object.assign(value, { [change]: true });
  mockFetch({ [path]: value }); render(<LinuxSoftwarePanel job={job} envelope={envelope} />); click();
  expect(await screen.findByRole("alert")).toHaveTextContent("inconsistent");
  expect(screen.queryByText(/IMPORTED software metadata/)).not.toBeInTheDocument();
});
it.each(["tenant", "auth", "storage", "resume", "history", "job"])("discards non-cooperative late response after %s", async change => {
  let resolve!: (r: Response) => void; globalThis.fetch = vi.fn(() => new Promise<Response>(r => { resolve = r; }));
  const view = render(<LinuxSoftwarePanel job={job} envelope={envelope} />); click();
  act(() => {
    if (change === "job") view.rerender(<LinuxSoftwarePanel job="another" envelope={envelope} />);
    else if (change === "storage") window.dispatchEvent(new StorageEvent("storage", { key: "zelinx_signed_in" }));
    else if (change === "resume") document.dispatchEvent(new Event("visibilitychange"));
    else if (change === "history") window.dispatchEvent(new PageTransitionEvent("pageshow", { persisted: true }));
    else window.dispatchEvent(new Event(`zelinx:${change}`));
  });
  await act(async () => resolve(new Response(JSON.stringify(inventory()))));
  expect(screen.queryByText(/IMPORTED software metadata/)).not.toBeInTheDocument();
});
it("bounds a stuck read without retry or late evidence", async () => {
  vi.useFakeTimers(); let resolve!: (r: Response) => void;
  const fetch = vi.fn(() => new Promise<Response>(r => { resolve = r; })); globalThis.fetch = fetch;
  render(<LinuxSoftwarePanel job={job} envelope={envelope} />); click();
  await act(async () => { await vi.advanceTimersByTimeAsync(20000); });
  expect(screen.getByRole("alert")).toHaveTextContent("timed out");
  await act(async () => resolve(new Response(JSON.stringify(inventory()))));
  expect(screen.queryByText(/IMPORTED software metadata/)).not.toBeInTheDocument(); expect(fetch).toHaveBeenCalledTimes(1);
});
it("renders retained package provenance without upgrading presence to crypto use", async () => {
  const value = inventory();
  Object.assign(value, { packages: [{ identity_slot: "slot", identity_status: "SINGLE_RECORD", package_manager: "dpkg", name: "openssl", version: "3.0.13", architecture: "UNKNOWN", licenses: "UNKNOWN", dependencies: "UNKNOWN", runtime_use: "UNKNOWN", cryptographic_use: "UNKNOWN", purl: null, package_artifact_sha256: null, records: [{ observation_id: "observation", evidence_id: "evidence", fact_sha256: envelope, source: { kind: "DPKG_STATUS", path: "/approved/status", input_content_sha256: envelope }, fact: { kind: "SOFTWARE", software_name: "openssl", software_version: "3.0.13", local_basis: "OBSERVED" } }] }] });
  value.coverage.bom_observation_counts.SBOM = 1;
  mockFetch({ [path]: value }); render(<LinuxSoftwarePanel job={job} envelope={envelope} />); click();
  expect(await screen.findByText(/openssl · 3.0.13/)).toBeInTheDocument();
  expect(screen.getByText(/evidence · local OBSERVED/)).toHaveTextContent("/approved/status");
  expect(screen.getByText(/Architecture, licenses/)).toHaveTextContent("UNKNOWN");
});
