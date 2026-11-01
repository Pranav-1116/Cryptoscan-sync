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
    expect(screen.getByText(/No remote execution/)).toBeTruthy();
    expect(screen.getByText(/Windows execution and production host admission are not qualified/)).toBeTruthy();
    expect(screen.getByText(/Host identity/, { selector: "span" })).toHaveTextContent("UNVERIFIED · runtime UNKNOWN");
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
    expect(screen.getByText(/runtime UNKNOWN · PQC UNKNOWN · NOT_EVALUATED/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Import approved metadata" })).toBeDisabled();
    expect(screen.queryByRole("button", { name: /Download CycloneDX/ })).toBeNull();
  });
  it("inspects a stored receipt without interpreting denied inputs as security results", async () => {
    const fetcher = mockFetch({ [`${P}/${id}/snapshot`]: detail }); mount(); inspect();
    await screen.findByText("payments-1"); expect(screen.getByText("prod")).toBeTruthy();
    expect(screen.getByText("UNAVAILABLE · NOT_FOUND")).toBeTruthy();
    expect(screen.getByText(/Host identity/, { selector: "span" })).toHaveTextContent("UNVERIFIED · runtime UNKNOWN");
    expect(screen.getByText(/Operator DECLARED scope/)).toHaveTextContent("not host attestation");
    expect(fetcher.mock.calls).toHaveLength(1);
    fireEvent.change(screen.getByLabelText("Host approval ID"), { target: { value: "b".repeat(36) } });
    expect(screen.queryByText("payments-1")).toBeNull();
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
    expect(screen.queryByText("payments-1")).toBeNull(); expect(fetcher.mock.calls).toHaveLength(1);
    expect(screen.getByLabelText("Host approval ID")).toHaveValue("");
  });
  it("discards a pending import response on logout", async () => {
    let finish!: (value: unknown) => void;
    mockFetch({ [`${P}/${id}/intake`]: () => new Promise(resolve => { finish = resolve; }) }); mount(); chooseApproval();
    await load("Offline host snapshot JSON", {}); fireEvent.click(screen.getByRole("button", { name: "Import approved metadata" }));
    await waitFor(() => expect(finish).toBeTypeOf("function"));
    act(() => window.dispatchEvent(new StorageEvent("storage", { key: "zelinx_signed_in", newValue: null })));
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
    expect(screen.getByText(/Host identity/, { selector: "span" })).toHaveTextContent("UNVERIFIED · runtime UNKNOWN");
    expect(screen.getByText(/Operator DECLARED scope/)).toHaveTextContent("not host attestation");
  });
  it("does not invent evidence when offline", async () => {
    offlineFetch(); mount(); inspect(); await screen.findByText(/No verified receipt or security verdict assumed/);
    expect(screen.queryByText("payments-1")).toBeNull();
  });
});

describe("Passive runtime metadata, not cryptographic operation proof", () => {
  const fact = { kind: "LISTENER", algorithm: "UNKNOWN", key_size: null, local_basis: "OBSERVED", runtime_use: "UNKNOWN", software_name: null, software_version: null, purpose: "HOST_RUNTIME_METADATA", operation_use: "UNKNOWN", capabilities_observed: false, identity_key: "scoped-listener", interface: "LINUX_PROCFS", interface_sha256: "a".repeat(64), address: "127.0.0.1", port: 443 };
  const runtimeDetail = (changes = {}) => ({ ...detail, snapshot: { ...detail.snapshot, receipts: [{ input_id: "listener", status: "PARSED", reason: "METADATA_ONLY", facts: [{ ...fact, ...changes }] }] } });
  it("shows a listener without inferring TLS from port 443", async () => {
    mockFetch({ [`${P}/${id}/snapshot`]: runtimeDetail() }); mount(); inspect();
    await screen.findByText(/LISTENER · 127.0.0.1:443/);
    expect(screen.getByText(/Host identity/, { selector: "span" })).toHaveTextContent("UNVERIFIED · runtime UNKNOWN");
    expect(screen.getByText(/Operator DECLARED scope/)).toHaveTextContent("not host attestation");
  });
  it.each([{ algorithm: "RSA" }, { local_basis: "DECLARED" }, { interface_sha256: "invalid" }, { operation_use: "OBSERVED" }, { capabilities_observed: true }])("refuses promoted or uncommitted runtime proof", async changes => {
    mockFetch({ [`${P}/${id}/snapshot`]: runtimeDetail(changes) }); mount(); inspect();
    await screen.findByText(/No verified receipt or security verdict assumed/);
    expect(screen.queryByText(/LISTENER · 127.0.0.1:443/)).toBeNull();
  });
});

describe("Windows exact process/module candidate", () => {
  const fact = { kind: "WINDOWS_MODULE", algorithm: "UNKNOWN", key_size: null, local_basis: "OBSERVED", runtime_use: "UNKNOWN", software_name: null, software_version: null, purpose: "WINDOWS_IMAGE_METADATA", operation_use: "UNKNOWN", capabilities_observed: false, identity_key: "scoped-image", interface: "WINDOWS_PROCESS_TOOLHELP", interface_sha256: "a".repeat(64), pid: 71, creation_filetime: "133800000000000001", image_path: "C:\\Reviewed\\libcrypto.dll", module_name: "libcrypto.dll", capture_basis: "REPEATED_MATCHING_METADATA_NOT_INVOCATION" };
  const images = (changes = {}) => ({ ...detail, snapshot: { ...detail.snapshot, receipts: [{ input_id: "images", status: "PARSED", reason: "METADATA_ONLY", facts: [{ ...fact, ...changes }] }] } });
  it("keeps FILETIME exactly as text and module presence separate from crypto use", async () => {
    const fetcher = mockFetch({ [`${P}/${id}/snapshot`]: images() }); mount(); inspect();
    await screen.findByText(/WINDOWS_MODULE · C:\\Reviewed\\libcrypto.dll/);
    expect(screen.getByText(/creation FILETIME 133800000000000001 · repeated module metadata, not invocation/)).toBeTruthy();
    expect(screen.getByText(/No remote execution/)).toBeTruthy();
    expect(screen.getByText(/Windows execution and production host admission are not qualified/)).toBeTruthy();
    expect(screen.getByText(/Host identity/, { selector: "span" })).toHaveTextContent("UNVERIFIED · runtime UNKNOWN");
    expect(fetcher.mock.calls).toHaveLength(1);
  });
  it.each([
    { creation_filetime: 133800000000000001 }, { creation_filetime: "18446744073709551616" },
    { creation_filetime: "0133800000000000001" }, { pid: 0 }, { pid: 4294967296 },
    { algorithm: "RSA" }, { runtime_use: "OBSERVED" }, { operation_use: "OBSERVED" },
    { interface: "LINUX_PROCFS" }, { capabilities_observed: true }, { capture_basis: "ATOMIC" },
    { software_name: "OpenSSL" }, { software_version: "1.1.1" },
  ])("refuses rounded or promoted module proof", async changes => {
    mockFetch({ [`${P}/${id}/snapshot`]: images(changes) }); mount(); inspect();
    await screen.findByText(/No verified receipt or security verdict assumed/);
    expect(screen.queryByRole("button", { name: /Download CycloneDX/ })).toBeNull();
  });
});

describe("Windows CNG registration candidate", () => {
  const fact = { kind: "WINDOWS_CNG_REGISTRATION", algorithm: "UNKNOWN", key_size: null, local_basis: "OBSERVED", runtime_use: "UNKNOWN", software_name: null, software_version: null, purpose: "PROVIDER_REGISTRATION_METADATA", operation_use: "UNKNOWN", capabilities_observed: false, identity_key: "microsoft-primitive:user:cipher", interface: "WINDOWS_CNG_REGISTRATION_QUERY", interface_sha256: "a".repeat(64), provider_name: "Microsoft Primitive Provider", registration_mode: "USER", registration_interface: "cipher", registration_flags: 0, registered_functions: ["3DES", "AES"], capture_basis: "REGISTERED_NOT_OPENED_OR_INVOKED" };
  const registration = (changes = {}) => ({ ...detail, snapshot: { ...detail.snapshot, receipts: [{ input_id: "registration", status: "PARSED", reason: "METADATA_ONLY", facts: [{ ...fact, ...changes }] }] } });
  it("displays registration labels without upgrading capability or invocation", async () => {
    const fetcher = mockFetch({ [`${P}/${id}/snapshot`]: registration() }); mount(); inspect();
    await screen.findByText(/WINDOWS_CNG_REGISTRATION · Microsoft Primitive Provider/);
    expect(screen.getByText(/cipher registered labels: 3DES, AES · registration only; capability\/use UNKNOWN/)).toBeTruthy();
    expect(fetcher.mock.calls).toHaveLength(1);
  });
  it.each([
    { algorithm: "AES" }, { capabilities_observed: true }, { runtime_use: "OBSERVED" }, { operation_use: "OBSERVED" },
    { software_version: "1.0" }, { provider_name: "Another Provider" }, { registration_mode: "KERNEL" },
    { registered_functions: [] }, { registered_functions: ["AES", "3DES"] }, { registered_functions: ["AES", "aes"] },
    { registered_functions: ["has spaces"] }, { registered_functions: Array(65).fill("AES") },
    { registration_interface: "signature" }, { capture_basis: "INVOKED" }, { registration_flags: -1 },
  ])("refuses promoted or malformed registration metadata", async changes => {
    mockFetch({ [`${P}/${id}/snapshot`]: registration(changes) }); mount(); inspect();
    await screen.findByText(/No verified receipt or security verdict assumed/);
    expect(screen.queryByRole("button", { name: /Download CycloneDX/ })).toBeNull();
  });
});

describe("Windows TPM metadata candidate", () => {
  const fact = { kind: "WINDOWS_TPM_METADATA", algorithm: "UNKNOWN", key_size: null, local_basis: "OBSERVED", runtime_use: "UNKNOWN", software_name: null, software_version: null, purpose: "OS_REPORTED_TPM_METADATA", operation_use: "UNKNOWN", capabilities_observed: false, identity_key: "windows-tpm:local:device-info", interface: "WINDOWS_TBS_DEVICE_INFO", interface_sha256: "a".repeat(64), hardware_type: "TPM", api_structure_version: 1, tpm_specification: "2.0", capture_basis: "OS_REPORTED_NOT_ATTESTED_OR_INVOKED", policy_result: "NOT_EVALUATED", pqc_assessment: "UNKNOWN" };
  const device = (changes = {}) => ({ ...detail, snapshot: { ...detail.snapshot, receipts: [{ input_id: "tpm", status: "PARSED", reason: "METADATA_ONLY", facts: [{ ...fact, ...changes }] }] } });
  it("displays only OS-reported TPM specification without hardware-use promotion", async () => {
    const fetcher = mockFetch({ [`${P}/${id}/snapshot`]: device() }); mount(); inspect();
    await screen.findByText(/WINDOWS_TPM_METADATA · TPM/);
    expect(screen.getByText(/TPM 2.0 · OS reported; not attestation, firmware or key use/)).toBeTruthy();
    expect(fetcher.mock.calls).toHaveLength(1);
  });
  it.each([{ tpm_specification: "3.0" }, { api_structure_version: 2 }, { algorithm: "RSA" }, { runtime_use: "OBSERVED" }, { capabilities_observed: true }, { manufacturer: "Attested Vendor" }, { identity_key: "physical-tpm-id" }, { capture_basis: "ATTESTED" }, { firmware_version: "attested firmware" }, { pqc_assessment: "SAFE" }, { policy_result: "PASS" }, { attested: true }])("rejects promoted or unsupported device claims", async changes => {
    mockFetch({ [`${P}/${id}/snapshot`]: device(changes) }); mount(); inspect();
    await screen.findByText(/No verified receipt or security verdict assumed/);
    expect(screen.queryByRole("button", { name: /Download CycloneDX/ })).toBeNull();
  });
});

describe("Windows legacy selection and TCP-table candidates", () => {
  const base = { algorithm: "UNKNOWN", key_size: null, local_basis: "OBSERVED", runtime_use: "UNKNOWN", software_name: null, software_version: null, operation_use: "UNKNOWN", capabilities_observed: false, policy_result: "NOT_EVALUATED", pqc_assessment: "UNKNOWN", interface_sha256: "a".repeat(64) };
  const capi = { ...base, kind: "WINDOWS_CAPI_DEFAULT_PROVIDER", purpose: "DEFAULT_PROVIDER_SELECTION_METADATA", interface: "WINDOWS_CAPI_DEFAULT_PROVIDER_QUERY", provider_context: "CURRENT_USER", provider_type: 24, provider_name: "Reviewed Provider", identity_key: "windows-capi:current-user:24:default-provider", capture_basis: "DEFAULT_SELECTION_NOT_OPENED_OR_INVOKED" };
  const tcp = { ...base, kind: "WINDOWS_TCP_LISTENER_TABLE", purpose: "OS_TCP_LISTENER_TABLE_METADATA", interface: "WINDOWS_IP_HELPER_TCP_TABLE", address_family: "ipv4", listener_count: 1, listeners: [{ address: "127.0.0.1", port: 443, owning_pid: 1234, scope_id: 0 }], identity_key: "windows-tcp-table:ipv4:owner-pid-listener", capture_basis: "REPEATED_TABLE_NOT_PROCESS_IDENTITY_OR_TLS", process_identity_verified: false, tls_observed: false, asset_absence_proven: false };
  const value = (fact: unknown) => ({ ...detail, snapshot: { ...detail.snapshot, receipts: [{ input_id: "metadata", status: "PARSED", reason: "METADATA_ONLY", facts: [fact] }] } });
  it.each([capi, tcp])("shows bounded metadata without inferred operation/use", async fact => {
    const fetcher = mockFetch({ [`${P}/${id}/snapshot`]: value(fact) }); mount(); inspect();
    await screen.findByText(/default provider selection; not opened|sampled TCP listener rows/);
    if (fact.kind === "WINDOWS_TCP_LISTENER_TABLE") expect(screen.getByText(/OS-reported owning PID 1234/)).toBeTruthy();
    expect(fetcher.mock.calls).toHaveLength(1);
  });
  it("supports explicit IPv6 scope without a process link", async () => {
    const fact = { ...tcp, address_family: "ipv6", identity_key: "windows-tcp-table:ipv6:owner-pid-listener", listeners: [{ address: "fe80::1", port: 443, owning_pid: 1234, scope_id: 3 }] };
    mockFetch({ [`${P}/${id}/snapshot`]: value(fact) }); mount(); inspect();
    await screen.findByText(/fe80::1:443 · scope 3/);
  });
  it("keeps empty table capture distinct from hardware/network absence", async () => {
    mockFetch({ [`${P}/${id}/snapshot`]: value({ ...tcp, listener_count: 0, listeners: [] }) }); mount(); inspect();
    await screen.findByText(/0 sampled TCP listener rows; TLS and process identity unverified/);
  });
  it.each([
    { ...capi, provider_context: "LOCAL_MACHINE" }, { ...capi, provider_type: 99 }, { ...capi, algorithm: "RSA" }, { ...capi, provider_name: "unsafe\nname" }, { ...capi, capabilities_observed: true },
    { ...tcp, listener_count: 2 }, { ...tcp, tls_observed: true }, { ...tcp, process_identity_verified: true }, { ...tcp, asset_absence_proven: true }, { ...tcp, listeners: [{ ...tcp.listeners[0], port: 0 }] },
    { ...tcp, listeners: [{ ...tcp.listeners[0], address: "::1" }] }, { ...tcp, listeners: [{ ...tcp.listeners[0], owning_pid: -1 }] }, { ...tcp, listener_count: 2, listeners: [tcp.listeners[0], tcp.listeners[0]] }, { ...tcp, attested: true }, { ...tcp, policy_result: "PASS" }
  ])("refuses invalid/promoted selection or TCP metadata", async fact => {
    mockFetch({ [`${P}/${id}/snapshot`]: value(fact) }); mount(); inspect();
    await screen.findByText(/No verified receipt or security verdict assumed/);
    expect(screen.queryByRole("button", { name: /Download CycloneDX/ })).toBeNull();
  });
  it.each(["asymmetric-encryption", "secret-agreement", "signature", "rng", "key-derivation"])("supports reviewed %s registration labels without capability", async selected => {
    const fact = { ...base, kind: "WINDOWS_CNG_REGISTRATION", purpose: "PROVIDER_REGISTRATION_METADATA", provider_name: "Microsoft Primitive Provider", interface: "WINDOWS_CNG_REGISTRATION_QUERY", registration_mode: "USER", registration_interface: selected, registration_flags: 0, registered_functions: ["RSA"], identity_key: `microsoft-primitive:user:${selected}`, capture_basis: "REGISTERED_NOT_OPENED_OR_INVOKED" };
    mockFetch({ [`${P}/${id}/snapshot`]: value(fact) }); mount(); inspect();
    await screen.findByText(/registered labels: RSA · registration only; capability\/use UNKNOWN/);
  });
});

describe("Offline OCI metadata candidate", () => {
  const fact = { kind: "OCI_IMAGE_METADATA", local_basis: "OBSERVED", purpose: "PINNED_OCI_MANIFEST_CONFIG_METADATA", algorithm: "UNKNOWN", key_size: null, software_name: null, software_version: null, runtime_use: "UNKNOWN", operation_use: "UNKNOWN", policy_result: "NOT_EVALUATED", pqc_assessment: "UNKNOWN", capabilities_observed: false, interface: "OFFLINE_OCI_LAYOUT_METADATA", configuration_basis: "DECLARED", capture_basis: "MANIFEST_CONFIG_BYTES_NOT_LAYERS_OR_RUNTIME", layout_sha256: "1".repeat(64), index_sha256: "2".repeat(64), manifest_sha256: "3".repeat(64), manifest_size: 400, config_sha256: "4".repeat(64), config_size: 300, image_os: "linux", image_architecture: "amd64", image_variant: null, layers: [{ digest: "sha256:" + "5".repeat(64), diff_id: "sha256:" + "6".repeat(64), size: 12345, media_type: "application/vnd.oci.image.layer.v1.tar+gzip" }], declared_ports: ["443/tcp"], declared_base_digest: null, identity_key: "oci-manifest:sha256:" + "3".repeat(64) + ":linux:amd64:unspecified", interface_sha256: "a".repeat(64), layer_contents_verified: false, filesystem_materialized: false, package_inventory_verified: false, deployment_verified: false, vendor_identity_verified: false };
  const value = (changes = {}) => ({ ...detail, snapshot: { ...detail.snapshot, receipts: [{ input_id: "image", status: "PARSED", reason: "METADATA_ONLY", facts: [{ ...fact, ...changes }] }] } });
  it("shows only image metadata and declared ports, not package or runtime verification", async () => {
    const fetcher = mockFetch({ [`${P}/${id}/snapshot`]: value() }); mount(); inspect();
    await screen.findByText(/manifest\/config only; layers, packages and runtime unverified/);
    expect(screen.getByText(/ports DECLARED: 443\/tcp/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Download CycloneDX 1.6 OCI image metadata SBOM" })).toBeTruthy();
    expect(fetcher.mock.calls).toHaveLength(1);
  });
  it.each([{ layer_contents_verified: true }, { package_inventory_verified: true }, { deployment_verified: true }, { vendor_identity_verified: true }, { algorithm: "AES" }, { image_os: "windows" }, { image_variant: "v8" }, { manifest_sha256: "0".repeat(64) }, { declared_ports: ["0/tcp"] }, { declared_ports: ["443/tcp", "443/tcp"] }, { layers: [{ ...fact.layers[0], size: -1 }] }, { layers: [{ ...fact.layers[0], digest: "md5:bad" }] }, { vendor: "Guessed supplier" }])("refuses invalid/promoted image metadata", async changes => {
    mockFetch({ [`${P}/${id}/snapshot`]: value(changes) }); mount(); inspect();
    await screen.findByText(/No verified receipt or security verdict assumed/);
    expect(screen.queryByRole("button", { name: /OCI image metadata SBOM/ })).toBeNull();
  });
  it("rejects an image export bound to another snapshot", async () => {
    mockFetch({ [`${P}/${id}/snapshot`]: value(), [`${P}/${id}/oci-image/cyclonedx-1.6`]: { bomFormat: "CycloneDX", specVersion: "1.6", metadata: { properties: [{ name: "cryptoscan:profile", value: "OCI_MANIFEST_CONFIG_METADATA_ONLY_NOT_PACKAGE_SBOM" }, { name: "cryptoscan:snapshot_sha256", value: "0".repeat(64) }] } } });
    mount(); inspect(); await screen.findByText(/ports DECLARED/);
    fireEvent.click(screen.getByRole("button", { name: /OCI image metadata SBOM/ }));
    await screen.findByText(/OCI export scope or profile unverified. No document downloaded./);
  });
});
