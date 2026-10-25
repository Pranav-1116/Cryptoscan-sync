import React, { useEffect, useRef, useState } from "react";
import { apiApproveHostScope, apiImportHostSnapshot, apiInspectHostSnapshot, apiHostCbom, apiHostOciSbom, apiHostContainerSbom, HostImportReceipt, HostSnapshotInspection } from "../lib/api";
import CollectionCoveragePanel from "./CollectionCoveragePanel";
import HostAssociationsPanel from "./HostAssociationsPanel";
import { usePrivateScopeCurrent } from "./PrivateScope";

function validReceipt(value: HostImportReceipt, approval: string) {
  return value?.approval_id === approval && value.source_basis === "IMPORTED"
    && value.host_identity_attested === false && value.whole_host_coverage_verified === false
    && value.runtime_use === "UNKNOWN" && value.pqc_assessment === "UNKNOWN" && value.policy_result === "NOT_EVALUATED"
    && /^[0-9a-f]{64}$/.test(value.snapshot_sha256 || "")
    && Number.isInteger(value.evidence_count) && value.evidence_count > 0 && value.evidence_count <= 1100;
}

type MetadataFact = HostSnapshotInspection["snapshot"]["receipts"][number]["facts"][number];
const metadataKeys = ["kind", "local_basis", "purpose", "algorithm", "key_size", "software_name", "software_version", "runtime_use", "operation_use", "policy_result", "pqc_assessment", "capabilities_observed", "interface", "identity_key", "interface_sha256", "capture_basis"];
function basicMetadata(f: MetadataFact, extra: string[]) {
  return f.local_basis === "OBSERVED" && f.algorithm === "UNKNOWN" && f.key_size === null
    && f.software_name === null && f.software_version === null && f.runtime_use === "UNKNOWN" && f.operation_use === "UNKNOWN"
    && f.policy_result === "NOT_EVALUATED" && f.pqc_assessment === "UNKNOWN" && f.capabilities_observed === false
    && /^[0-9a-f]{64}$/.test(f.interface_sha256 || "") && Object.keys(f).every(k => [...metadataKeys, ...extra].includes(k));
}
function tcpMetadata(f: MetadataFact) {
  if (!basicMetadata(f, ["address_family", "listener_count", "listeners", "process_identity_verified", "tls_observed", "asset_absence_proven"])
    || f.purpose !== "OS_TCP_LISTENER_TABLE_METADATA" || f.interface !== "WINDOWS_IP_HELPER_TCP_TABLE"
    || !["ipv4", "ipv6"].includes(f.address_family || "") || f.identity_key !== `windows-tcp-table:${f.address_family}:owner-pid-listener`
    || f.capture_basis !== "REPEATED_TABLE_NOT_PROCESS_IDENTITY_OR_TLS" || f.process_identity_verified !== false || f.tls_observed !== false || f.asset_absence_proven !== false
    || !Array.isArray(f.listeners) || f.listeners.length > 256 || f.listener_count !== f.listeners.length) return false;
  return f.listeners.every((row, i, rows) => {
    if (!row || Object.keys(row).sort().join(",") !== "address,owning_pid,port,scope_id" || typeof row.address !== "string"
      || !Number.isInteger(row.port) || row.port < 1 || row.port > 65535 || !Number.isInteger(row.owning_pid) || row.owning_pid < 0 || row.owning_pid > 0xffffffff
      || !Number.isInteger(row.scope_id) || row.scope_id < 0 || row.scope_id > 0xffffffff) return false;
    if (f.address_family === "ipv4") {
      if (row.scope_id !== 0 || !/^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(row.address) || row.address.split(".").some(n => +n > 255)) return false;
    } else {
      try { if (row.address.includes("%") || new URL(`http://[${row.address}]/`).hostname !== `[${row.address}]`) return false; } catch { return false; }
    }
    if (i === 0) return true;
    const prev = rows[i - 1];
    return prev.address < row.address || (prev.address === row.address && (prev.scope_id < row.scope_id
      || (prev.scope_id === row.scope_id && (prev.port < row.port || (prev.port === row.port && prev.owning_pid < row.owning_pid)))));
  });
}

function ociMetadata(f: MetadataFact) {
  if (!basicMetadata(f, ["layout_sha256", "index_sha256", "manifest_sha256", "manifest_size", "config_sha256", "config_size", "image_os", "image_architecture", "image_variant", "layers", "declared_ports", "declared_base_digest", "configuration_basis", "layer_contents_verified", "filesystem_materialized", "package_inventory_verified", "deployment_verified", "vendor_identity_verified"])
    || f.purpose !== "PINNED_OCI_MANIFEST_CONFIG_METADATA" || f.interface !== "OFFLINE_OCI_LAYOUT_METADATA"
    || f.capture_basis !== "MANIFEST_CONFIG_BYTES_NOT_LAYERS_OR_RUNTIME" || f.configuration_basis !== "DECLARED"
    || f.image_os !== "linux" || !["amd64", "arm64"].includes(f.image_architecture || "")
    || !(f.image_variant === null || (f.image_architecture === "arm64" && f.image_variant === "v8"))
    || f.identity_key !== `oci-manifest:sha256:${f.manifest_sha256}:linux:${f.image_architecture}:${f.image_variant || "unspecified"}`
    || ![f.layout_sha256, f.index_sha256, f.manifest_sha256, f.config_sha256].every(v => typeof v === "string" && /^[0-9a-f]{64}$/.test(v))
    || ![f.manifest_size, f.config_size].every(v => typeof v === "number" && Number.isInteger(v) && v > 0 && v <= 1048576)
    || f.layer_contents_verified !== false || f.filesystem_materialized !== false || f.package_inventory_verified !== false || f.deployment_verified !== false || f.vendor_identity_verified !== false
    || !Array.isArray(f.layers) || f.layers.length > 128 || !f.layers.every(l => l && Object.keys(l).sort().join(",") === "diff_id,digest,media_type,size"
      && /^sha256:[0-9a-f]{64}$/.test(l.digest) && /^sha256:[0-9a-f]{64}$/.test(l.diff_id) && Number.isSafeInteger(l.size) && l.size >= 0
      && ["application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.v1.tar+gzip", "application/vnd.oci.image.layer.v1.tar+zstd"].includes(l.media_type))
    || !Array.isArray(f.declared_ports) || f.declared_ports.length > 64 || !f.declared_ports.every((p, i, all) => typeof p === "string" && /^[1-9][0-9]{0,4}\/(tcp|udp)$/.test(p) && +p.split("/")[0] <= 65535 && (i === 0 || all[i - 1] < p))
    || !(f.declared_base_digest === null || typeof f.declared_base_digest === "string" && /^sha256:[0-9a-f]{64}$/.test(f.declared_base_digest))) return false;
  return true;
}

const hash = (v: unknown) => typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
function contentMetadata(f: MetadataFact) {
  if (!basicMetadata(f, ["image", "layer_contents_verified", "final_filesystem_view_verified", "filesystem_materialized", "rootfs_view_sha256", "packages", "databases", "package_inventory_verified", "complete_inventory_verified", "unsupported_package_surfaces", "deployment_verified", "vendor_identity_verified"])
    || "capture_basis" in f || f.purpose !== "VERIFIED_OCI_LAYERS_AND_PACKAGE_DATABASES" || f.interface !== "OFFLINE_OCI_VERIFIED_CONTENT"
    || !f.image || !ociMetadata(f.image) || f.identity_key !== f.image.identity_key + ":content"
    || f.layer_contents_verified !== true || f.final_filesystem_view_verified !== true || f.filesystem_materialized !== false
    || f.package_inventory_verified !== false || f.complete_inventory_verified !== false || f.deployment_verified !== false || f.vendor_identity_verified !== false
    || f.unsupported_package_surfaces !== "RPM_LANGUAGE_BINARY_AND_EXECUTABLE_CONTENT" || !hash(f.rootfs_view_sha256)
    || !Array.isArray(f.databases) || f.databases.length !== 2 || !f.databases.every((d, i) => d && Object.keys(d).sort().join(",") === "layer_index,manager,path,sha256,status"
      && d.manager === ["dpkg", "apk"][i] && d.path === ["var/lib/dpkg/status", "lib/apk/db/installed"][i]
      && (d.status === "PARSED" ? hash(d.sha256) && Number.isInteger(d.layer_index) && d.layer_index! >= 0 && d.layer_index! < f.image!.layers!.length : d.status === "NOT_PRESENT_IN_VERIFIED_VIEW" && d.sha256 === null && d.layer_index === null))
    || !Array.isArray(f.packages) || f.packages.length > 500 || !f.packages.every((p, i, all) => {
      if (!p || Object.keys(p).sort().join(",") !== "basis,layer_index,manager,name,source_path,source_sha256,version" || !["dpkg", "apk"].includes(p.manager)
        || typeof p.name !== "string" || !/^[^\x00-\x1f\x7f]{1,120}$/.test(p.name) || !(p.version === null || typeof p.version === "string" && /^[^\x00-\x1f\x7f]{0,100}$/.test(p.version))
        || p.basis !== "VERIFIED_IMAGE_PACKAGE_DATABASE_RECORD_NOT_EXECUTABLE_OR_USE") return false;
      const d = f.databases!.find(d => d.manager === p.manager);
      return d?.status === "PARSED" && p.source_path === d.path && p.source_sha256 === d.sha256 && p.layer_index === d.layer_index
        && (i === 0 || all[i - 1].manager < p.manager || all[i - 1].manager === p.manager && all[i - 1].name < p.name);
    })) return false;
  return true;
}
function containerRuntime(f: MetadataFact) {
  const p = f.process;
  const processKeys = ["kind", "local_basis", "purpose", "algorithm", "key_size", "software_name", "software_version", "runtime_use", "policy_result", "pqc_assessment", "interface", "interface_sha256", "identity_key", "pid", "process_start_ticks", "boot_id", "process_name", "service_name", "capabilities_observed", "operation_use"];
  const nullKeys = ["library_path", "mapped_file_deleted", "mapping_basis", "service_state", "network_namespace", "address", "port", "transport", "socket_inode", "hardware_type", "cpu_index", "core_id", "package_id", "manufacturer", "model", "firmware_version", "tpm_major_version"];
  return basicMetadata(f, ["runtime", "container_id", "image_manifest_sha256", "image_binding_basis", "runtime_image_verified", "process_observed", "process", "source_sha256", "cgroup_sha256", "deployment_verified", "vendor_identity_verified"])
    && !("capture_basis" in f) && f.purpose === "EXACT_PROCESS_CONTAINER_CGROUP_MEMBERSHIP" && f.interface === "LINUX_PROCFS_CONTAINER_MEMBERSHIP"
    && ["docker", "containerd"].includes(f.runtime || "") && hash(f.container_id) && hash(f.image_manifest_sha256) && hash(f.source_sha256) && hash(f.cgroup_sha256)
    && f.image_binding_basis === "OPERATOR_DECLARED_NOT_RUNTIME_VERIFIED" && f.runtime_image_verified === false && f.process_observed === true && f.deployment_verified === false && f.vendor_identity_verified === false
    && !!p && Object.keys(p).every(k => processKeys.includes(k) || nullKeys.includes(k) && (p as unknown as Record<string, unknown>)[k] === null)
    && p.kind === "PROCESS" && p.purpose === "HOST_RUNTIME_METADATA" && p.local_basis === "OBSERVED" && p.interface === "LINUX_PROCFS" && p.interface_sha256 === null
    && p.algorithm === "UNKNOWN" && p.key_size === null && p.software_name === null && p.software_version === null && p.runtime_use === "UNKNOWN" && p.operation_use === "UNKNOWN" && p.policy_result === "NOT_EVALUATED" && p.pqc_assessment === "UNKNOWN" && p.capabilities_observed === false
    && Number.isSafeInteger(p.pid) && p.pid! > 0 && Number.isSafeInteger(p.process_start_ticks) && p.process_start_ticks! > 0
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(p.boot_id || "")
    && typeof p.process_name === "string" && /^[^\x00-\x1f\x7f]{0,120}$/.test(p.process_name)
    && (p.service_name === null || typeof p.service_name === "string" && /^[A-Za-z0-9_.@:-]{1,120}$/.test(p.service_name))
    && p.identity_key === `${p.boot_id}:${p.pid}:${p.process_start_ticks}` && f.identity_key === `container:${f.runtime}:${f.container_id}:${p.identity_key}`;
}

/** Existing CBOM console workflow. No auto-collection/upload/replay or sample data. */
export default function HostEvidencePanel() {
  const current = usePrivateScopeCurrent(), generation = useRef(0), alive = useRef(true);
  const [system, setSystem] = useState(""), [approval, setApproval] = useState("");
  const [manifest, setManifest] = useState<unknown>(null), [snapshot, setSnapshot] = useState<unknown>(null);
  const [receipt, setReceipt] = useState<HostImportReceipt | null>(null), [detail, setDetail] = useState<HostSnapshotInspection | null>(null);
  const [busy, setBusy] = useState(false), [message, setMessage] = useState("");
  useEffect(() => { alive.current = true; return () => { alive.current = false; generation.current++; }; }, []);
  const valid = (token: number) => alive.current && current() && generation.current === token;
  function resetProof() { generation.current++; setReceipt(null); setDetail(null); setMessage(""); }
  function validDetail(value: HostSnapshotInspection): boolean {
    const snap = value.snapshot;
    if (!snap || typeof snap.manifest?.host_id !== "string" || typeof snap.manifest.environment !== "string" || typeof snap.finished_at !== "string"
      || !Array.isArray(snap.receipts) || snap.receipts.length < 1 || snap.receipts.length > 100) return false;
    let facts = 0;
    return snap.receipts.every(r => {
      if (!r || typeof r.input_id !== "string" || typeof r.reason !== "string" || !["PARSED", "DENIED", "UNSUPPORTED", "INVALID", "BUDGET_EXCEEDED", "UNAVAILABLE"].includes(r.status) || !Array.isArray(r.facts)) return false;
      facts += r.facts.length;
      return facts <= 1000 && (r.status === "PARSED" ? r.facts.length > 0 : r.facts.length === 0)
        && r.facts.every(f => f && ["CERTIFICATE", "TLS_CONFIGURATION", "SOFTWARE", "BINARY", "OS_RELEASE", "PROCESS", "LOADED_LIBRARY", "LISTENER", "SERVICE", "HARDWARE", "WINDOWS_PROCESS_IMAGE", "WINDOWS_MODULE", "WINDOWS_CNG_REGISTRATION", "WINDOWS_TPM_METADATA", "WINDOWS_CAPI_DEFAULT_PROVIDER", "WINDOWS_TCP_LISTENER_TABLE", "OCI_IMAGE_METADATA", "OCI_IMAGE_CONTENT", "OCI_RUNTIME_PROCESS"].includes(f.kind) && typeof f.algorithm === "string"
          && ["OBSERVED", "DECLARED"].includes(f.local_basis) && f.runtime_use === "UNKNOWN"
          && (f.kind !== "OS_RELEASE" || (f.local_basis === "DECLARED" && f.algorithm === "UNKNOWN" && f.key_size === null))
          && (!["PROCESS", "LOADED_LIBRARY", "LISTENER", "SERVICE", "HARDWARE"].includes(f.kind)
            || (f.local_basis === "OBSERVED" && f.algorithm === "UNKNOWN" && f.key_size === null
              && f.purpose === "HOST_RUNTIME_METADATA" && f.operation_use === "UNKNOWN" && f.capabilities_observed === false
              && typeof f.identity_key === "string" && /^[0-9a-f]{64}$/.test(f.interface_sha256 || "")))
          && (!["WINDOWS_PROCESS_IMAGE", "WINDOWS_MODULE"].includes(f.kind)
            || (f.local_basis === "OBSERVED" && f.algorithm === "UNKNOWN" && f.key_size === null
              && f.software_name === null && f.software_version === null
              && f.purpose === "WINDOWS_IMAGE_METADATA" && f.interface === "WINDOWS_PROCESS_TOOLHELP"
              && f.operation_use === "UNKNOWN" && f.capabilities_observed === false
              && typeof f.pid === "number" && Number.isInteger(f.pid) && f.pid > 0 && f.pid <= 4294967295
              && typeof f.creation_filetime === "string" && /^[1-9][0-9]{0,19}$/.test(f.creation_filetime)
              && BigInt(f.creation_filetime) <= 18446744073709551615n
              && typeof f.image_path === "string" && typeof f.identity_key === "string"
              && f.capture_basis === "REPEATED_MATCHING_METADATA_NOT_INVOCATION"
              && /^[0-9a-f]{64}$/.test(f.interface_sha256 || "")))
          && (f.kind !== "WINDOWS_CNG_REGISTRATION"
            || (f.local_basis === "OBSERVED" && f.algorithm === "UNKNOWN" && f.key_size === null
              && f.software_name === null && f.software_version === null && f.operation_use === "UNKNOWN"
              && f.capabilities_observed === false && f.purpose === "PROVIDER_REGISTRATION_METADATA"
              && f.interface === "WINDOWS_CNG_REGISTRATION_QUERY" && f.provider_name === "Microsoft Primitive Provider"
              && f.registration_mode === "USER" && ["cipher", "hash", "asymmetric-encryption", "secret-agreement", "signature", "rng", "key-derivation"].includes(f.registration_interface || "")
              && typeof f.registration_flags === "number" && Number.isInteger(f.registration_flags)
              && f.registration_flags >= 0 && f.registration_flags <= 4294967295
              && f.identity_key === `microsoft-primitive:user:${f.registration_interface}`
              && f.capture_basis === "REGISTERED_NOT_OPENED_OR_INVOKED"
              && /^[0-9a-f]{64}$/.test(f.interface_sha256 || "")
              && Array.isArray(f.registered_functions) && f.registered_functions.length > 0 && f.registered_functions.length <= 64
              && f.registered_functions.every((n, i, all) => typeof n === "string" && /^[A-Za-z0-9][A-Za-z0-9_.+\-]{0,63}$/.test(n)
                && (i === 0 || all[i - 1] < n))
              && new Set(f.registered_functions.map(n => n.toLowerCase())).size === f.registered_functions.length))
          && (f.kind !== "OCI_IMAGE_METADATA" || ociMetadata(f))
          && (f.kind !== "OCI_IMAGE_CONTENT" || contentMetadata(f))
          && (f.kind !== "OCI_RUNTIME_PROCESS" || containerRuntime(f))
          && (f.kind !== "WINDOWS_CAPI_DEFAULT_PROVIDER" || (basicMetadata(f, ["provider_context", "provider_type", "provider_name"])
            && f.purpose === "DEFAULT_PROVIDER_SELECTION_METADATA" && f.interface === "WINDOWS_CAPI_DEFAULT_PROVIDER_QUERY"
            && f.provider_context === "CURRENT_USER" && [1, 2, 3, 13, 24].includes(f.provider_type || 0)
            && typeof f.provider_name === "string" && /^[A-Za-z0-9][A-Za-z0-9 ._()+-]{0,254}$/.test(f.provider_name) && f.provider_name.trim() === f.provider_name
            && f.identity_key === `windows-capi:current-user:${f.provider_type}:default-provider` && f.capture_basis === "DEFAULT_SELECTION_NOT_OPENED_OR_INVOKED"))
          && (f.kind !== "WINDOWS_TCP_LISTENER_TABLE" || tcpMetadata(f))
          && (f.kind !== "WINDOWS_TPM_METADATA"
            || (f.local_basis === "OBSERVED" && f.algorithm === "UNKNOWN" && f.key_size === null
              && f.software_name === null && f.software_version === null && f.operation_use === "UNKNOWN"
              && f.capabilities_observed === false && f.purpose === "OS_REPORTED_TPM_METADATA"
              && f.interface === "WINDOWS_TBS_DEVICE_INFO" && f.hardware_type === "TPM"
              && f.api_structure_version === 1 && ["1.2", "2.0"].includes(f.tpm_specification || "")
              && f.identity_key === "windows-tpm:local:device-info"
              && f.policy_result === "NOT_EVALUATED" && f.pqc_assessment === "UNKNOWN"
              && Object.keys(f).every(k => ["kind", "algorithm", "key_size", "local_basis", "runtime_use", "software_name", "software_version", "purpose", "operation_use", "capabilities_observed", "identity_key", "interface", "interface_sha256", "hardware_type", "api_structure_version", "tpm_specification", "capture_basis", "policy_result", "pqc_assessment"].includes(k))
              && f.capture_basis === "OS_REPORTED_NOT_ATTESTED_OR_INVOKED"
              && /^[0-9a-f]{64}$/.test(f.interface_sha256 || "")))
          && (f.key_size === null || Number.isInteger(f.key_size)));
    });
  }
  async function read(file: File | undefined, kind: "manifest" | "snapshot") {
    if (!file || busy) return;
    const token = ++generation.current; if (!valid(token)) return;
    setBusy(true); setReceipt(null); setDetail(null); setMessage("");
    if (kind === "manifest") { setManifest(null); setApproval(""); setSnapshot(null); } else setSnapshot(null);
    try {
      if (file.size > (kind === "manifest" ? 131072 : 1500000)) throw new Error("Local JSON exceeds metadata size limit");
      const data: unknown = JSON.parse(await file.text()); if (!valid(token)) return;
      if (kind === "manifest") setManifest(data); else setSnapshot(data);
      setMessage(`${kind === "manifest" ? "Approval manifest" : "Offline snapshot"} loaded locally. Nothing uploaded yet.`);
    } catch { if (valid(token)) setMessage("Invalid or oversized JSON. No approval, import or collection performed."); }
    finally { if (valid(token)) setBusy(false); }
  }
  async function approve() {
    if (busy || !manifest || !system.trim()) return;
    const token = ++generation.current; if (!valid(token)) return;
    setBusy(true); setReceipt(null); setDetail(null); setMessage(""); setApproval("");
    const result = await apiApproveHostScope(system.trim(), manifest); if (!valid(token)) return;
    setBusy(false);
    if (result.source === "live" && result.ok && /^[0-9a-f-]{36}$/.test(result.data?.subject_id || "")) {
      setApproval(result.data!.subject_id); setMessage("Scope approved for one offline snapshot. This does not execute collection or attest host identity.");
    } else setMessage(`${result.error || "Approval unavailable"}. No collection authorized by this console. Production host adapter remains unqualified.`);
  }
  async function ingest() {
    if (busy || !snapshot || !approval.trim()) return;
    const id = approval.trim(), token = ++generation.current; if (!valid(token)) return;
    setBusy(true); setReceipt(null); setDetail(null); setMessage("");
    const result = await apiImportHostSnapshot(id, snapshot); if (!valid(token)) return;
    setBusy(false);
    if (result.source === "live" && result.ok && result.data && validReceipt(result.data, id)) {
      setReceipt(result.data); setSnapshot(null); setMessage("Metadata committed as IMPORTED. Collection failures remain unknown; no observed coverage grade was updated.");
    } else setMessage(`${result.error || "Import unavailable or receipt unverified"}. No success assumed. Inspect this approval before intentionally retrying.`);
  }
  async function inspect() {
    if (busy || !approval.trim()) return;
    const id = approval.trim(), token = ++generation.current; if (!valid(token)) return;
    setBusy(true); setReceipt(null); setDetail(null); setMessage("");
    const result = await apiInspectHostSnapshot(id); if (!valid(token)) return;
    setBusy(false);
    const value = result.data, proof = value?.integrity;
    if (result.source === "live" && result.ok && value && validReceipt(value, id)
      && proof?.result === "PASS" && proof.content_intact === true && proof.chain_intact === true
      && proof.manifest_intact === true && proof.hash_format_valid === true
      && validDetail(value)) {
      setReceipt(value); setDetail(value);
    } else setMessage(`${result.error || "Host evidence unavailable or integrity unverified"}. No verified receipt or security verdict assumed.`);
  }
  async function download(image: boolean | "content" = false) {
    if (busy || !detail) return;
    const id = approval.trim(), token = ++generation.current; if (!valid(token)) return;
    setBusy(true); setMessage("");
    const result = await (image === "content" ? apiHostContainerSbom(id) : image ? apiHostOciSbom(id) : apiHostCbom(id)); if (!valid(token)) return;
    setBusy(false);
    if (result.source !== "live" || !result.ok || result.data?.specVersion !== "1.6" || result.data?.bomFormat !== "CycloneDX") {
      setMessage(`${result.error || "Export unavailable"}. No validated document downloaded.`); return;
    }
    if (image) {
      const metadata = result.data?.metadata as { properties?: {name: string; value: string}[] } | undefined;
      if (!Array.isArray(metadata?.properties) || !metadata.properties.some(p => p?.name === "cryptoscan:profile" && p.value === (image === "content" ? "VERIFIED_OCI_LAYERS_AND_SCOPED_PACKAGE_DATABASES" : "OCI_MANIFEST_CONFIG_METADATA_ONLY_NOT_PACKAGE_SBOM"))
        || !metadata.properties.some(p => p?.name === "cryptoscan:snapshot_sha256" && p.value === detail.snapshot_sha256)) {
        setMessage("OCI export scope or profile unverified. No document downloaded."); return;
      }
    }
    const url = URL.createObjectURL(new Blob([JSON.stringify(result.data, null, 2)], { type: "application/json" }));
    const link = document.createElement("a"); link.href = url; link.download = `${image ? "oci-image" : "host"}-${id}-cyclonedx-1.6.json`; link.click(); URL.revokeObjectURL(url);
    setMessage("CycloneDX 1.6 metadata downloaded. Schema validity is not runtime evidence, complete discovery, migration compatibility or bank approval.");
  }
  return <><section aria-label="Approved offline host evidence" style={{ marginTop: 24 }}>
    <h3>Approved host collection · no Git required</h3>
    <p>Explicit files and supported package metadata only. No remote execution, privileged scan, automatic upload or unrestricted filesystem discovery. Run the offline collector as an unprivileged user after scope approval.</p>
    <p><strong>IMPORTED evidence — host identity and runtime use unverified.</strong> Windows execution and production host admission are not qualified. Library presence does not establish algorithm use; configured TLS does not establish effective TLS.</p>
    <p>Admin/CISO approve the scope; analysts import; auditors/viewers inspect without changing scans.</p>
    <label>Host system ID<input maxLength={120} value={system} disabled={busy} onChange={e => { resetProof(); setSystem(e.target.value); setManifest(null); setSnapshot(null); setApproval(""); }} /></label>
    <label>Approved host manifest JSON<input type="file" accept="application/json,.json" disabled={busy} onChange={e => { void read(e.target.files?.[0], "manifest"); e.target.value = ""; }} /></label>
    <button disabled={busy || !manifest || !system.trim()} onClick={() => void approve()}>Approve host scope</button>
    <label>Host approval ID<input maxLength={36} value={approval} disabled={busy} onChange={e => { resetProof(); setApproval(e.target.value); setSnapshot(null); }} /></label>
    <label>Offline host snapshot JSON<input type="file" accept="application/json,.json" disabled={busy} onChange={e => { void read(e.target.files?.[0], "snapshot"); e.target.value = ""; }} /></label>
    <button disabled={busy || !snapshot || !approval.trim()} onClick={() => void ingest()}>Import approved metadata</button>
    <button disabled={busy || !approval.trim()} onClick={() => void inspect()}>Inspect host evidence</button>
    {busy && <p role="status">Processing scoped host metadata…</p>}{message && <p role="status">{message}</p>}
    {receipt && <div style={{ overflowWrap: "anywhere" }}><p>Evidence status: IMPORTED · Scan {receipt.scan_id} · {receipt.evidence_count} chained records.</p>
      <p>Snapshot SHA-256: {receipt.snapshot_sha256}</p><p>Runtime use: UNKNOWN · PQC assessment: UNKNOWN · Policy: NOT_EVALUATED. Complete-host coverage is not proven.</p></div>}
    {detail && <><h4>{detail.snapshot.manifest.host_id} · {detail.snapshot.manifest.environment}</h4><p>Stored content, chain and manifest integrity checked. Claimed collection time: {detail.snapshot.finished_at}. This does not authenticate the originating host.</p>
      <table><thead><tr><th>Approved input</th><th>Receipt</th><th>Metadata / limitations</th></tr></thead><tbody>{detail.snapshot.receipts.map(r => <tr key={r.input_id}><td>{r.input_id}</td><td>{r.status} · {r.reason}</td><td>{r.facts.map((f, i) => <p key={i}>{f.kind} · {f.provider_name || f.image_path || f.process_name || f.library_path || f.service_name || (f.address ? `${f.address}:${f.port}` : null) || f.model || f.hardware_type || f.software_name || f.algorithm} · {f.software_version || f.key_size || "size/version UNKNOWN"}{f.image ? ` · verified layer bytes and virtual overlay · ${f.packages?.length} package DB records (not complete inventory); runtime image binding unverified` : ""}{f.process ? ` · ${f.runtime} ${f.container_id} · PID ${f.process.pid}; kernel cgroup membership only; image operator DECLARED` : ""}{f.manifest_sha256 ? ` · OCI manifest ${f.manifest_sha256} · ${f.image_os}/${f.image_architecture} · manifest/config only; layers, packages and runtime unverified · ports DECLARED: ${(f.declared_ports || []).join(", ") || "none declared"}` : ""}{f.provider_context ? ` · current-user default provider selection; not opened or invoked` : ""}{f.listeners ? ` · ${f.address_family}: ${f.listener_count} sampled TCP listener rows; TLS and process identity unverified` : ""}{f.tpm_specification ? ` · TPM ${f.tpm_specification} · OS reported; not attestation, firmware or key use` : ""}{f.registered_functions ? ` · ${f.registration_interface} registered labels: ${f.registered_functions.join(", ")} · registration only; capability/use UNKNOWN` : ""}{f.creation_filetime ? ` · PID ${f.pid} · creation FILETIME ${f.creation_filetime} · repeated module metadata, not invocation` : ""}{f.service_state ? ` · ${f.service_state}` : ""} · local claim {f.local_basis} · runtime UNKNOWN{f.listeners?.slice(0, 10).map((row, index) => <span key={index} style={{ display: "block" }}>{row.address}:{row.port} · scope {row.scope_id} · OS-reported owning PID {row.owning_pid} (not process identity or TLS)</span>)}{f.listeners && f.listeners.length > 10 ? <span>Showing first 10 rows; full metadata remains in the authorized snapshot.</span> : null}</p>)}</td></tr>)}</tbody></table>
      <p>System-to-host scope is operator DECLARED, not host attestation. Endpoint/HSM/KMS use and six-BOM dependencies are not established by co-existence.</p>
      <button disabled={busy} onClick={() => void download()}>Download CycloneDX 1.6 host CBOM</button>{detail.snapshot.receipts.some(r => r.facts.some(f => f.kind === "OCI_IMAGE_METADATA")) && <button disabled={busy} onClick={() => void download(true)}>Download CycloneDX 1.6 OCI image metadata SBOM</button>}{detail.snapshot.receipts.some(r => r.facts.some(f => f.kind === "OCI_IMAGE_CONTENT")) && <><button disabled={busy} onClick={() => void download("content")}>Download verified layer and package-record SBOM</button><p>Container production admission: BLOCKED. Image/runtime binding, independent qualification and a qualified executor remain required.</p></>}<HostAssociationsPanel key={detail.approval_id + detail.snapshot_sha256} detail={detail} /></>}
  </section><CollectionCoveragePanel /></>;
}
