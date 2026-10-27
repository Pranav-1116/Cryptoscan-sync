import React, { useEffect, useRef, useState } from "react";
import { apiApproveHostScope, apiImportHostSnapshot, apiInspectHostSnapshot, apiHostCbom, apiHostOciSbom, apiHostContainerSbom, apiHostTlsSessionBom, HostImportReceipt, HostSnapshotInspection } from "../lib/api";
import CollectionCoveragePanel from "./CollectionCoveragePanel";
import HostAssociationsPanel from "./HostAssociationsPanel";
import { usePrivateScopeCurrent } from "./PrivateScope";
import { Badge, Bar } from "./ui";
import { IconComponent, IconSecurity, IconCloud, IconHardware, IconCrypto, IconTarget } from "./icons";

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
function tlsSession(f: MetadataFact) {
  const extra = ["reviewed_target_sha256", "authorized_operation", "address", "port", "sni", "tls_version", "cipher_suite", "cipher_bits", "certificate", "peer_der_bytes", "wire_bytes_sent", "wire_bytes_received", "negotiated_session_observed", "peer_fingerprint_matched", "certificate_chain_validated", "hostname_validated", "revocation_checked", "all_tls_versions_tested", "application_data_sent", "application_identity_verified", "key_exchange_group", "server_signature_scheme"];
  if (!basicMetadata(f, extra) || f.purpose !== "ONE_PINNED_NEGOTIATED_TLS_SESSION" || f.interface !== "EXPLICIT_NUMERIC_TCP_TLS_MEMORY_BIO"
    || !/^[0-9a-f]{64}$/.test(f.reviewed_target_sha256 || "") || f.authorized_operation !== "OBSERVE_APPROVED_TLS_SESSION"
    || typeof f.address !== "string" || !Number.isInteger(f.port) || !f.port || f.port < 1 || f.port > 65535
    || !f.sni || f.sni.length > 253 || !f.sni.split(".").every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
    || /^(?:[0-9]+\.){3}[0-9]+$/.test(f.sni) || !["TLSv1.2", "TLSv1.3"].includes(f.tls_version || "")
    || !/^[A-Za-z0-9_-]{1,100}$/.test(f.cipher_suite || "") || !Number.isInteger(f.cipher_bits) || !f.cipher_bits || f.cipher_bits > 512
    || f.negotiated_session_observed !== true || f.peer_fingerprint_matched !== true
    || [f.certificate_chain_validated, f.hostname_validated, f.revocation_checked, f.all_tls_versions_tested, f.application_data_sent, f.application_identity_verified].some(v => v !== false)
    || f.key_exchange_group !== "UNKNOWN" || f.server_signature_scheme !== "UNKNOWN"
    || ![f.peer_der_bytes, f.wire_bytes_sent, f.wire_bytes_received].every(n => Number.isInteger(n) && typeof n === "number" && n > 0 && n <= 131072)
    || (f.peer_der_bytes || 0) > 65536) return false;
  if (f.address.includes(":")) {
    try { if (new URL(`http://[${f.address}]/`).hostname !== `[${f.address}]` || f.address === "::" || f.address.startsWith("ff") || f.address.startsWith("::ffff:") || /^fe[89ab]/.test(f.address)) return false; } catch { return false; }
  } else if (!/^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(f.address) || f.address.split(".").some(n => +n > 255) || f.address === "0.0.0.0" || f.address === "255.255.255.255" || (+f.address.split(".")[0] >= 224 && +f.address.split(".")[0] <= 239)) return false;
  const c = f.certificate;
  if (!c || Object.keys(c).sort().join(",") !== "algorithm,certificate_signature_oid,curve,fingerprint_sha256,key_size,signature_hash"
    || !/^[0-9a-f]{64}$/.test(c.fingerprint_sha256) || !["RSA", "EC", "DSA", "ED25519", "ED448", "UNKNOWN"].includes(c.algorithm)
    || !["secp256r1", "secp384r1", "secp521r1", "UNKNOWN"].includes(c.curve)
    || !["SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "UNKNOWN"].includes(c.signature_hash)
    || c.certificate_signature_oid.length > 100 || !/^(UNKNOWN|[0-9]+(?:\.[0-9]+)+)$/.test(c.certificate_signature_oid)
    || (["RSA", "EC", "DSA"].includes(c.algorithm) ? !Number.isInteger(c.key_size) || !c.key_size || c.key_size < 1 || c.key_size > 65536 : c.key_size !== null)
    || (c.algorithm !== "EC" && c.curve !== "UNKNOWN")) return false;
  const sizes: Record<string, number> = {secp256r1:256, secp384r1:384, secp521r1:521};
  const modern: Record<string, number> = {TLS_AES_128_GCM_SHA256:128, TLS_AES_256_GCM_SHA384:256, TLS_CHACHA20_POLY1305_SHA256:256};
  return (c.curve === "UNKNOWN" || sizes[c.curve] === c.key_size)
    && (f.tls_version === "TLSv1.3" ? modern[f.cipher_suite!] === f.cipher_bits : !f.cipher_suite!.startsWith("TLS_"))
    && f.identity_key === `tls-endpoint:${f.address.includes(":") ? `[${f.address}]` : f.address}:${f.port}:sni:${f.sni}`;
}

function tlsKeyShare(f: MetadataFact, requiredShareSize?: number) {
  const extra = ["selected_group_id", "group_classification", "group_classification_basis", "server_hello_hex", "server_hello_sha256", "hello_retry_request_seen", "pqc_implementation_verified", "pqc_readiness_verified", "all_groups_tested"];
  const base = Object.fromEntries(Object.entries(f).filter(([k]) => !extra.includes(k))) as MetadataFact;
  if (!tlsSession({...base, kind:"NETWORK_TLS_SESSION",purpose:"ONE_PINNED_NEGOTIATED_TLS_SESSION",key_exchange_group:"UNKNOWN"})
    || f.purpose !== "PINNED_TLS13_FINAL_SERVER_HELLO" || f.tls_version !== "TLSv1.3"
    || f.capture_basis !== "FINAL_SERVER_HELLO_SAME_PINNED_COMPLETED_HANDSHAKE"
    || f.group_classification_basis !== "PINNED_REGISTRY_MAPPING_NOT_IMPLEMENTATION_PROOF"
    || f.pqc_implementation_verified !== false || f.pqc_readiness_verified !== false || f.all_groups_tested !== false
    || typeof f.hello_retry_request_seen !== "boolean" || !/^[0-9a-f]{64}$/.test(f.server_hello_sha256 || "")
    || !f.server_hello_hex || f.server_hello_hex.length < 88 || f.server_hello_hex.length > 8192 || !/^(?:[0-9a-f]{2})+$/.test(f.server_hello_hex)) return false;
  const b = Uint8Array.from(f.server_hello_hex.match(/../g)!, n => parseInt(n,16));
  const u16 = (i: number) => (b[i] << 8) | b[i+1];
  if (b[0] !== 2 || ((b[1]<<16)|(b[2]<<8)|b[3]) !== b.length-4 || u16(4) !== 0x0303
    || f.server_hello_hex.slice(12,76) === "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c" || b[38]>32) return false;
  let pos = 39+b[38];
  const suites: Record<number,string> = {4865:"TLS_AES_128_GCM_SHA256",4866:"TLS_AES_256_GCM_SHA384",4867:"TLS_CHACHA20_POLY1305_SHA256"};
  if (pos+5>b.length || suites[u16(pos)] !== f.cipher_suite || b[pos+2] !== 0 || pos+5+u16(pos+3)!==b.length) return false;
  pos+=5; const seen = new Set<number>(); let version=false, group: number | undefined;
  while(pos<b.length) {
    if(pos+4>b.length) return false;
    const type=u16(pos), n=u16(pos+2);pos+=4;
    if(seen.has(type) || pos+n>b.length || ![43,51].includes(type)) return false;
    seen.add(type);
    if(type===43) {if(n!==2 || u16(pos)!==0x0304)return false;version=true;}
    if(type===51) {if(n<5 || u16(pos+2)!==n-4 || requiredShareSize !== undefined && requiredShareSize !== n-4)return false;group=u16(pos);const lengths: Record<number,number>={23:65,24:97,25:133,29:32,30:56,256:256,257:384,258:512,259:768,260:1024};if(lengths[group] && lengths[group]!==n-4)return false;}
    pos+=n;
  }
  const names: Record<number,string> = {23:"secp256r1",24:"secp384r1",25:"secp521r1",29:"X25519",30:"X448",256:"ffdhe2048",257:"ffdhe3072",258:"ffdhe4096",259:"ffdhe6144",260:"ffdhe8192",4587:"SecP256r1MLKEM768",4588:"X25519MLKEM768",4589:"SecP384r1MLKEM1024"};
  const classification = group !== undefined && [4587,4588,4589].includes(group) ? "REGISTERED_HYBRID_GROUP_SELECTED" : group !== undefined && names[group] ? "REGISTERED_CLASSICAL_GROUP_SELECTED" : "UNRECOGNIZED_GROUP";
  return version && group !== undefined && group === f.selected_group_id && f.key_exchange_group === (names[group] || "UNKNOWN") && f.group_classification === classification;
}

function tlsHybrid(f: MetadataFact) {
  const fields=["hybrid_session_completed","tls_provider","openssl_version","pyopenssl_version","cryptography_version","provider_identity_basis"];
  const base=Object.fromEntries(Object.entries(f).filter(([k])=>!fields.includes(k))) as MetadataFact;
  const version=/^OpenSSL ([0-9]+)\.([0-9]+)\.[0-9]+ [A-Za-z0-9 .-]+$/.exec(f.openssl_version || "");
  return tlsKeyShare({...base,kind:"NETWORK_TLS13_KEY_SHARE",purpose:"PINNED_TLS13_FINAL_SERVER_HELLO"},1120)
    && f.purpose === "PINNED_COMPLETED_X25519_MLKEM768_SESSION" && f.hybrid_session_completed === true
    && f.tls_provider === "PYOPENSSL_CRYPTOGRAPHY_OPENSSL" && !!version && (+version[1]>3 || +version[1]===3 && +version[2]>=5)
    && /^[0-9]+\.[0-9]+\.[0-9]+$/.test(f.pyopenssl_version || "") && /^[0-9]+\.[0-9]+\.[0-9]+$/.test(f.cryptography_version || "")
    && f.provider_identity_basis === "SELF_REPORTED_LIBRARY_VERSION_NOT_MEASURED_EXECUTION"
    && f.selected_group_id === 4588 && f.key_exchange_group === "X25519MLKEM768" && f.group_classification === "REGISTERED_HYBRID_GROUP_SELECTED";
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
        && r.facts.every(f => f && ["CERTIFICATE", "TLS_CONFIGURATION", "SOFTWARE", "BINARY", "OS_RELEASE", "PROCESS", "LOADED_LIBRARY", "LISTENER", "SERVICE", "HARDWARE", "WINDOWS_PROCESS_IMAGE", "WINDOWS_MODULE", "WINDOWS_CNG_REGISTRATION", "WINDOWS_TPM_METADATA", "WINDOWS_CAPI_DEFAULT_PROVIDER", "WINDOWS_TCP_LISTENER_TABLE", "OCI_IMAGE_METADATA", "OCI_IMAGE_CONTENT", "OCI_RUNTIME_PROCESS", "NETWORK_TLS_SESSION", "NETWORK_TLS13_KEY_SHARE", "NETWORK_TLS13_HYBRID"].includes(f.kind) && typeof f.algorithm === "string"
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
          && (f.kind !== "NETWORK_TLS_SESSION" || tlsSession(f))
          && (f.kind !== "NETWORK_TLS13_KEY_SHARE" || tlsKeyShare(f))
          && (f.kind !== "NETWORK_TLS13_HYBRID" || tlsHybrid(f))
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
  async function download(image: boolean | "content" | "tls" = false) {
    if (busy || !detail) return;
    const id = approval.trim(), token = ++generation.current; if (!valid(token)) return;
    setBusy(true); setMessage("");
    const result = await (image === "tls" ? apiHostTlsSessionBom(id) : image === "content" ? apiHostContainerSbom(id) : image ? apiHostOciSbom(id) : apiHostCbom(id)); if (!valid(token)) return;
    setBusy(false);
    if (result.source !== "live" || !result.ok || result.data?.specVersion !== "1.6" || result.data?.bomFormat !== "CycloneDX") {
      setMessage(`${result.error || "Export unavailable"}. No validated document downloaded.`); return;
    }
    if (image) {
      const metadata = result.data?.metadata as { properties?: {name: string; value: string}[] } | undefined;
      if (!Array.isArray(metadata?.properties) || !metadata.properties.some(p => p?.name === "cryptoscan:profile" && p.value === (image === "tls" ? "PINNED_SINGLE_TLS_SESSION_NOT_CAPABILITY_SCAN" : image === "content" ? "VERIFIED_OCI_LAYERS_AND_SCOPED_PACKAGE_DATABASES" : "OCI_MANIFEST_CONFIG_METADATA_ONLY_NOT_PACKAGE_SBOM"))
        || !metadata.properties.some(p => p?.name === "cryptoscan:snapshot_sha256" && p.value === detail.snapshot_sha256)) {
        setMessage(`${image === "tls" ? "TLS session" : "OCI"} export scope or profile unverified. No document downloaded.`); return;
      }
    }
    const url = URL.createObjectURL(new Blob([JSON.stringify(result.data, null, 2)], { type: "application/json" }));
    const link = document.createElement("a"); link.href = url; link.download = `${image === "tls" ? "tls-session" : image ? "oci-image" : "host"}-${id}-cyclonedx-1.6.json`; link.click(); URL.revokeObjectURL(url);
    setMessage("CycloneDX 1.6 metadata downloaded. Schema validity is not runtime evidence, complete discovery, migration compatibility or bank approval.");
  }
  return <><section className="panel" aria-label="Approved offline host evidence" style={{ marginTop: 16, padding: 16, borderTop: "2px solid var(--accent)" }}>
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10, flexWrap: "wrap", marginBottom: 10 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <span style={{ width: 32, height: 32, borderRadius: 8, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--accent) 14%, transparent)", border: "1px solid var(--accent)" }}><IconHardware size={14} style={{ color: "var(--accent)" }} /></span>
        <div>
          <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700 }}>Host Evidence — Offline Collector</h3>
          <div style={{ fontSize: 11, color: "var(--dim)" }}>Approved scope · offline files only · no Git · unprivileged run</div>
        </div>
        <Badge tone="cyan">OFFLINE</Badge><Badge tone="slate">NO EXEC</Badge>
      </div>
      <span style={{ fontSize: 11, color: "var(--dim)" }}>Admin → Analyst → Auditor — no privilege, no auto-upload</span>
    </div>
    <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 10 }}>
      {[
        ["Explicit files only", "var(--line-strong)"],
        ["No remote execution", "var(--accent)"],
        ["No privileged scan", "var(--line-strong)"],
        ["No filesystem discovery", "var(--line-strong)"],
      ].map(([t,c]) => <span key={t} style={{ fontSize: 10, padding: "4px 8px", borderRadius: "var(--r)", border: `1px solid ${c}`, background: "var(--bg-2)", color: "var(--dim)" }}>{t}</span>)}
    </div>
    <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 10, padding: "8px 10px", background: "color-mix(in srgb, var(--amber) 10%, transparent)", border: "1px solid color-mix(in srgb, var(--amber) 30%, var(--line))", borderRadius: "var(--r)" }}>
      <Badge tone="amber">IMPORTED</Badge>
      <span style={{ fontSize: 11, color: "var(--dim)" }}>Host identity <strong style={{ color: "var(--amber)" }}>UNVERIFIED</strong> · runtime <strong>UNKNOWN</strong> · library ≠ use · configured TLS ≠ effective TLS</span>
    </div>
    <div style={{ display: "grid", gridTemplateColumns: "repeat(3, minmax(0,1fr))", gap: 8, marginBottom: 12 }}>
      {[
        ["1 · Approve", "Admin/CISO · manifest → approval ID", "var(--accent)"],
        ["2 · Import", "Analyst · snapshot → IMPORTED", "var(--cyan)"],
        ["3 · Inspect", "Auditor · verify → no scan change", "var(--green)"],
      ].map(([title, sub, col]) => (
        <div key={title} style={{ padding: "8px 10px", background: "var(--bg-2)", border: "1px solid var(--line)", borderTop: `2px solid ${col}`, borderRadius: "var(--r)" }}>
          <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: .06, color: col }}>{title}</div>
          <div style={{ fontSize: 11, color: "var(--dim)", marginTop: 2 }}>{sub}</div>
        </div>
      ))}
    </div>
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 10, alignItems: "end" }}>
      <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 11, color: "var(--dim)" }}>Host system ID<input style={{ padding: "7px 10px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg-2)", color: "var(--text)", fontSize: 12.5 }} maxLength={120} value={system} disabled={busy} onChange={e => { resetProof(); setSystem(e.target.value); setManifest(null); setSnapshot(null); setApproval(""); }} /></label>
      <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 11, color: "var(--dim)" }}>Approved host manifest JSON<input type="file" accept="application/json,.json" disabled={busy} onChange={e => { void read(e.target.files?.[0], "manifest"); e.target.value = ""; }} /></label>
      <button className="btn primary sm" disabled={busy || !manifest || !system.trim()} onClick={() => void approve()} style={{ height: 32 }}>Approve host scope</button>
    </div>
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 10, alignItems: "end", marginTop: 10 }}>
      <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 11, color: "var(--dim)" }}>Host approval ID<input style={{ padding: "7px 10px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg-2)", color: "var(--text)", fontSize: 12.5, fontFamily: "var(--mono)" }} maxLength={36} value={approval} disabled={busy} onChange={e => { resetProof(); setApproval(e.target.value); setSnapshot(null); }} /></label>
      <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 11, color: "var(--dim)" }}>Offline host snapshot JSON<input type="file" accept="application/json,.json" disabled={busy} onChange={e => { void read(e.target.files?.[0], "snapshot"); e.target.value = ""; }} /></label>
      <div style={{ display: "flex", gap: 8 }}>
        <button className="btn sm" disabled={busy || !snapshot || !approval.trim()} onClick={() => void ingest()}>Import approved metadata</button>
        <button className="btn outline sm" disabled={busy || !approval.trim()} onClick={() => void inspect()}>Inspect host evidence</button>
      </div>
    </div>
    {busy && <div style={{ marginTop: 10, padding: "8px 10px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", fontSize: 12, display: "flex", alignItems: "center", gap: 8 }}><span style={{ width: 8, height: 8, borderRadius: 99, background: "var(--accent)", display: "inline-block" }} />Processing scoped host metadata…</div>}{message && <div role="status" style={{ marginTop: 10, padding: "8px 10px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", fontSize: 12, color: "var(--dim)" }}>{message}</div>}
    {receipt && <div style={{ marginTop: 12, padding: "12px 14px", background: "var(--panel-2)", border: "1px solid var(--line)", borderLeft: "3px solid var(--green)", borderRadius: "var(--r)", overflowWrap: "anywhere" }}><div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", marginBottom: 6 }}><Badge tone="green">IMPORTED</Badge><Badge tone="cyan">Scan {receipt.scan_id.slice(0,8)}…</Badge><Badge tone="slate">{receipt.evidence_count} records</Badge></div><div style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--dim)" }}>SHA-256 {receipt.snapshot_sha256.slice(0,24)}… · runtime UNKNOWN · PQC UNKNOWN · NOT_EVALUATED</div><Bar value={Math.min(1, receipt.evidence_count/100)} tone="green" /></div>}
    {detail && <>
      <div style={{ marginTop: 12, padding: "10px 12px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 8 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}><IconComponent size={14} style={{ color: "var(--accent)" }} /><span style={{ fontWeight: 700, fontSize: 12 }}>{detail.snapshot.manifest.host_id}</span><Badge tone="slate">{detail.snapshot.manifest.environment}</Badge><Badge tone="green">CHAIN PASS</Badge></div>
        <span style={{ fontSize: 11, color: "var(--dim)", fontFamily: "var(--mono)" }}>{detail.snapshot.finished_at} · not host attestation</span>
      </div>
      <table><thead><tr><th>Approved input</th><th>Receipt</th><th>Metadata / limitations</th></tr></thead><tbody>{detail.snapshot.receipts.map(r => <tr key={r.input_id}><td>{r.input_id}</td><td>{r.status} · {r.reason}</td><td>{r.facts.map((f, i) => <p key={i}>{f.kind} · {f.provider_name || f.image_path || f.process_name || f.library_path || f.service_name || (f.address ? `${f.address}:${f.port}` : null) || f.model || f.hardware_type || f.software_name || f.algorithm} · {f.software_version || f.key_size || "size/version UNKNOWN"}{f.kind === "NETWORK_TLS13_HYBRID" ? ` · completed hybrid TLS X25519MLKEM768 session; ${f.openssl_version}; provider version self-reported; not HSM/application or PQC readiness proof` : ""}{f.kind === "NETWORK_TLS13_KEY_SHARE" ? ` · final TLS 1.3 ServerHello selected group ${f.key_exchange_group} (#${f.selected_group_id}); registry classification ${f.group_classification}; PQC readiness, application/HSM use UNKNOWN; CA/hostname/revocation not validated; other groups/versions not tested` : ""}{f.kind === "NETWORK_TLS_SESSION" ? ` · one pinned ${f.tls_version} session · ${f.cipher_suite} · SNI ${f.sni}; certificate public key ${f.certificate?.algorithm} ${f.certificate?.key_size || "size UNKNOWN"}; CA/hostname/revocation not validated; key-exchange group and application linkage UNKNOWN; other TLS versions not tested` : ""}{f.image ? ` · verified layer bytes and virtual overlay · ${f.packages?.length} package DB records (not complete inventory); runtime image binding unverified` : ""}{f.process ? ` · ${f.runtime} ${f.container_id} · PID ${f.process.pid}; kernel cgroup membership only; image operator DECLARED` : ""}{f.manifest_sha256 ? ` · OCI manifest ${f.manifest_sha256} · ${f.image_os}/${f.image_architecture} · manifest/config only; layers, packages and runtime unverified · ports DECLARED: ${(f.declared_ports || []).join(", ") || "none declared"}` : ""}{f.provider_context ? ` · current-user default provider selection; not opened or invoked` : ""}{f.listeners ? ` · ${f.address_family}: ${f.listener_count} sampled TCP listener rows; TLS and process identity unverified` : ""}{f.tpm_specification ? ` · TPM ${f.tpm_specification} · OS reported; not attestation, firmware or key use` : ""}{f.registered_functions ? ` · ${f.registration_interface} registered labels: ${f.registered_functions.join(", ")} · registration only; capability/use UNKNOWN` : ""}{f.creation_filetime ? ` · PID ${f.pid} · creation FILETIME ${f.creation_filetime} · repeated module metadata, not invocation` : ""}{f.service_state ? ` · ${f.service_state}` : ""} · local claim {f.local_basis} · runtime UNKNOWN{f.listeners?.slice(0, 10).map((row, index) => <span key={index} style={{ display: "block" }}>{row.address}:{row.port} · scope {row.scope_id} · OS-reported owning PID {row.owning_pid} (not process identity or TLS)</span>)}{f.listeners && f.listeners.length > 10 ? <span>Showing first 10 rows; full metadata remains in the authorized snapshot.</span> : null}</p>)}</td></tr>)}</tbody></table>
      <div style={{ marginTop: 8, fontSize: 11, color: "var(--faint)", padding: "8px 10px", border: "1px dashed var(--line)", borderRadius: "var(--r)", background: "var(--bg-2)" }}>Operator DECLARED scope — not host attestation · Endpoint/HSM/KMS & 6-BOM dependencies not established by co-existence</div>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 10 }}>
        <button className="btn primary sm" disabled={busy} onClick={() => void download()}><IconCloud size={12} /> Download CycloneDX 1.6 host CBOM</button>
        {detail.snapshot.receipts.some(r => r.facts.some(f => f.kind === "OCI_IMAGE_METADATA")) && <button className="btn sm" disabled={busy} onClick={() => void download(true)}>Download CycloneDX 1.6 OCI image metadata SBOM</button>}
        {detail.snapshot.receipts.some(r => r.facts.some(f => f.kind === "OCI_IMAGE_CONTENT")) && <>
          <button className="btn sm" disabled={busy} onClick={() => void download("content")}>Download verified layer and package-record SBOM</button>
          <div style={{ fontSize: 11, color: "var(--amber)", padding: "6px 8px", border: "1px solid var(--amber)", borderRadius: "var(--r)" }}>Container admission BLOCKED — binding + qualification required</div>
        </>}
        {detail.snapshot.receipts.some(r => r.facts.some(f => ["NETWORK_TLS_SESSION", "NETWORK_TLS13_KEY_SHARE", "NETWORK_TLS13_HYBRID"].includes(f.kind))) && <>
          <button className="btn sm" disabled={busy} onClick={() => void download("tls")}>Download CycloneDX 1.6 observed TLS session</button>
          <div style={{ fontSize: 11, color: "var(--amber)", padding: "6px 8px", border: "1px solid var(--amber)", borderRadius: "var(--r)", background: "color-mix(in srgb, var(--amber) 10%, transparent)" }}>Active TLS: operator-run only · production BLOCKED</div>
        </>}
      </div>
      <HostAssociationsPanel key={detail.approval_id + detail.snapshot_sha256} detail={detail} />
    </>}
  </section><CollectionCoveragePanel /></>;
}
