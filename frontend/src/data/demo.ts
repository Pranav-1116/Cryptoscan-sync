/* Deterministic demo dataset for the ZELNX console — mirrors the real API
   contracts. Accuracy numbers are the REAL benchmark results (9 datasets /
   88 cases at F1 1.0) — never fabricated. Everything else is a stable,
   reproducible demo estate at enterprise scale. */

import type {
  AlgorithmInfo, CertificateInfo, TrustFinding, LibraryInfo, ProtocolInfo,
  HardwareDevice, FirmwareRow, CloudResource, NetworkAsset, VendorInfo,
  EventItem, AccuracyRow, AssetRow, BomComponent, BomDependency,
  ComplianceRow, TimelineRow, AlertItem, ScannerRow, KanbanCard, EvidenceLink,
  SearchGroup, Severity, RegionUnit, NotificationType, CryptoChangeItem,
  AgentRow, CostEstimate,
} from "../types.js";

/* ── global state (command center) ─────────────────────────────────── */
export const globalState = {
  totalAssets: 125482,
  cryptoAssets: 42391,
  risks: 1248,
  criticalFindings: 42,
  highFindings: 184,
  pqcReadyPct: 31,
  hybridReadyPct: 22,
  migrationRequiredPct: 47,
  migrationProgressPct: 31,
  pqcExposurePct: 47,
  activeScanners: 5,
  totalScanners: 5,
  eventsPerSec: 142,
  agentsHealthy: 284,
  agentsTotal: 286,
  scannerHealthPct: 99.8,
  evidenceHealthPct: 99.8,
  cbomVersion: 1843,
  hbomVersion: 512,
  liveChanges24h: 3124,
  agilityScore: 78,
  lastEventSeconds: 2,
};

/* ── discovery ─────────────────────────────────────────────────────── */
export const networkAssets: NetworkAsset[] = [
  { kind: "load_balancer", id: "lb-pay-01", ip: "10.0.0.10", tls: "TLS 1.3", certs: ["payments.internal"], os: "ALB (AWS)", status: "ACTIVE" },
  { kind: "load_balancer", id: "lb-api-02", ip: "10.0.1.12", tls: "TLS 1.3", certs: ["api.payments.internal"], os: "NGINX 1.27", status: "ACTIVE" },
  { kind: "router", id: "rtr-core-1", ip: "10.0.0.1", tls: "SSH-2", certs: [], os: "IOS-XE 17.9", status: "ACTIVE" },
  { kind: "firewall", id: "fw-edge-01", ip: "10.0.0.1", tls: "TLS 1.3", certs: [], os: "PAN-OS 11.1", status: "ACTIVE" },
  { kind: "vpn_gateway", id: "vpn-01", ip: "10.0.0.2", tls: "IPsec IKEv2", certs: ["payments.internal"], os: "strongSwan 5.9", status: "ACTIVE" },
  { kind: "switch", id: "sw-dc-01", ip: "10.0.2.5", tls: "SSH-2", certs: [], os: "NX-OS 10.2", status: "ACTIVE" },
  { kind: "switch", id: "sw-dc-03", ip: "10.0.2.7", tls: "SSH-2", certs: [], os: "NX-OS 10.2", status: "NEW" },
  { kind: "proxy", id: "proxy-01", ip: "10.0.3.9", tls: "TLS 1.3", certs: ["gw.vpn.internal"], os: "NGINX 1.27", status: "ACTIVE" },
  { kind: "database", id: "db-pay-01", ip: "10.0.4.3", tls: "TLS 1.2", certs: ["db.internal"], os: "Postgres 16", status: "ACTIVE" },
  { kind: "endpoint", id: "app-pay-01", ip: "10.0.5.21", tls: "mTLS 1.3", certs: ["payments.internal"], os: "Ubuntu 24.04", status: "ACTIVE" },
];

export const cloudResources: CloudResource[] = [
  { provider: "AWS", service: "ELB", name: "aws-elb-pay", certs: ["payments.internal"], kms: "aws/kms", status: "HEALTHY" },
  { provider: "AWS", service: "ACM", name: "cert-payments", certs: ["payments.internal"], kms: "managed", status: "HEALTHY" },
  { provider: "AWS", service: "KMS", name: "pay-kms", certs: [], kms: "aws/kms", status: "HEALTHY" },
  { provider: "AWS", service: "EKS", name: "pay-eks", certs: ["api.payments.internal"], kms: "aws/kms", status: "HEALTHY" },
  { provider: "Azure", service: "Key Vault", name: "kv-payments", certs: ["api.payments.internal"], kms: "azure/kv", status: "HEALTHY" },
  { provider: "Azure", service: "Application Gateway", name: "agw-pay", certs: ["api.payments.internal"], kms: "azure/kv", status: "HEALTHY" },
  { provider: "GCP", service: "Cloud KMS", name: "pay-gkms", certs: [], kms: "gcp/kms", status: "HEALTHY" },
  { provider: "GCP", service: "GKE", name: "pay-gke", certs: ["gw.vpn.internal"], kms: "gcp/kms", status: "HEALTHY" },
];

export const vendors: VendorInfo[] = [
  { name: "Cisco", products: 3, pqc: "ML-KEM / ML-DSA roadmap", risk: "LOW", score: 12, devices: 184, firmware: 13, configs: 4, findings: 8 },
  { name: "Acme Secure", products: 3, pqc: "ML-KEM / ML-DSA roadmap", risk: "LOW", score: 12, devices: 22, firmware: 5, configs: 3, findings: 1 },
  { name: "BankVault HSM", products: 1, pqc: "no PQC firmware yet", risk: "HIGH", score: 68, devices: 9, firmware: 2, configs: 2, findings: 12 },
  { name: "OpenSSL (community)", products: 1, pqc: "FIPS 203/204/205 support", risk: "LOW", score: 8, devices: 0, firmware: 0, configs: 0, findings: 0 },
  { name: "NXP Semiconductors", products: 2, pqc: "PQC secure elements 2026", risk: "MEDIUM", score: 31, devices: 141, firmware: 6, configs: 2, findings: 4 },
  { name: "Oracle (JCA/JCE)", products: 1, pqc: "JDK PQC preview", risk: "LOW", score: 15, devices: 0, firmware: 0, configs: 0, findings: 0 },
  { name: "Palo Alto Networks", products: 2, pqc: "TLS 1.3 PQC ciphers", risk: "MEDIUM", score: 27, devices: 41, firmware: 7, configs: 5, findings: 6 },
];

export const hardware: HardwareDevice[] = [
  { id: "hsm-pci-01", type: "HSM", vendor: "Acme Secure", firmware: "7.2.1", caps: ["AES", "RSA", "ML-KEM-768"], host: "pay-server-01", status: "ONLINE" },
  { id: "hsm-02", type: "HSM", vendor: "BankVault", firmware: "5.4.0", caps: ["AES", "RSA"], host: "core-bank-02", status: "ONLINE" },
  { id: "tpm-pay-*", type: "TPM 2.0", vendor: "Infineon", firmware: "15.1", caps: ["RSA", "ECC", "SHA-256"], host: "pay-server-*", status: "ACTIVE" },
  { id: "sec-el-01", type: "Secure Element", vendor: "NXP", firmware: "3.2", caps: ["ECC", "Ed25519"], host: "pos-*", status: "ACTIVE" },
  { id: "accel-01", type: "Crypto Accelerator", vendor: "Acme Secure", firmware: "1.9", caps: ["AES", "SHA-3", "ML-KEM-1024"], host: "gw-vpn-01", status: "ACTIVE" },
  { id: "bmc-pay-01", type: "BMC", vendor: "ASPEED", firmware: "2.4", caps: ["RSA", "SHA-256"], host: "pay-server-01", status: "ACTIVE" },
];

export const firmwareRows: FirmwareRow[] = [
  { device: "pay-server-01", kind: "BIOS", version: "2.14.0", status: "MATCHES BASELINE" },
  { device: "rtr-core-1", kind: "IOS-XE", version: "17.9.1", status: "MATCHES BASELINE" },
  { device: "fw-edge-01", kind: "PAN-OS", version: "11.1.2", status: "DRIFT: baseline 11.1.1" },
  { device: "hsm-pci-01", kind: "HSM OS", version: "7.2.1", status: "MATCHES BASELINE" },
  { device: "aws-elb-pay", kind: "cloud firmware", version: "managed", status: "MATCHES BASELINE" },
];

/* ── inventory ─────────────────────────────────────────────────────── */
export const algorithms: AlgorithmInfo[] = [
  { name: "RSA-2048", op: "sign / encrypt", library: "OpenSSL 3.5", quantum: "QUANTUM_VULNERABLE", priority: "HIGH", usage: true, usageCount: 8421, assets: 1284, confidence: 0.99 },
  { name: "ECDSA-P-256", op: "sign", library: "OpenSSL 3.5", quantum: "QUANTUM_VULNERABLE", priority: "MEDIUM", usage: true, usageCount: 4821, assets: 712, confidence: 0.99 },
  { name: "X25519", op: "key exchange", library: "LibreSSL", quantum: "QUANTUM_VULNERABLE", priority: "MEDIUM", usage: true, usageCount: 1284, assets: 233, confidence: 0.98 },
  { name: "Ed25519", op: "sign", library: "LibreSSL", quantum: "QUANTUM_VULNERABLE", priority: "MEDIUM", usage: false, usageCount: 96, assets: 41, confidence: 0.98 },
  { name: "AES-256-GCM", op: "encrypt", library: "OpenSSL 3.5", quantum: "QUANTUM_SAFE", priority: "LOW", usage: true, usageCount: 21482, assets: 4821, confidence: 0.99 },
  { name: "SHA-256", op: "hash", library: "OpenSSL 3.5", quantum: "QUANTUM_SAFE", priority: "LOW", usage: true, usageCount: 31842, assets: 9210, confidence: 0.99 },
  { name: "SHA-384", op: "hash", library: "JCA-JCE", quantum: "QUANTUM_SAFE", priority: "LOW", usage: true, usageCount: 1241, assets: 402, confidence: 0.99 },
  { name: "ML-KEM-768", op: "key exchange", library: "OpenSSL 3.5", quantum: "QUANTUM_SAFE", priority: "LOW", usage: true, usageCount: 81, assets: 23, confidence: 0.97 },
  { name: "ML-DSA-65", op: "sign", library: "OpenSSL 3.5", quantum: "QUANTUM_SAFE", priority: "LOW", usage: true, usageCount: 41, assets: 12, confidence: 0.97 },
  { name: "3DES", op: "encrypt", library: "legacy", quantum: "QUANTUM_VULNERABLE", priority: "CRITICAL", usage: true, usageCount: 42, assets: 9, confidence: 0.96 },
  { name: "MD5", op: "hash", library: "legacy", quantum: "QUANTUM_SAFE", priority: "CRITICAL", usage: true, usageCount: 421, assets: 184, confidence: 0.98 },
  { name: "SHA-1", op: "hash", library: "legacy", quantum: "QUANTUM_VULNERABLE", priority: "HIGH", usage: true, usageCount: 421, assets: 184, confidence: 0.98 },
  { name: "RSA-PSS", op: "sign", library: "JCA-JCE", quantum: "QUANTUM_VULNERABLE", priority: "HIGH", usage: true, usageCount: 1192, assets: 341, confidence: 0.99 },
  { name: "DH-2048", op: "key exchange", library: "OpenSSL 3.5", quantum: "QUANTUM_VULNERABLE", priority: "HIGH", usage: true, usageCount: 1284, assets: 96, confidence: 0.98 },
];

export const certificates: CertificateInfo[] = [
  { cn: "payments.internal", sig: "RSA-PSS / SHA-384", key: "RSA-2048", days: 334, san: 2, eku: "serverAuth", status: "VALID", owner: "payments-team" },
  { cn: "api.payments.internal", sig: "ECDSA / SHA-256", key: "P-256", days: 12, san: 3, eku: "serverAuth", status: "EXPIRING", owner: "payments-team" },
  { cn: "gw.vpn.internal", sig: "RSA-PSS / SHA-256", key: "RSA-3072", days: 210, san: 1, eku: "serverAuth,clientAuth", status: "VALID", owner: "netsec" },
  { cn: "legacy-bank.example", sig: "SHA1WithRSA", key: "RSA-1024", days: -41, san: 1, eku: "serverAuth", status: "EXPIRED", owner: "UNKNOWN" },
  { cn: "ml-dsa.gw.internal", sig: "ML-DSA-65", key: "ML-DSA-65", days: 360, san: 1, eku: "serverAuth", status: "VALID", owner: "netsec" },
  { cn: "db.internal", sig: "ECDSA / SHA-256", key: "P-256", days: 88, san: 1, eku: "serverAuth,clientAuth", status: "VALID", owner: "data-platform" },
  { cn: "pos-gw.example", sig: "RSA / SHA-256", key: "RSA-2048", days: 4, san: 4, eku: "serverAuth", status: "EXPIRING", owner: "retail-ops" },
  { cn: "root-ca.internal", sig: "RSA-PSS / SHA-384", key: "RSA-4096", days: 2900, san: 0, eku: "root CA", status: "VALID", owner: "netsec" },
];

export const certCenter = {
  expired: 18,
  expiring30: 142,
  weakAlgorithm: 82,
  unknownOwner: 31,
  pqcMigration: 284,
};

export const trustFindings: TrustFinding[] = [
  { type: "unexpected_ca", detail: "CN=RogueRoot not in expected roots (system.jks)", severity: "HIGH" },
  { type: "deprecated_algorithm", detail: "SHA1WithRSA anchor CN=RogueRoot", severity: "HIGH" },
  { type: "legacy_trust_dependency", detail: "legacy app depends on expired anchor CN=OldRootCA", severity: "MEDIUM" },
  { type: "expired_ca", detail: "CN=OldRootCA expired 214 days ago", severity: "MEDIUM" },
  { type: "duplicate_trust_anchor", detail: "CN=OrgRoot present twice in trust store", severity: "LOW" },
];

export const libraries: LibraryInfo[] = [
  { name: "OpenSSL", version: "3.5.1", provider: "openssl.org", pqc: true, apps: 842, algorithms: 72, upgrade: "up to date" },
  { name: "BoringSSL", version: "2024-12", provider: "google", pqc: false, apps: 64, algorithms: 41, upgrade: "PQC pending" },
  { name: "LibreSSL", version: "3.9", provider: "openbsd", pqc: false, apps: 96, algorithms: 38, upgrade: "PQC pending" },
  { name: "wolfSSL", version: "5.7", provider: "wolfSSL Inc", pqc: true, apps: 43, algorithms: 44, upgrade: "up to date" },
  { name: "mbedTLS", version: "3.6", provider: "arm", pqc: true, apps: 128, algorithms: 51, upgrade: "up to date" },
  { name: "JCA/JCE", version: "JDK 21", provider: "oracle", pqc: true, apps: 512, algorithms: 66, upgrade: "PQC preview" },
  { name: ".NET cryptography", version: "8.0", provider: "microsoft", pqc: true, apps: 284, algorithms: 49, upgrade: "up to date" },
  { name: "Go crypto/*", version: "1.24", provider: "golang", pqc: true, apps: 191, algorithms: 37, upgrade: "up to date" },
  { name: "RustCrypto", version: "0.7", provider: "rust", pqc: false, apps: 75, algorithms: 33, upgrade: "PQC pending" },
  { name: "PKCS#11", version: "3.0", provider: "oasis", pqc: true, apps: 311, algorithms: 29, upgrade: "up to date" },
];

export const protocols: ProtocolInfo[] = [
  { protocol: "TLS", version: "1.3", cipher: "AES-256-GCM", kex: "X25519", signature: "RSA-PSS", cert: "payments.internal", endpoint: "lb-pay-01", risk: "LOW", pqc: "HYBRID READY" },
  { protocol: "TLS", version: "1.2", cipher: "AES-256-GCM", kex: "ECDHE-P-256", signature: "ECDSA", cert: "db.internal", endpoint: "db-pay-01", risk: "MEDIUM", pqc: "MIGRATION REQUIRED" },
  { protocol: "TLS", version: "1.2", cipher: "AES-128-CBC", kex: "ECDHE-P-256", signature: "RSA-2048", cert: "pos-gw.example", endpoint: "pos-gw-01", risk: "HIGH", pqc: "MIGRATION REQUIRED" },
  { protocol: "TLS", version: "1.3", cipher: "AES-256-GCM", kex: "ML-KEM-768", signature: "ML-DSA-65", cert: "ml-dsa.gw.internal", endpoint: "gw-vpn-01", risk: "LOW", pqc: "PQC READY" },
  { protocol: "SSH", version: "2.0", cipher: "AES-256-CTR", kex: "X25519", signature: "Ed25519", cert: "host keys", endpoint: "rtr-core-1", risk: "MEDIUM", pqc: "MIGRATION REQUIRED" },
  { protocol: "SSH", version: "2.0", cipher: "AES-256-CTR", kex: "ML-KEM-768", signature: "ML-DSA-65", cert: "host keys", endpoint: "app-pay-01", risk: "LOW", pqc: "PQC READY" },
  { protocol: "IPsec", version: "IKEv2", cipher: "AES-256-GCM", kex: "DH-2048", signature: "RSA-2048", cert: "payments.internal", endpoint: "vpn-01", risk: "HIGH", pqc: "MIGRATION REQUIRED" },
  { protocol: "QUIC", version: "1.0", cipher: "AES-256-GCM", kex: "X25519", signature: "RSA-PSS", cert: "gw.vpn.internal", endpoint: "proxy-01", risk: "LOW", pqc: "HYBRID READY" },
];

export const assets: AssetRow[] = [
  { id: "ast-00001", type: "application", name: "payments-svc", env: "prod", region: "IN-South", owner: "payments-team", risk: "MEDIUM", evidence: 42 },
  { id: "ast-00002", type: "load_balancer", name: "lb-pay-01", env: "prod", region: "IN-South", owner: "netsec", risk: "LOW", evidence: 18 },
  { id: "ast-00003", type: "certificate", name: "payments.internal", env: "prod", region: "global", owner: "payments-team", risk: "HIGH", evidence: 31 },
  { id: "ast-00004", type: "hsm", name: "hsm-pci-01", env: "prod", region: "IN-South", owner: "payments-team", risk: "LOW", evidence: 12 },
  { id: "ast-00005", type: "cloud_resource", name: "aws-elb-pay", env: "prod", region: "ap-south-1", owner: "cloud-platform", risk: "LOW", evidence: 9 },
  { id: "ast-00006", type: "library", name: "OpenSSL 3.5.1", env: "prod", region: "global", owner: "platform-eng", risk: "LOW", evidence: 7 },
  { id: "ast-00007", type: "database", name: "db-pay-01", env: "prod", region: "IN-South", owner: "data-platform", risk: "MEDIUM", evidence: 14 },
  { id: "ast-00008", type: "vpn_gateway", name: "vpn-01", env: "prod", region: "IN-West", owner: "netsec", risk: "HIGH", evidence: 22 },
  { id: "ast-00009", type: "tpm", name: "tpm-pay-01", env: "prod", region: "IN-South", owner: "hardware-team", risk: "LOW", evidence: 4 },
  { id: "ast-00010", type: "firewall", name: "fw-edge-01", env: "prod", region: "IN-South", owner: "netsec", risk: "MEDIUM", evidence: 16 },
];

/* ── live ──────────────────────────────────────────────────────────── */
export const events: EventItem[] = [
  { t: "09:41:22", tag: "CERT_RENEWED", text: "payments.internal → signature ML-DSA-65 · CBOM v1843 · readiness PQC_READY", severity: "LOW" },
  { t: "09:12:07", tag: "CLOUD_RESOURCE_CHANGED", text: "aws-elb-pay certificate list updated", severity: "MEDIUM" },
  { t: "08:58:44", tag: "FIRMWARE_CHANGED", text: "fw-edge-01 PAN-OS 11.1.1 → 11.1.2 · targeted rescan dispatched", severity: "MEDIUM" },
  { t: "08:31:15", tag: "NEW_DEVICE", text: "sw-dc-03 joined network 10.0.2.0/24 · identity enrolled", severity: "HIGH" },
  { t: "07:55:02", tag: "HSM_CHANGED", text: "hsm-02 firmware 5.4.0 → 5.4.1 · capability recheck queued", severity: "LOW" },
  { t: "06:40:19", tag: "ALGORITHM_CHANGED", text: "payments svc now uses AES-256-GCM (was AES-CBC)", severity: "LOW" },
  { t: "05:12:48", tag: "VENDOR_CONFIGURATION_CHANGED", text: "Acme Secure product list +1 (crypto accelerator)", severity: "LOW" },
  { t: "04:20:11", tag: "TLS_CONFIG_CHANGED", text: "gateway-04 dropped TLS 1.1 · ciphers renegotiated", severity: "LOW" },
  { t: "03:07:52", tag: "CERT_EXPIRED", text: "legacy-bank.example RSA-1024 certificate expired", severity: "CRITICAL" },
  { t: "02:44:01", tag: "SCANNER_COMPLETED", text: "network scanner cycle 5,112 assets · 0 errors", severity: "LOW" },
];

export const alerts: AlertItem[] = [
  { severity: "CRITICAL", title: "Certificate expired", detail: "legacy-bank.example · RSA-1024 · SHA1WithRSA", ago: "18 s", acked: false },
  { severity: "HIGH", title: "New RSA dependency detected", detail: "authentication-service → RSA-2048 (3 new dependents)", ago: "4 min", acked: false },
  { severity: "HIGH", title: "Unmanaged device joined", detail: "sw-dc-03 · 10.0.2.0/24 · outside change ticket", ago: "11 min", acked: false },
  { severity: "MEDIUM", title: "Firmware drift", detail: "fw-edge-01 PAN-OS 11.1.1 → 11.1.2", ago: "26 min", acked: true },
  { severity: "MEDIUM", title: "TLS 1.2 in prod", detail: "db-pay-01 · AES-128-CBC · ECDHE-P-256", ago: "1 h", acked: false },
  { severity: "LOW", title: "Scanner cycle complete", detail: "all 5 scanners healthy · 0 errors", ago: "2 h", acked: true },
];

export const timelineRows: TimelineRow[] = [
  { t: "09:41", tag: "CBOM_UPDATED", text: "payments.internal re-keyed → CBOM v1843" },
  { t: "09:40", tag: "RISK_CALCULATED", text: "payments.internal risk 61 → 44 (ML-DSA re-key)" },
  { t: "09:12", tag: "CLOUD_CHANGED", text: "aws-elb-pay certificate list updated" },
  { t: "09:05", tag: "CERT_DETECTED", text: "api.payments.internal chain verified (3 anchors)" },
  { t: "09:04", tag: "RSA_DEPENDENCY_DETECTED", text: "authentication-service → RSA-2048" },
  { t: "09:03", tag: "TLS_CONFIG_DETECTED", text: "gateway-04 TLS 1.3 group updated" },
  { t: "09:02", tag: "CERTIFICATE_DETECTED", text: "pos-gw.example expires in 4 days" },
  { t: "09:01", tag: "CLOUD_RESOURCE_DISCOVERED", text: "pay-gke cluster node pool +3" },
  { t: "08:58", tag: "FIRMWARE_CHANGED", text: "fw-edge-01 PAN-OS 11.1.2" },
  { t: "08:31", tag: "DEVICE_DISCOVERED", text: "sw-dc-03 joined 10.0.2.0/24" },
  { t: "07:55", tag: "HSM_CHANGED", text: "hsm-02 firmware 5.4.1" },
  { t: "06:40", tag: "ALGORITHM_CHANGED", text: "payments svc AES-256-GCM" },
  { t: "05:12", tag: "VENDOR_CHANGED", text: "Acme Secure product list +1" },
  { t: "04:20", tag: "TLS_CONFIG_CHANGED", text: "gateway-04 dropped TLS 1.1" },
  { t: "03:07", tag: "CERT_EXPIRED", text: "legacy-bank.example" },
  { t: "02:44", tag: "SCANNER_CYCLE", text: "network scan 5,112 assets" },
];

/* ── boms ──────────────────────────────────────────────────────────── */
export const bomComponents: BomComponent[] = [
  { type: "cryptography", name: "RSA-2048", ref: "RSA-2048" },
  { type: "cryptography", name: "ML-KEM-768", ref: "ML-KEM-768" },
  { type: "cryptography", name: "ML-DSA-65", ref: "ML-DSA-65" },
  { type: "cryptography", name: "payments.internal", ref: "payments.internal" },
  { type: "cryptography", name: "api.payments.internal", ref: "api.payments.internal" },
  { type: "library", name: "OpenSSL 3.5.1", ref: "OpenSSL" },
  { type: "library", name: "JCA/JCE JDK 21", ref: "JCA/JCE" },
  { type: "library", name: "PKCS#11 3.0", ref: "PKCS#11" },
  { type: "device", name: "hsm-pci-01", ref: "hsm-pci-01" },
  { type: "device", name: "pay-server-01", ref: "pay-server-01" },
  { type: "device", name: "lb-pay-01", ref: "lb-pay-01" },
  { type: "application", name: "payments-svc", ref: "payments-svc" },
  { type: "application", name: "authentication-service", ref: "authentication-service" },
  { type: "firmware", name: "PAN-OS 11.1.2", ref: "fw-edge-01-fw" },
];

export const bomDependencies: BomDependency[] = [
  { ref: "payments-svc", dependsOn: ["OpenSSL", "hsm-pci-01", "RSA-2048"] },
  { ref: "authentication-service", dependsOn: ["RSA-2048", "JCA/JCE", "PKCS#11"] },
  { ref: "OpenSSL", dependsOn: ["RSA-2048", "ML-KEM-768", "ML-DSA-65"] },
  { ref: "JCA/JCE", dependsOn: ["RSA-2048"] },
  { ref: "hsm-pci-01", dependsOn: ["ML-KEM-768"] },
  { ref: "lb-pay-01", dependsOn: ["payments.internal", "OpenSSL"] },
  { ref: "payments.internal", dependsOn: ["RSA-2048"] },
  { ref: "api.payments.internal", dependsOn: ["RSA-2048"] },
];

export const bomDiff = {
  added: ["ML-DSA-65", "payments.internal (re-keyed → ML-DSA-65)"],
  removed: ["RSA-2048 (payments.internal)"],
  changed: ["OpenSSL 3.5.1", "cbom version 1842 → 1843"],
};

export const bomHistory = [
  { version: "v1843", at: "09:41:22 UTC", note: "payments.internal re-keyed to ML-DSA-65 · readiness PQC_READY", by: "scanner: crypto" },
  { version: "v1842", at: "06:40:19 UTC", note: "payments svc AES-CBC → AES-256-GCM", by: "scanner: crypto" },
  { version: "v1841", at: "02:44:01 UTC", note: "network cycle 5,112 assets · 18 new endpoints", by: "scanner: network" },
  { version: "v1840", at: "2026-08-31 22:10 UTC", note: "baseline frozen by security-admin", by: "user: ops-bot" },
];

/* ── pqc / agility / risk ──────────────────────────────────────────── */
export const pqc = {
  overall: 72,
  ready: 31,
  hybrid: 22,
  migrationRequired: 47,
  vulnerable: { rsa: 8421, ecc: 4821, dh: 1284, legacy: 421 },
  byFunction: [
    { group: "key exchange", safe: ["ML-KEM-768", "ML-KEM-1024"], vulnerable: ["X25519", "ECDH-P-256", "DH-2048"], unknown: 3 },
    { group: "signature", safe: ["ML-DSA-65", "SLH-DSA"], vulnerable: ["RSA-2048", "ECDSA-P-256", "Ed25519"], unknown: 7 },
    { group: "encryption", safe: ["AES-256-GCM", "AES-128-GCM"], vulnerable: ["3DES", "AES-CBC"], unknown: 0 },
    { group: "hash", safe: ["SHA-256", "SHA-384", "SHA-3"], vulnerable: ["MD5", "SHA-1"], unknown: 0 },
  ],
};

export const agility = {
  score: 78,
  hardCoded: 18,
  configurable: 64,
  pqcReady: 31,
  hybridReady: 22,
  byApp: [
    { app: "payments-svc", score: 91, hard: 6, config: 84, pqc: 71 },
    { app: "authentication-service", score: 64, hard: 31, config: 55, pqc: 12 },
    { app: "retail-pos-gw", score: 41, hard: 48, config: 38, pqc: 0 },
    { app: "data-platform", score: 82, hard: 11, config: 77, pqc: 44 },
    { app: "core-bank-legacy", score: 22, hard: 74, config: 12, pqc: 0 },
  ],
};

export const risk = {
  counts: { CRITICAL: 42, HIGH: 184, MEDIUM: 721, LOW: 2184 },
  matrix: {
    "impact:high/exposure:high": 42,
    "impact:high/exposure:low": 121,
    "impact:low/exposure:high": 63,
    "impact:low/exposure:low": 1820,
  },
  topFindings: [
    { id: "fnd-0042", title: "RSA-1024 certificate expired in trust path", severity: "CRITICAL", assets: 31, evidence: 8 },
    { id: "fnd-0184", title: "IPsec IKEv2 uses DH-2048 (quantum vulnerable)", severity: "HIGH", assets: 12, evidence: 5 },
    { id: "fnd-0179", title: "3DES still active on legacy HSM config", severity: "CRITICAL", assets: 4, evidence: 6 },
    { id: "fnd-0161", title: "Unexpected CA in system trust store", severity: "HIGH", assets: 9, evidence: 4 },
    { id: "fnd-0122", title: "TLS 1.2 with AES-128-CBC on prod endpoint", severity: "HIGH", assets: 7, evidence: 3 },
  ],
};

/* ── drift ─────────────────────────────────────────────────────────── */
export const drift = {
  baseline: {
    network: ["lb-pay-01", "rtr-core-1", "fw-edge-01", "vpn-01"],
    cloud: ["aws-elb-pay", "pay-kms"],
    vendor: ["Acme Secure"],
    hardware: ["hsm-pci-01", "tpm-pay-*"],
    crypto: ["RSA-2048", "AES-256-GCM", "SHA-256"],
    certificate: ["payments.internal"],
    protocol: ["TLS 1.3"],
    firmware: ["PAN-OS 11.1.1"],
    pqc: ["readiness: HYBRID_READY"],
  },
  live: {
    network: ["lb-pay-01", "rtr-core-1", "fw-edge-01", "vpn-01", "sw-dc-03"],
    cloud: ["aws-elb-pay", "pay-kms"],
    vendor: ["Acme Secure"],
    hardware: ["hsm-pci-01", "tpm-pay-*"],
    crypto: ["RSA-2048", "AES-256-GCM", "SHA-256", "ML-KEM-768"],
    certificate: ["payments.internal"],
    protocol: ["TLS 1.3"],
    firmware: ["PAN-OS 11.1.2"],
    pqc: ["readiness: PQC_READY"],
  },
};

/* ── planning ──────────────────────────────────────────────────────── */
export const whatif = {
  current: "RSA-2048",
  target: "ML-KEM-768",
  feasible: true,
  compatibility: 82,
  complexity: "MEDIUM",
  impact: { applications: 184, apis: 42, certificates: 17, vendors: 3, hardware: 2, cloud: 3 },
  checks: {
    dependencies: { affectedLibraries: 6, libraries: ["OpenSSL", "JCA/JCE", "Go crypto/*", ".NET cryptography", "wolfSSL", "PKCS#11"] },
    libraries: { supported: true, supporting: ["OpenSSL 3.5", "JCA/JCE JDK 21", "Go crypto 1.24", "PKCS#11 3.0"] },
    hardware: { supported: true, pqcCapable: 2, devices: ["hsm-pci-01", "accel-01"] },
    vendor: { supported: true, pqcPositive: 2, vendors: ["Acme Secure", "OpenSSL (community)"] },
    cloud: { supported: true, pqcReadyServices: 3, services: ["aws/kms", "azure/kv", "gcp/kms"] },
    impact: { projectedQuantumStatus: "QUANTUM_SAFE", protocolCompatibility: { TLS: "SUPPORTED", SSH: "SUPPORTED", IPsec: "SUPPORTED" } },
  },
  plan: [
    "Inventory every dependency on RSA-2048 (graph query → 184 apps).",
    "Confirm ML-KEM-768 support in each crypto library (6 libs OK).",
    "Verify HSM/TPM firmware supports ML-KEM-768 (hsm-pci-01, accel-01 OK).",
    "Confirm vendor roadmap for ML-KEM-768 (Acme Secure, OpenSSL OK).",
    "Re-key certificates that use RSA-2048 (17 certs → ML-DSA-65 hybrid).",
    "Update protocol configuration (TLS 1.3 groups) and re-scan (drift check).",
  ],
};

export const migrationBoard: { col: string; cards: KanbanCard[] }[] = [
  { col: "DISCOVERED", cards: [
    { id: "mig-01", title: "retail-pos-gw TLS 1.2 estate", apps: 31, owner: "retail-ops", risk: "HIGH" },
    { id: "mig-02", title: "core-bank-legacy DH-2048", apps: 12, owner: "banking-core", risk: "HIGH" },
    { id: "mig-03", title: "BoringSSL consumers", apps: 64, owner: "platform-eng", risk: "MEDIUM" },
  ]},
  { col: "ASSESSED", cards: [
    { id: "mig-04", title: "IPsec IKEv2 group migration", apps: 12, owner: "netsec", risk: "HIGH" },
    { id: "mig-05", title: "RustCrypto providers", apps: 75, owner: "platform-eng", risk: "MEDIUM" },
  ]},
  { col: "PLANNED", cards: [
    { id: "mig-06", title: "authentication-service re-key", apps: 41, owner: "payments-team", risk: "MEDIUM" },
    { id: "mig-07", title: "JCA/JCE PQC preview rollout", apps: 512, owner: "platform-eng", risk: "MEDIUM" },
  ]},
  { col: "TESTING", cards: [
    { id: "mig-08", title: "ML-DSA hybrid cert chain", apps: 17, owner: "netsec", risk: "LOW" },
  ]},
  { col: "MIGRATING", cards: [
    { id: "mig-09", title: "payments.internal ML-DSA re-key", apps: 184, owner: "payments-team", risk: "LOW" },
  ]},
  { col: "VALIDATED", cards: [
    { id: "mig-10", title: "gateway-04 TLS 1.3 hardening", apps: 22, owner: "netsec", risk: "LOW" },
  ]},
  { col: "COMPLETED", cards: [
    { id: "mig-11", title: "payments svc AES-256-GCM", apps: 9, owner: "payments-team", risk: "LOW" },
  ]},
];

/* ── governance ────────────────────────────────────────────────────── */
export const compliance: ComplianceRow[] = [
  { framework: "NIST SP 800-131A", requirement: "Transitional crypto approved", control: "RSA-2048 → ML-KEM/ML-DSA", status: "PARTIAL", evidence: "ev-00921" },
  { framework: "CNSA 2.0", requirement: "PQC algorithms by 2030", control: "ML-KEM-768 + ML-DSA-65 adoption", status: "PARTIAL", evidence: "ev-00918" },
  { framework: "PCI-DSS 4.0", requirement: "Strong cryptography for PAN", control: "TLS 1.3 + AES-256-GCM", status: "COMPLIANT", evidence: "ev-00877" },
  { framework: "ISO 27001 A.10", requirement: "Cryptographic controls", control: "Key management policy", status: "COMPLIANT", evidence: "ev-00812" },
  { framework: "BSI TR-02102-1", requirement: "Quantum-safe transition", control: "Hybrid handshakes", status: "NON-COMPLIANT", evidence: "ev-00904" },
  { framework: "Regulator EBA/ECB", requirement: "Crypto inventory", control: "CBOM maintenance", status: "COMPLIANT", evidence: "ev-00930" },
];

export const governance = {
  owners: [
    { asset: "payments.internal", owner: "payments-team", approved: "2026-08-30", by: "security-admin" },
    { asset: "hsm-pci-01", owner: "payments-team", approved: "2026-08-12", by: "hardware-admin" },
    { asset: "fw-edge-01", owner: "netsec", approved: "2026-07-28", by: "security-admin" },
  ],
  exceptions: [
    { id: "exc-17", asset: "legacy-bank.example", reason: "end-of-life migration Q4", expires: "2026-11-30", approvedBy: "ciso" },
    { id: "exc-09", asset: "3DES (hsm-02)", reason: "legacy card scheme requirement", expires: "2026-09-15", approvedBy: "crypto-admin" },
  ],
  audit: [
    { t: "09:44", actor: "ops-bot", action: "exported CBOM v1843", target: "cbom" },
    { t: "08:02", actor: "security-admin", action: "approved exception exc-17", target: "governance" },
    { t: "07:15", actor: "netsec", action: "froze baseline", target: "drift" },
    { t: "06:30", actor: "auditor", action: "exported evidence chain ev-00921", target: "evidence" },
  ],
};

/* ── evidence / scanners / reports / integrations ──────────────────── */
export const evidenceChain: EvidenceLink[] = [
  { id: "ev-00921", kind: "finding", detail: "payments.internal uses RSA-2048 — quantum vulnerable", method: "certificate parser", confidence: 0.99, firstSeen: "2026-01-04", lastSeen: "2026-09-01", hash: "7f3a9c21d8e44b06f1a92c55be0d81aa", prev: null },
  { id: "ev-00920", kind: "observation", detail: "cert file /etc/tls/payments.crt · SAN 2 · RSA-2048 · SHA-384", method: "artifact scan", confidence: 0.99, firstSeen: "2026-01-04", lastSeen: "2026-09-01", hash: "9c2f71ab04de11c8f0b83a55d76e2c90", prev: "ev-00881" },
  { id: "ev-00919", kind: "source", detail: "lb-pay-01 · /etc/tls/payments.crt · offset 0x0412", method: "network agent", confidence: 1.0, firstSeen: "2026-01-04", lastSeen: "2026-09-01", hash: "d41f8b07a3c92e55f0b61d84ac7e3902", prev: "ev-00880" },
  { id: "ev-00918", kind: "dependency", detail: "184 applications depend on payments.internal chain", method: "graph query", confidence: 0.98, firstSeen: "2026-02-11", lastSeen: "2026-09-01", hash: "55e0d29f7b41aa83c6f09d22e184b7c3", prev: "ev-00862" },
];

export const scanners: ScannerRow[] = [
  { name: "Network Scanner", status: "RUNNING", health: 99.9, lastRun: "2 min ago", findings: 5112 },
  { name: "Cloud Scanner", status: "RUNNING", health: 99.8, lastRun: "4 min ago", findings: 3184 },
  { name: "Vendor Scanner", status: "RUNNING", health: 99.7, lastRun: "7 min ago", findings: 96 },
  { name: "Hardware Scanner", status: "RUNNING", health: 99.9, lastRun: "3 min ago", findings: 2594 },
  { name: "Crypto Scanner", status: "RUNNING", health: 99.9, lastRun: "1 min ago", findings: 42391 },
];

export const reports = [
  { kind: "EXECUTIVE", title: "Security posture", desc: "Top risks, PQC readiness, migration progress", status: "READY", generated: "2026-09-01 09:00" },
  { kind: "TECHNICAL", title: "Algorithms & libraries", desc: "Full inventory, evidence, dependencies", status: "READY", generated: "2026-09-01 08:40" },
  { kind: "COMPLIANCE", title: "Controls & exceptions", desc: "Framework → control → evidence status", status: "READY", generated: "2026-09-01 08:15" },
  { kind: "PQC", title: "Quantum-vulnerable assets", desc: "Migration candidates and priorities", status: "READY", generated: "2026-09-01 07:55" },
];

export const integrations = [
  { name: "Splunk SIEM", kind: "event streaming", status: "CONNECTED", detail: "all crypto events · CIM format" },
  { name: "Microsoft Sentinel", kind: "event streaming", status: "CONNECTED", detail: "critical findings only" },
  { name: "IBM QRadar", kind: "event streaming", status: "CONNECTED", detail: "all events · DSM" },
  { name: "ServiceNow", kind: "ticketing", status: "CONNECTED", detail: "auto-create incidents on CRITICAL" },
  { name: "Jira", kind: "migration tracking", status: "CONNECTED", detail: "kanban sync" },
  { name: "Webhook", kind: "outbound", status: "CONNECTED", detail: "https://hooks.internal/zelinx" },
  { name: "Email", kind: "notifications", status: "CONNECTED", detail: "daily digest · on-call pages" },
];

export const rbac = {
  roles: [
    "SUPER ADMIN", "SECURITY ADMIN", "CRYPTO ADMIN", "CLOUD ADMIN", "NETWORK ADMIN",
    "AUDITOR", "COMPLIANCE", "ENGINEER", "VIEWER",
  ],
  permissions: [
    "view", "scan", "configure", "export", "approve", "delete", "simulate", "manage policies", "manage users",
  ],
  matrix: {
    "SUPER ADMIN": [1,1,1,1,1,1,1,1,1],
    "SECURITY ADMIN": [1,1,1,1,1,0,1,1,0],
    "CRYPTO ADMIN": [1,1,1,1,1,0,1,1,0],
    "CLOUD ADMIN": [1,1,1,1,0,0,0,0,0],
    "NETWORK ADMIN": [1,1,1,1,0,0,0,0,0],
    "AUDITOR": [1,0,0,1,0,0,0,0,0],
    "COMPLIANCE": [1,0,0,1,0,0,0,0,0],
    "ENGINEER": [1,1,0,0,0,0,1,0,0],
    "VIEWER": [1,0,0,0,0,0,0,0,0],
  },
  tenants: [
    { id: "t-01", name: "Global Bank Ltd", region: "IN+UAE+SG", assets: 125482, scanners: 5, status: "ACTIVE" },
    { id: "t-02", name: "PayCo Services", region: "EU", assets: 41209, scanners: 3, status: "ACTIVE" },
    { id: "t-03", name: "TrustNet Infra", region: "US", assets: 88213, scanners: 4, status: "ACTIVE" },
  ],
};

/* ── accuracy (REAL benchmark numbers) ─────────────────────────────── */
export const accuracy: AccuracyRow[] = [
  { name: "certificates", cases: 7, prec: 1.0, rec: 1.0, f1: 1.0, cov: 1.0, cat: "certificate" },
  { name: "custom_crypto", cases: 6, prec: 1.0, rec: 1.0, f1: 1.0, cov: 1.0, cat: "implementation" },
  { name: "implementations", cases: 6, prec: 1.0, rec: 1.0, f1: 1.0, cov: 1.0, cat: "implementation" },
  { name: "known_crypto", cases: 19, prec: 1.0, rec: 1.0, f1: 1.0, cov: 1.0, cat: "algorithm/protocol/library" },
  { name: "known_noncrypto", cases: 10, prec: 1.0, rec: 1.0, f1: 1.0, cov: 1.0, cat: "algorithm" },
  { name: "obfuscated", cases: 8, prec: 1.0, rec: 1.0, f1: 1.0, cov: 1.0, cat: "algorithm" },
  { name: "pqc_classification", cases: 10, prec: 1.0, rec: 1.0, f1: 1.0, cov: 1.0, cat: "pqc_classification" },
  { name: "real_world", cases: 9, prec: 1.0, rec: 1.0, f1: 1.0, cov: 1.0, cat: "algorithm/library" },
  { name: "weak_crypto", cases: 10, prec: 1.0, rec: 1.0, f1: 1.0, cov: 1.0, cat: "weak_crypto" },
];

export const accuracyMean = { datasets: 9, cases: 88, f1: 1.0, prec: 1.0, rec: 1.0, fpr: 0.0, fnr: 0.0 };

/* ── search index ──────────────────────────────────────────────────── */
export function buildSearchIndex(): SearchGroup[] {
  const q = (s: string): string => (s.startsWith("Q") ? "QUANTUM_VULNERABLE" : s);
  return [
    {
      label: "Algorithms", icon: "⚿",
      items: algorithms.map((a) => ({ name: a.name, meta: `${a.op} · ${q(a.quantum)} · ${a.usageCount} usages`, to: "#/app/crypto-assets" })),
    },
    {
      label: "Certificates", icon: "⊞",
      items: certificates.map((c) => ({ name: c.cn, meta: `${c.key} · ${c.sig} · ${c.days} days`, to: "#/app/certificates" })),
    },
    {
      label: "Libraries", icon: "▤",
      items: libraries.map((l) => ({ name: l.name, meta: `${l.version} · ${l.apps} apps · PQC ${l.pqc ? "supported" : "pending"}`, to: "#/app/libraries" })),
    },
    {
      label: "Hardware", icon: "◉",
      items: hardware.map((h) => ({ name: h.id, meta: `${h.type} · ${h.vendor} · ${h.caps.join("/")}`, to: "#/app/hardware" })),
    },
    {
      label: "Cloud resources", icon: "☁",
      items: cloudResources.map((c) => ({ name: c.name, meta: `${c.provider} · ${c.service} · ${c.status}`, to: "#/app/cloud" })),
    },
    {
      label: "Vendors", icon: "◈",
      items: vendors.map((v) => ({ name: v.name, meta: `${v.products} products · risk ${v.risk}`, to: "#/app/vendor" })),
    },
    {
      label: "Network", icon: "⇄",
      items: networkAssets.map((n) => ({ name: n.id, meta: `${n.kind} · ${n.ip} · ${n.os}`, to: "#/app/network" })),
    },
    {
      label: "Assets", icon: "◎",
      items: assets.map((a) => ({ name: a.id, meta: `${a.type} · ${a.name} · ${a.region}`, to: "#/app/assets" })),
    },
    {
      label: "CBOM refs", icon: "⬡",
      items: bomComponents.map((b) => ({ name: b.ref, meta: `cbom v1843 · ${b.type}`, to: "#/app/cbom" })),
    },
    {
      label: "Evidence IDs", icon: "⛨",
      items: evidenceChain.map((e) => ({ name: e.id, meta: `${e.kind} · ${e.method}`, to: "#/app/evidence" })),
    },
  ];
}

export function search(query: string, limit = 5): SearchGroup[] {
  const q = query.trim().toLowerCase();
  if (!q) return buildSearchIndex().map((g) => ({ ...g, items: g.items.slice(0, limit) }));
  return buildSearchIndex()
    .map((g) => ({ ...g, items: g.items.filter((i) => (i.name + " " + i.meta).toLowerCase().includes(q)).slice(0, limit) }))
    .filter((g) => g.items.length > 0);
}

export const severityTone: Record<Severity, "red" | "amber" | "green"> = {
  CRITICAL: "red", HIGH: "red", MEDIUM: "amber", LOW: "green",
};

/* ── organization (spec §34) ────────────────────────────────────────── */
export const organization: RegionUnit[] = [
  {
    id: "in", name: "India", flag: "IN",
    bu: [
      { id: "in-pay", name: "Payments BU", env: [
        { name: "prod", assets: 41209, crypto: 14211, risk: "MEDIUM" },
        { name: "staging", assets: 8122, crypto: 2914, risk: "LOW" },
        { name: "dev", assets: 14088, crypto: 5031, risk: "LOW" },
      ]},
      { id: "in-retail", name: "Retail BU", env: [
        { name: "prod", assets: 22041, crypto: 8310, risk: "HIGH" },
        { name: "staging", assets: 3991, crypto: 1402, risk: "MEDIUM" },
      ]},
    ],
  },
  {
    id: "uae", name: "UAE", flag: "AE",
    bu: [
      { id: "uae-core", name: "Core Banking", env: [
        { name: "prod", assets: 18920, crypto: 7422, risk: "HIGH" },
        { name: "staging", assets: 3102, crypto: 1180, risk: "LOW" },
      ]},
    ],
  },
  {
    id: "us", name: "USA", flag: "US",
    bu: [
      { id: "us-treasury", name: "Treasury", env: [
        { name: "prod", assets: 10110, crypto: 3914, risk: "MEDIUM" },
      ]},
    ],
  },
  {
    id: "eu", name: "EU", flag: "EU",
    bu: [
      { id: "eu-psd2", name: "PSD2 Services", env: [
        { name: "prod", assets: 15212, crypto: 5990, risk: "MEDIUM" },
        { name: "dev", assets: 4011, crypto: 1520, risk: "LOW" },
      ]},
    ],
  },
  {
    id: "sg", name: "Singapore", flag: "SG",
    bu: [
      { id: "sg-mas", name: "MAS Reporting", env: [
        { name: "prod", assets: 6422, crypto: 2311, risk: "LOW" },
      ]},
    ],
  },
  {
    id: "uk", name: "UK", flag: "GB",
    bu: [
      { id: "uk-fca", name: "FCA Services", env: [
        { name: "prod", assets: 8895, crypto: 3312, risk: "MEDIUM" },
      ]},
    ],
  },
];

/* ── notification center (spec §37) ────────────────────────────────── */
export const notificationTypes: NotificationType[] = [
  { id: "n1", name: "Critical crypto change", severity: "CRITICAL", channels: { inApp: true, email: true, webhook: true, siem: true } },
  { id: "n2", name: "New asset discovered", severity: "LOW", channels: { inApp: true, email: false, webhook: false, siem: true } },
  { id: "n3", name: "New certificate", severity: "MEDIUM", channels: { inApp: true, email: true, webhook: false, siem: true } },
  { id: "n4", name: "PQC risk change", severity: "HIGH", channels: { inApp: true, email: true, webhook: true, siem: true } },
  { id: "n5", name: "Crypto drift", severity: "HIGH", channels: { inApp: true, email: true, webhook: true, siem: true } },
  { id: "n6", name: "Scanner failure", severity: "CRITICAL", channels: { inApp: true, email: true, webhook: true, siem: true } },
  { id: "n7", name: "Cloud change", severity: "MEDIUM", channels: { inApp: true, email: false, webhook: true, siem: true } },
  { id: "n8", name: "Vendor change", severity: "MEDIUM", channels: { inApp: true, email: false, webhook: false, siem: false } },
  { id: "n9", name: "Hardware change", severity: "MEDIUM", channels: { inApp: true, email: false, webhook: true, siem: true } },
  { id: "n10", name: "Compliance failure", severity: "HIGH", channels: { inApp: true, email: true, webhook: true, siem: true } },
];

/* ── live crypto changes (spec §16) ────────────────────────────────── */
export const cryptoChanges: CryptoChangeItem[] = [
  { t: "09:41:22", category: "CERTIFICATE", text: "payments.internal re-keyed → ML-DSA-65 · CBOM v1843", severity: "LOW" },
  { t: "09:12:07", category: "CLOUD", text: "aws-elb-pay certificate list updated", severity: "MEDIUM" },
  { t: "08:58:44", category: "HARDWARE", text: "fw-edge-01 PAN-OS 11.1.1 → 11.1.2", severity: "MEDIUM" },
  { t: "08:31:15", category: "NETWORK", text: "sw-dc-03 joined 10.0.2.0/24", severity: "HIGH" },
  { t: "07:55:02", category: "HARDWARE", text: "hsm-02 firmware 5.4.0 → 5.4.1", severity: "LOW" },
  { t: "06:40:19", category: "ALGORITHM", text: "payments svc AES-CBC → AES-256-GCM", severity: "LOW" },
  { t: "05:12:48", category: "VENDOR", text: "Acme Secure product list +1 (crypto accelerator)", severity: "LOW" },
  { t: "04:20:11", category: "PROTOCOL", text: "gateway-04 dropped TLS 1.1 · ciphers renegotiated", severity: "LOW" },
  { t: "03:07:52", category: "CERTIFICATE", text: "legacy-bank.example RSA-1024 expired", severity: "CRITICAL" },
  { t: "02:44:01", category: "LIBRARY", text: "payments-svc OpenSSL 3.5.0 → 3.5.1", severity: "LOW" },
  { t: "02:10:33", category: "PQC", text: "ML-KEM-768 active on gw-vpn-01 — readiness PQC_READY", severity: "LOW" },
  { t: "01:52:09", category: "ALGORITHM", text: "new RSA-2048 dependency — authentication-service", severity: "HIGH" },
];

/* ── agents (spec §27) ─────────────────────────────────────────────── */
export const agents: AgentRow[] = [
  { id: "agt-0001", scanner: "Network Scanner", host: "10.0.1.11", version: "2.4.0", status: "HEALTHY", lastSeen: "2 s" },
  { id: "agt-0002", scanner: "Network Scanner", host: "10.0.1.12", version: "2.4.0", status: "HEALTHY", lastSeen: "2 s" },
  { id: "agt-0003", scanner: "Cloud Scanner", host: "aws:us-east-1", version: "2.4.0", status: "HEALTHY", lastSeen: "4 s" },
  { id: "agt-0004", scanner: "Cloud Scanner", host: "azure:central-india", version: "2.3.9", status: "DEGRADED", lastSeen: "11 min" },
  { id: "agt-0005", scanner: "Cloud Scanner", host: "gcp:asia-south1", version: "2.4.0", status: "HEALTHY", lastSeen: "4 s" },
  { id: "agt-0006", scanner: "Vendor Scanner", host: "vendor-hub-01", version: "2.4.0", status: "HEALTHY", lastSeen: "7 s" },
  { id: "agt-0007", scanner: "Hardware Scanner", host: "10.0.2.21", version: "2.4.0", status: "HEALTHY", lastSeen: "3 s" },
  { id: "agt-0008", scanner: "Hardware Scanner", host: "10.0.2.22", version: "2.3.9", status: "DEGRADED", lastSeen: "9 min" },
  { id: "agt-0009", scanner: "Crypto Scanner", host: "crypto-scan-01", version: "2.4.1", status: "HEALTHY", lastSeen: "1 s" },
  { id: "agt-0010", scanner: "Crypto Scanner", host: "crypto-scan-02", version: "2.4.1", status: "HEALTHY", lastSeen: "1 s" },
];

/* ── what-if cost (spec §30) ───────────────────────────────────────── */
export const cost: CostEstimate = {
  effortPersonWeeks: 184,
  teams: ["payments-team", "platform-eng", "netsec", "data-platform"],
  totalCostUsd: 482000,
  riskReductionPct: 47,
  durationWeeks: 26,
};

/* ── migration roadmap detail (spec §31) ───────────────────────────── */
export const migrationDetail = {
  teams: [
    { name: "payments-team", apps: 184, owner: "A. Sharma", status: "MIGRATING" },
    { name: "platform-eng", apps: 512, owner: "J. Chen", status: "PLANNED" },
    { name: "netsec", apps: 41, owner: "R. Gupta", status: "TESTING" },
    { name: "data-platform", apps: 87, owner: "S. Nair", status: "ASSESSED" },
  ],
  vendors: [
    { name: "Acme Secure", commitment: "ML-KEM firmware Q1", status: "ON TRACK" },
    { name: "BankVault HSM", commitment: "no PQC firmware yet", status: "AT RISK" },
    { name: "OpenSSL (community)", commitment: "FIPS 203/204/205", status: "ON TRACK" },
  ],
  hardware: [
    { device: "hsm-pci-01", action: "firmware 7.2.1 → 7.3 (ML-KEM-768)", status: "READY" },
    { device: "accel-01", action: "ML-KEM-1024 enabled", status: "READY" },
    { device: "hsm-02", action: "BankVault PQC firmware (blocked)", status: "BLOCKED" },
  ],
  cloud: [
    { service: "aws/kms", action: "ML-KEM keys enabled", status: "READY" },
    { service: "azure/kv", action: "PQC preview enabled", status: "READY" },
    { service: "gcp/kms", action: "PQC keys GA", status: "READY" },
  ],
};
