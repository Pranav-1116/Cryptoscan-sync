/* Core domain types shared across the console. */

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type QuantumStatus = "QUANTUM_SAFE" | "QUANTUM_VULNERABLE" | "PQC_UNKNOWN";
export type PqcReady = "PQC_READY" | "HYBRID_READY" | "MIGRATION_REQUIRED";

export interface AlgorithmInfo {
  name: string;
  op: string;
  library: string;
  quantum: QuantumStatus;
  priority: Severity;
  usage: boolean;
  usageCount: number;
  assets: number;
  confidence: number;
}

export interface CertificateInfo {
  cn: string;
  sig: string;
  key: string;
  days: number;
  san: number;
  eku: string;
  status: "VALID" | "EXPIRING" | "EXPIRED";
  owner: string;
}

export interface TrustFinding {
  type: string;
  detail: string;
  severity: Severity;
}

export interface LibraryInfo {
  name: string;
  version: string;
  provider: string;
  pqc: boolean;
  apps: number;
  algorithms: number;
  upgrade: string;
}

export interface ProtocolInfo {
  protocol: string;
  version: string;
  cipher: string;
  kex: string;
  signature: string;
  cert: string;
  endpoint: string;
  risk: Severity;
  pqc: string;
}

export interface HardwareDevice {
  id: string;
  type: string;
  vendor: string;
  firmware: string;
  caps: string[];
  host: string;
  status: string;
}

export interface FirmwareRow {
  device: string;
  kind: string;
  version: string;
  status: string;
}

export interface CloudResource {
  provider: string;
  service: string;
  name: string;
  certs: string[];
  kms: string;
  status: string;
}

export interface NetworkAsset {
  kind: string;
  id: string;
  ip: string;
  tls: string;
  certs: string[];
  os: string;
  status: string;
}

export interface VendorInfo {
  name: string;
  products: number;
  pqc: string;
  risk: Severity;
  score: number;
  devices: number;
  firmware: number;
  configs: number;
  findings: number;
}

export interface EventItem {
  t: string;
  tag: string;
  text: string;
  severity?: Severity;
}

export interface AccuracyRow {
  name: string;
  cases: number;
  prec: number;
  rec: number;
  f1: number;
  cov: number;
  cat: string;
}

export interface AssetRow {
  id: string;
  type: string;
  name: string;
  env: string;
  region: string;
  owner: string;
  risk: Severity;
  evidence: number;
}

export interface BomComponent {
  type: string;
  name: string;
  ref: string;
}

export interface BomDependency {
  ref: string;
  dependsOn: string[];
}

export interface ComplianceRow {
  framework: string;
  requirement: string;
  control: string;
  status: "COMPLIANT" | "PARTIAL" | "NON-COMPLIANT" | "UNKNOWN";
  evidence: string;
}

export interface TimelineRow {
  t: string;
  tag: string;
  text: string;
}

export interface AlertItem {
  severity: Severity;
  title: string;
  detail: string;
  ago: string;
  acked: boolean;
}

export interface ScannerRow {
  name: string;
  status: "RUNNING" | "PAUSED" | "STOPPED" | "SCHEDULED";
  health: number;
  lastRun: string;
  findings: number;
}

export interface KanbanCard {
  id: string;
  title: string;
  apps: number;
  owner: string;
  risk: Severity;
}

export interface EvidenceLink {
  id: string;
  kind: string;
  detail: string;
  method: string;
  confidence: number;
  firstSeen: string;
  lastSeen: string;
  hash: string;
  prev: string | null;
}

export interface SearchGroup {
  label: string;
  icon: string;
  items: { name: string; meta: string; to: string }[];
}

export interface RegionUnit {
  id: string;
  name: string;
  flag: string;
  bu: { id: string; name: string; env: { name: string; assets: number; crypto: number; risk: Severity }[] }[];
}

export interface NotificationType {
  id: string;
  name: string;
  channels: { inApp: boolean; email: boolean; webhook: boolean; siem: boolean };
  severity: Severity;
}

export interface CryptoChangeItem {
  t: string;
  category: "CERTIFICATE" | "PROTOCOL" | "LIBRARY" | "PQC" | "HARDWARE" | "CLOUD" | "NETWORK" | "ALGORITHM" | "VENDOR";
  text: string;
  severity: Severity;
}

export interface AgentRow {
  id: string;
  scanner: string;
  host: string;
  version: string;
  status: "HEALTHY" | "DEGRADED";
  lastSeen: string;
}

export interface CostEstimate {
  effortPersonWeeks: number;
  teams: string[];
  totalCostUsd: number;
  riskReductionPct: number;
  durationWeeks: number;
}
