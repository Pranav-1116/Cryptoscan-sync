/* Empty initial state for the ZELNX console.
 *
 * There is NO demo / sample / seed data in the product. Every collection
 * starts empty and every metric starts at zero; the console is populated
 * only by the live control plane once a real discovery/scan runs. Nested
 * object keys are retained where pages index into them, but all values are
 * empty/zero so nothing renders fabricated content.
 */

import type {
  AlgorithmInfo, CertificateInfo, TrustFinding, LibraryInfo, ProtocolInfo,
  HardwareDevice, FirmwareRow, CloudResource, NetworkAsset, VendorInfo,
  EventItem, AccuracyRow, AssetRow, BomComponent, BomDependency,
  ComplianceRow, TimelineRow, AlertItem, ScannerRow, KanbanCard, EvidenceLink,
  SearchGroup, Severity, RegionUnit, NotificationType, CryptoChangeItem,
  AgentRow, CostEstimate,
} from "../types.js";

/* ── global state (command center) — zero until the platform reports ── */
export const globalState = {
  totalAssets: 0,
  cryptoAssets: 0,
  risks: 0,
  criticalFindings: 0,
  highFindings: 0,
  pqcReadyPct: 0,
  hybridReadyPct: 0,
  migrationRequiredPct: 0,
  migrationProgressPct: 0,
  pqcExposurePct: 0,
  activeScanners: 0,
  totalScanners: 0,
  eventsPerSec: 0,
  agentsHealthy: 0,
  agentsTotal: 0,
  scannerHealthPct: 0,
  evidenceHealthPct: 0,
  cbomVersion: 0,
  hbomVersion: 0,
  liveChanges24h: 0,
  agilityScore: 0,
  lastEventSeconds: 0,
};

/* ── discovery / inventory — empty until a scan runs ───────────────── */
export const networkAssets: NetworkAsset[] = [];
export const cloudResources: CloudResource[] = [];
export const vendors: VendorInfo[] = [];
export const hardware: HardwareDevice[] = [];
export const firmwareRows: FirmwareRow[] = [];
export const algorithms: AlgorithmInfo[] = [];
export const certificates: CertificateInfo[] = [];

export const certCenter = {
  expired: 0,
  expiring30: 0,
  weakAlgorithm: 0,
  unknownOwner: 0,
  pqcMigration: 0,
};

export const trustFindings: TrustFinding[] = [];
export const libraries: LibraryInfo[] = [];
export const protocols: ProtocolInfo[] = [];
export const assets: AssetRow[] = [];

/* ── live feed / alerts / timeline ─────────────────────────────────── */
export const events: EventItem[] = [];
export const alerts: AlertItem[] = [];
export const timelineRows: TimelineRow[] = [];

/* ── bills of materials ────────────────────────────────────────────── */
export const bomComponents: BomComponent[] = [];
export const bomDependencies: BomDependency[] = [];
export const bomDiff = { added: [] as string[], removed: [] as string[], changed: [] as string[] };
export const bomHistory: { version: string; at: string; note: string; by: string }[] = [];

/* ── pqc / agility / risk — zeros and empty breakdowns ─────────────── */
export const pqc = {
  overall: 0,
  ready: 0,
  hybrid: 0,
  migrationRequired: 0,
  vulnerable: { rsa: 0, ecc: 0, dh: 0, legacy: 0 },
  byFunction: [] as { group: string; safe: string[]; vulnerable: string[]; unknown: number }[],
};

export const agility = {
  score: 0,
  hardCoded: 0,
  configurable: 0,
  pqcReady: 0,
  hybridReady: 0,
  byApp: [] as { app: string; score: number; hard: number; config: number; pqc: number }[],
};

export const risk = {
  counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
  matrix: {
    "impact:high/exposure:high": 0,
    "impact:high/exposure:low": 0,
    "impact:low/exposure:high": 0,
    "impact:low/exposure:low": 0,
  },
  topFindings: [] as { id: string; title: string; severity: string; assets: number; evidence: number }[],
};

/* ── drift baseline vs live — empty (no baseline frozen yet) ───────── */
const emptyDriftSide = () => ({
  network: [] as string[],
  cloud: [] as string[],
  vendor: [] as string[],
  hardware: [] as string[],
  crypto: [] as string[],
  certificate: [] as string[],
  protocol: [] as string[],
  firmware: [] as string[],
  pqc: [] as string[],
});
export const drift = { baseline: emptyDriftSide(), live: emptyDriftSide() };

/* ── planning / what-if — no analysis until the user runs one ──────── */
export const whatif = {
  current: "",
  target: "",
  feasible: false,
  compatibility: 0,
  complexity: "—",
  impact: { applications: 0, apis: 0, certificates: 0, vendors: 0, hardware: 0, cloud: 0 },
  checks: {
    dependencies: { affectedLibraries: 0, libraries: [] as string[] },
    libraries: { supported: false, supporting: [] as string[] },
    hardware: { supported: false, pqcCapable: 0, devices: [] as string[] },
    vendor: { supported: false, pqcPositive: 0, vendors: [] as string[] },
    cloud: { supported: false, pqcReadyServices: 0, services: [] as string[] },
    impact: { projectedQuantumStatus: "—", protocolCompatibility: {} as Record<string, string> },
  },
  plan: [] as string[],
};

export const migrationBoard: { col: string; cards: KanbanCard[] }[] = [];

/* ── governance / compliance / evidence ────────────────────────────── */
export const compliance: ComplianceRow[] = [];
export const governance = {
  owners: [] as { asset: string; owner: string; approved: string; by: string }[],
  exceptions: [] as { id: string; asset: string; reason: string; expires: string; approvedBy: string }[],
  audit: [] as { t: string; actor: string; action: string; target: string }[],
};
export const evidenceChain: EvidenceLink[] = [];

/* ── scanners / reports / integrations ─────────────────────────────── */
export const scanners: ScannerRow[] = [];
export const reports: { kind: string; title: string; desc: string; status: string; generated: string }[] = [];
export const integrations: { name: string; kind: string; status: string; detail: string }[] = [];

/* RBAC reference model — static product configuration (the 8-role catalog
   enforced by the backend), not scan/estate data. Tenants start empty. */
export const rbac = {
  roles: [
    "SUPER ADMIN", "SECURITY ADMIN", "CRYPTO ADMIN", "CLOUD ADMIN", "NETWORK ADMIN",
    "AUDITOR", "COMPLIANCE", "ENGINEER", "VIEWER",
  ],
  permissions: [
    "view", "scan", "configure", "export", "approve", "delete", "simulate", "manage policies", "manage users",
  ],
  matrix: {
    "SUPER ADMIN": [1, 1, 1, 1, 1, 1, 1, 1, 1],
    "SECURITY ADMIN": [1, 1, 1, 1, 1, 0, 1, 1, 0],
    "CRYPTO ADMIN": [1, 1, 1, 1, 1, 0, 1, 1, 0],
    "CLOUD ADMIN": [1, 1, 1, 1, 0, 0, 0, 0, 0],
    "NETWORK ADMIN": [1, 1, 1, 1, 0, 0, 0, 0, 0],
    "AUDITOR": [1, 0, 0, 1, 0, 0, 0, 0, 0],
    "COMPLIANCE": [1, 0, 0, 1, 0, 0, 0, 0, 0],
    "ENGINEER": [1, 1, 0, 0, 0, 0, 1, 0, 0],
    "VIEWER": [1, 0, 0, 0, 0, 0, 0, 0, 0],
  } as Record<string, number[]>,
  tenants: [] as { id: string; name: string; region: string; assets: number; scanners: number; status: string }[],
};

/* ── accuracy — zero until a real benchmark run produces measurements ─ */
export const accuracy: AccuracyRow[] = [];
export const accuracyMean = { datasets: 0, cases: 0, f1: 0, prec: 0, rec: 0, fpr: 0, fnr: 0 };

/* ── search index — empty until real inventory exists ──────────────── */
export function buildSearchIndex(): SearchGroup[] {
  return [];
}
export function search(_query: string, _limit = 5): SearchGroup[] {
  return [];
}

export const severityTone: Record<Severity, "red" | "amber" | "green"> = {
  CRITICAL: "red", HIGH: "red", MEDIUM: "amber", LOW: "green",
};

/* ── organization — empty until onboarding defines the estate scope ── */
export const organization: RegionUnit[] = [];

/* Notification event-class catalog is served live by the control plane
   (GET /notifications/catalog + /notifications/routing); no static catalog. */

/* ── live crypto changes / agents — populated by real streams ──────── */
export const cryptoChanges: CryptoChangeItem[] = [];
export const agents: AgentRow[] = [];

/* ── what-if cost / migration roadmap — empty until a plan exists ──── */
export const cost: CostEstimate = {
  effortPersonWeeks: 0,
  teams: [],
  totalCostUsd: 0,
  riskReductionPct: 0,
  durationWeeks: 0,
};

export const migrationDetail = {
  teams: [] as { name: string; apps: number; owner: string; status: string }[],
  vendors: [] as { name: string; commitment: string; status: string }[],
  hardware: [] as { device: string; action: string; status: string }[],
  cloud: [] as { service: string; action: string; status: string }[],
};
