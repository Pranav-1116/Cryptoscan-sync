// Intelligence workbench types — mirrored from the shared_models roadmap modules
// (threat_intelligence, risk_dimensions, pqc_claims, estate_coverage,
// scenario_simulation). Field names match the Python schemas so payloads can be
// dropped in without a translation layer that could drift.

export type ThreatClass =
  | "CRYPTO_REGRESSION"
  | "WEAK_ALGORITHM_EXPOSURE"
  | "CERTIFICATE_RISK"
  | "TRUST_PATH_MUTATION"
  | "HSM_DEPENDENCY"
  | "LIBRARY_RISK"
  | "VENDOR_RISK"
  | "COLLECTION_BLIND_SPOT"
  | "PQC_REGRESSION";

export interface ThreatFinding {
  class: ThreatClass;
  asset: string;
  what_changed: string;
  why_it_matters: string;
  evidence_ids: string[];
  not_proven: string;
  investigate: string;
  compromise_declared: boolean;
}

export interface RiskFactor {
  rule: string;
  input: string;
  contribution: number;
  evidence_ids: string[];
}

export interface RiskDimension {
  dimension: string;
  score: number | null;
  band: string;
  sense: "risk" | "confidence";
  factors: RiskFactor[];
  evidence_ids: string[];
  reason: string | null;
  known: boolean;
  rules_version?: string;
}

export type PqcStageName =
  | "SUPPORT_AVAILABLE"
  | "CONFIGURED"
  | "RUNTIME_OBSERVED"
  | "NETWORK_NEGOTIATED"
  | "MIGRATION_VALIDATED";

export interface PqcStageState {
  state: string; // CLAIMED | CLAIMED_STALE | NOT_CLAIMED
  reason?: string;
}

export interface PqcSubject {
  subject: string;
  stages: Record<PqcStageName, PqcStageState>;
  readiness: string;
  readiness_reason: string;
  contradictions: Array<Record<string, unknown>>;
}

export interface CoverageGap {
  kind: string;
  count: number;
  detail: string;
  is_clean_result: boolean;
}

export interface CoverageIntelligence {
  verdict: string; // COVERAGE_COMPLETE | COVERAGE_ATTENTION | COVERAGE_INCOMPLETE
  reason: string;
  authorized_targets: number;
  discovered_assets: number;
  unknown_assets: number;
  stale_evidence: number;
  access_denied_targets: number;
  unverified_relationships: number;
  gaps: CoverageGap[];
  coverage_percent: number | null;
  percent_note: string | null;
}

export interface ChainHop {
  from: string;
  predicate: string;
  to: string;
  provenance: "PROVEN" | "INFERRED" | "UNKNOWN";
  evidence_ids: string[];
}

export interface SimulatedDependency {
  asset: string;
  chain: ChainHop[];
  why_assumed?: string;
}

export interface SimulationResult {
  scenario: string;
  description: string;
  hypothetical: boolean;
  snapshot: { snapshot_id: string; version: number | string; captured_at: string };
  proven_dependencies: SimulatedDependency[];
  assumed_dependencies: SimulatedDependency[];
  approvals_required: string[];
  rollback_plan: string[];
}

// ---- API response shapes (api/routers/roadmap_intelligence.py) ----------

export interface ThreatReport {
  findings: ThreatFinding[];
  counts: Record<string, number>;
  compromise_declared: boolean;
  note: string;
  detectors_fired?: string[];
  detectors_not_fired?: Record<string, string>;
  sources?: Record<string, string>;
}

export interface PqcReport {
  subjects: Record<string, Omit<PqcSubject, "subject">>;
  counts: Record<string, number>;
  note: string;
  derived_from?: string;
}

export interface RiskProfile {
  dimensions: Record<string, RiskDimension>;
  blended_requested: boolean;
  blended_score: number | null;
  blended_arithmetic: string[];
  excluded_dimensions: string[];
  note: string;
  asset_id?: string;
  algorithm?: string | null;
  usage_state?: string | null;
}

export interface IntelligenceOverview {
  schema: string;
  endpoints: Record<string, string>;
  scenarios: string[];
  threat_classes: string[];
  note: string;
}

export interface IntelligenceSimulationRequest {
  scenario: string;
  focal_asset: string;
  snapshot_id?: string;
  snapshot_version?: number;
}
