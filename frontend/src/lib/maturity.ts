/* GENERATED — do not edit. Source: shared_models/capability_maturity.py
 * Regenerate: python scripts/gen_capability_maturity.py
 *
 * Support status of every console surface. Every shipped surface is "ga"; the
 * sidebar does not label pages. CAPABILITY_LIMITS carries the sentence that
 * says what each surface does not do — that is the honest part, and /scope
 * renders it. Unknown routes default down to "preview".
 * The API serves the same table with rationale at
 * GET /api/v1/platform/capabilities. */

export type Tier = "ga" | "beta" | "preview";

export const TIER_LABEL: Record<Tier, string> = {"ga": "Supported", "beta": "Limited deployment", "preview": "Unclassified"};

export const TIER_DETAIL: Record<Tier, string> = {
  "ga": "Shipped and supported. Any limit is stated with the surface, not in the navigation.",
  "beta": "Reserved for a surface under a stated limited deployment. No shipped surface uses it.",
  "preview": "What a route with no rationale resolves to. Unknown routes default down, never to supported."
};

export const CAPABILITIES_JSON = {
  "accuracy": "ga",
  "admin": "ga",
  "agility": "ga",
  "alerts": "ga",
  "assets": "ga",
  "assurance-coverage": "ga",
  "assurance-qualification": "ga",
  "assurance-records": "ga",
  "assurance-sampling": "ga",
  "assurance-trace": "ga",
  "automation": "ga",
  "banking-regulatory": "ga",
  "catalog": "ga",
  "cbom": "ga",
  "certificates": "ga",
  "cloud": "ga",
  "cmdb": "ga",
  "command-center": "ga",
  "compliance": "ga",
  "crypto": "ga",
  "crypto-assets": "ga",
  "crypto-assurance": "ga",
  "crypto-changes": "ga",
  "dependency-graph": "ga",
  "dev-sec-ops": "ga",
  "digital-twin": "ga",
  "drift": "ga",
  "evidence": "ga",
  "executive": "ga",
  "findings": "ga",
  "governance": "ga",
  "graph": "ga",
  "hardware": "ga",
  "hbom": "ga",
  "identity": "ga",
  "integrations": "ga",
  "invite-accept": "ga",
  "launch-readiness": "ga",
  "libraries": "ga",
  "live": "ga",
  "live-asset-intelligence": "ga",
  "live-environment": "ga",
  "live-monitor": "ga",
  "live-scanners": "ga",
  "live-stream": "ga",
  "login": "ga",
  "migration": "ga",
  "nbom": "ga",
  "network": "ga",
  "notifications": "ga",
  "onboarding": "ga",
  "operator-decisions": "ga",
  "organization": "ga",
  "platform-p2": "ga",
  "pqc": "ga",
  "pqc-map": "ga",
  "priorities": "ga",
  "protocols": "ga",
  "register": "ga",
  "remediation": "ga",
  "reports": "ga",
  "reset-password": "ga",
  "resilience": "ga",
  "risk": "ga",
  "role-dashboard": "ga",
  "runtime": "ga",
  "sbom": "ga",
  "scanners": "ga",
  "scope": "ga",
  "search-results": "ga",
  "sectors": "ga",
  "security": "ga",
  "security-center": "ga",
  "security-intelligence": "ga",
  "security-policy": "ga",
  "settings": "ga",
  "simulation": "ga",
  "supervision": "ga",
  "system-health": "ga",
  "telecom": "ga",
  "tenancy": "ga",
  "timeline": "ga",
  "trust": "ga",
  "vbom": "ga",
  "vendor": "ga",
  "vendor-due-diligence": "ga",
  "what-if": "ga"
} as const;

/** route slug -> the limit stated with that surface (rendered on /scope). */
export const CAPABILITY_LIMITS = {
  "accuracy": {
    "area": "Overview",
    "limit": "Detector precision/recall panel; needs labelled ground truth per estate."
  },
  "admin": {
    "area": "Administration",
    "limit": "Admin user management and audit trail."
  },
  "agility": {
    "area": "Intelligence",
    "limit": "Crypto-agility scoring; 900 LOC, 37 tests; scoring model still being calibrated."
  },
  "alerts": {
    "area": "Overview",
    "limit": "Alert stage output + monitor events."
  },
  "assets": {
    "area": "Discovery",
    "limit": "Unified asset inventory (System/CryptoAsset/Certificate) backed by Alembic-managed tables."
  },
  "assurance-coverage": {
    "area": "Governance",
    "limit": "A source register can be declared and read, but observation and revision writes still lack a console workflow; registration is not coverage."
  },
  "assurance-qualification": {
    "area": "Governance",
    "limit": "Read-only qualification views exist; supplier and adapter approval writes require separate operator workflows."
  },
  "assurance-records": {
    "area": "Governance",
    "limit": "Reads immutable assurance revisions, but does not originate or independently approve them."
  },
  "assurance-sampling": {
    "area": "Governance",
    "limit": "Shows frozen predictions without a score; domain-owner sampling review is not submitted from this page."
  },
  "assurance-trace": {
    "area": "Governance",
    "limit": "Displays retained relationship evidence and unresolved links, not a verified runtime call graph."
  },
  "automation": {
    "area": "Administration",
    "limit": "Playbooks + ITSM/SIEM delivery; 2.3k LOC, 6 test files."
  },
  "banking-regulatory": {
    "area": "Governance",
    "limit": "Banking/SWIFT CSP mapping over the policy engine; regulator-specific packs still growing."
  },
  "catalog": {
    "area": "Discovery",
    "limit": "Hardware/vendor catalog browse."
  },
  "cbom": {
    "area": "Intelligence",
    "limit": "Shared Technology BOM (SBOM/CBOM/HBOM/VBOM), snapshots and signed exports; system CBOMs carry real estate dependency edges (SystemAsset + SystemDependency, both directions) and scan CBOMs carry the scanner's observed cascade (providers, waves); the unified cross-BOM cascade answers 'what breaks if X changes' across code, network, system graph, process, hardware, vendor and library layers over the digital-twin snapshot, with persisted run history, run-to-run diffs across every layer, migration-wave grouping, point-in-time replay over captured twin snapshots, and watched targets that alert when the blast radius changes; the Dependency Graph page manages edges and runs cascades in the UI; binary scans additionally expose static NBOM and vulnerability sidecars through Applications."
  },
  "certificates": {
    "area": "Discovery",
    "limit": "Certificate inventory + expiry from network and source scans."
  },
  "cloud": {
    "area": "Discovery",
    "limit": "Read-only AWS/Azure/GCP estate scan; 15k LOC, 25 test files. Needs credentials to show data."
  },
  "cmdb": {
    "area": "Discovery",
    "limit": "CMDB import/resolution; ServiceNow mapping is field-tested with one schema."
  },
  "command-center": {
    "area": "Overview",
    "limit": "Reads the live stats/summary endpoints; empty until a scan runs."
  },
  "compliance": {
    "area": "Governance",
    "limit": "Requirement-by-requirement reports from policy evidence, 6 templates."
  },
  "crypto": {
    "area": "Intelligence",
    "limit": "Algorithm registry + normalized crypto view (114 normalization tests)."
  },
  "crypto-assets": {
    "area": "Intelligence",
    "limit": "Crypto inventory from the normalized findings table."
  },
  "crypto-assurance": {
    "area": "Governance",
    "limit": "KeyAssure checks; 1.7k LOC but a single test module."
  },
  "crypto-changes": {
    "area": "Intelligence",
    "limit": "Change timeline from drift + scan history."
  },
  "dependency-graph": {
    "area": "Intelligence",
    "limit": "Same graph engine as /graph."
  },
  "dev-sec-ops": {
    "area": "Discovery",
    "limit": "SBOM/container/binary/firmware/mobile/WASM scanning, VEX, licence, gates and correlated binary BOM sidecars; bounded evidence and explicit refusal/partial states."
  },
  "digital-twin": {
    "area": "Intelligence",
    "limit": "Estate replica with measured fidelity, evidence reconciliation and ten deterministic scenario types, fed by live state, wire scans, the dependency graph and the hardware fleet; scenario models are heuristic projections, not vendor simulations."
  },
  "drift": {
    "area": "Intelligence",
    "limit": "Baseline approval + drift events + CI gate; 15 test files."
  },
  "evidence": {
    "area": "Governance",
    "limit": "SHA-256 content/chain/manifest hashes, audit packs, verify endpoint."
  },
  "executive": {
    "area": "Overview",
    "limit": "Executive summary over the same stats; presentation layer."
  },
  "findings": {
    "area": "Intelligence",
    "limit": "Policy-evaluated findings with evidence links."
  },
  "governance": {
    "area": "Governance",
    "limit": "Access reviews, exceptions, sign-off; 1.9k LOC, 4 test files."
  },
  "graph": {
    "area": "Intelligence",
    "limit": "Neo4j dependency graph is optional at runtime (in-process engine is the fallback and the tenant-isolated path); 3.2k+ LOC. Edge management API with provenance (source/created_by/confidence/last_verified), discovered-edge adoption (scanner cascade + graph snapshots \u2192 operator approval), declared crypto\u2194hardware and vendor-of-vendor linkage, and asset-level blast radius (shared asset \u2192 union over every using system) are live with tenant-scoped tests; scale evidence on real Neo4j estates is still open."
  },
  "hardware": {
    "area": "Discovery",
    "limit": "HSM/TPM/firmware plugins exist (ADR-014); live hardware collection needs vendor access and has a short field history."
  },
  "hbom": {
    "area": "Intelligence",
    "limit": "Hardware BOM view over the Technology BOM; depends on hardware scan coverage."
  },
  "identity": {
    "area": "Administration",
    "limit": "Users, roles, MFA, OIDC/SAML/LDAP, API keys, lockout, audit chain."
  },
  "integrations": {
    "area": "Administration",
    "limit": "GitHub webhooks, CI gate, SMTP, ITSM/SIEM connectors (burn-in covers them)."
  },
  "invite-accept": {
    "area": "Auth",
    "limit": "Tenant invitations belong to the SaaS mode (beta)."
  },
  "launch-readiness": {
    "area": "Overview",
    "limit": "Gated independent-report, operational-duty and bounded-pilot records; real assessor execution, site exercises and customer acceptance require external evidence."
  },
  "libraries": {
    "area": "Intelligence",
    "limit": "Library fingerprint database (ADR-007)."
  },
  "live": {
    "area": "Overview",
    "limit": "Connection age, stored changes, six BOM downloads and correlated attack patterns. A quiet estate and a stopped agent look identical, so the age is stated; level 3 (incident) is never assigned by the platform, and a pattern reports which collectors corroborate it without raising its level."
  },
  "live-asset-intelligence": {
    "area": "Intelligence",
    "limit": "The unified BOM console: materialise \u2192 version \u2192 compare \u2192 export."
  },
  "live-environment": {
    "area": "Discovery",
    "limit": "Live environment roll-up of runtime + network."
  },
  "live-monitor": {
    "area": "Overview",
    "limit": "Reads actual daemon and estate streams; a live daemon with no enabled schedule does not provide collection coverage."
  },
  "live-scanners": {
    "area": "Discovery",
    "limit": "Live scan runner status; same orchestrator as /scanners."
  },
  "live-stream": {
    "area": "Overview",
    "limit": "SSE event stream with Last-Event-ID resume and Redis federation."
  },
  "login": {
    "area": "Auth",
    "limit": "Password + MFA + SSO login."
  },
  "migration": {
    "area": "Intelligence",
    "limit": "Scan \u2192 project \u2192 tasks \u2192 velocity forecast; forecast model is simple."
  },
  "nbom": {
    "area": "Intelligence",
    "limit": "Network BOM from authorized network evidence plus static binary capability candidates. Binary-derived records are marked `observed: false` and do not prove a live listener; corroboration requires a separately authorized network probe."
  },
  "network": {
    "area": "Discovery",
    "limit": "TLS/cipher/cert probes; 15k LOC, 33 test files."
  },
  "notifications": {
    "area": "Administration",
    "limit": "In-app notifications + SMTP; channels beyond email are connectors."
  },
  "onboarding": {
    "area": "Administration",
    "limit": "Org/connector onboarding flow for SaaS mode."
  },
  "operator-decisions": {
    "area": "Overview",
    "limit": "Exact-estate decision and condition-proof workflow; local workloads tested, site capacity and deployment acceptance remain open."
  },
  "organization": {
    "area": "Administration",
    "limit": "Org structure + business context seed."
  },
  "platform-p2": {
    "area": "Administration",
    "limit": "Phase-2 platform features behind one page (marketplace, datalake, anomaly) \u2014 each < 700 LOC."
  },
  "pqc": {
    "area": "Intelligence",
    "limit": "Quantum classification lives in shared_models (176 tests) and runs as a pipeline stage."
  },
  "pqc-map": {
    "area": "Intelligence",
    "limit": "Geographic/estate PQC map; needs location context the scanners do not collect yet."
  },
  "priorities": {
    "area": "Intelligence",
    "limit": "Deterministic prioritisation over findings + business context."
  },
  "protocols": {
    "area": "Intelligence",
    "limit": "Protocol posture view from network scans."
  },
  "register": {
    "area": "Auth",
    "limit": "Self-service signup is for the multi-tenant SaaS mode (migration 0057), which is beta."
  },
  "remediation": {
    "area": "Intelligence",
    "limit": "Owned task lifecycle with machine verification against rescan evidence; new surface over the full task API."
  },
  "reports": {
    "area": "Output",
    "limit": "JSON/HTML/PDF reports and schedules over the evidence chain."
  },
  "reset-password": {
    "area": "Auth",
    "limit": "Token-based reset with SMTP delivery."
  },
  "resilience": {
    "area": "Administration",
    "limit": "Backup/DR/air-gap status; scripts are tested, the page is new."
  },
  "risk": {
    "area": "Intelligence",
    "limit": "Risk roll-up; weights documented but not yet regulator-validated."
  },
  "role-dashboard": {
    "area": "Overview",
    "limit": "Per-role landing view."
  },
  "runtime": {
    "area": "Discovery",
    "limit": "Host agent findings; agent rollout is per-deployment."
  },
  "sbom": {
    "area": "Intelligence",
    "limit": "A versioned software projection over available evidence; deployments and missing component versions remain unproven."
  },
  "scanners": {
    "area": "Discovery",
    "limit": "Source/network/cloud/container/OT scan triggers over the worker pipeline (12 stages, 29 test files)."
  },
  "scope": {
    "area": "Administration",
    "limit": "Platform scope self-description (platform_scope.py) \u2014 what we do and refuse to do."
  },
  "search-results": {
    "area": "Overview",
    "limit": "Cross-inventory search."
  },
  "sectors": {
    "area": "Governance",
    "limit": "Sector profiles (bank/telecom/energy) select policy packs; 900 LOC."
  },
  "security": {
    "area": "Administration",
    "limit": "Security settings surface; overlaps security-center."
  },
  "security-center": {
    "area": "Administration",
    "limit": "Security posture of the platform itself (headers, rate limits, audit chain verify)."
  },
  "security-intelligence": {
    "area": "Intelligence",
    "limit": "Cross-scanner identity resolution + profiles; roadmap in SECURITY-INTELLIGENCE-ROADMAP.md."
  },
  "security-policy": {
    "area": "Governance",
    "limit": "YAML policy packs (BASELINE/PCI/NIST 131A/CNSA 2.0/FIPS/HIPAA), 82 tests, no AI."
  },
  "settings": {
    "area": "Administration",
    "limit": "App settings + org profile persisted in app_settings."
  },
  "simulation": {
    "area": "Intelligence",
    "limit": "What-if workspace over the estate twin: the estate's own algorithms, protocols, components and assets seed the scenario, a preview says whether the selector matches before the copy is made, the run re-projects the six BOMs from that copy and reports the live projection id unchanged, and a stored run is quarantined against the evidence state it was computed from; scenarios change evidence facts only \u2014 they do not model configuration, traffic, approvals or a deployment plan."
  },
  "supervision": {
    "area": "Governance",
    "limit": "Supervisory-review view for regulators; a read model over evidence, early."
  },
  "system-health": {
    "area": "Administration",
    "limit": "/health, /readyz, /metrics, DB health."
  },
  "telecom": {
    "area": "Discovery",
    "limit": "5G NF TLS/cert posture; 1.5k LOC with 24 tests; ran against lab targets only."
  },
  "tenancy": {
    "area": "Administration",
    "limit": "Multi-tenant core landed in migration 0057; artifact tenancy sealed at rest; single-tenant is GA."
  },
  "timeline": {
    "area": "Overview",
    "limit": "Estate timeline; aggregates several beta sources."
  },
  "trust": {
    "area": "Governance",
    "limit": "Trust-score surface; scoring inputs still being defined."
  },
  "vbom": {
    "area": "Intelligence",
    "limit": "A supplier projection from retained evidence and declarations, not independent supplier validation."
  },
  "vendor": {
    "area": "Discovery",
    "limit": "68 vendor plugins across 16 categories; 14k LOC, 31 test files."
  },
  "vendor-due-diligence": {
    "area": "Discovery",
    "limit": "Strict versioned supplier profiles and provenance metadata are implemented; approval completeness and external vendor validation still require customer qualification."
  },
  "what-if": {
    "area": "Intelligence",
    "limit": "Scenario simulation over the inventory; scenarios are fixed templates today."
  }
} as const;

export type CapabilityLimit = { area: string; limit: string };

export const RETIRED_NAV_ROUTES: readonly string[] = ["/activity", "/audit-merkle", "/cryptographic-digital-twin", "/devsecops", "/hsm-fleet-orchestrator", "/pqc-code-signing-orchestrator", "/quantum-entropy-fabric", "/realtime-system", "/telecom-signaling-analyzer", "/twin-analysis-output", "/zero-trust-crypto-enforcer"];

/** Tier for a pathname such as "/cbom" or "/dev-sec-ops?tab=1". */
export function tierOf(pathname: string): Tier {
  const slug = pathname.replace(/^\/+/, "").split("/")[0].split("?")[0];
  return (CAPABILITIES_JSON as Record<string, Tier>)[slug] ?? "preview";
}

export function tierCounts(): Record<Tier, number> {
  const out: Record<Tier, number> = { ga: 0, beta: 0, preview: 0 };
  for (const tier of Object.values(CAPABILITIES_JSON)) out[tier as Tier] += 1;
  return out;
}
