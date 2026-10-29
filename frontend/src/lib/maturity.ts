/* GENERATED — do not edit. Source: shared_models/capability_maturity.py
 * Regenerate: python scripts/gen_capability_maturity.py
 *
 * Which console surfaces are GA, beta or preview. The Layout reads this to
 * label every page; unknown routes default down to preview.
 * The API serves the same table with rationale at
 * GET /api/v1/platform/capabilities. */

export type Tier = "ga" | "beta" | "preview";

export const TIER_LABEL: Record<Tier, string> = {"ga": "GA", "beta": "Beta", "preview": "Preview"};

export const TIER_DETAIL: Record<Tier, string> = {
  "ga": "Production-supported. Deterministic core, broad tests, in the burn-in.",
  "beta": "Real code and real data; thinner test coverage or short deployment history.",
  "preview": "Working surface over a small engine, or analysis over inputs not yet collected at scale."
};

export const CAPABILITIES_JSON = {
  "accuracy": "ga",
  "admin": "ga",
  "agility": "ga",
  "alerts": "ga",
  "assets": "ga",
  "assurance-coverage": "preview",
  "assurance-qualification": "preview",
  "assurance-records": "preview",
  "assurance-sampling": "preview",
  "assurance-trace": "preview",
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
  "live-asset-intelligence": "ga",
  "live-environment": "ga",
  "live-monitor": "beta",
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
  "sbom": "beta",
  "scanners": "ga",
  "scope": "ga",
  "search-results": "ga",
  "sectors": "ga",
  "security": "ga",
  "security-center": "ga",
  "security-intelligence": "ga",
  "security-policy": "ga",
  "settings": "ga",
  "supervision": "ga",
  "system-health": "ga",
  "telecom": "ga",
  "tenancy": "ga",
  "timeline": "ga",
  "trust": "ga",
  "vbom": "beta",
  "vendor": "ga",
  "vendor-due-diligence": "ga",
  "what-if": "ga"
} as const;

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
