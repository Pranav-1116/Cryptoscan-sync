/* GENERATED — do not edit. Source: shared_models/capability_maturity.py
 * Regenerate: python scripts/gen_capability_maturity.py
 *
 * Which console surfaces are GA, beta or preview. The Layout reads this to
 * label every page; unknown routes are "preview" (nothing is promoted by
 * omission). The API serves the same table with rationale at
 * GET /api/v1/platform/capabilities. */

export type Tier = "ga" | "beta" | "preview";

export const TIER_LABEL: Record<Tier, string> = {"ga": "GA", "beta": "Beta", "preview": "Preview"};

export const TIER_DETAIL: Record<Tier, string> = {
  "ga": "Production-supported. Deterministic core, broad tests, in the burn-in.",
  "beta": "Real code and real data; thinner test coverage or short deployment history.",
  "preview": "Working surface over a small engine, or analysis over inputs not yet collected at scale."
};

export const CAPABILITIES_JSON = {
  "accuracy": "preview",
  "admin": "ga",
  "agility": "beta",
  "alerts": "ga",
  "assets": "ga",
  "automation": "beta",
  "banking-regulatory": "beta",
  "catalog": "beta",
  "cbom": "ga",
  "certificates": "ga",
  "cloud": "ga",
  "cmdb": "beta",
  "command-center": "ga",
  "compliance": "ga",
  "crypto": "ga",
  "crypto-assets": "ga",
  "crypto-assurance": "beta",
  "crypto-changes": "beta",
  "dependency-graph": "beta",
  "dev-sec-ops": "ga",
  "digital-twin": "beta",
  "drift": "ga",
  "evidence": "ga",
  "executive": "beta",
  "findings": "ga",
  "governance": "beta",
  "graph": "beta",
  "hardware": "beta",
  "hbom": "beta",
  "identity": "ga",
  "integrations": "ga",
  "invite-accept": "beta",
  "libraries": "ga",
  "live-asset-intelligence": "ga",
  "live-environment": "beta",
  "live-scanners": "ga",
  "live-stream": "ga",
  "login": "ga",
  "migration": "beta",
  "nbom": "preview",
  "network": "ga",
  "notifications": "beta",
  "onboarding": "beta",
  "operator-decisions": "preview",
  "organization": "beta",
  "platform-p2": "preview",
  "pqc": "ga",
  "pqc-map": "preview",
  "priorities": "beta",
  "protocols": "beta",
  "register": "beta",
  "remediation": "beta",
  "reports": "ga",
  "reset-password": "ga",
  "resilience": "beta",
  "risk": "beta",
  "role-dashboard": "beta",
  "runtime": "beta",
  "scanners": "ga",
  "scope": "ga",
  "search-results": "ga",
  "sectors": "beta",
  "security": "beta",
  "security-center": "ga",
  "security-intelligence": "preview",
  "security-policy": "ga",
  "settings": "ga",
  "supervision": "preview",
  "system-health": "ga",
  "telecom": "beta",
  "tenancy": "beta",
  "timeline": "preview",
  "trust": "preview",
  "vendor": "ga",
  "vendor-due-diligence": "preview",
  "what-if": "preview"
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
