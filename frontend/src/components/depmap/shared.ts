import type { DepRisk } from "../../lib/api";

/* One risk vocabulary for the dependency map and the cascade simulator.
   Worst-first; colours use the theme tokens only (flat, no glow). */
export const RISK_ORDER: DepRisk[] = ["disallowed", "deprecated", "quantum_vulnerable", "unknown", "acceptable", "quantum_safe"];

export const RISK_COLOR: Record<DepRisk, string> = {
  disallowed: "var(--red)",
  deprecated: "var(--orange)",
  quantum_vulnerable: "var(--amber)",
  unknown: "var(--slate)",
  acceptable: "var(--green)",
  quantum_safe: "var(--violet)",
};

export const RISK_TONE: Record<DepRisk, string> = {
  disallowed: "red",
  deprecated: "orange",
  quantum_vulnerable: "amber",
  unknown: "slate",
  acceptable: "green",
  quantum_safe: "violet",
};

export const RISK_SHORT: Record<DepRisk, string> = {
  disallowed: "DISALLOWED",
  deprecated: "DEPRECATED",
  quantum_vulnerable: "QUANTUM-VULNERABLE",
  unknown: "UNCLASSIFIED",
  acceptable: "ACCEPTABLE",
  quantum_safe: "POST-QUANTUM",
};

export const riskColor = (r?: DepRisk | null) => (r ? RISK_COLOR[r] : "var(--line-strong)");

export const CRIT_TONE: Record<string, string> = { CRITICAL: "red", HIGH: "orange", MEDIUM: "amber", LOW: "green" };

export const COMPONENT_KIND_LABEL: Record<string, string> = {
  source: "source file",
  config: "config file",
  keystore: "keystore",
  tls_endpoint: "live TLS endpoint",
};

export function truncate(text: string, max: number): string {
  if (!text) return "";
  return text.length > max ? text.slice(0, Math.max(1, max - 1)) + "…" : text;
}

export const isWeak = (r?: DepRisk | null) => r === "disallowed" || r === "deprecated";
export const needsMigration = (r?: DepRisk | null) => isWeak(r) || r === "quantum_vulnerable";
