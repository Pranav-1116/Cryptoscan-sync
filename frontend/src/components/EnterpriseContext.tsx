/* ── Enterprise Multi-Tenant & Role Context (Sections 52–57) ── */

import React, { createContext, useContext, useState, useEffect, ReactNode } from "react";
import { getRoles, getUserName } from "../lib/api";

export type UserRole = "Admin" | "Security Administrator" | "Security Engineer" | "Auditor" | "Compliance Officer" | "Viewer";
export type InfoLevel = "Level 1 — Executive" | "Level 2 — Security Operations" | "Level 3 — Technical Investigation";
export type Environment = "Production" | "Staging" | "Development" | "DR" | "Testing";

export interface OrganizationTenant {
  id: string;
  name: string;
  region: string;
  subsidiary: string;
}

export interface EnterpriseState {
  role: UserRole;
  setRole: (r: UserRole) => void;
  infoLevel: InfoLevel;
  setInfoLevel: (l: InfoLevel) => void;
  env: Environment;
  setEnv: (e: Environment) => void;
  org: OrganizationTenant;
  setOrg: (o: OrganizationTenant) => void;
  timezone: "UTC" | "Local" | "GST";
  setTimezone: (tz: "UTC" | "Local" | "GST") => void;
  dataFreshness: "Fresh" | "Delayed" | "Stale" | "Unavailable";
  lastObservationTimestamp: string;
  canPerformAction: (action: "scan" | "policy_edit" | "baseline_change" | "user_manage" | "audit_export") => boolean;
}

export const ORGANIZATIONS: OrganizationTenant[] = [
  { id: "uae", name: "Enterprise Tenant · UAE", region: "Middle East", subsidiary: "UAE Core Banking" },
  { id: "saudi", name: "Enterprise Tenant · Saudi Arabia", region: "Middle East", subsidiary: "KSA Payments" },
  { id: "europe", name: "Enterprise Tenant · Europe", region: "EU (DORA Regulated)", subsidiary: "EU Clearing & Settlement" },
  { id: "singapore", name: "Enterprise Tenant · Singapore", region: "APAC", subsidiary: "Singapore Treasury" },
];

const EnterpriseContext = createContext<EnterpriseState | null>(null);

export function EnterpriseProvider({ children }: { children: ReactNode }) {
  const [role, setRoleState] = useState<UserRole>(() => {
    try { return (localStorage.getItem("zelnx_active_role") as UserRole) || "Security Engineer"; } catch { return "Security Engineer"; }
  });
  const [infoLevel, setInfoLevel] = useState<InfoLevel>("Level 2 — Security Operations");
  const [env, setEnvState] = useState<Environment>(() => {
    try { return (localStorage.getItem("zelnx_active_env") as Environment) || "Production"; } catch { return "Production"; }
  });
  const [org, setOrgState] = useState<OrganizationTenant>(() => {
    try {
      const saved = localStorage.getItem("zelnx_active_org");
      return saved ? JSON.parse(saved) : ORGANIZATIONS[0];
    } catch { return ORGANIZATIONS[0]; }
  });
  const [timezone, setTimezone] = useState<"UTC" | "Local" | "GST">("UTC");
  const [lastObservationTimestamp, setLastObservationTimestamp] = useState("Just now");

  const setRole = (r: UserRole) => {
    setRoleState(r);
    try { localStorage.setItem("zelnx_active_role", r); } catch { /* ignore */ }
  };

  const setEnv = (e: Environment) => {
    setEnvState(e);
    try { localStorage.setItem("zelnx_active_env", e); } catch { /* ignore */ }
  };

  const setOrg = (o: OrganizationTenant) => {
    setOrgState(o);
    try { localStorage.setItem("zelnx_active_org", JSON.stringify(o)); } catch { /* ignore */ }
  };

  const canPerformAction = (action: "scan" | "policy_edit" | "baseline_change" | "user_manage" | "audit_export"): boolean => {
    switch (role) {
      case "Viewer":
        return false;
      case "Auditor":
        return action === "audit_export";
      case "Compliance Officer":
        return action === "audit_export";
      case "Security Engineer":
        return action === "scan" || action === "audit_export";
      case "Security Administrator":
        return action === "scan" || action === "policy_edit" || action === "baseline_change" || action === "audit_export";
      case "Admin":
        return true;
      default:
        return false;
    }
  };

  return (
    <EnterpriseContext.Provider
      value={{
        role,
        setRole,
        infoLevel,
        setInfoLevel,
        env,
        setEnv,
        org,
        setOrg,
        timezone,
        setTimezone,
        dataFreshness: "Fresh",
        lastObservationTimestamp,
        canPerformAction,
      }}
    >
      {children}
    </EnterpriseContext.Provider>
  );
}

export function useEnterprise(): EnterpriseState {
  const ctx = useContext(EnterpriseContext);
  if (!ctx) {
    throw new Error("useEnterprise must be used within an EnterpriseProvider");
  }
  return ctx;
}
