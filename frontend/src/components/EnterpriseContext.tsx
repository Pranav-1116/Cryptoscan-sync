/* EnterpriseContext — platform view-profile state for the console shell.
 *
 * What is REAL here:
 *  - `role` and `roles` come from the authenticated session (localStorage
 *    written by the /auth/login + /auth/me flow in lib/api.ts). There is no
 *    fake role: an anonymous session is "offline".
 *  - `org` (organization / tenant) comes from the live backend
 *    (GET /api/v1/scope/tenant/isolation) when reachable; otherwise it is
 *    the honest "no tenant" state.
 *
 * What is a VIEW PROFILE (display only, persisted per browser):
 *  - `env` (Production/Staging/Development/DR) — the deployment environment
 *    the operator is *reviewing*; it colours the header badge and is used by
 *    dashboards as context. It never changes backend behaviour.
 *  - `infoLevel` — Executive / SecOps / Technical display density.
 *  - `timezone` — UTC / Local / GST display timezone.
 */
import React, {
  createContext, useCallback, useContext, useEffect, useState,
} from "react";
import {
  activeTenantId, apiTenantIsolation, getRoles, getUserName, setActiveTenantId,
} from "../lib/api.js";
import { useAuth } from "../lib/auth.js";

export type InfoLevel =
  | "Level 1 — Executive"
  | "Level 2 — Security Operations"
  | "Level 3 — Technical Investigation";

export type EnvProfile = "Production" | "Staging" | "Development" | "DR";

export interface EnterpriseState {
  /** Display name of the signed-in user (null when offline). */
  user: string | null;
  /** Real RBAC roles from the session (e.g. ["superadmin"]). */
  roles: string[];
  /** Human label for the primary role, "offline" when anonymous. */
  role: string;
  /** Organization / tenant display name from the live backend. */
  org: { name: string; sector: string };
  env: EnvProfile;
  setEnv: (e: EnvProfile) => void;
  infoLevel: InfoLevel;
  setInfoLevel: (l: InfoLevel) => void;
  timezone: "UTC" | "Local" | "GST";
  setTimezone: (t: "UTC" | "Local" | "GST") => void;
}

const ROLE_LABELS: Record<string, string> = {
  superadmin: "Super Admin",
  admin: "Super Admin",
  ciso: "CISO",
  security_analyst: "Security Analyst",
  developer: "Developer",
  auditor: "Auditor",
  business_owner: "Business Owner",
  scanner: "Scanner",
  readonly: "Read-only",
  viewer: "Read-only",
  supervisor: "Supervisor",
};

const Ctx = createContext<EnterpriseState | null>(null);

function readStored<T>(key: string, fallback: T): T {
  try {
    const v = localStorage.getItem(key);
    return (v as T) ?? fallback;
  } catch {
    return fallback;
  }
}

function writeStored(key: string, value: string) {
  try { localStorage.setItem(key, value); } catch { /* private mode */ }
}

export function EnterpriseProvider({ children }: { children: React.ReactNode }) {
  // Identity and roles come from AuthProvider, which holds what
  // GET /auth/me returned. Cached values are used only for the first paint;
  // privileged controls use RequireRole, which reads the verified AuthProvider
  // state rather than this display context.
  const auth = useAuth();
  const [user, setUser] = useState<string | null>(() => getUserName());
  const [roles, setRoles] = useState<string[]>(() => getRoles());
  const [org, setOrg] = useState<{ name: string; sector: string }>({ name: "Platform", sector: "—" });
  const [env, setEnvState] = useState<EnvProfile>(() => readStored("zelnx_env_profile", "Production") as EnvProfile);
  const [infoLevel, setInfoLevelState] = useState<InfoLevel>(() => readStored("zelnx_info_level", "Level 1 — Executive") as InfoLevel);
  const [timezone, setTimezoneState] = useState<"UTC" | "Local" | "GST">(() => readStored("zelnx_timezone", "UTC") as "UTC");
  const [selectedTenant, setSelectedTenant] = useState<string | null>(() => activeTenantId());

  // Tenant selection is changed by the modal and may also be cleared on
  // logout. Keep the display and live-data refresh tied to that event rather
  // than leaving the previous organization painted until a full reload.
  useEffect(() => {
    const refreshTenant = () => setSelectedTenant(activeTenantId());
    window.addEventListener("zelinx:tenant", refreshTenant);
    window.addEventListener("zelinx:auth", refreshTenant);
    return () => {
      window.removeEventListener("zelinx:tenant", refreshTenant);
      window.removeEventListener("zelinx:auth", refreshTenant);
    };
  }, []);

  // Adopt the server's answer as soon as it arrives, and never fall back to
  // localStorage afterwards: once verified, an edited cache must not be able
  // to re-grant a role the server did not return.
  useEffect(() => {
    if (!auth.verified) return;
    setUser(auth.user);
    setRoles(auth.roles);
  }, [auth.verified, auth.user, auth.roles]);

  // Organization: the active tenant's name from the live backend (honest
  // fallback when offline).
  useEffect(() => {
    let cancelled = false;
    if (!selectedTenant) {
      setOrg({ name: "Platform", sector: "—" });
      return;
    }
    apiTenantIsolation().then((res) => {
      if (cancelled) return;
      if (res.source === "live" && res.data) {
        const current = (res.data.tenants || []).find(
          (t) => t.id === selectedTenant || t.name === selectedTenant,
        );
        if (!current) {
          // A stale/foreign browser value is not a tenant choice. Clear it
          // only after the authorized live directory answered; transport
          // failures must not destroy a valid offline selection.
          setActiveTenantId(null);
          setOrg({ name: "Platform", sector: "—" });
          return;
        }
        setOrg({ name: `${current.name} · ${current.sector}`, sector: current.sector || "—" });
      }
    });
    return () => { cancelled = true; };
  }, [selectedTenant]);

  const setEnv = useCallback((e: EnvProfile) => {
    setEnvState(e);
    writeStored("zelnx_env_profile", e);
  }, []);
  const setInfoLevel = useCallback((l: InfoLevel) => {
    setInfoLevelState(l);
    writeStored("zelnx_info_level", l);
  }, []);
  const setTimezone = useCallback((t: "UTC" | "Local" | "GST") => {
    setTimezoneState(t);
    writeStored("zelnx_timezone", t);
  }, []);

  const primaryRole = roles[0]
    ? (ROLE_LABELS[roles[0]] || roles[0])
    : (user ? "Member" : "offline");

  const value: EnterpriseState = {
    user, roles, role: primaryRole, org,
    env, setEnv, infoLevel, setInfoLevel, timezone, setTimezone,
  };

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useEnterprise(): EnterpriseState {
  const ctx = useContext(Ctx);
  if (!ctx) {
    // Sensible defaults outside the provider (e.g. in storybook/tests).
    return {
      user: null, roles: [], role: "offline", org: { name: "Platform", sector: "—" },
      env: "Production", setEnv: () => {}, infoLevel: "Level 1 — Executive",
      setInfoLevel: () => {}, timezone: "UTC", setTimezone: () => {},
    };
  }
  return ctx;
}
