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
  createContext, useCallback, useContext, useEffect, useMemo, useState,
} from "react";
import {
  activeTenantId, apiTenantIsolation, getRoles, getUserName,
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
  /** Deterministic RBAC check derived from the session's real roles. */
  canPerformAction: (action: "scan" | "approve" | "admin" | "view") => boolean;
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

function deriveCanPerform(roles: string[], user: string | null) {
  const r = new Set(roles);
  const write = r.has("superadmin") || r.has("admin") || r.has("ciso")
    || r.has("security_analyst") || r.has("auditor") || r.has("developer");
  return (action: "scan" | "approve" | "admin" | "view"): boolean => {
    if (!user) return false; // anonymous session: nothing
    switch (action) {
      case "scan": return write;
      case "approve": return r.has("superadmin") || r.has("admin") || r.has("ciso") || r.has("auditor");
      case "admin": return r.has("superadmin") || r.has("admin");
      case "view": return true;
    }
  };
}

export function EnterpriseProvider({ children }: { children: React.ReactNode }) {
  // Identity and roles come from AuthProvider, which holds what
  // GET /auth/me returned. They used to be read straight out of localStorage,
  // which the person at the browser can edit -- so every canPerformAction()
  // decision was taken from attacker-controlled input. The cached values are
  // still used for the very first paint, before the server has answered.
  const auth = useAuth();
  const [user, setUser] = useState<string | null>(() => getUserName());
  const [roles, setRoles] = useState<string[]>(() => getRoles());
  const [org, setOrg] = useState<{ name: string; sector: string }>({ name: "Platform", sector: "—" });
  const [env, setEnvState] = useState<EnvProfile>(() => readStored("zelnx_env_profile", "Production") as EnvProfile);
  const [infoLevel, setInfoLevelState] = useState<InfoLevel>(() => readStored("zelnx_info_level", "Level 1 — Executive") as InfoLevel);
  const [timezone, setTimezoneState] = useState<"UTC" | "Local" | "GST">(() => readStored("zelnx_timezone", "UTC") as "UTC");

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
    if (!activeTenantId()) {
      setOrg({ name: "Platform", sector: "—" });
      return;
    }
    apiTenantIsolation().then((res) => {
      if (cancelled) return;
      if (res.source === "live" && res.data) {
        const current = (res.data.tenants || []).find(
          (t) => t.id === activeTenantId() || t.name === activeTenantId(),
        );
        setOrg({
          name: current ? `${current.name} · ${current.sector}` : "Platform",
          sector: current?.sector || "—",
        });
      }
    });
    return () => { cancelled = true; };
  }, []);

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

  const canPerformAction = useMemo(() => deriveCanPerform(roles, user), [roles, user]);

  const primaryRole = roles[0]
    ? (ROLE_LABELS[roles[0]] || roles[0])
    : (user ? "Member" : "offline");

  const value: EnterpriseState = {
    user, roles, role: primaryRole, org,
    env, setEnv, infoLevel, setInfoLevel, timezone, setTimezone,
    canPerformAction,
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
      canPerformAction: () => false,
    };
  }
  return ctx;
}
