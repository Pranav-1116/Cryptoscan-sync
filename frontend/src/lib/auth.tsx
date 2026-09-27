/* Server-verified session state and the route guard built on it.
 *
 * Why this exists
 * ---------------
 * Every route used to render for anonymous visitors. `/admin` and `/tenancy`
 * mounted and ran their data fetches; only the backend's 401 kept the data
 * back. That is a real finding in a security review even though no data
 * leaked: the console advertised its whole surface, and any page that fell
 * back to an empty state on error looked like a legitimately empty estate
 * rather than a locked one.
 *
 * Worse, `roles` were read from localStorage, which the person sitting at the
 * browser can edit. Any UI decision taken from them ("can this user approve a
 * baseline?") was therefore advisory at best.
 *
 * So: the session is whatever `GET /api/v1/auth/me` says it is, held in
 * memory, refreshed on auth events. localStorage stays as a first-paint hint
 * only — it can make the UI briefly optimistic, never permissive, because the
 * server answer always replaces it and the backend enforces regardless.
 */
import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { apiAuthMe, getRoles, getUserName } from "./api.js";

export type AuthStatus = "loading" | "authenticated" | "anonymous";

export type AuthState = {
  status: AuthStatus;
  /** Username as the server reports it, null when not signed in. */
  user: string | null;
  /** Roles as the server reports them. Never read from localStorage. */
  roles: string[];
  /** True once the server has answered at least once. */
  verified: boolean;
  /** Re-ask the server (after sign-in, or when a 401 is observed). */
  refresh: () => Promise<void>;
};

const AuthContext = createContext<AuthState>({
  status: "loading",
  user: null,
  roles: [],
  verified: false,
  refresh: async () => {},
});

export function useAuth(): AuthState {
  return useContext(AuthContext);
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [status, setStatus] = useState<AuthStatus>("loading");
  const [user, setUser] = useState<string | null>(null);
  const [roles, setRoles] = useState<string[]>([]);
  const [verified, setVerified] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const me = await apiAuthMe();
      if (me && me.username) {
        setUser(me.username);
        setRoles(me.roles || []);
        setStatus("authenticated");
      } else {
        // The server did answer, and the answer is "nobody".
        setUser(null);
        setRoles([]);
        setStatus("anonymous");
      }
    } catch {
      // Network/backend failure is not proof of a session. Treat it as
      // anonymous so the guard fails closed rather than admitting on an
      // outage; the login screen surfaces backend reachability separately.
      setUser(null);
      setRoles([]);
      setStatus("anonymous");
    } finally {
      setVerified(true);
    }
  }, []);

  useEffect(() => {
    void refresh();
    // setToken() dispatches this on sign-in and sign-out.
    const onAuthChange = () => void refresh();
    window.addEventListener("zelinx:auth", onAuthChange);
    return () => window.removeEventListener("zelinx:auth", onAuthChange);
  }, [refresh]);

  const value = useMemo<AuthState>(
    () => ({ status, user, roles, verified, refresh }),
    [status, user, roles, verified, refresh],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

/** Best-effort cached identity, for first paint only. Never authorises. */
export function cachedIdentity(): { user: string | null; roles: string[] } {
  return { user: getUserName(), roles: getRoles() };
}

/**
 * Gate a subtree behind a verified session.
 *
 * While the server is still answering this renders `fallback` rather than
 * redirecting, so a slow /auth/me does not bounce a signed-in operator to the
 * login screen on every reload.
 */
export function RequireAuth({ children }: { children: React.ReactNode }) {
  const { status } = useAuth();
  const location = useLocation();

  if (status === "loading") {
    return <div style={{ padding: 20 }}>Checking your session…</div>;
  }
  if (status === "anonymous") {
    // Remember where they were headed so sign-in can return them there.
    return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />;
  }
  return <>{children}</>;
}

/**
 * Hide a control the session's roles do not allow.
 *
 * This is presentation only. The backend authorises every request regardless;
 * hiding a button the server would refuse is a courtesy to the operator, not
 * a control, and must never be the only thing standing between a user and an
 * action.
 */
export function RequireRole({
  anyOf,
  children,
  fallback = null,
}: {
  anyOf: string[];
  children?: React.ReactNode;
  fallback?: React.ReactNode;
}) {
  const { roles } = useAuth();
  const allowed = roles.some((r) => anyOf.includes(r));
  return <>{allowed ? children : fallback}</>;
}
