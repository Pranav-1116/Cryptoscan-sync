/**
 * Presentation-side RBAC, one vocabulary.
 *
 * The backend authorises every request (this is a courtesy that keeps the
 * UI honest: you cannot click what the server would refuse). Role lists
 * here mirror the backend's `require_roles(...)` tuples so a control and
 * its endpoint agree — keep them in step when the router changes.
 */

/** Roles allowed automation/policy writes (matches automation.py `_ADMINS`). */
export const AUTOMATION_WRITE_ROLES = ["admin", "superadmin", "ciso", "security_analyst"] as const;

/** Roles allowed evidence/configuration writes (matches write routers). */
export const EVIDENCE_WRITE_ROLES = ["admin", "superadmin", "ciso", "security_analyst"] as const;
