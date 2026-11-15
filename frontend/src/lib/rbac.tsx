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

/**
 * Each list below mirrors the backend tuple that guards the corresponding
 * write route — a control and its endpoint must agree. When a router's
 * tuple changes, change it here too.
 *
 * Writes that the backend leaves to ANY authenticated principal
 * (host-evidence approvals, controlled-history actions, runtime crypto-scope,
 * network inventory/scope saves, report-snapshot pinning) are deliberately
 * NOT gated here: those are tracked in 102-authenticated-only-writes.json
 * and every session CAN perform them — hiding the control would misstate
 * what the server allows.
 */

/** Dependency-edge registry writes (graph.py edges POST/PATCH/DELETE). */
export const EDGE_WRITE_ROLES = ["admin", "superadmin", "security_analyst"] as const;

/** CBOM legacy reconciliation (cbom.py `require_cbom_writer`). */
export const CBOM_WRITE_ROLES = ["superadmin", "ciso", "security_analyst"] as const;

/** Knowledge-pack install/uninstall (devsecops.py `_SBOM_OPERATORS`). */
export const PACK_OPERATE_ROLES = ["admin", "auditor", "security_analyst", "superadmin"] as const;

/** Live-scan run/start/stop (live_scan.py `_OPERATORS`). */
export const SCAN_OPERATE_ROLES = ["admin", "superadmin", "ciso", "security_analyst", "scanner"] as const;

/** Active-sector switch + notification routing (sectors.py, notifications.py). */
export const ADMIN_CISO_ROLES = ["admin", "superadmin", "ciso"] as const;

/** Report schedule creation (report_schedules.py `require_auditor`). */
export const SCHEDULE_WRITE_ROLES = ["admin", "auditor"] as const;
