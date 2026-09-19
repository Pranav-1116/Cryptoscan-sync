/* authService — thin bridge for account credential flows.
 *
 * The platform's credential (re)establishment path is the SaaS invite flow:
 * POST /api/v1/saas/invites/accept redeems a token and, for an invited
 * account, sets the password (a valid invite token is the only way an
 * outsider's password state changes). This module maps that real endpoint
 * onto the small surface the auth pages need — it never invents outcomes.
 */
import { apiSaasAcceptInvite } from "./api.js";

export const authService = {
  /**
   * Reset / set the password bound to `token`.
   *
   * @param token   invite/reset token from the link the user opened
   * @param password new password (must satisfy the server password policy)
   * @returns `{ ok: true }` on success; `{ ok: false, error }` when the
   *          token is invalid/expired, the password is rejected by policy,
   *          or the backend is unreachable.
   */
  async resetPassword(token: string | null, password: string): Promise<{ ok: boolean; error?: string }> {
    if (!token) return { ok: false, error: "No reset token found in the link." };
    if (!password) return { ok: false, error: "Password is required." };
    const res = await apiSaasAcceptInvite({ token, password });
    if (res.ok) return { ok: true };
    // Translate the specific backend errors into page-friendly copy.
    const e = res.error || "";
    if (e.includes("invalid, expired, revoked or already used")) {
      return { ok: false, error: "Reset link expired or invalid." };
    }
    if (e.includes("password")) return { ok: false, error: e };
    return { ok: false, error: e || "Reset failed." };
  },
};

export default authService;
