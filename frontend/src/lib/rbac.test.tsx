/* RBAC-aware UI (Critical): controls the session's roles cannot use are
 * hidden — presentation courtesy only; the backend authorises regardless.
 * Roles come from the server via /auth/me (never localStorage). */

import { describe, expect, it } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import React from "react";
import { AuthProvider, RequireRole } from "./auth";
import { AUTOMATION_WRITE_ROLES, EDGE_WRITE_ROLES, SCHEDULE_WRITE_ROLES, PACK_OPERATE_ROLES, SCAN_OPERATE_ROLES, ADMIN_CISO_ROLES } from "./rbac";
import { mockFetch } from "../test/setup";

function DeleteControl() {
  return (
    <RequireRole anyOf={[...AUTOMATION_WRITE_ROLES]}>
      <button>delete rule</button>
    </RequireRole>
  );
}

describe("RequireRole", () => {
  it("hides the control when the session's roles do not match", async () => {
    mockFetch({ "/api/v1/auth/me": { username: "vera", roles: ["viewer"] } });
    render(
      <AuthProvider>
        <DeleteControl />
      </AuthProvider>,
    );
    await waitFor(() => expect(screen.queryByText("delete rule")).toBeNull());
  });

  it("shows the control when a role matches", async () => {
    mockFetch({ "/api/v1/auth/me": { username: "vera", roles: ["auditor", "admin"] } });
    render(
      <AuthProvider>
        <DeleteControl />
      </AuthProvider>,
    );
    await waitFor(() => expect(screen.getByText("delete rule")).toBeTruthy());
  });
});

function Gate({ roles, anyOf }: { roles: string[]; anyOf: string[] }) {
  (globalThis as { __TEST_ROLES__?: string[] }).__TEST_ROLES__ = roles;
  return (
    <RequireRole anyOf={anyOf}>
      <button>write</button>
    </RequireRole>
  );
}

describe("role-family mirrors (UI list == backend tuple)", () => {
  const cases: Array<[string, string[], string[], boolean]> = [
    // [name, session roles, allowed family, visible?]
    ["edge writes hide from auditor", ["auditor"], [...EDGE_WRITE_ROLES], false],
    ["edge writes show for security_analyst", ["security_analyst"], [...EDGE_WRITE_ROLES], true],
    ["schedule creation shows for auditor (require_auditor)", ["auditor"], [...SCHEDULE_WRITE_ROLES], true],
    ["pack operate hides from viewer", ["viewer"], [...PACK_OPERATE_ROLES], false],
    ["scan operate shows for scanner service role", ["scanner"], [...SCAN_OPERATE_ROLES], true],
    ["admin/ciso writes hide from scanner", ["scanner"], [...ADMIN_CISO_ROLES], false],
  ];
  for (const [name, roles, family, visible] of cases) {
    it(name, async () => {
      mockFetch({ "/api/v1/auth/me": { username: "vera", roles } });
      render(
        <AuthProvider>
          <Gate roles={roles} anyOf={family} />
        </AuthProvider>,
      );
      await waitFor(() =>
        visible
          ? expect(screen.getByText("write")).toBeTruthy()
          : expect(screen.queryByText("write")).toBeNull());
    });
  }
});
