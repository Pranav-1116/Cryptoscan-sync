/* RBAC-aware UI (Critical): controls the session's roles cannot use are
 * hidden — presentation courtesy only; the backend authorises regardless.
 * Roles come from the server via /auth/me (never localStorage). */

import { describe, expect, it } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import React from "react";
import { AuthProvider, RequireRole } from "./auth";
import { AUTOMATION_WRITE_ROLES } from "./rbac";
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
