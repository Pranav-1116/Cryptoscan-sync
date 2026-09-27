/* Route guard and server-verified roles.
 *
 * The failure these protect against is specific: every route used to render
 * for anonymous visitors, and `roles` came from localStorage, which the person
 * at the browser can edit. So the tests that matter are "an anonymous visitor
 * is redirected" and "an edited localStorage role is discarded once the server
 * has answered".
 */
import React from "react";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AuthProvider, RequireAuth, RequireRole, useAuth } from "./auth.js";

const mockAuthMe = vi.fn();
vi.mock("./api.js", () => ({
  apiAuthMe: () => mockAuthMe(),
  getRoles: () => {
    try {
      return JSON.parse(localStorage.getItem("zelinx_roles") || "[]");
    } catch {
      return [];
    }
  },
  getUserName: () => localStorage.getItem("zelinx_user"),
}));

function Protected() {
  return <div>estate findings</div>;
}

function LoginScreen() {
  return <div>sign in</div>;
}

function renderApp(initial = "/admin") {
  return render(
    <AuthProvider>
      <MemoryRouter initialEntries={[initial]}>
        <Routes>
          <Route path="/login" element={<LoginScreen />} />
          <Route
            path="*"
            element={
              <RequireAuth>
                <Protected />
              </RequireAuth>
            }
          />
        </Routes>
      </MemoryRouter>
    </AuthProvider>,
  );
}

beforeEach(() => {
  localStorage.clear();
  mockAuthMe.mockReset();
});

afterEach(() => {
  localStorage.clear();
});

describe("RequireAuth", () => {
  it("sends an anonymous visitor to the login screen", async () => {
    mockAuthMe.mockResolvedValue(null);
    renderApp("/admin");
    expect(await screen.findByText("sign in")).toBeTruthy();
    expect(screen.queryByText("estate findings")).toBeNull();
  });

  it("renders the page for a verified session", async () => {
    mockAuthMe.mockResolvedValue({ username: "analyst", roles: ["auditor"] });
    renderApp("/admin");
    expect(await screen.findByText("estate findings")).toBeTruthy();
  });

  it("does not render the page while the session is still being checked", () => {
    // Never resolves: the guard must show the checking state, not the page,
    // and must not bounce a signed-in operator to /login on a slow /auth/me.
    mockAuthMe.mockReturnValue(new Promise(() => {}));
    renderApp("/admin");
    expect(screen.queryByText("estate findings")).toBeNull();
    expect(screen.queryByText("sign in")).toBeNull();
  });

  it("fails closed when /auth/me errors", async () => {
    // A backend outage is not proof of a session.
    mockAuthMe.mockRejectedValue(new Error("network down"));
    renderApp("/admin");
    expect(await screen.findByText("sign in")).toBeTruthy();
  });

  it("a forged localStorage identity does not get past the guard", async () => {
    localStorage.setItem("zelinx_user", "attacker");
    localStorage.setItem("zelinx_roles", JSON.stringify(["superadmin"]));
    mockAuthMe.mockResolvedValue(null);
    renderApp("/admin");
    expect(await screen.findByText("sign in")).toBeTruthy();
  });
});

describe("roles come from the server", () => {
  function ShowRoles() {
    const { roles, verified } = useAuth();
    return <div data-testid="roles">{verified ? roles.join(",") || "none" : "pending"}</div>;
  }

  it("discards an edited localStorage role once the server answers", async () => {
    localStorage.setItem("zelinx_roles", JSON.stringify(["superadmin"]));
    mockAuthMe.mockResolvedValue({ username: "analyst", roles: ["readonly"] });

    render(
      <AuthProvider>
        <ShowRoles />
      </AuthProvider>,
    );

    await waitFor(() => {
      expect(screen.getByTestId("roles").textContent).toBe("readonly");
    });
  });

  it("RequireRole hides a control the session's roles do not allow", async () => {
    localStorage.setItem("zelinx_roles", JSON.stringify(["superadmin"]));
    mockAuthMe.mockResolvedValue({ username: "analyst", roles: ["readonly"] });

    render(
      <AuthProvider>
        <RequireRole anyOf={["superadmin", "admin"]}>
          <button>approve baseline</button>
        </RequireRole>
      </AuthProvider>,
    );

    await waitFor(() => {
      expect(screen.queryByText("approve baseline")).toBeNull();
    });
  });

  it("RequireRole shows a control the session's roles allow", async () => {
    mockAuthMe.mockResolvedValue({ username: "boss", roles: ["superadmin"] });

    render(
      <AuthProvider>
        <RequireRole anyOf={["superadmin"]}>
          <button>approve baseline</button>
        </RequireRole>
      </AuthProvider>,
    );

    expect(await screen.findByText("approve baseline")).toBeTruthy();
  });
});
