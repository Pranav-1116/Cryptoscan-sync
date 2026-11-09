import React from "react";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider, RequireAuth } from "../lib/auth";
import { I18nProvider } from "../i18n/I18n";
import en from "../i18n/en.json";
import Login from "./Login";

const authMocks = vi.hoisted(() => ({
  me: vi.fn(),
  login: vi.fn(),
}));
vi.mock("../lib/api.js", () => ({
  apiAuthMe: () => authMocks.me(),
  apiLogin: (...args: unknown[]) => authMocks.login(...args),
  isBackendLive: async () => true,
  getRoles: () => [],
  getUserName: () => null,
}));

function Location() {
  const { pathname } = useLocation();
  return <output data-testid="path">{pathname}</output>;
}

function renderLogin() {
  return render(
    <AuthProvider>
      <I18nProvider>
        <MemoryRouter initialEntries={["/login"]}>
          <Routes>
            <Route path="/login" element={<><Login /><Location /></>} />
            <Route path="/command-center" element={
              <RequireAuth><h1>Workspace ready</h1><Location /></RequireAuth>
            } />
          </Routes>
        </MemoryRouter>
      </I18nProvider>
    </AuthProvider>,
  );
}

beforeEach(() => {
  authMocks.me.mockReset();
  authMocks.login.mockReset();
});

describe("login to authenticated workspace", () => {
  it("waits for /auth/me instead of bouncing back to login", async () => {
    let resolveVerified!: (value: { username: string; roles: string[] }) => void;
    const verified = new Promise<{ username: string; roles: string[] }>((resolve) => {
      resolveVerified = resolve;
    });
    authMocks.me.mockResolvedValueOnce(null).mockImplementation(() => verified);
    authMocks.login.mockImplementation(async () => {
      window.dispatchEvent(new CustomEvent("zelinx:auth", { detail: { token: true } }));
      return { ok: true };
    });
    renderLogin();
    await waitFor(() => expect(authMocks.me).toHaveBeenCalledTimes(1));
    fireEvent.change(screen.getByLabelText(en["login.username"]), { target: { value: "operator" } });
    fireEvent.change(screen.getByLabelText(en["login.password"]), { target: { value: "strong-credential" } });
    fireEvent.click(screen.getByRole("button", { name: en["login.signIn"] }));
    await waitFor(() => expect(authMocks.me).toHaveBeenCalledTimes(3));
    expect(screen.getByTestId("path")).toHaveTextContent("/login");
    await act(async () => resolveVerified({ username: "operator", roles: ["superadmin"] }));
    expect(await screen.findByRole("heading", { name: "Workspace ready" })).toBeInTheDocument();
    expect(screen.getByTestId("path")).toHaveTextContent("/command-center");
  });

  it("ignores an older anonymous check that finishes after sign-in", async () => {
    let resolveInitial!: (value: null) => void;
    const initial = new Promise<null>((resolve) => { resolveInitial = resolve; });
    authMocks.me.mockImplementationOnce(() => initial)
      .mockResolvedValue({ username: "operator", roles: ["superadmin"] });
    authMocks.login.mockImplementation(async () => {
      window.dispatchEvent(new CustomEvent("zelinx:auth", { detail: { token: true } }));
      return { ok: true };
    });
    renderLogin();
    await waitFor(() => expect(authMocks.me).toHaveBeenCalledTimes(1));
    fireEvent.change(screen.getByLabelText(en["login.username"]), { target: { value: "operator" } });
    fireEvent.change(screen.getByLabelText(en["login.password"]), { target: { value: "strong-credential" } });
    fireEvent.click(screen.getByRole("button", { name: en["login.signIn"] }));
    expect(await screen.findByRole("heading", { name: "Workspace ready" })).toBeInTheDocument();
    await act(async () => resolveInitial(null));
    expect(screen.getByTestId("path")).toHaveTextContent("/command-center");
  });

  it("stays at login when the server cannot verify the new session", async () => {
    authMocks.me.mockResolvedValue(null);
    authMocks.login.mockResolvedValue({ ok: true });
    renderLogin();
    await waitFor(() => expect(authMocks.me).toHaveBeenCalledTimes(1));
    fireEvent.change(screen.getByLabelText(en["login.username"]), { target: { value: "operator" } });
    fireEvent.change(screen.getByLabelText(en["login.password"]), { target: { value: "strong-credential" } });
    fireEvent.click(screen.getByRole("button", { name: en["login.signIn"] }));
    expect(await screen.findByRole("alert")).toHaveTextContent("session could not be verified");
    expect(screen.getByTestId("path")).toHaveTextContent("/login");
    expect(screen.queryByRole("heading", { name: "Workspace ready" })).toBeNull();
  });
});
