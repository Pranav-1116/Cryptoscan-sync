import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";
import Register from "./Register";

const scope = { platform: "CryptoScan", schema_version: 1, covered_areas: [], non_goals: [] };

function fill(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

describe("registration workspace", () => {
  it("shows a useful offline state without presenting a dead role picker or accepting credentials", async () => {
    renderWithProviders(<Register />);
    expect(await screen.findByText("Registration is temporarily unavailable")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Create read-only account" })).toBeNull();
    expect(screen.queryByText("superadmin")).toBeNull();
    expect(screen.getByRole("link", { name: "Return to sign in" })).toHaveAttribute("href", "/login");
  });

  it("submits a least-privilege real API request when the backend is reachable", async () => {
    const fetcher = mockFetch({
      "/api/v1/platform/scope": scope,
      "/api/v1/auth/register": () => new Response(JSON.stringify({ username: "analyst", roles: ["readonly"] }), {
        status: 201, headers: { "Content-Type": "application/json" },
      }),
    });
    renderWithProviders(<Register />);
    expect(await screen.findByRole("heading", { name: "Create your account" })).toBeInTheDocument();
    expect(await screen.findByLabelText("Username")).toBeInTheDocument();
    expect(screen.queryByText("superadmin")).toBeNull();
    fill("Username", "analyst");
    fill("Password", "Str0ng!Test-2026");
    fill("Confirm password", "Str0ng!Test-2026");
    fireEvent.click(screen.getByRole("button", { name: "Show password" }));
    expect(screen.getByLabelText("Password")).toHaveAttribute("type", "text");
    fireEvent.click(screen.getByRole("button", { name: "Create read-only account" }));
    await waitFor(() => expect(fetcher.mock.calls.some(([url]) => String(url) === "/api/v1/auth/register")).toBe(true));
    const request = fetcher.mock.calls.find(([url]) => String(url) === "/api/v1/auth/register");
    expect(JSON.parse(String(request?.[1]?.body))).toMatchObject({ username: "analyst", role: "readonly" });
  });
});
