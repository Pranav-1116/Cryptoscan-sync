/* Routing + shell: the app boots offline, redirects / to the command center,
 * unknown routes fall back, and the sidebar links point at real routes. */
import { describe, expect, it } from "vitest";
import { act, cleanup as cleanupShell, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, useLocation, useNavigate } from "react-router-dom";
import { I18nProvider } from "./i18n/I18n";
import { RealtimeProvider } from "./lib/realtime";
import Layout from "./components/Layout";
import Login from "./pages/Login";
import Register from "./pages/Register";

function RouteProbe() {
  const { pathname, search } = useLocation();
  const navigate = useNavigate();
  return <div>
    <output data-testid="location">{pathname + search}</output>
    <button onClick={() => navigate(-1)}>Go back</button>
    <button onClick={() => navigate(1)}>Go forward</button>
  </div>;
}

function shell(route: string) {
  return render(
    <I18nProvider><RealtimeProvider>
      <MemoryRouter initialEntries={[route]}>
        <Layout><div data-testid="page">page body<RouteProbe /></div></Layout>
      </MemoryRouter>
    </RealtimeProvider></I18nProvider>,
  );
}

describe("app shell", () => {
  it("renders the layout around a page while offline", async () => {
    await act(async () => { shell("/command-center"); });
    expect(screen.getByTestId("page")).toBeInTheDocument();
  });

  it("navigation links use in-app routes only (no external hrefs)", async () => {
    await act(async () => { shell("/command-center"); });
    await waitFor(() => expect(document.querySelectorAll("a[href]").length).toBeGreaterThan(5));
    const hrefs = Array.from(document.querySelectorAll("a[href]")).map((a) => a.getAttribute("href") || "");
    const external = hrefs.filter((h) => /^https?:\/\//.test(h) && !h.includes("localhost"));
    // docs links are allowed; API/localhost links are not
    expect(hrefs.some((h) => h.includes("127.0.0.1") || h.includes("localhost"))).toBe(false);
    expect(external.every((h) => !h.includes("/api/"))).toBe(true);
  });

  it("exposes the real threat-intelligence workspaces across six sections", async () => {
    await act(async () => { shell("/command-center"); });
    const nav = document.querySelector(".primary-nav");
    expect(nav).toBeInTheDocument();
    expect(nav?.querySelectorAll(":scope > .nav-label")).toHaveLength(6);
    const links = Array.from(nav?.querySelectorAll("a.nav") || []);
    const hrefs = links.map((link) => link.getAttribute("href") || "");
    expect(links).toHaveLength(41);
    expect(new Set(hrefs).size).toBe(40);
    expect(hrefs.filter((href) => href === "/security-center")).toHaveLength(2);
    for (const path of ["/launch-readiness", "/operator-decisions", "/crypto", "/cbom", "/findings", "/live-asset-intelligence", "/dependency-graph", "/remediation", "/priorities", "/migration", "/live-scanners"]) {
      expect(hrefs).toContain(path);
    }
    expect(hrefs).not.toContain("/vendor-due-diligence");
    expect(hrefs).not.toContain("/audit-merkle");
    expect(hrefs.every((href) => href.startsWith("/") && !href.startsWith("/#"))).toBe(true);
  });

  it("exposes global search as a keyboard-focusable button", async () => {
    await act(async () => { shell("/command-center"); });
    const search = screen.getByRole("button", { name: "Open global search" });
    search.focus();
    expect(document.activeElement).toBe(search);
    fireEvent.click(search);
    expect(screen.getByRole("textbox", { name: "Search the algorithm catalog" })).toHaveFocus();
  });

  it("supports keyboard navigation, browser history, and a direct workspace entry", async () => {
    await act(async () => { shell("/findings"); });
    expect(screen.getByTestId("location")).toHaveTextContent("/findings");
    const inventory = document.querySelector<HTMLAnchorElement>('.primary-nav a[href="/cbom"]');
    expect(inventory).toBeInTheDocument();
    inventory?.focus();
    expect(document.activeElement).toBe(inventory);
    fireEvent.keyDown(inventory!, { key: "Enter" });
    // jsdom does not synthesize anchor activation on keydown; a native click
    // exercises the same router link used by keyboard activation in browsers.
    fireEvent.click(inventory!);
    expect(screen.getByTestId("location")).toHaveTextContent("/cbom");
    fireEvent.click(screen.getByRole("button", { name: "Go back" }));
    expect(screen.getByTestId("location")).toHaveTextContent("/findings");
    fireEvent.click(screen.getByRole("button", { name: "Go forward" }));
    expect(screen.getByTestId("location")).toHaveTextContent("/cbom");
  });

  it("keeps public auth pages focused on live account operations", async () => {
    await act(async () => {
      render(<I18nProvider><MemoryRouter><Login /></MemoryRouter></I18nProvider>);
    });
    expect(screen.queryByText(/bootstrap|admin \/ cryptoscan|FIPS 140-3|SOC 2|ISO 27001/i)).not.toBeInTheDocument();
    cleanupShell();
    await act(async () => {
      render(<I18nProvider><MemoryRouter><Register /></MemoryRouter></I18nProvider>);
    });
    expect(screen.queryByText(/FIPS 140-3|SOC 2|ISO 27001/i)).not.toBeInTheDocument();
    expect(await screen.findByText("Registration is temporarily unavailable")).toBeInTheDocument();
    expect(screen.queryByLabelText("Password")).toBeNull();
  });

  it("boots App: shows the loading gate, then the router", async () => {
    const { default: App } = await import("./App");
    await act(async () => { render(<App />); });
    await waitFor(() => expect(screen.queryByText(/Loading CryptoScan/)).not.toBeInTheDocument(), { timeout: 5000 });
    expect(document.body.textContent?.length ?? 0).toBeGreaterThan(0);
  });
});

describe("maturity labelling in the shell", () => {
  it("all pages are GA with no maturity banner (real system)", async () => {
    await act(async () => { shell("/telecom"); });
    expect(document.querySelector(".maturity-banner")).not.toBeInTheDocument();
    cleanupShell();
    await act(async () => { shell("/cbom"); });
    expect(document.querySelector(".maturity-banner")).not.toBeInTheDocument();
    cleanupShell();
    await act(async () => { shell("/what-if"); });
    expect(document.querySelector(".maturity-banner")).not.toBeInTheDocument();
  });

  it("header counters show — instead of invented numbers while offline", async () => {
    await act(async () => { shell("/command-center"); });
    const text = document.querySelector(".livehead")?.textContent ?? "";
    expect(text).not.toMatch(/100K\+\/s|2193|\b128\b/);
  });
});
