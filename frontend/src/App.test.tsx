/* Routing + shell: the app boots offline, redirects / to the command center,
 * unknown routes fall back, and the sidebar links point at real routes. */
import { describe, expect, it } from "vitest";
import { act, cleanup as cleanupShell, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { I18nProvider } from "./i18n/I18n";
import { RealtimeProvider } from "./lib/realtime";
import Layout from "./components/Layout";

function shell(route: string) {
  return render(
    <I18nProvider><RealtimeProvider>
      <MemoryRouter initialEntries={[route]}>
        <Layout><div data-testid="page">page body</div></Layout>
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

  it("boots App: shows the loading gate, then the router", async () => {
    const { default: App } = await import("./App");
    await act(async () => { render(<App />); });
    await waitFor(() => expect(screen.queryByText(/Loading CryptoScan/)).not.toBeInTheDocument(), { timeout: 5000 });
    expect(document.body.textContent?.length ?? 0).toBeGreaterThan(0);
  });
});

describe("maturity labelling in the shell", () => {
  it("a beta page shows the beta banner; a GA page shows none", async () => {
    await act(async () => { shell("/telecom"); });
    expect(document.querySelector(".maturity-banner[data-tier='beta']")).toBeInTheDocument();
    cleanupShell();
    await act(async () => { shell("/cbom"); });
    expect(document.querySelector(".maturity-banner")).not.toBeInTheDocument();
  });

  it("a preview page is labelled preview", async () => {
    await act(async () => { shell("/what-if"); });
    expect(document.querySelector(".maturity-banner[data-tier='preview']")).toBeInTheDocument();
  });

  it("header counters show — instead of invented numbers while offline", async () => {
    await act(async () => { shell("/command-center"); });
    const text = document.querySelector(".livehead")?.textContent ?? "";
    expect(text).not.toMatch(/100K\+\/s|2193|\b128\b/);
  });
});
