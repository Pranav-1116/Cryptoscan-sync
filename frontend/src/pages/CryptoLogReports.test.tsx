/* Reports tests (docs/cryptolog/01_PRODUCT_SPEC.md §9): the export
   carries its filters to the store, the success names the report and its
   manifest contract, and a refused export is a named refusal — never an
   empty archive drawn as a report. */

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mockFetch, offlineFetch } from "../test/setup";
import { apiCryptologReportExport, setActiveTenantId, setToken } from "../lib/api";
import CryptoLogReports from "./CryptoLogReports";
import { withTitles } from "../test/withTitles";

const renderReports = () => render(<CryptoLogReports />);

const stubDownload = () => {
  (globalThis.URL as unknown as { createObjectURL: (b: Blob) => string }).createObjectURL =
    vi.fn(() => "blob:test");
  (globalThis.URL as unknown as { revokeObjectURL: (u: string) => void }).revokeObjectURL =
    vi.fn();
};

describe("CryptoLog reports (§9)", () => {
  afterEach(() => {
    setToken(null);
    setActiveTenantId(null);
    vi.unstubAllGlobals();
  });

  it("exports the pack with the window filters and names the report and its contract", async () => {
    stubDownload();
    const fetchSpy = mockFetch({
      "/api/v1/cryptolog/reports/export": new Response("zip-bytes", {
        status: 200,
        headers: { "X-Report-Id": "cryptolog-20261107T120000Z-abcd1234", "X-Archive-Files": "5" },
      }),
    });
    renderReports();
    fireEvent.change(screen.getByLabelText("report start"), { target: { value: "2026-11-01" } });
    fireEvent.click(screen.getByTestId("export-pack"));
    const done = await screen.findByTestId("report-done");
    expect(done).toHaveTextContent(/cryptolog-20261107T120000Z-abcd1234/);
    expect(done).toHaveTextContent(/5 files/);
    expect(withTitles(done)).toMatch(/missing artifact is unverifiable, not valid/);
    await waitFor(() => {
      const calls = fetchSpy.mock.calls.map(([, init]) => String(init?.body ?? ""));
      expect(calls.some((b) => b.includes("start_occurred") && b.includes("2026-11-01"))).toBe(true);
    });
  });

  it("sends bearer, selected tenant and cookie credentials for ZIP bytes", async () => {
    setToken("bank-session");
    setActiveTenantId("bank-tenant");
    const fetchSpy = mockFetch({
      "/api/v1/cryptolog/reports/export": new Response("zip-bytes", { status: 200 }),
    });
    const exported = await apiCryptologReportExport();
    expect(exported.ok).toBe(true);
    const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(init.credentials).toBe("include");
    expect(init.headers).toMatchObject({
      Authorization: "Bearer bank-session", "X-Tenant-ID": "bank-tenant",
      "Content-Type": "application/json",
    });
  });

  it("never releases ZIP bytes from a tenant switched during the request", async () => {
    setToken("bank-session");
    setActiveTenantId("bank-a");
    let release!: (value: Response) => void;
    mockFetch({
      "/api/v1/cryptolog/reports/export": () =>
        new Promise<Response>((resolve) => { release = resolve; }),
    });
    const pending = apiCryptologReportExport();
    setActiveTenantId("bank-b");
    release(new Response("bank-a-archive", { status: 200 }));
    expect(await pending).toMatchObject({ ok: false, error: "context changed" });
  });

  it("names a refused export instead of drawing an empty archive as a report", async () => {
    offlineFetch();
    renderReports();
    fireEvent.click(screen.getByTestId("export-pack"));
    const failure = await screen.findByTestId("report-failure");
    expect(failure).toHaveTextContent(/never an empty archive drawn as a report/);
  });

  it("starts honest: no export is no report", () => {
    mockFetch({});
    renderReports();
    expect(screen.getByTestId("report-idle")).toHaveTextContent(/No export built yet/);
  });
});
