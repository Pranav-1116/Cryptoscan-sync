import React from "react";
import { act, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import AuthenticatedDownload from "./AuthenticatedDownload";
import { downloadAuthenticatedResource } from "../lib/api";

function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(r => { resolve = r; }); return { promise, resolve }; }
beforeEach(() => { vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {}); vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:scope-test"); });
const click = () => screen.getByRole("button", { name: "Export" }).click();

describe("Authenticated export privacy", () => {
  it.each(["cryptoscan_tenant", "zelinx_signed_in", "zelinx_roles", "zelinx_user", null, "auth", "tenant", "resume", "bfcache"])("does not release old bytes after %s, even if fetch ignores abort", async key => {
    const bytes = deferred<Blob>();
    const response = new Response("private-old-bytes");
    vi.spyOn(response, "blob").mockImplementation(() => bytes.promise);
    globalThis.fetch = vi.fn(async () => response);
    const download = downloadAuthenticatedResource("/api/v1/private-export", "evidence.json");
    const settled = download.then(() => "DOWNLOADED", () => "REFUSED");
    await waitFor(() => expect(response.blob).toHaveBeenCalledOnce());
    if (key === "auth" || key === "tenant") window.dispatchEvent(new Event(`zelinx:${key}`));
    else if (key === "bfcache") window.dispatchEvent(new PageTransitionEvent("pageshow", { persisted: true }));
    else if (key === "resume") document.dispatchEvent(new Event("visibilitychange"));
    else window.dispatchEvent(new StorageEvent("storage", { key }));
    bytes.resolve(new Blob(["private-old-bytes"]));
    expect(await settled).toBe("REFUSED");
    expect(HTMLAnchorElement.prototype.click).not.toHaveBeenCalled();
    expect(URL.createObjectURL).not.toHaveBeenCalled();
  });

  it("blocks a same-turn double click before the busy render", async () => {
    const pending = deferred<Response>();
    globalThis.fetch = vi.fn(() => pending.promise);
    render(<AuthenticatedDownload path="/api/v1/private-export" filename="evidence.json">Export</AuthenticatedDownload>);
    act(() => { click(); click(); });
    expect(globalThis.fetch).toHaveBeenCalledOnce();
  });

  it("does not download after leaving the page while response bytes are pending", async () => {
    const bytes = deferred<Blob>();
    const response = new Response("private-old-bytes");
    vi.spyOn(response, "blob").mockImplementation(() => bytes.promise);
    globalThis.fetch = vi.fn(async () => response);
    const view = render(<AuthenticatedDownload path="/api/v1/private-export" filename="evidence.json">Export</AuthenticatedDownload>);
    act(click);
    await waitFor(() => expect(response.blob).toHaveBeenCalledOnce());
    view.unmount();
    await act(async () => bytes.resolve(new Blob(["private-old-bytes"])));
    expect(HTMLAnchorElement.prototype.click).not.toHaveBeenCalled();
  });

  it("allows unchanged-scope downloads and cleans up the object URL", async () => {
    globalThis.fetch = vi.fn(async () => new Response("retained historical evidence", { headers: { "content-disposition": 'attachment; filename="retained.json"' } }));
    const revoke = vi.spyOn(URL, "revokeObjectURL");
    window.dispatchEvent(new StorageEvent("storage", { key: "unrelated" }));
    await downloadAuthenticatedResource("/api/v1/private-export", "fallback.json");
    expect(HTMLAnchorElement.prototype.click).toHaveBeenCalledOnce();
    expect(revoke).toHaveBeenCalledWith("blob:scope-test");
    expect(document.querySelector('a[download]')).toBeNull();
  });
});
