import { describe, expect, it } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";
import Audit from "./Audit";

/* The audit trail's honest states.
 *
 * On an audit screen the dangerous failure is not an error message — it is a
 * green badge over a chain nobody read, or an empty table standing in for a
 * trail that could not be fetched. Each test below pins one of those. */

const list = "/api/v1/auth/audit";
const verify = "/api/v1/auth/audit/verify";

const event = (id: string, extra: Record<string, unknown> = {}) => ({
  id, actor: "alice.operator", action: "login", target_type: "user", target_id: id,
  outcome: "SUCCESS", ip_address: "10.10.4.7", created_at: "2026-10-31T09:15:00Z", ...extra,
});

describe("Audit trail", () => {
  it("renders the recorded rows with actor, action and time", async () => {
    mockFetch({
      [list]: { events: [event("evt-1")], page: 1, page_size: 50 },
      [verify]: { status: "OK", checked: 12, entry_count: 12, chain_head: "a91f" },
    });
    renderWithProviders(<Audit />);
    expect(await screen.findByText("alice.operator")).toBeInTheDocument();
    expect(screen.getByText("2026-10-31T09:15:00Z")).toBeInTheDocument();
    expect(screen.getByText("user evt-1")).toBeInTheDocument();
    expect(screen.getByText("CHAIN VERIFIED")).toBeInTheDocument();
  });

  it("quotes the server's own counts when the chain verifies", async () => {
    mockFetch({
      [list]: { events: [event("evt-1")], page: 1, page_size: 50 },
      [verify]: { status: "OK", checked: 12, entry_count: 12, chain_head: "a91f" },
    });
    renderWithProviders(<Audit />);
    const verdict = await screen.findByText(/Verified: 12 link\(s\) checked across 12 recorded event\(s\)/);
    expect(verdict).toBeInTheDocument();
    expect(screen.getByText(/chain head a91f/)).toBeInTheDocument();
  });

  it("shows a broken chain as TAMPERED, with the break and the reason", async () => {
    mockFetch({
      [list]: { events: [event("evt-1")], page: 1, page_size: 50 },
      [verify]: { status: "TAMPERED", checked: 8, entry_count: 12, break_at_sequence: 9, reason: "hash mismatch at entry 9" },
    });
    renderWithProviders(<Audit />);
    expect(await screen.findByText("TAMPERED.")).toBeInTheDocument();
    expect(screen.getByText(/breaks at sequence 9: hash mismatch at entry 9/)).toBeInTheDocument();
    expect(screen.getByText("CHAIN NOT VERIFIED")).toBeInTheDocument();
    expect(screen.queryByText("CHAIN VERIFIED")).toBeNull();
  });

  it("never shows a verified chain when the verifier did not answer", async () => {
    mockFetch({
      [list]: { events: [event("evt-1")], page: 1, page_size: 50 },
      // the verify endpoint is deliberately absent → 404 from mockFetch
    });
    renderWithProviders(<Audit />);
    expect(await screen.findByText(/CHAIN NOT VERIFIED\./)).toBeInTheDocument();
    expect(screen.queryByText("CHAIN VERIFIED")).toBeNull();
    // the trail itself still renders: an unproven chain is not a hidden trail
    expect(screen.getByText("alice.operator")).toBeInTheDocument();
  });

  it("distinguishes a trail it could not read from an empty trail", async () => {
    mockFetch({ [list]: new Response("{}", { status: 403 }), [verify]: { status: "OK", checked: 0, entry_count: 0 } });
    renderWithProviders(<Audit />);
    expect(await screen.findByText(/The audit trail could not be read/)).toBeInTheDocument();
    expect(screen.getByText(/This is not an empty\s+trail/)).toBeInTheDocument();
    expect(screen.queryByText(/No action has been recorded yet/)).toBeNull();
  });

  it("says the window is empty when the server returns no events", async () => {
    mockFetch({
      [list]: { events: [], page: 1, page_size: 50 },
      [verify]: { status: "OK", checked: 0, entry_count: 0 },
    });
    renderWithProviders(<Audit />);
    expect(await screen.findByText(/No action has been recorded yet/)).toBeInTheDocument();
    expect(screen.queryByText(/could not be read/)).toBeNull();
  });

  it("sends the filters to the API rather than hiding rows on the client", async () => {
    const fetchMock = mockFetch({
      [list]: { events: [event("evt-1")], page: 1, page_size: 50 },
      [verify]: { status: "OK", checked: 1, entry_count: 1 },
    });
    renderWithProviders(<Audit />);
    fireEvent.change(await screen.findByLabelText("Filter by actor"), { target: { value: "bob" } });
    fireEvent.change(screen.getByLabelText("Filter by action"), { target: { value: "export_bom" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    await waitFor(() => {
      const urls = fetchMock.mock.calls.map(([input]) => String(input));
      expect(urls.some((u) => u.includes("actor=bob") && u.includes("action=export_bom"))).toBe(true);
    });
    // and the page says a filtered window is a smaller history
    expect(await screen.findByText(/Filtered through the API/)).toBeInTheDocument();
  });

  it("states the page bound instead of implying the trail ends here", async () => {
    const many = Array.from({ length: 50 }, (_, i) => event(`evt-${i + 1}`));
    mockFetch({
      [list]: { events: many, page: 1, page_size: 50 },
      [verify]: { status: "OK", checked: 50, entry_count: 50 },
    });
    renderWithProviders(<Audit />);
    expect(await screen.findByText(/page 1 · 50 row\(s\) this page/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Older" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Newer" })).toBeDisabled();
  });
});
