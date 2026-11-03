import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { mockFetch } from "../test/setup";
import Resilience from "./Resilience";

function openBackup() {
  render(<Resilience />);
  fireEvent.click(screen.getByRole("button", { name: /^encrypted backups$/i }));
}

describe("Resilience backup authority", () => {
  it("never manufactures retention examples or offers an unqualified restore", async () => {
    const fetch = mockFetch({ "/api/v1/resilience/backup/list": { backups: [] } });
    openBackup();
    expect(screen.queryByRole("button", { name: /^restore$/i })).toBeNull();
    expect(screen.queryByText(/daily-stale|daily-fresh/)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /plan retention for stored backups/i }));
    await waitFor(() => expect(screen.getAllByText(/no retained backups exist/i).length).toBeGreaterThan(0));
    expect(fetch.mock.calls.some(([url]) => String(url).includes("/retention-plan"))).toBe(false);
  });

  it("plans retention only for records returned by the real backup list", async () => {
    const backups = [{ backup_id: "retained-real-1", created_at: "2026-11-01T00:00:00Z" }];
    const fetch = mockFetch({
      "/api/v1/resilience/backup/list": { backups },
      "/api/v1/resilience/backup/retention-plan": (_url: string, init?: RequestInit) => {
        expect(JSON.parse(String(init?.body)).backups).toEqual(backups);
        return { kept: 1, purged: 0, purge: [] };
      },
    });
    openBackup();
    fireEvent.click(screen.getByRole("button", { name: /plan retention for stored backups/i }));
    await waitFor(() => expect(screen.getByText(/kept 1 · purged 0/)).toBeTruthy());
    expect(fetch.mock.calls.some(([url]) => String(url).includes("/retention-plan"))).toBe(true);
  });

  it("surfaces a failed live dump instead of presenting a green backup receipt", async () => {
    mockFetch({
      "/api/v1/resilience/backup/run-scheduled": {
        ran: 1, skipped: 0, stored_backups: 0,
        results: [{ database_id: "named-db", ok: false, error: "pg_dump unavailable" }],
      },
      "/api/v1/resilience/backup/list": { backups: [] },
    });
    openBackup();
    fireEvent.change(screen.getByLabelText(/approved PostgreSQL database name/i),
                     { target: { value: "named-db" } });
    fireEvent.click(screen.getByRole("button", { name: /run scheduled backup cycle/i }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("pg_dump unavailable"));
    expect(screen.getByText(/failures reported/)).toBeTruthy();
  });
});
