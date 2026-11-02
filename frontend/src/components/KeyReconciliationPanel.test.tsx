import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { mockFetch } from "../test/setup";
import KeyReconciliationPanel from "./KeyReconciliationPanel";

/* A live answer is not automatically the shape a panel reads.
 *
 * The panel used to call `r.data.scans.filter(...)` on whatever came back, so an
 * answer without `scans` threw an unhandled rejection and left the panel on
 * "Loading…" for ever — the screen then read as "still checking" instead of "this
 * page cannot tell". The guard is what makes the third state possible. */

describe("Key inventory reconciliation", () => {
  it("says the scan list was unreadable rather than staying on Loading…", async () => {
    mockFetch({ "/api/v1/scans*": {} });
    render(<KeyReconciliationPanel />);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /answered without a readable set of scans/,
    );
    expect(screen.getByRole("alert")).toHaveTextContent(/not the same as none existing/);
    expect(screen.queryByText("Loading…")).toBeNull();
  });

  it("says there is no key-inventory scan when the list is empty", async () => {
    mockFetch({ "/api/v1/scans*": { scans: [], total_count: 0, page: 1, page_size: 50 } });
    render(<KeyReconciliationPanel />);
    expect(await screen.findByText(/No key-inventory scan yet/)).toBeInTheDocument();
  });

  it("says the backend is offline when the read does not land", async () => {
    mockFetch({});
    render(<KeyReconciliationPanel />);
    expect(await screen.findByText("Backend offline.")).toBeInTheDocument();
  });
});
