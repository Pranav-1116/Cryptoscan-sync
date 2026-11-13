/* Timeline tests (docs/cryptolog/01_PRODUCT_SPEC.md §9): server-side
   buckets, window filters that travel to the store, gaps named as gaps —
   never a quiet-estate claim — and named failures for failed reads. */

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { mockFetch, offlineFetch } from "../test/setup";
import CryptoLogTimeline from "./CryptoLogTimeline";

const timeline = (over: Record<string, unknown> = {}) => ({
  bucket: "day",
  window: { start_occurred: null, end_occurred: null },
  event_count: 3,
  buckets: [
    {
      bucket_start: "2026-11-07", total: 2,
      by_category: { TLS: 1, HSM_KMS: 1 },
      by_severity: { INFO: 1, HIGH: 1 },
      critical_changes: 1,
    },
    {
      bucket_start: "2026-11-08", total: 1,
      by_category: { TLS: 1 },
      by_severity: { MEDIUM: 1 },
      critical_changes: 0,
    },
  ],
  note: "Counts cover recorded CryptoLog events only. A gap is a gap in the record, never proof the estate was quiet: sampling or aggregation never claims complete event coverage.",
  ...over,
});

const renderTimeline = () => render(<CryptoLogTimeline />);

describe("CryptoLog timeline (§9)", () => {
  it("renders server-side buckets with their counts and the gap honesty note", async () => {
    mockFetch({ "/api/v1/cryptolog/timeline": timeline() });
    renderTimeline();
    expect(await screen.findByTestId("timeline-buckets")).toBeInTheDocument();
    const buckets = screen.getAllByTestId("timeline-bucket");
    expect(buckets).toHaveLength(2);
    expect(buckets[0]).toHaveTextContent(/2026-11-07/);
    expect(buckets[0]).toHaveTextContent(/2 events/);
    expect(buckets[0]).toHaveTextContent(/1 critical change/);
    expect(screen.getByTestId("timeline-count")).toHaveTextContent(/3 recorded events across 2 buckets/);
    expect(screen.getByTestId("timeline-note")).toHaveTextContent(/never proof the estate was quiet/);
    expect(screen.getByTestId("timeline-note")).toHaveTextContent(/never claims complete event coverage/);
  });

  it("sends bucket and window filters to the store, never a page-local filter", async () => {
    const fetchSpy = mockFetch({ "/api/v1/cryptolog/timeline": timeline() });
    renderTimeline();
    await screen.findByTestId("timeline-buckets");
    fireEvent.change(screen.getByLabelText("timeline bucket"), { target: { value: "hour" } });
    fireEvent.change(screen.getByLabelText("timeline start"), { target: { value: "2026-11-01" } });
    fireEvent.change(screen.getByLabelText("timeline asset"), { target: { value: "pay-api" } });
    fireEvent.click(screen.getByTestId("apply-timeline"));
    await waitFor(() => {
      const urls = fetchSpy.mock.calls.map(([u]) => String(u));
      expect(urls.some((u) => u.includes("bucket=hour") && u.includes("start_occurred=2026-11-01") &&
        u.includes("asset_id=pay-api"))).toBe(true);
    });
  });

  it("states an empty window as a gap in the record, never invented quiet", async () => {
    mockFetch({ "/api/v1/cryptolog/timeline": timeline({ event_count: 0, buckets: [] }) });
    renderTimeline();
    expect(await screen.findByTestId("timeline-empty")).toHaveTextContent(/gap in the record/);
    expect(screen.getByTestId("timeline-empty")).toHaveTextContent(/never invents events or quiet/);
  });

  it("names a failed read instead of drawing an empty timeline", async () => {
    offlineFetch();
    renderTimeline();
    expect(await screen.findByTestId("timeline-failure")).toHaveTextContent(/not a timeline with no events/);
    expect(screen.queryByTestId("timeline-buckets")).not.toBeInTheDocument();
  });
});
