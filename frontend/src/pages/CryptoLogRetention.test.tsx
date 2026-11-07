/* Retention tests (docs/cryptolog/01_PRODUCT_SPEC.md §10): policy in the
   open with its disposition bar, plans drawn as projections —
   DELETE_CANDIDATE is the strongest claim, never_proven says execution is
   separate, and refused reads are named refusals. */

import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { mockFetch, offlineFetch } from "../test/setup";
import CryptoLogRetention from "./CryptoLogRetention";

const policy = (over: Record<string, unknown> = {}) => ({
  schema: "cryptoscan.cryptolog-retention/1",
  activity_retention_days: 180,
  change_retention_days: 3650,
  audit_retention_days: 3650,
  archive_after_days: 90,
  require_disposition_ref: true,
  note: "policy is stated, not hidden: every planned action cites the window it applied, and a deletion always requires a named disposition — the plan grants none",
  ...over,
});

const plan = (over: Record<string, unknown> = {}) => ({
  schema: "cryptoscan.cryptolog-retention-plan/1",
  generated_at: "2026-11-07T12:00:00+00:00",
  policy: policy(),
  counts: { RETAIN: 1, ARCHIVE: 1, DELETE_CANDIDATE: 1 },
  rows: [
    { event_id: "clog_01", retention_class: "SHORT", age_days: 6, action: "RETAIN", reason: "recorded 6 days ago, inside its retention window" },
    { event_id: "clog_02", retention_class: "LONG", age_days: 200, action: "ARCHIVE", reason: "recorded 200 days ago, beyond the 90-day archive threshold and inside its retention window" },
    { event_id: "clog_03", retention_class: "SHORT", age_days: 1041, action: "DELETE_CANDIDATE", reason: "recorded 1041 days ago, beyond the 180-day short retention window" },
  ],
  proven: ["each action is derived from the recorded observation time and the stated policy, deterministically"],
  not_proven: [
    "that any deletion is approved: DELETE_CANDIDATE is a projection, and execution needs a named disposition this plan does not grant",
    "that execution occurred: a plan is never presented as a production change",
  ],
  note: "a retention plan is a projection over recorded events; executing it is a separate, disposition-gated act",
  ...over,
});

const renderRetention = () => render(<CryptoLogRetention />);

describe("CryptoLog retention (§10)", () => {
  it("shows the policy windows and the disposition bar", async () => {
    mockFetch({ "/api/v1/cryptolog/retention/policy": policy() });
    renderRetention();
    const panel = await screen.findByTestId("retention-policy");
    expect(panel).toHaveTextContent(/180 days/);
    expect(panel).toHaveTextContent(/3650 days/);
    expect(panel).toHaveTextContent(/disposition required for deletion: yes/);
    expect(screen.getByTestId("retention-policy-note")).toHaveTextContent(/never default drawn|grants none/);
  });

  it("draws the plan as a projection and keeps the not-proven boundary on screen", async () => {
    mockFetch({
      "/api/v1/cryptolog/retention/policy": policy(),
      "/api/v1/cryptolog/retention/plan": plan(),
    });
    renderRetention();
    fireEvent.click(await screen.findByTestId("run-retention-plan"));
    const panel = await screen.findByTestId("retention-plan");
    expect(panel).toHaveTextContent(/retain 1/);
    expect(panel).toHaveTextContent(/archive 1/);
    expect(panel).toHaveTextContent(/delete candidates 1/);
    expect(screen.getByTestId("retention-plan-rows")).toHaveTextContent(/DELETE_CANDIDATE/);
    expect(screen.getByTestId("retention-plan-not-proven")).toHaveTextContent(/never presented as a production change/);
    expect(screen.getByTestId("retention-plan-not-proven")).toHaveTextContent(/disposition this plan does not grant/);
  });

  it("states an empty plan as a gap, never a clean estate", async () => {
    mockFetch({
      "/api/v1/cryptolog/retention/policy": policy(),
      "/api/v1/cryptolog/retention/plan": plan({ counts: {}, rows: [] }),
    });
    renderRetention();
    fireEvent.click(await screen.findByTestId("run-retention-plan"));
    expect(await screen.findByTestId("retention-plan-empty")).toHaveTextContent(/gap in the record, never a clean estate/);
  });

  it("names refused reads instead of defaults and empty plans", async () => {
    offlineFetch();
    renderRetention();
    expect(await screen.findByTestId("retention-policy-failure")).toHaveTextContent(/never a default drawn as a policy/);
    fireEvent.click(screen.getByTestId("run-retention-plan"));
    expect(await screen.findByTestId("retention-plan-failure")).toHaveTextContent(/never an empty plan drawn as a clean estate/);
  });
});
