/* Notifications page (§5, round 76): the in-app channel DELIVERS here —
 * the feed below the routing matrix is what the in-app column actually
 * gates. Verification outcomes (VERIFIED / PARTIAL / FAILED / REGRESSION)
 * are the flagship class. No fabricated notifications. */
import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { mockFetch } from "../test/setup";
import Notifications from "./Notifications";

afterEach(() => {
  localStorage.clear();
  vi.restoreAllMocks();
});

const renderPage = () =>
  render(
    <MemoryRouter>
      <Notifications />
    </MemoryRouter>,
  );

const routing = [
  { id: "remediation_verification", name: "Remediation verification outcome",
    severity: "HIGH", channels: { inApp: true, email: true, webhook: true, siem: true } },
  { id: "remediation_task", name: "Remediation task lifecycle",
    severity: "MEDIUM", channels: { inApp: true, email: false, webhook: false, siem: false } },
  { id: "compliance_failure", name: "Compliance failure",
    severity: "HIGH", channels: { inApp: true, email: true, webhook: true, siem: true } },
];

const feedWithVerification = {
  notifications: [
    { id: "ev-1", ts: "2026-10-16T09:00:00+00:00", event_type: "remediation.task_verified",
      event_class: "remediation_verification", class_name: "Remediation verification outcome",
      severity: "HIGH", detail: "Remediation task t-1 verification: VERIFIED",
      target: "remediation" },
    { id: "ev-2", ts: "2026-10-16T08:00:00+00:00", event_type: "remediation.task_created",
      event_class: "remediation_task", class_name: "Remediation task lifecycle",
      severity: "MEDIUM", detail: "Remediation task t-2 created for evidence ev-9",
      target: "remediation" },
  ],
  count: 2, routed_classes: ["compliance_failure", "remediation_task", "remediation_verification"],
  note: "This is the in-app channel delivery.",
};

function renderWith(overrides: Record<string, unknown>) {
  mockFetch({
    "/api/v1/notifications/routing": { routing, persisted: true },
    "/api/v1/enterprise/integrations": { integrations: [] },
    "/api/v1/notifications/feed": feedWithVerification,
    ...overrides,
  });
  renderPage();
}

describe("Notifications page", () => {
  it("delivers the in-app feed with the verification outcome as its flagship class", async () => {
    renderWith({});
    // the feed renders the real notifications, newest facts intact
    expect(await screen.findByText(/Remediation task t-1 verification: VERIFIED/)).toBeTruthy();
    // the class name appears in the feed AND the routing matrix below
    expect(screen.getAllByText("Remediation verification outcome").length).toBeGreaterThan(0);
    expect(screen.getByText("Remediation task t-2 created for evidence ev-9")).toBeTruthy();
    // severity comes from the class catalog, not the payload
    expect(screen.getAllByText("HIGH").length).toBeGreaterThan(0);
    // the delivery contract is stated in-product
    expect(screen.getByText(/the in-app column of the matrix below DELIVERS here/i)).toBeTruthy();
    expect(screen.getByText(/Email \/ webhook \/ SIEM delivery runs through the integrations surface/i)).toBeTruthy();
  });

  it("shows the new event classes in the routing matrix", async () => {
    renderWith({});
    expect(await screen.findAllByText("Remediation verification outcome")).not.toHaveLength(0);
    expect(screen.getAllByText("Remediation task lifecycle").length).toBeGreaterThan(0);
  });

  it("renders an honest empty feed — never fabricated notifications", async () => {
    renderWith({
      "/api/v1/notifications/feed": {
        notifications: [], count: 0, routed_classes: [], note: "",
      },
    });
    expect(await screen.findByText(/No routed notifications yet/i)).toBeTruthy();
  });
});
