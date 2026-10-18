/* Notifications page (§5, round 76): the in-app channel DELIVERS here —
 * the feed below the routing matrix is what the in-app column actually
 * gates. Verification outcomes (VERIFIED / PARTIAL / FAILED / REGRESSION)
 * are the flagship class. No fabricated notifications. */
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
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

  it("dispatches outward over the drain button and shows per-integration outcomes", async () => {
    const dispatchResult = {
      ok: true, window: 6, examined: 1, dispatched: 1, registry_size: 1,
      delivered: 1, failed: 1, skipped: 0, email_routed: 1,
      integrations: { siem: 1, webhook: 1 },
      attempts: [{
        monitor_event_id: "ev-1", event_type: "remediation.task_verified",
        event_class: "remediation_verification", channels: ["siem", "webhook"],
        results: [
          { integration_id: "soc-1", kind: "siem", endpoint: "https://soc.example/hook",
            status: "delivered", http_status: 200, error: null, attempts: 1 },
          { integration_id: "ops-1", kind: "itsm", endpoint: "http://ops.example/hook",
            status: "failed", http_status: 503, error: "receiver unavailable", attempts: 2 },
        ],
      }],
      note: "Operator-triggered outward drain.",
    };
    const fetchMock = mockFetch({
      "/api/v1/notifications/routing": { routing },
      "/api/v1/enterprise/integrations": { integrations: [] },
      "/api/v1/notifications/feed": feedWithVerification,
      "/api/v1/notifications/dispatch": dispatchResult,
      "/api/v1/health/connectors": { connectors: [] },
    });
    renderPage();
    const btn = await screen.findByRole("button", { name: /Dispatch outward now/i });
    fireEvent.click(btn);
    // the POST hit the real dispatch route
    await waitFor(() => {
      const called = fetchMock.mock.calls.some((call) => String(call?.[0]).includes("/api/v1/notifications/dispatch"));
      expect(called).toBe(true);
    });
    // honest per-attempt outcome rows — delivered AND failed, never fabricated
    expect(await screen.findByText(/dispatched 1 · delivered 1 · failed 1 · skipped 0/)).toBeTruthy();
    expect(screen.getByText(/soc-1:/)).toBeTruthy();
    expect(screen.getByText(/ops-1:/)).toBeTruthy();
    expect(screen.getByText(/receiver unavailable/)).toBeTruthy();
    // the email channel stays count-only, stated in-product
    expect(screen.getByText(/Email routing is stored but no SMTP transport is wired/i)).toBeTruthy();
  });

  it("shows MEASURED connector status — never a CONNECTED derivation from the enabled flag", async () => {
    mockFetch({
      "/api/v1/notifications/routing": { routing },
      "/api/v1/enterprise/integrations": { integrations: [
        { id: "soc-1", kind: "siem", provider: "webhook", name: "soc", enabled: true },
        { id: "ops-1", kind: "itsm", provider: "webhook", name: "ops", enabled: true },
      ] },
      "/api/v1/notifications/feed": feedWithVerification,
      "/api/v1/health/connectors": { connectors: [
        { integration_id: "soc-1", status: "Operational", detail: "delivered" },
        { integration_id: "ops-1", status: "Not measured", detail: "no delivery attempt recorded" },
      ] },
    });
    renderPage();
    // the delivered connector is Operational; the registered-but-never-
    // delivered one is Not measured — CONNECTED is never fabricated
    expect(await screen.findByText("Operational")).toBeTruthy();
    expect(screen.getAllByText("Not measured").length).toBeGreaterThan(0);
    expect(screen.queryByText("CONNECTED")).toBeNull();
    expect(screen.getByText(/measured from the outbound delivery audit/i)).toBeTruthy();
  });

  it("renders the honest nothing-new state after a dry drain", async () => {
    const dispatchResult = {
      ok: true, window: 6, examined: 0, dispatched: 0, registry_size: 3,
      delivered: 0, failed: 0, skipped: 0, email_routed: 0,
      integrations: { siem: 0, webhook: 0 }, attempts: [], note: "",
    };
    mockFetch({
      "/api/v1/notifications/routing": { routing },
      "/api/v1/enterprise/integrations": { integrations: [] },
      "/api/v1/notifications/feed": feedWithVerification,
      "/api/v1/notifications/dispatch": dispatchResult,
    });
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: /Dispatch outward now/i }));
    expect(await screen.findByText(/No destination attempts in this drain/i)).toBeTruthy();
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

it("does not label deferred receipts or legacy history as delivered", async () => {
  mockFetch({
    "/api/v1/notifications/routing": { routing },
    "/api/v1/enterprise/integrations": { integrations: [] },
    "/api/v1/notifications/feed": feedWithVerification,
    "/api/v1/notifications/dispatch": {
      ok: true, window: 0, examined: 0, dispatched: 0, registry_size: 4,
      delivered: 0, failed: 0, skipped: 0, email_routed: 0,
      receipts: { failed: 1, inflight: 1, legacy_unknown: 2 },
      integrations: {}, attempts: [], note: "",
    },
  });
  renderPage();
  fireEvent.click(await screen.findByRole("button", { name: /Dispatch outward now/i }));
  expect(await screen.findByText(/Pending receipts: 2; legacy outcomes unknown: 2/i)).toBeTruthy();
  expect(screen.getByText(/does not prove all events were delivered/i)).toBeTruthy();
  expect(screen.queryByText(/exactly once/i)).toBeNull();
  expect(screen.getByText(/at-least-once delivery/i)).toBeTruthy();
});

it("renders a lost receipt fence as unconfirmed, not a durable delivered outcome", async () => {
  mockFetch({
    "/api/v1/notifications/routing": { routing },
    "/api/v1/enterprise/integrations": { integrations: [] },
    "/api/v1/notifications/feed": feedWithVerification,
    "/api/v1/notifications/dispatch": {
      ok: false, window: 0, examined: 1, dispatched: 1, registry_size: 1,
      delivered: 0, failed: 0, skipped: 0, email_routed: 0, lease_lost: 1,
      receipts: { inflight: 1 }, integrations: {}, note: "",
      attempts: [{ monitor_event_id: "m1", event_type: "remediation.task_verified", event_class: "remediation_verification",
        channels: ["siem"], results: [{ integration_id: "soc-1", provider: "webhook", kind: "siem",
          status: "delivered", http_status: 202, attempts: 1, error: null, recorded: false }] }],
    },
  });
  renderPage();
  fireEvent.click(await screen.findByRole("button", { name: /Dispatch outward now/i }));
  expect(await screen.findByText("receipt unconfirmed")).toBeTruthy();
  expect(screen.getByText(/delivered 0.*pending 1/i)).toBeTruthy();
});
