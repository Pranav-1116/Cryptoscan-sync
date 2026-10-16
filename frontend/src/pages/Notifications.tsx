import { Link } from "react-router-dom";
import React, { useState } from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import { useLive, LiveStatus } from "../lib/useLive.js";
import { apiNotificationRoutingPut, apiNotificationDispatch, DispatchResult } from "../lib/api.js";

const CHANNELS = ["inApp", "email", "webhook", "siem"] as const;
const CHANNEL_LABEL: Record<string, string> = { inApp: "in-app", email: "email", webhook: "webhook", siem: "SIEM / SOC" };

type RouteItem = { id: string; name: string; severity: string; channels: Record<string, boolean> };

/* Notification center (spec §37) — in-app · email · webhook · SIEM.
   The event-class catalog AND defaults are served live by the control plane
   (/notifications/routing merges catalog defaults with persisted overrides);
   toggles PERSIST so the routing survives reloads. No static catalog. */

export default function Notifications() {
  const routing = useLive<{ routing: RouteItem[]; persisted?: boolean }>("/api/v1/notifications/routing", { routing: [] });
  const state = routing.data.routing ?? [];
  const [saved, setSaved] = useState<boolean | null>(null);
  const integ = useLive<{ integrations: any[] }>("/api/v1/enterprise/integrations", { integrations: [] });
  const integrations = integ.data.integrations ?? [];
  /* §4.8 (round 79): connector health is MEASURED from the outbound
   * delivery audit — the old row derived "CONNECTED" from the enabled
   * flag, which is configuration, not health. */
  const connHealth = useLive<{ connectors: Array<{ integration_id: string; status: string; detail: string }> }>(
    "/api/v1/health/connectors", { connectors: [] });
  const measured = new Map((connHealth.data.connectors ?? [])
    .map((c) => [String(c.integration_id), c]));
  /* §5 (round 76): the in-app channel DELIVERY — the feed below is what
   * the in-app column of the routing matrix actually gates. Verification
   * outcomes (VERIFIED / PARTIAL / FAILED / REGRESSION) land here. */
  const feed = useLive<{
    notifications: Array<{ id: string; ts: string | null; event_type: string;
      event_class: string; class_name: string; severity: string;
      detail: string | null; target: string | null }>;
    count: number; routed_classes: string[]; note: string;
  }>("/api/v1/notifications/feed", { notifications: [], count: 0, routed_classes: [], note: "" });
  const notifications = feed.data.notifications ?? [];

  /* §5 (round 77): the OUTWARD channel consumer — the webhook / SIEM columns
   * of the matrix gate a real operator-triggered drain that sends each NEW
   * routed notification to the registered integrations its channel claims
   * (siem → SIEM/SOAR receivers, webhook → ITSM/CMDB receivers), over real
   * signed HTTP, every attempt audited in the integrations delivery log. */
  const [drain, setDrain] = useState<DispatchResult | null>(null);
  const [draining, setDraining] = useState(false);
  const [drainError, setDrainError] = useState<string | null>(null);
  const runDispatch = () => {
    setDraining(true); setDrainError(null);
    apiNotificationDispatch(50)
      .then((r) => { if (r.ok && r.data) setDrain(r.data); else setDrainError(r.error ?? "dispatch failed"); })
      .catch((e) => setDrainError(String(e)))
      .finally(() => setDraining(false));
  };

  const persist = (next: RouteItem[]) => {
    setSaved(null);
    apiNotificationRoutingPut(next.map((n) => ({ id: n.id, name: n.name, severity: n.severity, channels: n.channels })))
      .then((r) => { setSaved(!!r.ok); if (r.ok) routing.reload(); });
  };

  const toggle = (idx: number, ch: (typeof CHANNELS)[number]) => {
    const next = state.map((n, i) => (i === idx ? { ...n, channels: { ...n.channels, [ch]: !n.channels[ch] } } : n));
    persist(next);
  };

  const enabled = (ch: (typeof CHANNELS)[number]) => state.filter((n) => n.channels[ch]).length;

  return (
    <>
      <PageHead
        crumb="operate / notifications"
        title="Notification center"
        sub="Every event class routes to the channels you choose — in-app, email, webhook, SIEM/SOC"
        right={<Badge tone="green"><span className="dot" /> CHANNELS ACTIVE: {enabled("inApp")} / {enabled("email")} / {enabled("webhook")} / {enabled("siem")}</Badge>}
      />
      <div style={{ marginBottom: 12 }} className="row">
        <LiveStatus loading={integ.loading} error={integ.error} />
        {saved === true && <Badge tone="green">routing saved</Badge>}
        {saved === false && <Badge tone="red">save failed</Badge>}
      </div>
      <Panel
        title="In-app notification feed"
        sub="the in-app column of the matrix below DELIVERS here — switch a class off and it leaves this feed"
      >
        <Table
          head={["severity", "class", "what happened", "when"]}
          rows={notifications.map((n) => [
            <Badge tone={n.severity === "CRITICAL" || n.severity === "HIGH" ? "red" : n.severity === "MEDIUM" ? "amber" : ""}>{n.severity}</Badge>,
            <span style={{ fontSize: 12.5 }}>{n.class_name}</span>,
            <span style={{ fontSize: 12.5 }}>{n.detail || "—"}</span>,
            <span className="dim" style={{ fontSize: 12 }}>{n.ts ? new Date(n.ts).toLocaleString() : "—"}</span>,
          ])}
        />
        {!notifications.length && (
          <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>
            No routed notifications yet — events appear here when a mapped event class fires and
            its in-app routing is on. Verification outcomes (VERIFIED / PARTIAL / FAILED /
            REGRESSION) are the flagship class.
          </div>
        )}
        <div className="dim" style={{ fontSize: 11.5, marginTop: 8 }}>
          Email / webhook / SIEM delivery runs through the integrations surface; emitted event
          types without a catalog mapping stay in the events stream, unrouted.
        </div>
      </Panel>

      <Panel title="Event → channel routing" sub="toggles are saved to the control plane — changes persist across sessions" className="mt">
        <Table
          head={["event type", "severity", ...CHANNELS.map((c) => CHANNEL_LABEL[c])]}
          rows={state.map((n, i) => [
            <span style={{ fontWeight: 600 }} key="n">{n.name}</span>,
            <Badge key="s">{n.severity}</Badge>,
            ...CHANNELS.map((c) => (
              <button
                key={c}
                className="btn sm"
                style={n.channels[c] ? { borderColor: "var(--green)", color: "var(--green)" } : { opacity: 0.55 }}
                onClick={() => toggle(i, c)}
              >
                {n.channels[c] ? "ON" : "off"}
              </button>
            )),
          ])}
        />
      </Panel>
      <Panel title="Outward delivery — webhook / SIEM dispatch" sub="the operator-triggered drain the two outward columns actually gate" className="mt">
        <div className="dim" style={{ fontSize: 13, marginBottom: 10 }}>
          Dispatch sends each <b>new</b> routed notification once (per-tenant dispatch registry): the <b>SIEM / SOC</b> column delivers to registered SIEM/SOAR integrations, the <b>webhook</b> column to ITSM/CMDB receivers — over real signed HTTP, every attempt audited in the integrations delivery log. <b>Email routing is stored but no SMTP transport is wired in this deployment</b> — nothing is claimed sent. Unmapped event types are never force-fit.
        </div>
        <div className="row" style={{ marginBottom: 10 }}>
          <button className="btn" onClick={runDispatch} disabled={draining}>{draining ? "dispatching…" : "Dispatch outward now"}</button>
          {drainError && <Badge tone="red">dispatch failed: {drainError}</Badge>}
          {drain && !drainError && (
            <Badge tone={drain.failed > 0 ? "amber" : "green"}>
              dispatched {drain.dispatched} · delivered {drain.delivered} · failed {drain.failed} · skipped {drain.skipped}
            </Badge>
          )}
        </div>
        {drain && (
          drain.attempts.length ? (
            <Table
              head={["Event", "Class", "Channels", "Outcome"]}
              rows={drain.attempts.map((a) => [
                <span key="e" style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{a.event_type}</span>,
                a.event_class,
                a.channels.join(", "),
                <span key="o">
                  {a.results.map((r, i) => (
                    <span key={i} style={{ fontFamily: "var(--mono)", fontSize: 11.5, display: "block" }}>
                      {r.integration_id}: <b style={{ color: r.status === "delivered" ? "var(--ok, green)" : r.status === "failed" ? "var(--bad, crimson)" : "inherit" }}>{r.status}</b>
                      {r.http_status ? ` (HTTP ${r.http_status})` : ""}{r.error ? ` — ${r.error}` : ""}
                    </span>
                  ))}
                </span>,
              ])}
            />
          ) : (
            <div className="dim" style={{ fontSize: 13 }}>Nothing new to dispatch — every routed notification in the recent window has already been sent outward exactly once.</div>
          )
        )}
      </Panel>
      <div className="grid cols-2 mt">
        <Panel title="Channels" sub="delivery configuration">
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {CHANNELS.map((c) => (
              <div className="spread" key={c}>
                <span style={{ fontWeight: 600 }}>{CHANNEL_LABEL[c]}</span>
                <Badge tone={enabled(c) > 0 ? "green" : "amber"}>{enabled(c)}/{state.length} event types</Badge>
              </div>
            ))}
          </div>
        </Panel>
        <Panel title="SIEM / SOC integration" sub="events fan out to every connected system">
          {integrations.length ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 8, fontFamily: "var(--mono)", fontSize: 12.5 }}>
              {integrations.map((i, idx) => {
                const m = measured.get(String(i.id));
                const status = m?.status ?? (i.enabled ? "Not measured" : "Disabled");
                return (
                  <div className="spread" key={i.id ?? i.name ?? idx}>
                    <span>{i.name ?? i.provider ?? i.kind}</span>
                    <Badge tone={status === "Operational" ? "green" : status === "Degraded" ? "red" : status === "Disabled" ? "neutral" : "amber"}>{status}</Badge>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="dim" style={{ fontSize: 13 }}>No integrations registered yet. Configure SIEM/SOC, ticketing and webhook destinations in <Link to="/integrations">Integrations</Link>.</div>
          )}
          <div className="dim" style={{ fontSize: 12, marginTop: 10 }}>
            Status is measured from the outbound delivery audit — a registered connector with no delivery history is Not measured, never a derived &quot;connected&quot;.
          </div>
          <Link to="/integrations" className="mono" style={{ fontSize: 12, display: "inline-block", marginTop: 12 }}>manage integrations →</Link>
        </Panel>
      </div>
    </>
  );
}
