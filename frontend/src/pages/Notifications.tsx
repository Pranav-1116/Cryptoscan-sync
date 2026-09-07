import React, { useState } from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import { useLive, LiveStatus } from "../lib/useLive.js";
import { apiNotificationRoutingPut } from "../lib/api.js";

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
      <Panel title="Event → channel routing" sub="toggles are saved to the control plane — changes persist across sessions">
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
              {integrations.map((i, idx) => (
                <div className="spread" key={i.id ?? i.name ?? idx}><span>{i.name ?? i.provider ?? i.kind}</span><Badge tone={(i.status ?? "").toLowerCase() === "connected" || i.enabled ? "green" : "amber"}>{i.status ?? (i.enabled ? "CONNECTED" : "DISABLED")}</Badge></div>
              ))}
            </div>
          ) : (
            <div className="dim" style={{ fontSize: 13 }}>No integrations connected yet. Configure SIEM/SOC, ticketing and webhook destinations in <a href="#/integrations">Integrations</a>.</div>
          )}
          <a href="#/integrations" className="mono" style={{ fontSize: 12, display: "inline-block", marginTop: 12 }}>manage integrations →</a>
        </Panel>
      </div>
    </>
  );
}
