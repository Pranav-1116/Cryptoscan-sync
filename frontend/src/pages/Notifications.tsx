import React, { useState } from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import { notificationTypes, integrations } from "../data/initial.js";

const CHANNELS = ["inApp", "email", "webhook", "siem"] as const;
const CHANNEL_LABEL: Record<string, string> = { inApp: "in-app", email: "email", webhook: "webhook", siem: "SIEM / SOC" };

/* Notification center (spec §37) — in-app · email · webhook · SIEM. */

export default function Notifications() {
  const [state, setState] = useState(notificationTypes.map((n) => ({ ...n })));

  const toggle = (idx: number, ch: (typeof CHANNELS)[number]) => {
    setState((prev) => prev.map((n, i) => (i === idx ? { ...n, channels: { ...n.channels, [ch]: !n.channels[ch] } } : n)));
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
      <Panel title="Event → channel routing" sub="toggles are stored per tenant — changes take effect immediately">
        <Table
          head={["event type", "severity", ...CHANNELS.map((c) => CHANNEL_LABEL[c])]}
          rows={state.map((n, i) => [
            <span style={{ fontWeight: 600 }}>{n.name}</span>,
            <Badge>{n.severity}</Badge>,
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
              {integrations.map((i) => (
                <div className="spread" key={i.name}><span>{i.name}</span><Badge tone={i.status === "CONNECTED" ? "green" : "amber"}>{i.status}</Badge></div>
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
