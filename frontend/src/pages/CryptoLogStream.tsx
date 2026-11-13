import React, { useEffect, useState } from "react";
import { Badge, Panel } from "../components/ui.jsx";
import {
  apiCryptologEvents, type ApiResult, type CryptologEventRow,
} from "../lib/api.js";

/* Workspace 1 — Crypto Event Stream: a chronological stream of recorded
   cryptographic events across authorized bank assets. The architecture and
   detection flow are RULES this workspace works by, never copy shown to the
   operator. The stream counts what the store returned: "X loaded", never an
   invented total, and an empty stream is absence of recorded events, never
   a quiet estate. */

function observedAt(event: CryptologEventRow): string {
  const observation = event.observation as Record<string, unknown>;
  return String(observation?.observed_at ?? "") || "unknown time";
}

export default function CryptoLogStream() {
  const [events, setEvents] = useState<CryptologEventRow[]>([]);
  const [failure, setFailure] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(0);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    apiCryptologEvents({ limit: 25 }).then((result: ApiResult<{ events: CryptologEventRow[]; returned: number }>) => {
      if (!alive) return;
      if (!result.data) {
        setFailure(result.error ?? "the event stream did not load");
      } else {
        setEvents(result.data.events);
        setLoaded(result.data.returned);
      }
      setLoading(false);
    });
    return () => { alive = false; };
  }, []);

  const sorted = [...events].sort((a, b) =>
    String(observedAt(b)).localeCompare(String(observedAt(a))));

  return (
    <div data-testid="cryptolog-stream">
      <Panel title="Crypto Event Stream" sub="recorded cryptographic events across authorized bank assets — certificate changes, TLS configuration changes, HSM status changes, algorithm and crypto-provider changes">
        {loading ? (
          <div className="dim" data-testid="stream-loading" role="status">
            Reading recorded events… no absence can be claimed until the read completes.
          </div>
        ) : failure ? (
          <div className="dim" data-testid="stream-failure">
            {failure} A source that could not be read is not a source with no events.
          </div>
        ) : sorted.length === 0 ? (
          <div
            data-testid="stream-empty"
            style={{
              display: "flex", gap: 10, alignItems: "flex-start",
              border: "1px dashed var(--rule)", borderRadius: 8, padding: "12px 14px",
              background: "var(--panel-2)",
            }}
          >
            <span
              aria-hidden
              style={{ width: 8, height: 8, borderRadius: 99, border: "1.5px dashed var(--slate, #64748b)", marginTop: 4, flex: "0 0 auto" }}
            />
            <div className="dim" style={{ fontSize: 12, lineHeight: 1.5 }}>
              No events recorded. An empty stream is absence of recorded events —
              never a quiet estate — and this stream never invents events.
            </div>
          </div>
        ) : (
          <>
            <div className="dim" data-testid="stream-loaded" style={{ fontSize: 12, marginBottom: 8 }}>
              {loaded} loaded · newest first among the loaded events · the store may hold more
            </div>
            <div data-testid="stream-rows" style={{ display: "grid", gap: 6 }}>
              {sorted.map((event) => (
                <div key={event.event_id} style={{
                  border: "1px solid var(--rule)", borderRadius: 6, padding: "8px 10px",
                  display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap",
                }}>
                  <span className="mono" data-testid="stream-row-time" style={{ fontSize: 11, color: "var(--faint)", minWidth: 150 }}>
                    {observedAt(event)}
                  </span>
                  <Badge tone={event.severity === "HIGH" || event.severity === "CRITICAL" ? "red"
                    : event.severity === "MEDIUM" ? "amber" : "slate"}>
                    {event.severity}
                  </Badge>
                  <span className="mono" style={{ fontSize: 12 }}>{event.event_type}</span>
                  <span className="dim" style={{ fontSize: 12 }}>{event.asset_id}</span>
                  <span className="dim" style={{ fontSize: 11, marginLeft: "auto" }}>
                    {event.investigation_status}
                  </span>
                </div>
              ))}
            </div>
          </>
        )}
      </Panel>
    </div>
  );
}
